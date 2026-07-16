/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file table_drive_lsc.c
 * @brief Function to start a table driven lsc.
 */

#include "table_driven_lsc.h"

#include "base/networking.h"
#include "kb_cache.h"
#include "plugutils.h"
#include "result_message.h"

#include <ctype.h> // for tolower()
#include <curl/curl.h>
#include <gnutls/gnutls.h>
#include <gvm/base/prefs.h>
#include <gvm/util/mqtt.h>      // for mqtt_reset
#include <gvm/util/uuidutils.h> // for gvm_uuid_make
#include <json-glib/json-glib.h>
#include <stddef.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  misc"

/** @brief LSC ran or didn't
 * 0 didn't run. 1 ran.
 */
static int lsc_flag = 0;

static gboolean
bounded_notus_field (const char *value, size_t max_length,
                     gboolean require_exact_length)
{
  size_t length;

  if (value == NULL || value[0] == '\0')
    return FALSE;

  length = strnlen (value, max_length + 1);
  if (length > max_length)
    return FALSE;

  return require_exact_length == FALSE || length == max_length;
}

static gboolean
bounded_notus_optional_field (const char *value, size_t max_length)
{
  return value == NULL || strnlen (value, max_length + 1) <= max_length;
}

static gboolean
bounded_notus_package_list (const char *packages)
{
  const gchar *cursor;
  size_t length;
  size_t line_bytes = 0;
  size_t package_count = 0;
  size_t separator_count = 0;

  if (packages == NULL)
    return FALSE;
  length = strnlen (packages, TABLE_DRIVEN_LSC_PACKAGE_LIST_MAX_BYTES + 1);
  if (length == 0 || length > TABLE_DRIVEN_LSC_PACKAGE_LIST_MAX_BYTES
      || !g_utf8_validate (packages, length, NULL))
    return FALSE;

  cursor = packages;
  while (*cursor)
    {
      const gchar *next;

      if (*cursor == '\n')
        {
          separator_count++;
          if (separator_count > TABLE_DRIVEN_LSC_PACKAGE_MAX_COUNT)
            return FALSE;
          if (line_bytes > 0)
            package_count++;
          line_bytes = 0;
          cursor++;
          continue;
        }

      if (!g_unichar_isprint (g_utf8_get_char (cursor)))
        return FALSE;
      next = g_utf8_next_char (cursor);
      line_bytes += (size_t) (next - cursor);
      if (line_bytes > TABLE_DRIVEN_LSC_PACKAGE_MAX_BYTES)
        return FALSE;
      cursor = next;
    }

  if (line_bytes > 0)
    package_count++;
  return package_count > 0
         && package_count <= TABLE_DRIVEN_LSC_PACKAGE_MAX_COUNT;
}

static gboolean
make_notus_start_ids (gchar **message_id, gchar **group_id)
{
  if (message_id == NULL || group_id == NULL)
    return FALSE;

  *message_id = gvm_uuid_make ();
  *group_id = gvm_uuid_make ();
  if (!bounded_notus_field (*message_id, TABLE_DRIVEN_LSC_ID_LENGTH, TRUE)
      || !bounded_notus_field (*group_id, TABLE_DRIVEN_LSC_ID_LENGTH, TRUE)
      || g_strcmp0 (*message_id, *group_id) == 0)
    {
      g_clear_pointer (message_id, g_free);
      g_clear_pointer (group_id, g_free);
      return FALSE;
    }

  return TRUE;
}

const char *
table_driven_lsc_transport_name (void)
{
  if (!prefs_get_bool ("table_driven_lsc")
      || (!prefs_get_bool ("mqtt_enabled")
          && !prefs_get_bool ("openvasd_lsc_enabled")))
    return "none";

  if (prefs_get ("openvasd_server"))
    return "openvasd";

  return "mqtt";
}

/** @brief Set lsc_flag to 1
 */
void
set_lsc_flag (void)
{
  lsc_flag = 1;
}

/** @brief Get lsc_flag value.
 */
int
lsc_has_run (void)
{
  return lsc_flag;
}

/**
 * @brief Split the package list string and creates a json array.
 *
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param[in/out] builder   The Json builder to add the array to.
 * @param[in]     packages  The installed package list as string
 *
 * @return JSON builder including the package list as array.
 */
static JsonBuilder *
add_packages_str_to_list (JsonBuilder *builder, const gchar *packages)
{
  gchar **package_list = NULL;

  json_builder_set_member_name (builder, "package_list");
  json_builder_begin_array (builder);

  package_list = g_strsplit (packages, "\n", 0);
  if (package_list && package_list[0])
    {
      int i;
      for (i = 0; package_list[i]; i++)
        if (package_list[i][0] != '\0')
          json_builder_add_string_value (builder, package_list[i]);
    }

  json_builder_end_array (builder);
  g_strfreev (package_list);

  return builder;
}

/**
 * @brief Build a json object with data necessary to start a table drive LSC
 *
 * JSON result consists of scan_id, message type, host ip,  hostname, port
 * together with proto, OID, result message and uri.
 *
 * @param scan_id     Scan Id.
 * @param ip_str      IP string of host.
 * @param hostname    Name of host.
 * @param os_release  OS release
 * @param package_list The installed package list in the target system to be
 * evaluated
 *
 * @return JSON string on success. Must be freed by caller. NULL on error.
 */
static gchar *
make_table_driven_lsc_info_json_str (const char *message_id,
                                     const char *group_id, const char *scan_id,
                                     const char *ip_str, const char *hostname,
                                     const char *os_release,
                                     const char *package_list)
{
  JsonBuilder *builder;
  JsonGenerator *gen;
  JsonNode *root;
  gsize json_length = 0;
  gchar *json_str;
  const char *safe_hostname;

  if (!bounded_notus_field (message_id, TABLE_DRIVEN_LSC_ID_LENGTH, TRUE)
      || !bounded_notus_field (group_id, TABLE_DRIVEN_LSC_ID_LENGTH, TRUE)
      || !bounded_notus_field (scan_id, TABLE_DRIVEN_LSC_SCAN_ID_MAX_LENGTH,
                               FALSE)
      || !bounded_notus_field (ip_str, TABLE_DRIVEN_LSC_HOST_IP_MAX_LENGTH,
                               FALSE)
      || !bounded_notus_optional_field (hostname,
                                        TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH)
      || !bounded_notus_field (os_release,
                               TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH, FALSE)
      || !bounded_notus_package_list (package_list))
    return NULL;
  safe_hostname = hostname == NULL ? "" : hostname;

  /* Build the message in json format to be published. */
  builder = json_builder_new ();

  json_builder_begin_object (builder);

  json_builder_set_member_name (builder, "message_id");
  builder = json_builder_add_string_value (builder, message_id);

  json_builder_set_member_name (builder, "group_id");
  builder = json_builder_add_string_value (builder, group_id);

  json_builder_set_member_name (builder, "message_type");
  builder = json_builder_add_string_value (builder, "scan.start");

  json_builder_set_member_name (builder, "created");
  builder = json_builder_add_int_value (builder, time (NULL));

  json_builder_set_member_name (builder, "scan_id");
  builder = json_builder_add_string_value (builder, scan_id);

  json_builder_set_member_name (builder, "host_ip");
  json_builder_add_string_value (builder, ip_str);

  json_builder_set_member_name (builder, "host_name");
  json_builder_add_string_value (builder, safe_hostname);

  json_builder_set_member_name (builder, "os_release");
  json_builder_add_string_value (builder, os_release);

  add_packages_str_to_list (builder, package_list);

  json_builder_end_object (builder);

  gen = json_generator_new ();
  root = json_builder_get_root (builder);
  json_generator_set_root (gen, root);
  json_str = json_generator_to_data (gen, &json_length);

  json_node_free (root);
  g_object_unref (gen);
  g_object_unref (builder);

  if (json_str != NULL
      && json_length > TABLE_DRIVEN_LSC_START_PAYLOAD_MAX_BYTES)
    g_clear_pointer (&json_str, g_free);

  if (json_str == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);

  return json_str;
}

static gchar *
make_notus_manifest_json_str (const char *group_id, const char *message_id,
                              const char *ip_str)
{
  JsonBuilder *builder;
  JsonGenerator *generator;
  JsonNode *root;
  gchar *json_str;

  if (!bounded_notus_field (group_id, TABLE_DRIVEN_LSC_ID_LENGTH, TRUE)
      || !bounded_notus_field (message_id, TABLE_DRIVEN_LSC_ID_LENGTH, TRUE)
      || !bounded_notus_field (ip_str, TABLE_DRIVEN_LSC_HOST_IP_MAX_LENGTH,
                               FALSE))
    return NULL;

  builder = json_builder_new ();
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "run_id");
  json_builder_add_string_value (builder, group_id);
  json_builder_set_member_name (builder, "start_message_id");
  json_builder_add_string_value (builder, message_id);
  json_builder_set_member_name (builder, "host_ip");
  json_builder_add_string_value (builder, ip_str);
  json_builder_end_object (builder);

  generator = json_generator_new ();
  root = json_builder_get_root (builder);
  json_generator_set_root (generator, root);
  json_str = json_generator_to_data (generator, NULL);

  json_node_free (root);
  g_object_unref (generator);
  g_object_unref (builder);

  return json_str;
}

static void
record_notus_manifest_failure (kb_t main_kb, const char *failure)
{
  if (main_kb == NULL
      || kb_item_set_str_with_main_kb_check (
        main_kb, TABLE_DRIVEN_LSC_MANIFEST_FAILURE_KEY, failure, 0))
    g_warning ("%s: Unable to persist the Notus manifest failure marker.",
               __func__);
}

/**
 * @brief Get the status of table driven lsc from json object
 *
 * Checks for the corresponding status inside the JSON. If the status does not
 * belong the the scan or host, NULL is returned instead. NULL is also returned
 * if message JSON cannot be parsed correctly. Return value has to be freed by
 * caller.
 *
 * @param scan_id id of scan
 * @param host_ip ip of host
 * @param json json to get information from
 * @param len length of json
 * @return gchar* Status of table driven lsc or NULL
 */
static gchar *
get_status_of_table_driven_lsc_from_json (const char *scan_id,
                                          const char *host_ip, const char *json,
                                          int len)
{
  JsonParser *parser;
  JsonReader *reader = NULL;

  GError *err = NULL;
  gchar *ret = NULL;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, json, len, &err))
    {
      goto cleanup;
    }

  reader = json_reader_new (json_parser_get_root (parser));

  // Check for Scan ID
  if (!json_reader_read_member (reader, "scan_id"))
    {
      goto cleanup;
    }
  if (g_strcmp0 (json_reader_get_string_value (reader), scan_id))
    {
      goto cleanup;
    }
  json_reader_end_member (reader);

  // Check Host IP
  if (!json_reader_read_member (reader, "host_ip"))
    {
      goto cleanup;
    }
  if (g_strcmp0 (json_reader_get_string_value (reader), host_ip))
    {
      goto cleanup;
    }
  json_reader_end_member (reader);

  // Check Status
  if (!json_reader_read_member (reader, "status"))
    {
      goto cleanup;
    }
  ret = g_strdup (json_reader_get_string_value (reader));

  json_reader_end_member (reader);

cleanup:
  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);
  if (err != NULL)
    {
      g_warning ("%s: Unable to parse json. Reason: %s", __func__,
                 err->message);
    }
  return ret;
}

#define RSNOTUS
#ifdef RSNOTUS
/** @brief Struct to hold necessary information to call and run notus
 *
 */
struct notus_info
{
  char *server; // original openvasd server URL
  char *schema; // schema is http or https
  char *host;   // server hostname
  char *alpn; // Application layer protocol negotiation: http/1.0, http/1.1, h2
  char *http_version; // same version as in application layer
  int port;           // server port
  int tls;            // 0: TLS encapsulation disable. Otherwise enable
};

typedef struct notus_info *notus_info_t;

/** @brief Initialize a notus info struct and stores the server URL
 *
 *  @param server Original server to store and to get the info from
 *
 *  @return the initialized struct. NULL on error.
 */
static notus_info_t
init_notus_info (const char *server)
{
  notus_info_t notusdata;
  notusdata = g_malloc0 (sizeof (struct notus_info));
  if (!notusdata)
    return NULL;
  notusdata->server = g_strdup (server);
  return notusdata;
}

/** @brief Free notus info structure
 *
 * @param notusdata The data to free()
 */
static void
free_notus_info (notus_info_t notusdata)
{
  if (notusdata)
    {
      g_free (notusdata->server);
      g_free (notusdata->schema);
      g_free (notusdata->host);
      g_free (notusdata->alpn);
      g_free (notusdata->http_version);
    }
}

/** @brief helper function to lower case
 *
 *  @param s the string to lower case
 *
 *  @return pointer to the modified string.
 */
static char *
help_tolower (char *s)
{
  for (char *p = s; *p; p++)
    *p = tolower (*p);
  return s;
}

/**
 * @brief Build a json array from the package list to start a table drive LSC
 *
 * @param packages The installed package list in the target system to be
 * evaluated
 *
 * @return String in json format on success. Must be freed by caller. NULL on
 * error.
 */
static gchar *
make_package_list_as_json_str (const char *packages)
{
  JsonBuilder *builder;
  JsonGenerator *gen;
  JsonNode *root;
  gsize json_length = 0;
  gchar *json_str = NULL;
  gchar **package_list = NULL;

  if (!bounded_notus_package_list (packages))
    return NULL;
  builder = json_builder_new ();

  json_builder_begin_array (builder);

  package_list = g_strsplit (packages, "\n", 0);
  if (package_list && package_list[0])
    {
      int i;
      for (i = 0; package_list[i]; i++)
        if (package_list[i][0] != '\0')
          json_builder_add_string_value (builder, package_list[i]);
    }

  json_builder_end_array (builder);
  g_strfreev (package_list);

  gen = json_generator_new ();
  root = json_builder_get_root (builder);
  json_generator_set_root (gen, root);
  json_str = json_generator_to_data (gen, &json_length);

  json_node_free (root);
  g_object_unref (gen);
  g_object_unref (builder);

  if (json_str != NULL
      && json_length > TABLE_DRIVEN_LSC_START_PAYLOAD_MAX_BYTES)
    g_clear_pointer (&json_str, g_free);

  if (json_str == NULL)
    g_warning ("%s: Error while creating JSON.", __func__);

  return json_str;
}

/** @brief Parse the server URL
 *
 *  @param[in] server String containing the server URL
 *                Valid is http://example.com:1234
 *                or https://example.com.1234.
 *  @notusdata[out] Structure to store information from the URL
 *
 *  @return 0 on success, -1 on error.
 */
static int
parse_server (notus_info_t *notusdata)
{
  CURLU *h = curl_url ();
  char *schema = NULL;
  char *host = NULL;
  char *port = NULL;

  if (!notusdata)
    return -1;

  if (curl_url_set (h, CURLUPART_URL, (*notusdata)->server, 0) > 0)
    {
      g_warning ("%s: Error parsing URL %s", __func__, (*notusdata)->server);
      return -1;
    }

  curl_url_get (h, CURLUPART_SCHEME, &schema, 0);
  curl_url_get (h, CURLUPART_HOST, &host, 0);
  curl_url_get (h, CURLUPART_PORT, &port, 0);

  if (!schema || !host)
    {
      g_warning ("%s: Invalid URL %s. It must be in format: "
                 "schema://host:port. E.g. http://localhost:8080",
                 __func__, (*notusdata)->server);
      curl_url_cleanup (h);
      curl_free (schema);
      curl_free (host);
      curl_free (port);
      return -1;
    }

  (*notusdata)->host = g_strdup (host);
  if (port)
    (*notusdata)->port = atoi (port);
  else if (g_strcmp0 (schema, "https"))
    (*notusdata)->port = 443;
  else
    (*notusdata)->port = 80;

  (*notusdata)->schema = g_strdup (help_tolower (schema));
  if (g_strrstr ((*notusdata)->schema, "https"))
    {
      (*notusdata)->tls = 1;
      (*notusdata)->http_version = g_strdup ("2");
      (*notusdata)->alpn = g_strdup ("h2");
    }
  else if (g_strrstr ((*notusdata)->schema, "http"))
    {
      (*notusdata)->tls = 0;
      (*notusdata)->http_version = g_strdup ("1.1");
      (*notusdata)->alpn = g_strdup ("http/1.1");
    }
  else
    {
      g_warning ("%s: Invalid openvasd server schema", (*notusdata)->server);
      curl_url_cleanup (h);
      curl_free (schema);
      curl_free (host);
      curl_free (port);
      return -1;
    }

  curl_url_cleanup (h);
  curl_free (schema);
  curl_free (host);
  curl_free (port);

  return 0;
}

/** @brief Initialize a new advisories struct with 100 slots
 *
 *  @return initialized advisories_t struct. It must be free by the caller
 *          with advisories_free()
 */
static advisories_t *
advisories_new_notus ()
{
  advisories_t *advisories_list = g_malloc0 (sizeof (advisories_t));
  advisories_list->max_size = 100;
  advisories_list->advisories =
    g_malloc0_n (advisories_list->max_size, sizeof (advisory_t));
  advisories_list->type = NOTUS;

  return advisories_list;
}

/** @brief Initialize a new advisories struct with 100 slots
 *
 *  @return initialized advisories_t struct. It must be free by the caller
 *          with advisories_free()
 */
static advisories_t *
advisories_new_skiron ()
{
  advisories_t *advisories_list = g_malloc0 (sizeof (advisories_t));
  advisories_list->max_size = 100;
  advisories_list->skiron_advisories =
    g_malloc0_n (advisories_list->max_size, sizeof (skiron_advisory_t));
  advisories_list->type = SKIRON;

  return advisories_list;
}

/** @brief Initialize a new advisories struct with 100 slots
 *
 *  @param advisories_list[in/out] An advisories holder to add new advisories
into.
 *  @param notus_advisory[in] the new notus_advisory to add in the list
 *
 */
static void
advisories_add (advisories_t *advisories_list, advisory_t *notus_advisory)
{
  // Reallocate more memory if the list is full
  if (advisories_list->count == advisories_list->max_size)
    {
      advisories_list->max_size *= 2;
      advisories_list->advisories =
        g_realloc_n (advisories_list->advisories, advisories_list->max_size,
                     sizeof (advisory_t));
      memset (advisories_list->advisories + advisories_list->count, '\0',
              (advisories_list->max_size - advisories_list->count)
                * sizeof (advisory_t *));
    }
  advisories_list->advisories[advisories_list->count] = notus_advisory;
  advisories_list->count++;
}

/** @brief Initialize a new notus_advisory
 *
 *  @param oid The notus_advisory's OID
 *
 *  @return initialized advisory_t struct
 */
static advisory_t *
advisory_new (char *oid)
{
  advisory_t *adv = NULL;
  adv = g_malloc0 (sizeof (advisory_t));
  adv->oid = g_strdup (oid);
  adv->count = 0;
  return adv;
}

static skiron_advisory_t *
skiron_advisory_new (char *oid, char *message)
{
  skiron_advisory_t *adv = NULL;
  adv = g_malloc0 (sizeof (skiron_advisory_t));
  adv->oid = g_strdup (oid);
  adv->message = g_strdup (message);
  return adv;
}

/** @brief Add a new vulnerability to the notus_advisory.
 *
 *  @description Each notus_advisory can have multiple vulnerable packages
 *               This structure can hold up to 100 packages.
 *
 *  @param adv[in/out] The notus_advisory to add the vulnerable package into
 *  @param vuln[in] The vulnerable package to add.
 */
static void
advisory_add_vuln_pkg (advisory_t *adv, vuln_pkg_t *vuln)
{
  if (adv->count == 100)
    {
      g_warning (
        "%s: Failed adding new vulnerable package to the notus_advisory %s. "
        "No more free slots",
        __func__, adv->oid);
      return;
    }

  adv->pkgs[adv->count] = vuln;
  adv->count++;
}

/** @brief Free()'s an notus_advisory
 *
 *  @param notus_advisory The notus_advisory to be free()'ed.
 *  It free()'s all vulnerable packages that belong to this notus_advisory.
 */
static void
advisory_free (advisory_t *notus_advisory)
{
  if (notus_advisory == NULL)
    return;

  g_free (notus_advisory->oid);
  for (size_t i = 0; i < notus_advisory->count; i++)
    {
      if (notus_advisory->pkgs[i] != NULL)
        {
          g_free (notus_advisory->pkgs[i]->pkg_name);
          g_free (notus_advisory->pkgs[i]->install_version);
          if (notus_advisory->pkgs[i]->type == RANGE)
            {
              g_free (notus_advisory->pkgs[i]->range->start);
              g_free (notus_advisory->pkgs[i]->range->stop);
            }
          else if (notus_advisory->pkgs[i]->type == SINGLE)
            {
              g_free (notus_advisory->pkgs[i]->version->version);
              g_free (notus_advisory->pkgs[i]->version->specifier);
            }
        }
    }
  notus_advisory = NULL;
}

static void
skiron_advisory_free (skiron_advisory_t *skiron_advisory)
{
  if (skiron_advisory == NULL)
    return;

  g_free (skiron_advisory->oid);
  g_free (skiron_advisory->message);
  skiron_advisory = NULL;
}

/** @brief Free()'s an advisories
 *
 *  @param notus_advisory The advisories holder to be free()'ed.
 *  It free()'s all advisories members.
 */
void
advisories_free (advisories_t *advisories)
{
  if (advisories == NULL)
    return;
  for (size_t i = 0; i < advisories->count; i++)
    {
      if (advisories->type == NOTUS)
        advisory_free (advisories->advisories[i]);
      else
        skiron_advisory_free (advisories->skiron_advisories[i]);
    }
  advisories = NULL;
}

/** @brief Creates a new Vulnerable packages which belongs to an notus_advisory
 *
 *  @param pkg_name
 *  @param install_version
 *  @param type Data type specifying how the fixed version is stored.
 *              Can be RANGE or SINGLE
 *  @param item1 Depending on the type is the "version" for SINGLE type,
 *               or the "less than" for RANGE type
 *  @param item2 Depending on the type is the "specifier" for SINGLE type,
 *               or the "greater than" for RANGE type
 *
 *  @return a vulnerable packages struct. Members are a copy of the passed
 *          parameters. They must be free separately.
 */
static vuln_pkg_t *
vulnerable_pkg_new (const char *pkg_name, const char *install_version,
                    enum fixed_type type, char *item1, char *item2)
{
  vuln_pkg_t *vuln = NULL;
  version_range_t *range = NULL;
  fixed_version_t *fixed_ver = NULL;

  vuln = g_malloc0 (sizeof (vuln_pkg_t));
  vuln->pkg_name = g_strdup (pkg_name);
  vuln->install_version = g_strdup (install_version);
  vuln->type = type;
  if (type == RANGE)
    {
      range = g_malloc0 (sizeof (range_t));
      range->start = g_strdup (item1);
      range->stop = g_strdup (item2);
      vuln->range = range;
    }
  else
    {
      fixed_ver = g_malloc0 (sizeof (fixed_version_t));
      fixed_ver->version = g_strdup (item1);
      fixed_ver->specifier = g_strdup (item2);
      vuln->version = fixed_ver;
    }

  return vuln;
}

static advisories_t *
lsc_process_response_notus (JsonReader *reader)
{
  advisories_t *advisories = advisories_new_notus ();
  advisories->type = NOTUS;
  char **members = json_reader_list_members (reader);

  if (!members || !members[0])
    {
      return advisories;
    }

  for (int i = 0; members[i]; i++)
    {
      advisory_t *notus_advisory;

      if (!json_reader_read_member (reader, members[i]))
        {
          g_debug ("No member oid");
          return NULL;
        }
      if (!json_reader_is_array (reader))
        {
          g_debug ("Is not an array");
          return NULL;
        }

      notus_advisory = advisory_new (g_strdup (members[i]));

      int count_pkgs = json_reader_count_elements (reader);
      g_debug ("There are %d packages for notus_advisory %s", count_pkgs,
               members[i]);
      for (int j = 0; j < count_pkgs; j++)
        {
          vuln_pkg_t *pkg = NULL;
          char *name = NULL;
          char *installed_version = NULL;
          char *start = NULL;
          char *stop = NULL;
          char *version = NULL;
          char *specifier = NULL;
          enum fixed_type type = UNKNOWN;

          json_reader_read_element (reader, j);
          if (!json_reader_is_object (reader))
            {
              g_warning ("%s: Package %d of notus_advisory %s is not an object",
                         __func__, j, members[i]);
              advisories_free (advisories);
              return NULL;
            }

          json_reader_read_member (reader, "name");
          name = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("name: %s", name);

          json_reader_read_member (reader, "installed_version");
          installed_version = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("installed_version: %s", installed_version);

          json_reader_read_member (reader, "fixed_version");
          g_debug ("Fixed_version has %d members",
                   json_reader_count_members (reader));

          // Version Range
          json_reader_read_member (reader, "start");
          start = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          json_reader_read_member (reader, "end");
          stop = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("start %s, end: %s", start, stop);

          // version and specifier
          json_reader_read_member (reader, "version");
          version = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          json_reader_read_member (reader, "specifier");
          specifier = g_strdup (json_reader_get_string_value (reader));
          json_reader_end_member (reader);
          g_debug ("version %s, specifier: %s", version, specifier);

          // end read fixes version member
          json_reader_end_member (reader);

          // end package element
          json_reader_end_element (reader);

          char *item1 = NULL, *item2 = NULL;
          if (start && stop)
            {
              type = RANGE;
              item1 = start;
              item2 = stop;
            }
          else if (version && specifier)
            {
              type = SINGLE;
              item1 = version;
              item2 = specifier;
            }
          else
            {
              g_warning ("%s: Error parsing json element", __func__);
              g_free (name);
              g_free (installed_version);
              g_free (item1);
              g_free (item2);
              advisory_free (notus_advisory);
              advisories_free (advisories);
              return NULL;
            }

          pkg =
            vulnerable_pkg_new (name, installed_version, type, item1, item2);
          g_free (name);
          g_free (installed_version);
          g_free (item1);
          g_free (item2);

          advisory_add_vuln_pkg (notus_advisory, pkg);
        }
      // end notus_advisory
      json_reader_end_member (reader);
      advisories_add (advisories, notus_advisory);
    }
  return advisories;
}

static advisories_t *
lsc_process_response_skiron (JsonReader *reader)
{
  advisories_t *advisories = advisories_new_skiron ();

  for (int i = 0; json_reader_read_element (reader, i); i++)
    {
      skiron_advisory_t *skiron_advisory;
      char *oid = NULL;
      char *message = NULL;

      json_reader_read_member (reader, "oid");
      oid = (char *) json_reader_get_string_value (reader);
      json_reader_end_member (reader);

      json_reader_read_member (reader, "message");
      message = (char *) json_reader_get_string_value (reader);
      json_reader_end_member (reader);

      skiron_advisory = skiron_advisory_new (oid, message);

      advisories_add (advisories, (advisory_t *) skiron_advisory);

      // end element
      json_reader_end_element (reader);
    }

  return advisories;
}

/** @brief Process a json object which contains advisories and vulnerable
 *         packages
 *
 *  @description This is the body string in response get from an openvasd server
 *
 *  @param resp String containing the json object to be processed.
 *  @param len String length.
 *
 *  @return a advisories_t struct containing all advisories and vulnerable
 *                         packages.
 *                         After usage must be free()'ed with advisories_free().
 */
advisories_t *
lsc_process_response (const gchar *resp, const size_t len)
{
  JsonParser *parser = NULL;
  JsonReader *reader = NULL;
  GError *err = NULL;

  advisories_t *advisories = NULL;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, resp, len, &err))
    {
      g_message ("Error parsing");
    }

  reader = json_reader_new (json_parser_get_root (parser));

  if (json_reader_is_object (reader))
    {
      advisories = lsc_process_response_notus (reader);
    }
  else if (json_reader_is_array (reader))
    {
      advisories = lsc_process_response_skiron (reader);
    }
  else
    {
      g_debug ("Unknown JSON response format");
    }

  if (reader)
    g_object_unref (reader);
  g_object_unref (parser);

  return advisories;
}

/** @brief Define a string struct for storing the response.
 */
struct string
{
  char *ptr;
  size_t len;
};

/** @brief Initialize the string struct to hold the response
 *
 *  @param s[in/out] The string struct to be initialized
 */
static gboolean
init_string (struct string *s)
{
  s->len = 0;
  s->ptr = g_try_malloc0 (1);
  if (s->ptr == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return FALSE;
    }
  return TRUE;
}

/** @brief Call back function to stored the response.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the response in s. It reallocate memory if necessary.
 */
static size_t
response_callback_fn (void *ptr, size_t size, size_t nmemb, void *struct_string)
{
  struct string *s = struct_string;
  size_t chunk_bytes;
  size_t new_len;
  char *ptr_aux;

  if (size != 0 && nmemb > TABLE_DRIVEN_LSC_RESPONSE_MAX_BYTES / size)
    return 0;
  chunk_bytes = size * nmemb;
  if (s->len > TABLE_DRIVEN_LSC_RESPONSE_MAX_BYTES
      || chunk_bytes > TABLE_DRIVEN_LSC_RESPONSE_MAX_BYTES - s->len)
    return 0;
  new_len = s->len + chunk_bytes;
  ptr_aux = g_try_realloc (s->ptr, new_len + 1);
  if (ptr_aux == NULL)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return 0; // no memory left
    }
  s->ptr = ptr_aux;
  memcpy (s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return chunk_bytes;
}

/** @brief Send a request to the server
 *
 *  @param[in] notusdata Structure containing information necessary for the
request
 *  @param[in] os Target's operative system. Necessary for the URL path part.
 *  @param[in] pkg_list The package list installed in the target, to be checked
 *  @param[out] response The string containing the results in json format.
 *
 *  @return the http code or -1 on error
 */
static long
send_request (notus_info_t notusdata, const char *os, const char *pkg_list,
              char **response)
{
  CURL *curl;
  GString *url = NULL;
  long http_code = -1;
  struct string resp;
  struct curl_slist *customheader = NULL;
  char *escaped_os = NULL;
  char *os_aux;
  GString *xapikey = NULL;

  if (!bounded_notus_field (os, TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH, FALSE)
      || pkg_list == NULL
      || strnlen (pkg_list, TABLE_DRIVEN_LSC_START_PAYLOAD_MAX_BYTES + 1)
           > TABLE_DRIVEN_LSC_START_PAYLOAD_MAX_BYTES)
    return http_code;

  if ((curl = curl_easy_init ()) == NULL)
    {
      g_warning ("Not possible to initialize curl library");
      return http_code;
    }

  url = g_string_new (notusdata->server);
  g_string_append (url, "/notus/");

  //
  os_aux = help_tolower (g_strdup (os));
  for (size_t i = 0; i < strlen (os_aux); i++)
    {
      if (os_aux[i] == ' ')
        os_aux[i] = '_';
    }

  escaped_os = curl_easy_escape (curl, os_aux, 0);
  g_free (os_aux);
  if (escaped_os == NULL)
    {
      g_string_free (url, TRUE);
      curl_easy_cleanup (curl);
      return http_code;
    }
  g_string_append (url, escaped_os);
  curl_free (escaped_os);

  g_debug ("%s: URL: %s", __func__, url->str);
  // Set URL
  if (curl_easy_setopt (curl, CURLOPT_URL, url->str) != CURLE_OK)
    {
      g_warning ("Not possible to set the URL");
      curl_easy_cleanup (curl);
      return http_code;
    }
  g_string_free (url, TRUE);

  // Accept an insecure connection. Don't verify the server certificate
  curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);

  // Set API KEY
  if (prefs_get ("x-apikey"))
    {
      xapikey = g_string_new ("X-APIKEY: ");
      g_string_append (xapikey, prefs_get ("x-apikey"));
      customheader = curl_slist_append (customheader, g_strdup (xapikey->str));
      g_string_free (xapikey, TRUE);
    }
  // SET Content type
  customheader =
    curl_slist_append (customheader, "Content-Type: application/json");
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, customheader);
  // Set body
  curl_easy_setopt (curl, CURLOPT_POSTFIELDS, pkg_list);
  curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, strlen (pkg_list));

  // Init the struct where the response is stored and set the callback function
  if (!init_string (&resp))
    {
      curl_slist_free_all (customheader);
      curl_easy_cleanup (curl);
      return http_code;
    }
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, response_callback_fn);
  curl_easy_setopt (curl, CURLOPT_WRITEDATA, &resp);

  int ret = CURLE_OK;
  if ((ret = curl_easy_perform (curl)) != CURLE_OK)
    {
      g_warning ("%s: Error sending request: %d", __func__, ret);
      curl_slist_free_all (customheader);
      curl_easy_cleanup (curl);
      g_free (resp.ptr);
      return http_code;
    }

  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

  curl_slist_free_all (customheader);
  curl_easy_cleanup (curl);
  g_debug ("%s: Server response bytes: %zu", __func__, resp.len);
  *response = g_strdup (resp.ptr);
  g_free (resp.ptr);
  // already free()'ed with curl_easy_cleanup().

  return http_code;
}

/** @brief Sent the installed package list and OS to notus
 *
 *  @param pkg_list Installed package list
 *  @param os The target's OS
 *
 *  @return String containing the server response or NULL
 *          Must be free()'ed by the caller.
 */
char *
lsc_get_response (const char *pkg_list, const char *os)
{
  const char *server = NULL;
  char *json_pkglist;
  char *response = NULL;
  notus_info_t notusdata;
  long ret;

  // Parse the server and get the port, host, schema
  // and necessary information to build the message
  server = prefs_get ("openvasd_server");
  notusdata = init_notus_info (server);

  if (parse_server (&notusdata) < 0)
    {
      free_notus_info (notusdata);
      return NULL;
    }

  // Convert the package list string into a string containing json
  // array of packages
  if ((json_pkglist = make_package_list_as_json_str (pkg_list)) == NULL)
    {
      free_notus_info (notusdata);
      return NULL;
    }

  ret = send_request (notusdata, os, json_pkglist, &response);
  if (ret != 200)
    g_warning ("%ld: Error sending request to openvasd (response bytes: %zu)",
               ret, response == NULL ? 0 : strlen (response));

  free_notus_info (notusdata);
  g_free (json_pkglist);

  return response;
}

/** @brief Call notus and stores the results
 *
 *  @param ip_str Target's IP address.
 *  @param hostname Target's hostname.
 *  @param pkg_list List of packages installed in the target. The packages are
 * "\n" separated.
 *  @param os Name of the target's operating system.
 *
 *  @result Count of stored results. -1 on error.
 */
static int
call_rs_notus (const char *ip_str, const char *hostname, const char *pkg_list,
               const char *os)
{
  char *body = NULL;
  advisories_t *advisories = NULL;
  int res_count = 0;
  if ((body = lsc_get_response (pkg_list, os)) == NULL)
    return -1;

  advisories = lsc_process_response (body, strlen (body));
  g_free (body);

  if (!advisories)
    {
      g_message ("%s: Unable to process response", __func__);
      return -1;
    }

  // Process the advisories, generate results and store them in the kb
  for (size_t i = 0; i < advisories->count; i++)
    {
      advisory_t *notus_advisory = advisories->advisories[i];
      gchar *buffer;
      GString *result = g_string_new (NULL);

      if (!notus_advisory)
        {
          g_message ("%s: Unable to process response. No notus advisories",
                     __func__);
          g_string_free (result, TRUE);
          advisories_free (advisories);
          return -1;
        }
      for (size_t j = 0; j < notus_advisory->count; j++)
        {
          vuln_pkg_t *pkg = notus_advisory->pkgs[j];
          GString *res = g_string_new (NULL);

          if (pkg->type == RANGE)
            {
              g_string_printf (res,
                               "\n"
                               "Vulnerable package:   %s\n"
                               "Installed version:    %s-%s\n"
                               "Fixed version:      < %s-%s\n"
                               "Fixed version:      >=%s-%s\n",
                               pkg->pkg_name, pkg->pkg_name,
                               pkg->install_version, pkg->pkg_name,
                               pkg->range->start, pkg->pkg_name,
                               pkg->range->stop);
            }
          else if (pkg->type == SINGLE)
            {
              g_string_printf (res,
                               "\n"
                               "Vulnerable package:   %s\n"
                               "Installed version:    %s-%s\n"
                               "Fixed version:      %2s%s-%s\n",
                               pkg->pkg_name, pkg->pkg_name,
                               pkg->install_version, pkg->version->specifier,
                               pkg->pkg_name, pkg->version->version);
            }
          else
            {
              g_warning ("%s: Unknown fixed version type for notus_advisory %s",
                         __func__, notus_advisory->oid);
              g_string_free (result, TRUE);
              advisories_free (advisories);
              return -1;
            }
          g_string_append (result, res->str);
          g_string_free (res, TRUE);
        }

      buffer = openvas_result_message_new (
        "ALARM", ip_str, hostname ? hostname : " ", "package",
        notus_advisory->oid, result->str, "");
      g_string_free (result, TRUE);
      kb_item_push_str_with_main_kb_check (get_main_kb (), "internal/results",
                                           buffer);
      res_count++;
      g_free (buffer);
    }

  advisories_free (advisories);
  return res_count;
}

#endif // End RSNOTUS

/**
 * @brief Publish the necessary data to start a Table driven LSC scan.
 *
 * If the gather-package-list.nasl plugin was launched, and it generated
 * a valid package list for a supported OS, the table driven LSC scan
 * which is subscribed to the topic will perform a scan an publish the
 * the results to be handle by the sensor/client.
 *
 * @param scan_id     Scan Id.
 * @param kb
 * @param ip_str      IP string of host.
 * @param hostname    Name of host.
 *
 * @return 0 on success, less than 0 on error.
 */
int
run_table_driven_lsc (const char *scan_id, const char *ip_str,
                      const char *hostname, const char *package_list,
                      const char *os_release)
{
  int err = 0;
  if (!os_release || !package_list)
    return 0;
  if (!bounded_notus_field (scan_id, TABLE_DRIVEN_LSC_SCAN_ID_MAX_LENGTH, FALSE)
      || !bounded_notus_field (ip_str, TABLE_DRIVEN_LSC_HOST_IP_MAX_LENGTH,
                               FALSE)
      || !bounded_notus_optional_field (hostname,
                                        TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH)
      || !bounded_notus_field (os_release,
                               TABLE_DRIVEN_LSC_START_FIELD_MAX_LENGTH, FALSE)
      || !bounded_notus_package_list (package_list))
    return -1;

  if (prefs_get ("openvasd_server"))
    {
      g_message ("Running Notus for %s via openvasd", ip_str);
      err = call_rs_notus (ip_str, hostname, package_list, os_release);

      return err;
    }
  else
    {
      gchar *group_id = NULL;
      gchar *json_str;
      kb_t main_kb;
      gchar *manifest_str = NULL;
      gchar *message_id = NULL;
      gchar *topic;
      gchar *payload;
      gchar *status = NULL;
      int topic_len;
      int payload_len;

      // Subscribe to status topic
      err = mqtt_subscribe ("scanner/status");
      if (err)
        {
          g_warning ("%s: Error starting lsc. Unable to subscribe", __func__);
          return -1;
        }

      main_kb = get_main_kb ();
      if (!make_notus_start_ids (&message_id, &group_id))
        {
          record_notus_manifest_failure (main_kb, "manifest");
          g_warning ("%s: Unable to generate Notus start identifiers.",
                     __func__);
          return -1;
        }

      json_str = make_table_driven_lsc_info_json_str (message_id, group_id,
                                                      scan_id, ip_str, hostname,
                                                      os_release, package_list);
      manifest_str =
        make_notus_manifest_json_str (group_id, message_id, ip_str);

      // Run table driven lsc
      if (json_str == NULL || manifest_str == NULL)
        {
          record_notus_manifest_failure (main_kb, "manifest");
          g_warning ("%s: Unable to serialize the bounded Notus start.",
                     __func__);
          g_free (manifest_str);
          g_free (json_str);
          g_free (group_id);
          g_free (message_id);
          return -1;
        }

      if (main_kb == NULL
          || kb_item_push_str_with_main_kb_check (
            main_kb, TABLE_DRIVEN_LSC_MANIFEST_KEY, manifest_str))
        {
          record_notus_manifest_failure (main_kb, "manifest");
          g_warning ("%s: Refusing to publish an unrecorded Notus start.",
                     __func__);
          g_free (manifest_str);
          g_free (json_str);
          g_free (group_id);
          g_free (message_id);
          return -1;
        }
      g_free (manifest_str);

      g_message ("Running Notus for %s", ip_str);
      err = mqtt_publish ("scanner/package/cmd/notus", json_str);
      if (err)
        {
          record_notus_manifest_failure (main_kb, "publish");
          g_warning ("%s: Error publishing message for Notus.", __func__);
          g_free (json_str);
          g_free (group_id);
          g_free (message_id);
          return -1;
        }

      g_free (json_str);
      g_free (group_id);
      g_free (message_id);

      // Wait for Notus scanner to start or interrupt
      while (!status)
        {
          err = mqtt_retrieve_message (&topic, &topic_len, &payload,
                                       &payload_len, 60000);
          if (err == -1 || err == 1)
            {
              g_warning ("%s: Unable to retrieve status message from notus. %s",
                         __func__, err == 1 ? "Timeout after 60 s." : "");
              return -1;
            }

          // Get status if it belongs to corresponding scan and host
          // Else wait for next status message
          status = get_status_of_table_driven_lsc_from_json (
            scan_id, ip_str, payload, payload_len);

          g_free (topic);
          g_free (payload);
        }
      // If started wait for it to finish or interrupt
      if (!g_strcmp0 (status, "running"))
        {
          g_debug ("%s: table driven LSC with scan id %s successfully started "
                   "for host %s",
                   __func__, scan_id, ip_str);
          g_free (status);
          status = NULL;
          while (!status)
            {
              err = mqtt_retrieve_message (&topic, &topic_len, &payload,
                                           &payload_len, 60000);
              if (err == -1)
                {
                  g_warning (
                    "%s: Unable to retrieve status message from notus.",
                    __func__);
                  return -1;
                }
              if (err == 1)
                {
                  g_warning (
                    "%s: Unable to retrieve message. Timeout after 60s.",
                    __func__);
                  return -1;
                }

              status = get_status_of_table_driven_lsc_from_json (
                scan_id, ip_str, payload, payload_len);
              g_free (topic);
              g_free (payload);
            }
        }
      else
        {
          g_warning ("%s: Unable to start lsc. Got status: %s", __func__,
                     status);
          g_free (status);
          return -1;
        }

      if (g_strcmp0 (status, "finished"))
        {
          g_warning (
            "%s: table driven lsc with scan id %s did not finish successfully "
            "for host %s. Last status was %s",
            __func__, scan_id, ip_str, status);
          err = -1;
        }
      else
        g_debug ("%s: table driven lsc with scan id %s successfully finished "
                 "for host %s",
                 __func__, scan_id, ip_str);
      g_free (status);
    }
  return err;
}
