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

#include "kb_cache.h"
#include "plugutils.h"

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
  if (!prefs_get_bool ("table_driven_lsc") || !prefs_get_bool ("mqtt_enabled"))
    return "none";

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
      g_warning ("%s: Unable to generate Notus start identifiers.", __func__);
      return -1;
    }

  json_str = make_table_driven_lsc_info_json_str (
    message_id, group_id, scan_id, ip_str, hostname, os_release, package_list);
  manifest_str = make_notus_manifest_json_str (group_id, message_id, ip_str);

  // Run table driven lsc
  if (json_str == NULL || manifest_str == NULL)
    {
      record_notus_manifest_failure (main_kb, "manifest");
      g_warning ("%s: Unable to serialize the bounded Notus start.", __func__);
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
      err = mqtt_retrieve_message (&topic, &topic_len, &payload, &payload_len,
                                   60000);
      if (err == -1 || err == 1)
        {
          g_warning ("%s: Unable to retrieve status message from notus. %s",
                     __func__, err == 1 ? "Timeout after 60 s." : "");
          return -1;
        }

      // Get status if it belongs to corresponding scan and host
      // Else wait for next status message
      status = get_status_of_table_driven_lsc_from_json (scan_id, ip_str,
                                                         payload, payload_len);

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
              g_warning ("%s: Unable to retrieve status message from notus.",
                         __func__);
              return -1;
            }
          if (err == 1)
            {
              g_warning ("%s: Unable to retrieve message. Timeout after 60s.",
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
      g_warning ("%s: Unable to start lsc. Got status: %s", __func__, status);
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
  return err;
}
