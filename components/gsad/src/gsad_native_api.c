/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_native_api.c
 * @brief Authenticated same-origin proxy for bounded TurboVAS native API paths.
 */

#include "gsad_native_api.h"

#include "gsad_connection_info.h"
#include "gsad_credentials.h"
#include "gsad_http.h"
#include "gsad_params.h"
#include "gsad_user.h"

#include <errno.h>
#include <cjson/cJSON.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gsad native api"

#define DEFAULT_NATIVE_API_HOST "turbovas-api"
#define DEFAULT_NATIVE_API_PORT "9080"
#define NATIVE_API_MAX_RESPONSE_BYTES (10 * 1024 * 1024)
#define NATIVE_API_MAX_PDF_RESPONSE_BYTES (32 * 1024 * 1024)
#define PDF_REPORT_FORMAT_ID "c402cc3e-b531-11e1-9163-406186ea4fc5"
#define BROWSER_PROXY_SECRET_ENV "TURBOVAS_API_BROWSER_PROXY_SECRET"
#define BROWSER_PROXY_SECRET_HEADER "x-turbovas-browser-proxy-secret"
#define BROWSER_PROXY_OPERATOR_HEADER "x-turbovas-operator-name"
#define BROWSER_PROXY_SECRET_MIN_LENGTH 32
#define BROWSER_PROXY_SECRET_MAX_LENGTH 4096
#define BROWSER_PROXY_OPERATOR_MAX_LENGTH 256

static void
secure_clear (void *value, gsize length)
{
  volatile unsigned char *cursor = value;

  if (value == NULL)
    return;
  while (length--)
    *cursor++ = 0;
}

static void
secure_gstring_free (GString *value)
{
  if (value == NULL)
    return;
  secure_clear (value->str, value->len);
  g_string_free (value, TRUE);
}

static gboolean
is_uuid_segment (const gchar *value, gsize length)
{
  if (value == NULL || length != 36)
    return FALSE;

  for (gsize i = 0; i < length; i++)
    {
      gboolean should_be_dash = (i == 8 || i == 13 || i == 18 || i == 23);
      if (should_be_dash)
        {
          if (value[i] != '-')
            return FALSE;
        }
      else if (!g_ascii_isxdigit (value[i]))
        return FALSE;
    }

  return TRUE;
}

typedef struct
{
  guint status_code;
  GBytes *body;
  gchar *content_disposition;
} native_api_pdf_response_t;

static void
native_api_pdf_response_clear (native_api_pdf_response_t *response)
{
  if (response == NULL)
    return;

  g_clear_pointer (&response->body, g_bytes_unref);
  g_clear_pointer (&response->content_disposition, g_free);
  response->status_code = 0;
}

static gssize
find_crlf (const guint8 *data, gsize start, gsize limit)
{
  for (gsize index = start; index + 1 < limit; index++)
    if (data[index] == '\r' && data[index + 1] == '\n')
      return (gssize) index;

  return -1;
}

static gssize
find_header_end (const guint8 *data, gsize length)
{
  for (gsize index = 0; index + 3 < length; index++)
    if (memcmp (data + index, "\r\n\r\n", 4) == 0)
      return (gssize) index;

  return -1;
}

static gboolean
parse_response_status (const guint8 *data, gsize length, guint *status_code)
{
  gchar *status_line;
  int parsed_status;

  status_line = g_strndup ((const gchar *) data, length);
  if (sscanf (status_line, "HTTP/%*d.%*d %d", &parsed_status) != 1
      || parsed_status < 100 || parsed_status > 599)
    {
      g_free (status_line);
      return FALSE;
    }

  g_free (status_line);
  *status_code = (guint) parsed_status;
  return TRUE;
}

static gboolean
parse_content_length_value (const gchar *value, gsize *content_length)
{
  gchar *endptr;
  guint64 parsed;

  if (value == NULL || *value == '\0' || !g_ascii_isdigit (*value))
    return FALSE;

  errno = 0;
  parsed = g_ascii_strtoull (value, &endptr, 10);
  if (errno || *endptr != '\0' || parsed > G_MAXSIZE)
    return FALSE;

  *content_length = (gsize) parsed;
  return TRUE;
}

static gboolean
content_disposition_is_safe (const gchar *value)
{
  const gchar *separator;
  gsize disposition_type_length;

  if (value == NULL || value[0] == '\0' || strlen (value) > 1024)
    return FALSE;

  separator = strchr (value, ';');
  disposition_type_length =
    separator ? (gsize) (separator - value) : strlen (value);
  if (!((disposition_type_length == strlen ("attachment")
         && g_ascii_strncasecmp (value, "attachment", disposition_type_length)
              == 0)
        || (disposition_type_length == strlen ("inline")
            && g_ascii_strncasecmp (value, "inline", disposition_type_length)
                 == 0)))
    return FALSE;

  for (const guchar *cursor = (const guchar *) value; *cursor != '\0'; cursor++)
    if (*cursor < 0x20 || *cursor > 0x7e)
      return FALSE;

  return TRUE;
}

static gboolean
parse_native_api_pdf_response (const guint8 *data, gsize length,
                               native_api_pdf_response_t *response,
                               gchar **error_message)
{
  gssize header_end;
  gssize status_end;
  gsize cursor;
  gsize content_length = 0;
  gboolean content_length_present = FALSE;
  gchar *content_type = NULL;
  gchar *content_disposition = NULL;

  native_api_pdf_response_clear (response);
  header_end = find_header_end (data, length);
  status_end =
    find_crlf (data, 0, header_end < 0 ? length : (gsize) header_end);
  if (header_end < 0 || status_end < 0
      || !parse_response_status (data, (gsize) status_end,
                                 &response->status_code))
    {
      *error_message = g_strdup ("Native API returned a malformed response.");
      return FALSE;
    }

  cursor = (gsize) status_end + 2;
  while (cursor < (gsize) header_end)
    {
      gssize line_end = find_crlf (data, cursor, (gsize) header_end + 2);
      const guint8 *colon;
      gchar *name;
      gchar *value;

      if (line_end < 0 || data[cursor] == ' ' || data[cursor] == '\t')
        goto malformed;
      colon = memchr (data + cursor, ':', (gsize) line_end - cursor);
      if (colon == NULL)
        goto malformed;

      name = g_strndup ((const gchar *) data + cursor,
                        (gsize) (colon - data - cursor));
      value = g_strndup ((const gchar *) colon + 1,
                         (gsize) line_end - (gsize) (colon - data) - 1);
      g_strstrip (value);
      if (g_ascii_strcasecmp (name, "Content-Length") == 0)
        {
          if (content_length_present
              || !parse_content_length_value (value, &content_length))
            {
              g_free (name);
              g_free (value);
              goto malformed;
            }
          content_length_present = TRUE;
        }
      else if (g_ascii_strcasecmp (name, "Content-Type") == 0)
        {
          if (content_type != NULL)
            {
              g_free (name);
              g_free (value);
              goto malformed;
            }
          content_type = g_steal_pointer (&value);
        }
      else if (g_ascii_strcasecmp (name, "Content-Disposition") == 0)
        {
          if (content_disposition != NULL
              || !content_disposition_is_safe (value))
            {
              g_free (name);
              g_free (value);
              goto malformed;
            }
          content_disposition = g_steal_pointer (&value);
        }
      g_free (name);
      g_free (value);
      cursor = (gsize) line_end + 2;
    }

  if (!content_length_present
      || length - (gsize) header_end - 4 != content_length)
    goto malformed;

  if (response->status_code == MHD_HTTP_OK
      && (content_type == NULL
          || g_ascii_strcasecmp (content_type, "application/pdf") != 0
          || content_length < 5
          || memcmp (data + header_end + 4, "%PDF-", 5) != 0))
    goto malformed;

  response->body = g_bytes_new (data + header_end + 4, content_length);
  response->content_disposition = content_disposition;
  g_free (content_type);
  return TRUE;

malformed:
  native_api_pdf_response_clear (response);
  g_free (content_type);
  g_free (content_disposition);
  *error_message =
    g_strdup ("Native API returned invalid PDF response framing.");
  return FALSE;
}

static gboolean
native_api_pdf_download_path_is_allowed (const gchar *path)
{
  const gchar *prefix = "/api/v1/reports/";
  const gchar *suffix = "/download";
  const gchar *report_id;
  gsize report_id_length;

  if (path == NULL || strchr (path, '?') != NULL
      || !g_str_has_prefix (path, prefix) || !g_str_has_suffix (path, suffix))
    return FALSE;

  report_id = path + strlen (prefix);
  report_id_length = strlen (path) - strlen (prefix) - strlen (suffix);
  return is_uuid_segment (report_id, report_id_length);
}

static gchar *
native_api_pdf_download_target (const gchar *path,
                                const gchar *report_format_id)
{
  if (!native_api_pdf_download_path_is_allowed (path)
      || g_strcmp0 (report_format_id, PDF_REPORT_FORMAT_ID) != 0)
    return NULL;

  return g_strdup_printf ("%s?report_format_id=%s", path, PDF_REPORT_FORMAT_ID);
}

static gboolean
response_body_is_json_object (const gchar *body)
{
  cJSON *document;
  const char *parse_end = NULL;
  gboolean valid;

  if (body == NULL)
    return FALSE;
  document = cJSON_ParseWithOpts (body, &parse_end, TRUE);
  valid = document != NULL && cJSON_IsObject (document) && parse_end != NULL
          && *parse_end == '\0';
  cJSON_Delete (document);
  return valid;
}

static gboolean
is_cve_id_segment (const gchar *value, gsize length)
{
  if (value == NULL || length < 13)
    return FALSE;

  if (g_ascii_strncasecmp (value, "CVE-", 4) != 0)
    return FALSE;

  for (gsize i = 4; i < length; i++)
    if (!g_ascii_isdigit (value[i]) && value[i] != '-')
      return FALSE;

  const gchar *year = value + 4;
  const gchar *suffix = value + 9;
  if (value[8] != '-' || strlen (year) < 5 || strlen (suffix) < 4)
    return FALSE;

  for (gsize i = 0; i < 4; i++)
    if (!g_ascii_isdigit (year[i]))
      return FALSE;

  for (const gchar *cursor = suffix; *cursor != '\0'; cursor++)
    if (!g_ascii_isdigit (*cursor))
      return FALSE;

  return TRUE;
}

static gboolean
is_cpe_id_segment (const gchar *value, gsize length)
{
  if (value == NULL || length < 4 || length > 4096)
    return FALSE;

  if (g_ascii_strncasecmp (value, "cpe:", 4) != 0
      && g_ascii_strncasecmp (value, "cpe%3a", 6) != 0)
    return FALSE;

  for (gsize i = 0; i < length; i++)
    {
      if (g_ascii_isalnum (value[i]) || value[i] == '-' || value[i] == '_'
          || value[i] == '.' || value[i] == ':' || value[i] == '~'
          || value[i] == '/')
        continue;

      if (value[i] == '%')
        {
          if (i + 2 >= length || !g_ascii_isxdigit (value[i + 1])
              || !g_ascii_isxdigit (value[i + 2]))
            return FALSE;
          i += 2;
          continue;
        }

      return FALSE;
    }

  return TRUE;
}

static gboolean
is_nvt_oid_segment (const gchar *value, gsize length)
{
  gboolean saw_dot = FALSE;
  gboolean previous_dot = FALSE;

  if (value == NULL || length < 3 || length > 128)
    return FALSE;

  for (gsize i = 0; i < length; i++)
    {
      if (g_ascii_isdigit (value[i]))
        {
          previous_dot = FALSE;
          continue;
        }

      if (value[i] == '.')
        {
          if (i == 0 || previous_dot)
            return FALSE;
          saw_dot = TRUE;
          previous_dot = TRUE;
          continue;
        }

      return FALSE;
    }

  return saw_dot && !previous_dot;
}

static gboolean
is_advisory_id_char (gchar value)
{
  return g_ascii_isalnum (value) || value == '-' || value == '_' || value == '.'
         || value == ':' || value == '/';
}

static gint
hex_value (gchar value)
{
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  if (value >= 'A' && value <= 'F')
    return value - 'A' + 10;
  return -1;
}

static gboolean
is_advisory_id_segment (const gchar *value, gsize length)
{
  gsize decoded_length = 0;
  gsize segment_length = 0;
  gboolean segment_all_dots = TRUE;

  if (value == NULL || length == 0 || length > 768)
    return FALSE;

  for (gsize i = 0; i < length; i++)
    {
      gchar decoded = value[i];

      if (decoded == '%')
        {
          gint high;
          gint low;

          if (i + 2 >= length)
            return FALSE;

          high = hex_value (value[i + 1]);
          low = hex_value (value[i + 2]);
          if (high < 0 || low < 0)
            return FALSE;

          decoded = (gchar) ((high << 4) | low);
          i += 2;
        }

      if (!is_advisory_id_char (decoded))
        return FALSE;

      decoded_length++;
      if (decoded_length > 256)
        return FALSE;

      if (decoded == '/')
        {
          if (segment_length == 0 || segment_all_dots)
            return FALSE;
          segment_length = 0;
          segment_all_dots = TRUE;
          continue;
        }

      segment_length++;
      if (decoded != '.')
        segment_all_dots = FALSE;
    }

  return segment_length > 0 && !segment_all_dots;
}

static gboolean
is_tag_resource_type_segment (const gchar *value, gsize length)
{
  static const gchar *allowed_types[] = {
    "alert",         "cert_bund_adv", "cpe",          "cve",
    "credential",    "dfn_cert_adv",  "host",         "nvt",
    "os",
    "port_list",     "report_format", "config",
    "scanner",       "schedule",      "target",       "task",
    "tls_certificate"
  };

  if (value == NULL || length == 0 || length > 32)
    return FALSE;

  for (gsize i = 0; i < G_N_ELEMENTS (allowed_types); i++)
    if (strlen (allowed_types[i]) == length
        && strncmp (allowed_types[i], value, length) == 0)
      return TRUE;

  return FALSE;
}

static gboolean
is_uuid_segment_with_suffix (const gchar *value, const gchar *suffix)
{
  gsize id_length;

  if (!g_str_has_suffix (value, suffix))
    return FALSE;

  id_length = strlen (value) - strlen (suffix);
  return is_uuid_segment (value, id_length);
}

static gboolean
is_uuid_segment_pair_with_middle (const gchar *value, const gchar *middle)
{
  const gchar *second;
  gsize first_length;

  if (value == NULL || middle == NULL)
    return FALSE;

  second = strstr (value, middle);
  if (second == NULL)
    return FALSE;

  first_length = second - value;
  second += strlen (middle);
  return is_uuid_segment (value, first_length)
         && is_uuid_segment (second, strlen (second));
}

static gboolean
native_api_delete_path_is_allowed (const gchar *path)
{
  const gchar *alert_prefix = "/api/v1/alerts/";
  const gchar *filter_prefix = "/api/v1/filters/";
  const gchar *host_prefix = "/api/v1/hosts/";
  const gchar *host_identifier_prefix = "/api/v1/host-identifiers/";
  const gchar *host_operating_system_prefix = "/api/v1/host-operating-systems/";
  const gchar *override_prefix = "/api/v1/overrides/";
  const gchar *port_list_prefix = "/api/v1/port-lists/";
  const gchar *scan_config_prefix = "/api/v1/scan-configs/";
  const gchar *schedule_prefix = "/api/v1/schedules/";
  const gchar *scope_prefix = "/api/v1/scopes/";
  const gchar *scope_report_prefix = "/api/v1/scope-reports/";
  const gchar *tag_prefix = "/api/v1/tags/";
  const gchar *target_prefix = "/api/v1/targets/";
  const gchar *task_prefix = "/api/v1/tasks/";
  const gchar *tls_certificate_prefix = "/api/v1/tls-certificates/";
  const gchar *trash_suffix = "/trash";

  if (path == NULL || strchr (path, '?') != NULL)
    return FALSE;

  if (g_str_has_prefix (path, alert_prefix))
    {
      const gchar *id = path + strlen (alert_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, filter_prefix))
    {
      const gchar *id = path + strlen (filter_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix);
    }

  if (g_str_has_prefix (path, host_prefix))
    {
      const gchar *id = path + strlen (host_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, host_identifier_prefix))
    {
      const gchar *id = path + strlen (host_identifier_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, host_operating_system_prefix))
    {
      const gchar *id = path + strlen (host_operating_system_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, override_prefix))
    {
      const gchar *id = path + strlen (override_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix);
    }

  if (g_str_has_prefix (path, tls_certificate_prefix))
    {
      const gchar *id = path + strlen (tls_certificate_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, port_list_prefix))
    {
      const gchar *id = path + strlen (port_list_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix)
             || is_uuid_segment_pair_with_middle (id, "/ranges/");
    }

  if (g_str_has_prefix (path, scan_config_prefix))
    {
      const gchar *id = path + strlen (scan_config_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix);
    }

  if (g_str_has_prefix (path, schedule_prefix))
    {
      const gchar *id = path + strlen (schedule_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix);
    }

  if (g_str_has_prefix (path, scope_prefix))
    {
      const gchar *id = path + strlen (scope_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, scope_report_prefix))
    {
      const gchar *id = path + strlen (scope_report_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, tag_prefix))
    {
      const gchar *id = path + strlen (tag_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix);
    }

  if (g_str_has_prefix (path, target_prefix))
    {
      const gchar *id = path + strlen (target_prefix);
      return is_uuid_segment (id, strlen (id))
             || is_uuid_segment_with_suffix (id, trash_suffix);
    }

  if (g_str_has_prefix (path, task_prefix))
    {
      const gchar *id = path + strlen (task_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  return FALSE;
}

static gboolean
native_api_post_path_is_allowed (const gchar *path)
{
  const gchar *alerts_path = "/api/v1/alerts";
  const gchar *alert_prefix = "/api/v1/alerts/";
  const gchar *credentials_path = "/api/v1/credentials";
  const gchar *filters_path = "/api/v1/filters";
  const gchar *hosts_path = "/api/v1/hosts";
  const gchar *overrides_path = "/api/v1/overrides";
  const gchar *port_list_imports_path = "/api/v1/port-list-imports";
  const gchar *port_lists_path = "/api/v1/port-lists";
  const gchar *scanners_path = "/api/v1/scanners";
  const gchar *schedules_path = "/api/v1/schedules";
  const gchar *scopes_path = "/api/v1/scopes";
  const gchar *scan_configs_path = "/api/v1/scan-configs";
  const gchar *tags_path = "/api/v1/tags";
  const gchar *targets_path = "/api/v1/targets";
  const gchar *tasks_path = "/api/v1/tasks";
  const gchar *trashcan_empty_path = "/api/v1/trashcan/empty";
  const gchar *scope_prefix = "/api/v1/scopes/";
  const gchar *filter_prefix = "/api/v1/filters/";
  const gchar *override_prefix = "/api/v1/overrides/";
  const gchar *port_list_prefix = "/api/v1/port-lists/";
  const gchar *scan_config_prefix = "/api/v1/scan-configs/";
  const gchar *scanner_prefix = "/api/v1/scanners/";
  const gchar *schedule_prefix = "/api/v1/schedules/";
  const gchar *tag_prefix = "/api/v1/tags/";
  const gchar *target_prefix = "/api/v1/targets/";
  const gchar *task_prefix = "/api/v1/tasks/";
  const gchar *clone_suffix = "/clone";
  const gchar *restore_suffix = "/restore";
  const gchar *resources_suffix = "/resources";
  const gchar *ranges_suffix = "/ranges";
  const gchar *replace_target_suffix = "/replace-target";
  const gchar *replace_configuration_suffix = "/replace-configuration";
  const gchar *start_suffix = "/start";
  const gchar *stop_suffix = "/stop";
  const gchar *verify_suffix = "/verify";
  const gchar *reports_suffix = "/reports";

  if (path == NULL || strchr (path, '?') != NULL)
    return FALSE;

  if (g_strcmp0 (path, alerts_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, credentials_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, filters_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, hosts_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, overrides_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, port_lists_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, port_list_imports_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, schedules_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, scopes_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, scan_configs_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, scanners_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, tags_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, targets_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, tasks_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, trashcan_empty_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, alert_prefix))
    {
      const gchar *id = path + strlen (alert_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix);
    }

  if (g_str_has_prefix (path, scope_prefix))
    {
      const gchar *id = path + strlen (scope_prefix);
      return is_uuid_segment_with_suffix (id, reports_suffix);
    }

  if (g_str_has_prefix (path, filter_prefix))
    {
      const gchar *id = path + strlen (filter_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, restore_suffix);
    }

  if (g_str_has_prefix (path, override_prefix))
    {
      const gchar *id = path + strlen (override_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, restore_suffix);
    }

  if (g_str_has_prefix (path, port_list_prefix))
    {
      const gchar *id = path + strlen (port_list_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, restore_suffix)
             || is_uuid_segment_with_suffix (id, ranges_suffix);
    }

  if (g_str_has_prefix (path, scan_config_prefix))
    {
      const gchar *id = path + strlen (scan_config_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, restore_suffix);
    }

  if (g_str_has_prefix (path, scanner_prefix))
    {
      const gchar *id = path + strlen (scanner_prefix);
      return is_uuid_segment_with_suffix (id, verify_suffix)
             || is_uuid_segment_with_suffix (id, replace_configuration_suffix);
    }

  if (g_str_has_prefix (path, schedule_prefix))
    {
      const gchar *id = path + strlen (schedule_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, restore_suffix);
    }

  if (g_str_has_prefix (path, tag_prefix))
    {
      const gchar *id = path + strlen (tag_prefix);
      gsize id_length;

      if (g_str_has_suffix (id, clone_suffix))
        id_length = strlen (id) - strlen (clone_suffix);
      else if (g_str_has_suffix (id, restore_suffix))
        id_length = strlen (id) - strlen (restore_suffix);
      else if (g_str_has_suffix (id, resources_suffix))
        id_length = strlen (id) - strlen (resources_suffix);
      else
        return FALSE;
      return is_uuid_segment (id, id_length);
    }

  if (g_str_has_prefix (path, target_prefix))
    {
      const gchar *id = path + strlen (target_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, restore_suffix);
    }

  if (g_str_has_prefix (path, task_prefix))
    {
      const gchar *id = path + strlen (task_prefix);
      return is_uuid_segment_with_suffix (id, clone_suffix)
             || is_uuid_segment_with_suffix (id, start_suffix)
             || is_uuid_segment_with_suffix (id, stop_suffix)
             || is_uuid_segment_with_suffix (id, replace_configuration_suffix)
             || is_uuid_segment_with_suffix (id, replace_target_suffix);
    }

  return FALSE;
}

static gboolean
native_api_header_value_is_safe (const gchar *value, gsize min_length,
                                 gsize max_length)
{
  gsize length;

  if (value == NULL)
    return FALSE;

  length = strlen (value);
  if (length < min_length || length > max_length)
    return FALSE;

  for (const gchar *cursor = value; *cursor != '\0'; cursor++)
    if (!g_ascii_isprint (*cursor))
      return FALSE;

  return TRUE;
}

static const gchar *
browser_proxy_secret (void)
{
  const gchar *secret = g_getenv (BROWSER_PROXY_SECRET_ENV);

  if (!native_api_header_value_is_safe (secret, BROWSER_PROXY_SECRET_MIN_LENGTH,
                                        BROWSER_PROXY_SECRET_MAX_LENGTH))
    return NULL;

  return secret;
}

static const gchar *
browser_proxy_operator_name (gsad_credentials_t *credentials)
{
  gsad_user_t *user;
  const gchar *username;

  if (credentials == NULL)
    return NULL;

  user = gsad_credentials_get_user (credentials);
  if (user == NULL)
    return NULL;

  username = gsad_user_get_username (user);
  if (!native_api_header_value_is_safe (username, 1,
                                        BROWSER_PROXY_OPERATOR_MAX_LENGTH))
    return NULL;

  return username;
}

static gboolean
native_api_patch_path_is_allowed (const gchar *path)
{
  const gchar *alert_prefix = "/api/v1/alerts/";
  const gchar *credential_prefix = "/api/v1/credentials/";
  const gchar *filter_prefix = "/api/v1/filters/";
  const gchar *host_prefix = "/api/v1/hosts/";
  const gchar *override_prefix = "/api/v1/overrides/";
  const gchar *port_list_prefix = "/api/v1/port-lists/";
  const gchar *scan_config_prefix = "/api/v1/scan-configs/";
  const gchar *scanner_prefix = "/api/v1/scanners/";
  const gchar *schedule_prefix = "/api/v1/schedules/";
  const gchar *scope_prefix = "/api/v1/scopes/";
  const gchar *tag_prefix = "/api/v1/tags/";
  const gchar *target_prefix = "/api/v1/targets/";
  const gchar *task_prefix = "/api/v1/tasks/";

  if (path == NULL || strchr (path, '?') != NULL)
    return FALSE;

  if (g_str_has_prefix (path, alert_prefix))
    {
      const gchar *id = path + strlen (alert_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, credential_prefix))
    {
      const gchar *id = path + strlen (credential_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, filter_prefix))
    {
      const gchar *id = path + strlen (filter_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, host_prefix))
    {
      const gchar *id = path + strlen (host_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, override_prefix))
    {
      const gchar *id = path + strlen (override_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, port_list_prefix))
    {
      const gchar *id = path + strlen (port_list_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, scan_config_prefix))
    {
      const gchar *id = path + strlen (scan_config_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, scanner_prefix))
    {
      const gchar *id = path + strlen (scanner_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, schedule_prefix))
    {
      const gchar *id = path + strlen (schedule_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, scope_prefix))
    {
      const gchar *id = path + strlen (scope_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, tag_prefix))
    {
      const gchar *id = path + strlen (tag_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, target_prefix))
    {
      const gchar *id = path + strlen (target_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, task_prefix))
    {
      const gchar *id = path + strlen (task_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  return FALSE;
}

static gboolean
native_api_path_is_allowed (const gchar *path)
{
  const gchar *raw_reports_path = "/api/v1/reports";
  const gchar *raw_report_prefix = "/api/v1/reports/";
  const gchar *results_path = "/api/v1/results";
  const gchar *result_export_suffix = "/export";
  const gchar *vulnerabilities_path = "/api/v1/vulnerabilities";
  const gchar *vulnerability_prefix = "/api/v1/vulnerabilities/";
  const gchar *vulnerability_export_suffix = "/export";
  const gchar *cpes_path = "/api/v1/cpes";
  const gchar *cpe_prefix = "/api/v1/cpes/";
  const gchar *cves_path = "/api/v1/cves";
  const gchar *cve_prefix = "/api/v1/cves/";
  const gchar *cve_export_suffix = "/export";
  const gchar *cert_bund_advisories_path = "/api/v1/cert-bund-advisories";
  const gchar *cert_bund_advisory_prefix = "/api/v1/cert-bund-advisories/";
  const gchar *cert_bund_advisory_export_suffix = "/export";
  const gchar *dfn_cert_advisories_path = "/api/v1/dfn-cert-advisories";
  const gchar *dfn_cert_advisory_prefix = "/api/v1/dfn-cert-advisories/";
  const gchar *dfn_cert_advisory_export_suffix = "/export";
  const gchar *nvts_path = "/api/v1/nvts";
  const gchar *nvt_prefix = "/api/v1/nvts/";
  const gchar *nvt_export_suffix = "/export";
  const gchar *operating_systems_path = "/api/v1/operating-systems";
  const gchar *operating_system_prefix = "/api/v1/operating-systems/";
  const gchar *operating_system_export_suffix = "/export";
  const gchar *hosts_path = "/api/v1/hosts";
  const gchar *host_prefix = "/api/v1/hosts/";
  const gchar *host_export_suffix = "/export";
  const gchar *tls_certificates_path = "/api/v1/tls-certificates";
  const gchar *tls_certificate_prefix = "/api/v1/tls-certificates/";
  const gchar *tls_certificate_export_suffix = "/export";
  const gchar *tls_certificate_pem_suffix = "/certificate";
  const gchar *scanners_path = "/api/v1/scanners";
  const gchar *scanner_prefix = "/api/v1/scanners/";
  const gchar *scanner_export_suffix = "/export";
  const gchar *credentials_path = "/api/v1/credentials";
  const gchar *credential_prefix = "/api/v1/credentials/";
  const gchar *credential_export_suffix = "/export";
  const gchar *users_path = "/api/v1/users";
  const gchar *user_prefix = "/api/v1/users/";
  const gchar *scan_configs_path = "/api/v1/scan-configs";
  const gchar *scan_config_prefix = "/api/v1/scan-configs/";
  const gchar *scan_config_export_suffix = "/export";
  const gchar *scan_config_families_suffix = "/families";
  const gchar *filters_path = "/api/v1/filters";
  const gchar *filter_prefix = "/api/v1/filters/";
  const gchar *filter_export_suffix = "/export";
  const gchar *feeds_path = "/api/v1/feeds";
  const gchar *alerts_path = "/api/v1/alerts";
  const gchar *alert_prefix = "/api/v1/alerts/";
  const gchar *alert_export_suffix = "/export";
  const gchar *tags_path = "/api/v1/tags";
  const gchar *tag_resource_names_prefix = "/api/v1/tags/resource-names/";
  const gchar *tag_prefix = "/api/v1/tags/";
  const gchar *tag_resources_suffix = "/resources";
  const gchar *tag_export_suffix = "/export";
  const gchar *overrides_path = "/api/v1/overrides";
  const gchar *override_prefix = "/api/v1/overrides/";
  const gchar *override_export_suffix = "/export";
  const gchar *port_lists_path = "/api/v1/port-lists";
  const gchar *port_list_prefix = "/api/v1/port-lists/";
  const gchar *port_list_export_suffix = "/export";
  const gchar *schedules_path = "/api/v1/schedules";
  const gchar *schedule_prefix = "/api/v1/schedules/";
  const gchar *schedule_export_suffix = "/export";
  const gchar *timezones_path = "/api/v1/timezones";
  const gchar *report_formats_path = "/api/v1/report-formats";
  const gchar *report_format_prefix = "/api/v1/report-formats/";
  const gchar *report_format_export_suffix = "/export";
  const gchar *trashcan_summary_path = "/api/v1/trashcan/summary";
  const gchar *trashcan_items_path = "/api/v1/trashcan/items";
  const gchar *trashcan_empty_preview_path = "/api/v1/trashcan/empty-preview";
  const gchar *scopes_path = "/api/v1/scopes";
  const gchar *targets_path = "/api/v1/targets";
  const gchar *target_prefix = "/api/v1/targets/";
  const gchar *target_export_suffix = "/export";
  const gchar *tasks_path = "/api/v1/tasks";
  const gchar *task_prefix = "/api/v1/tasks/";
  const gchar *task_export_suffix = "/export";
  const gchar *scope_reports_path = "/api/v1/scope-reports";
  const gchar *scope_report_prefix = "/api/v1/scope-reports/";
  const gchar *scope_report_results_suffix = "/results";
  const gchar *scope_prefix = "/api/v1/scopes/";
  const gchar *metrics_suffix = "/metrics";
  const gchar *results_suffix = "/results";
  const gchar *raw_results_suffix = "/raw-results";
  const gchar *hosts_suffix = "/hosts";
  const gchar *ports_suffix = "/ports";
  const gchar *applications_suffix = "/applications";
  const gchar *operating_systems_suffix = "/operating-systems";
  const gchar *cves_suffix = "/cves";
  const gchar *tls_certificates_suffix = "/tls-certificates";
  const gchar *errors_suffix = "/errors";
  const gchar *scope_collection_suffixes[] = { "/metrics",
                                               "/results",
                                               "/hosts",
                                               "/ports",
                                               "/applications",
                                               "/operating-systems",
                                               "/cves",
                                               "/tls-certificates",
                                               "/errors",
                                               "/retention-plan",
                                               NULL };

  if (path == NULL || strchr (path, '?') != NULL)
    return FALSE;

  if (g_strcmp0 (path, raw_reports_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, results_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, results_path)
      && path[strlen (results_path)] == '/')
    {
      const gchar *id = path + strlen (results_path) + 1;
      if (g_str_has_suffix (id, result_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (result_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, vulnerabilities_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, vulnerability_prefix))
    {
      const gchar *id = path + strlen (vulnerability_prefix);
      if (g_str_has_suffix (id, vulnerability_export_suffix))
        return is_nvt_oid_segment (id,
                                   strlen (id)
                                   - strlen (vulnerability_export_suffix));
      return is_nvt_oid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, cpes_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, cpe_prefix))
    {
      const gchar *id = path + strlen (cpe_prefix);
      return is_cpe_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, cves_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, cve_prefix))
    {
      const gchar *id = path + strlen (cve_prefix);
      if (g_str_has_suffix (id, cve_export_suffix))
        return is_cve_id_segment (id,
                                  strlen (id)
                                  - strlen (cve_export_suffix));
      return is_cve_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, cert_bund_advisories_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, cert_bund_advisory_prefix))
    {
      const gchar *id = path + strlen (cert_bund_advisory_prefix);
      if (g_str_has_suffix (id, cert_bund_advisory_export_suffix))
        return is_advisory_id_segment (id,
                                       strlen (id)
                                       - strlen (cert_bund_advisory_export_suffix));
      return is_advisory_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, dfn_cert_advisories_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, dfn_cert_advisory_prefix))
    {
      const gchar *id = path + strlen (dfn_cert_advisory_prefix);
      if (g_str_has_suffix (id, dfn_cert_advisory_export_suffix))
        return is_advisory_id_segment (id,
                                       strlen (id)
                                       - strlen (dfn_cert_advisory_export_suffix));
      return is_advisory_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, nvts_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, nvt_prefix))
    {
      const gchar *id = path + strlen (nvt_prefix);
      if (g_str_has_suffix (id, nvt_export_suffix))
        return is_nvt_oid_segment (id,
                                   strlen (id)
                                   - strlen (nvt_export_suffix));
      return is_nvt_oid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, operating_systems_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, operating_system_prefix))
    {
      const gchar *id = path + strlen (operating_system_prefix);
      if (g_str_has_suffix (id, operating_system_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (operating_system_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, hosts_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, host_prefix))
    {
      const gchar *id = path + strlen (host_prefix);
      if (g_str_has_suffix (id, host_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (host_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, tls_certificates_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, tls_certificate_prefix))
    {
      const gchar *id = path + strlen (tls_certificate_prefix);
      if (g_str_has_suffix (id, tls_certificate_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (tls_certificate_export_suffix));
      if (g_str_has_suffix (id, tls_certificate_pem_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (tls_certificate_pem_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, scanners_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, scanner_prefix))
    {
      const gchar *id = path + strlen (scanner_prefix);
      if (g_str_has_suffix (id, scanner_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (scanner_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, credentials_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, credential_prefix))
    {
      const gchar *id = path + strlen (credential_prefix);
      if (g_str_has_suffix (id, credential_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (credential_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, users_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, user_prefix))
    return is_uuid_segment (path + strlen (user_prefix),
                            strlen (path + strlen (user_prefix)));

  if (g_strcmp0 (path, scan_configs_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, scan_config_prefix))
    {
      const gchar *id = path + strlen (scan_config_prefix);
      if (g_str_has_suffix (id, scan_config_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (scan_config_export_suffix));
      if (g_str_has_suffix (id, scan_config_families_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (scan_config_families_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, filters_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, filter_prefix))
    {
      const gchar *id = path + strlen (filter_prefix);
      if (g_str_has_suffix (id, filter_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (filter_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, feeds_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, alerts_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, alert_prefix))
    {
      const gchar *id = path + strlen (alert_prefix);
      if (g_str_has_suffix (id, alert_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (alert_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, tags_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, tag_resource_names_prefix))
    {
      const gchar *resource_type = path + strlen (tag_resource_names_prefix);
      return is_tag_resource_type_segment (resource_type,
                                           strlen (resource_type));
    }

  if (g_str_has_prefix (path, tag_prefix)
      && g_str_has_suffix (path, tag_resources_suffix))
    {
      const gchar *id = path + strlen (tag_prefix);
      gsize id_len = strlen (path) - strlen (tag_prefix)
                     - strlen (tag_resources_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, tag_prefix))
    {
      const gchar *id = path + strlen (tag_prefix);
      if (g_str_has_suffix (id, tag_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (tag_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, overrides_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, override_prefix))
    {
      const gchar *id = path + strlen (override_prefix);
      if (g_str_has_suffix (id, override_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (override_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, port_lists_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, port_list_prefix))
    {
      const gchar *id = path + strlen (port_list_prefix);
      if (g_str_has_suffix (id, port_list_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (port_list_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, schedules_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, timezones_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, schedule_prefix))
    {
      const gchar *id = path + strlen (schedule_prefix);
      if (g_str_has_suffix (id, schedule_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (schedule_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, report_formats_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, report_format_prefix))
    {
      const gchar *id = path + strlen (report_format_prefix);
      if (g_str_has_suffix (id, report_format_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (report_format_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, trashcan_summary_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, trashcan_items_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, trashcan_empty_preview_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, scopes_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, targets_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, tasks_path) == 0)
    return TRUE;

  if (g_strcmp0 (path, scope_reports_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, scope_report_prefix))
    {
      const gchar *id = path + strlen (scope_report_prefix);
      if (g_str_has_suffix (id, scope_report_results_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                  - strlen (scope_report_results_suffix));

      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, target_prefix))
    {
      const gchar *id = path + strlen (target_prefix);
      if (g_str_has_suffix (id, target_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (target_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, task_prefix))
    {
      const gchar *id = path + strlen (task_prefix);
      if (g_str_has_suffix (id, task_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (task_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, metrics_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (metrics_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, cves_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (cves_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, errors_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (errors_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, raw_results_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (raw_results_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, results_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (results_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, hosts_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (hosts_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, ports_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (ports_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, applications_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (applications_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, operating_systems_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (operating_systems_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix)
      && g_str_has_suffix (path, tls_certificates_suffix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      gsize id_len = strlen (path) - strlen (raw_report_prefix)
                     - strlen (tls_certificates_suffix);
      return is_uuid_segment (id, id_len);
    }

  if (g_str_has_prefix (path, raw_report_prefix))
    {
      const gchar *id = path + strlen (raw_report_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_str_has_prefix (path, scope_prefix))
    {
      const gchar *scope_id = path + strlen (scope_prefix);
      const gchar *reports_sep = strstr (scope_id, "/reports/");
      const gchar *suffix = NULL;
      if (reports_sep == NULL)
        return is_uuid_segment (scope_id, strlen (scope_id));

      const gchar *report_id = reports_sep + strlen ("/reports/");
      gsize scope_id_len = reports_sep - scope_id;
      gsize report_id_len;

      for (gsize i = 0; scope_collection_suffixes[i] != NULL; i++)
        if (g_str_has_suffix (path, scope_collection_suffixes[i]))
          {
            suffix = scope_collection_suffixes[i];
            break;
          }

      if (suffix == NULL)
        return FALSE;

      report_id_len = strlen (report_id) - strlen (suffix);

      return is_uuid_segment (scope_id, scope_id_len)
             && is_uuid_segment (report_id, report_id_len);
    }

  return FALSE;
}

static void
append_query_param (GString *target, params_t *params, const gchar *name)
{
  const gchar *value;
  gchar *escaped_name;
  gchar *escaped_value;

  if (params == NULL)
    return;

  value = params_value (params, name);
  if (value == NULL)
    return;

  escaped_name = g_uri_escape_string (name, NULL, TRUE);
  escaped_value = g_uri_escape_string (value, NULL, TRUE);
  g_string_append_c (target, strchr (target->str, '?') == NULL ? '?' : '&');
  g_string_append_printf (target, "%s=%s", escaped_name, escaped_value);
  g_free (escaped_name);
  g_free (escaped_value);
}

static gchar *
native_api_request_target (const gchar *path, params_t *params)
{
  GString *target = g_string_new (path);

  append_query_param (target, params, "page");
  append_query_param (target, params, "page_size");
  append_query_param (target, params, "sort");
  append_query_param (target, params, "filter");

  return g_string_free (target, FALSE);
}

static gchar *
native_api_pdf_download_request_target (const gchar *path, params_t *params)
{
  return native_api_pdf_download_target (
    path, params ? params_value (params, "report_format_id") : NULL);
}

static gsad_http_result_t
send_json_error (gsad_http_connection_t *connection, int status_code,
                 const gchar *code, const gchar *message)
{
  GString *escaped_code = g_string_new (NULL);
  GString *escaped_message = g_string_new (NULL);
  const unsigned char *cursor;
  gchar *body;

  for (cursor = (const unsigned char *) code; *cursor; cursor++)
    {
      if (*cursor == '"' || *cursor == '\\')
        g_string_append_c (escaped_code, '\\');
      if (*cursor < 0x20)
        g_string_append_printf (escaped_code, "\\u%04x", *cursor);
      else
        g_string_append_c (escaped_code, (gchar) *cursor);
    }
  for (cursor = (const unsigned char *) message; *cursor; cursor++)
    {
      switch (*cursor)
        {
          case '"':
          case '\\':
            g_string_append_c (escaped_message, '\\');
            g_string_append_c (escaped_message, (gchar) *cursor);
            break;
          case '\b':
            g_string_append (escaped_message, "\\b");
            break;
          case '\f':
            g_string_append (escaped_message, "\\f");
            break;
          case '\n':
            g_string_append (escaped_message, "\\n");
            break;
          case '\r':
            g_string_append (escaped_message, "\\r");
            break;
          case '\t':
            g_string_append (escaped_message, "\\t");
            break;
          default:
            if (*cursor < 0x20)
              g_string_append_printf (escaped_message, "\\u%04x", *cursor);
            else
              g_string_append_c (escaped_message, (gchar) *cursor);
        }
    }
  body = g_strdup_printf (
    "{\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}\n",
    escaped_code->str, escaped_message->str);
  g_string_free (escaped_code, TRUE);
  g_string_free (escaped_message, TRUE);
  gsad_http_result_t ret = gsad_http_send_response_for_content (
    connection, body, status_code, NULL, GSAD_CONTENT_TYPE_APP_JSON, NULL, 0);
  g_free (body);
  return ret;
}

static gboolean
response_content_length (GString *raw_response, gsize *content_length,
                         gboolean *present)
{
  const gchar *header_end = strstr (raw_response->str, "\r\n\r\n");
  const gchar *cursor = strstr (raw_response->str, "\r\n");

  *content_length = 0;
  *present = FALSE;
  if (header_end == NULL || cursor == NULL || cursor >= header_end)
    return FALSE;
  cursor += 2;
  while (cursor < header_end)
    {
      const gchar *line_end = strstr (cursor, "\r\n");
      const gchar *value;
      gchar *endptr;
      guint64 parsed;

      if (line_end == NULL || line_end > header_end)
        return FALSE;
      if ((gsize) (line_end - cursor) < strlen ("Content-Length:")
          || g_ascii_strncasecmp (cursor, "Content-Length:",
                                  strlen ("Content-Length:")))
        {
          cursor = line_end + 2;
          continue;
        }
      value = cursor + strlen ("Content-Length:");
      while (value < line_end && g_ascii_isspace (*value))
        value++;
      if (*present || value == line_end || !g_ascii_isdigit (*value))
        return FALSE;
      endptr = (gchar *) value;
      while (endptr < line_end && g_ascii_isdigit (*endptr))
        endptr++;
      {
        gchar *number_end = endptr;
        while (endptr < line_end && g_ascii_isspace (*endptr))
          endptr++;
        if (endptr != line_end)
          return FALSE;
        errno = 0;
        parsed = g_ascii_strtoull (value, &endptr, 10);
        if (errno || endptr != number_end || parsed > G_MAXSIZE)
          return FALSE;
      }
      *content_length = (gsize) parsed;
      *present = TRUE;
      cursor = line_end + 2;
    }
  return TRUE;
}

static int
connect_to_native_api (const gchar *host, const gchar *port)
{
  struct addrinfo hints;
  struct addrinfo *result = NULL;
  int fd = -1;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo (host, port, &hints, &result) != 0)
    return -1;

  for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd == -1)
        continue;

      struct timeval timeout;
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
      setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout));
      setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof (timeout));

      if (connect (fd, rp->ai_addr, rp->ai_addrlen) == 0)
        break;

      close (fd);
      fd = -1;
    }

  freeaddrinfo (result);
  return fd;
}

static gboolean
send_all (int fd, const gchar *data, gsize length)
{
  gsize sent = 0;

  while (sent < length)
    {
      ssize_t written = send (fd, data + sent, length - sent, 0);
      if (written <= 0)
        return FALSE;
      sent += (gsize) written;
    }

  return TRUE;
}

static gchar *
extract_response_body (GString *raw_response, guint *status_code,
                       gchar **error_message)
{
  gchar *header_end = strstr (raw_response->str, "\r\n\r\n");
  gchar *status_end = strstr (raw_response->str, "\r\n");
  int parsed_status = 0;

  if (header_end == NULL || status_end == NULL || status_end > header_end)
    {
      *error_message = g_strdup ("Native API returned a malformed response.");
      return NULL;
    }

  gchar *status_line = g_strndup (raw_response->str,
                                  (gsize) (status_end - raw_response->str));
  if (sscanf (status_line, "HTTP/%*d.%*d %d", &parsed_status) != 1
      || parsed_status < 100 || parsed_status > 599)
    {
      g_free (status_line);
      *error_message = g_strdup ("Native API returned an invalid status line.");
      return NULL;
    }
  g_free (status_line);

  *status_code = (guint) parsed_status;
  return g_strdup (header_end + 4);
}

static gchar *
fetch_native_api_json (const gchar *method, const gchar *path,
                       const gchar *request_body, gsize request_body_length,
                       const gchar *browser_proxy_secret,
                       const gchar *operator_name, guint *status_code,
                       gchar **error_message,
                       gboolean *mutation_outcome_indeterminate)
{
  const gchar *host = g_getenv ("TURBOVAS_NATIVE_API_HOST");
  const gchar *port = g_getenv ("TURBOVAS_NATIVE_API_PORT");
  int fd;
  GString *request;
  GString *response;
  gchar buffer[8192];
  gchar *body;
  gsize request_capacity;
  gboolean mutation_method;
  gsize proxy_secret_length;
  gsize operator_name_length;
  gsize declared_content_length;
  gboolean content_length_present;

  if (host == NULL || host[0] == 0)
    host = DEFAULT_NATIVE_API_HOST;
  if (port == NULL || port[0] == 0)
    port = DEFAULT_NATIVE_API_PORT;
  mutation_method = g_strcmp0 (method, "POST") == 0
                    || g_strcmp0 (method, "PATCH") == 0
                    || g_strcmp0 (method, "DELETE") == 0;
  *mutation_outcome_indeterminate = FALSE;
  if (mutation_method
      && (browser_proxy_secret == NULL || operator_name == NULL))
    {
      *error_message = g_strdup ("Native API browser write proxy is not configured.");
      return NULL;
    }
  proxy_secret_length = browser_proxy_secret
                          ? strlen (browser_proxy_secret) : 0;
  operator_name_length = operator_name ? strlen (operator_name) : 0;

  fd = connect_to_native_api (host, port);
  if (fd == -1)
    {
      *error_message = g_strdup ("Native API service is unavailable.");
      return NULL;
    }

  if (request_body_length
      > G_MAXSIZE - strlen (method) - strlen (path) - strlen (host)
          - strlen (port) - proxy_secret_length
          - operator_name_length - 512)
    {
      close (fd);
      *error_message = g_strdup ("Native API request is too large.");
      return NULL;
    }
  request_capacity = request_body_length + strlen (method) + strlen (path)
                     + strlen (host) + strlen (port)
                     + proxy_secret_length + operator_name_length
                     + 512;
  request = g_string_sized_new (request_capacity);
  g_string_printf (request,
                   "%s %s HTTP/1.1\r\n"
                   "Host: %s:%s\r\n"
                   "Accept: application/json\r\n"
                   "Connection: close\r\n"
                   "User-Agent: gsad-native-api-proxy\r\n",
                   method, path, host, port);
  if (mutation_method)
    {
      g_string_append_printf (request,
                              "Content-Type: application/json\r\n"
                              "Content-Length: %" G_GSIZE_FORMAT "\r\n"
                              BROWSER_PROXY_SECRET_HEADER ": %s\r\n"
                              BROWSER_PROXY_OPERATOR_HEADER ": %s\r\n",
                              request_body_length, browser_proxy_secret,
                              operator_name);
    }
  g_string_append (request, "\r\n");
  if (request_body != NULL && request_body_length > 0)
    g_string_append_len (request, request_body, request_body_length);

  if (!send_all (fd, request->str, request->len))
    {
      secure_gstring_free (request);
      close (fd);
      *error_message = g_strdup (
        mutation_method
          ? "The mutation may have been forwarded; verify current state before retrying."
          : "Native API request could not be sent.");
      *mutation_outcome_indeterminate = mutation_method;
      return NULL;
    }
  secure_gstring_free (request);

  response = g_string_new (NULL);
  while (TRUE)
    {
      ssize_t count = recv (fd, buffer, sizeof (buffer), 0);
      if (count == 0)
        break;
      if (count < 0)
        {
          g_string_free (response, TRUE);
          close (fd);
          *error_message = g_strdup (
            mutation_method
              ? "The mutation may have committed; verify current state before retrying."
              : "Native API response could not be read.");
          *mutation_outcome_indeterminate = mutation_method;
          return NULL;
        }

      if (response->len + (gsize) count > NATIVE_API_MAX_RESPONSE_BYTES)
        {
          g_string_free (response, TRUE);
          close (fd);
          *error_message = g_strdup ("Native API response is too large.");
          *mutation_outcome_indeterminate = mutation_method;
          return NULL;
        }

      g_string_append_len (response, buffer, count);
    }
  close (fd);

  body = extract_response_body (response, status_code, error_message);
  if (!response_content_length (response, &declared_content_length,
                                &content_length_present))
    {
      g_free (body);
      body = NULL;
      g_free (*error_message);
      *error_message = g_strdup ("Native API returned invalid response framing.");
    }
  g_string_free (response, TRUE);
  if (body == NULL)
    *mutation_outcome_indeterminate = mutation_method;
  else if ((content_length_present
            && strlen (body) != declared_content_length)
           || (mutation_method && *status_code != MHD_HTTP_NO_CONTENT
               && !content_length_present))
    {
      g_free (body);
      body = NULL;
      g_free (*error_message);
      *error_message = g_strdup ("Native API returned incomplete response framing.");
      *mutation_outcome_indeterminate = mutation_method;
    }
  else if (mutation_method && *status_code != MHD_HTTP_NO_CONTENT)
    {
      if (!response_body_is_json_object (body))
        {
          g_free (body);
          body = NULL;
          g_free (*error_message);
          *error_message =
            g_strdup ("Native API returned a truncated or malformed mutation response.");
          *mutation_outcome_indeterminate = TRUE;
        }
    }
  return body;
}

static gboolean
fetch_native_api_pdf (const gchar *path,
                      native_api_pdf_response_t *pdf_response,
                      gchar **error_message)
{
  const gchar *host = g_getenv ("TURBOVAS_NATIVE_API_HOST");
  const gchar *port = g_getenv ("TURBOVAS_NATIVE_API_PORT");
  int fd;
  GString *request;
  GByteArray *response;
  gchar buffer[8192];
  gboolean parsed;

  if (host == NULL || host[0] == 0)
    host = DEFAULT_NATIVE_API_HOST;
  if (port == NULL || port[0] == 0)
    port = DEFAULT_NATIVE_API_PORT;

  fd = connect_to_native_api (host, port);
  if (fd == -1)
    {
      *error_message = g_strdup ("Native API service is unavailable.");
      return FALSE;
    }

  request = g_string_new (NULL);
  g_string_printf (request,
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s:%s\r\n"
                   "Accept: application/pdf\r\n"
                   "Connection: close\r\n"
                   "User-Agent: gsad-native-api-proxy\r\n"
                   "\r\n",
                   path, host, port);
  if (!send_all (fd, request->str, request->len))
    {
      secure_gstring_free (request);
      close (fd);
      *error_message = g_strdup ("Native API request could not be sent.");
      return FALSE;
    }
  secure_gstring_free (request);

  response = g_byte_array_new ();
  while (TRUE)
    {
      ssize_t count = recv (fd, buffer, sizeof (buffer), 0);

      if (count == 0)
        break;
      if (count < 0)
        {
          g_byte_array_unref (response);
          close (fd);
          *error_message = g_strdup ("Native API response could not be read.");
          return FALSE;
        }
      if ((gsize) count > NATIVE_API_MAX_PDF_RESPONSE_BYTES - response->len)
        {
          g_byte_array_unref (response);
          close (fd);
          *error_message = g_strdup ("Native API response is too large.");
          return FALSE;
        }
      g_byte_array_append (response, (const guint8 *) buffer, (guint) count);
    }
  close (fd);

  parsed = parse_native_api_pdf_response (response->data, response->len,
                                          pdf_response, error_message);
  g_byte_array_unref (response);
  return parsed;
}

gsad_http_result_t
gsad_http_handle_native_api_get (gsad_http_handler_t *handler_next,
                                 void *handler_data,
                                 gsad_http_connection_t *connection,
                                 gsad_connection_info_t *con_info, void *data)
{
  gsad_credentials_t *credentials = (gsad_credentials_t *) data;
  const gchar *path = gsad_connection_info_get_url (con_info);
  params_t *params = gsad_connection_info_get_params (con_info);
  gchar *request_target = NULL;
  gchar *body = NULL;
  gchar *error_message = NULL;
  guint status_code = MHD_HTTP_BAD_GATEWAY;
  gsad_http_result_t ret;
  gboolean mutation_outcome_indeterminate;

  (void) handler_next;
  (void) handler_data;

  if (browser_proxy_operator_name (credentials) == NULL)
    {
      gsad_credentials_free (credentials);
      return send_json_error (
        connection, MHD_HTTP_UNAUTHORIZED, "unauthorized",
        "Native API browser reads require an authenticated session user.");
    }

  if (native_api_pdf_download_path_is_allowed (path))
    {
      native_api_pdf_response_t pdf_response = {0};
      gchar *pdf_request_target =
        native_api_pdf_download_request_target (path, params);

      if (pdf_request_target == NULL)
        {
          gsad_credentials_free (credentials);
          return send_json_error (connection, MHD_HTTP_NOT_FOUND, "not_found",
                                  "Native API path is not available.");
        }

      if (!fetch_native_api_pdf (pdf_request_target, &pdf_response,
                                 &error_message))
        {
          g_warning ("%s: %s", __func__, error_message);
          g_free (pdf_request_target);
          gsad_credentials_free (credentials);
          g_free (error_message);
          return send_json_error (connection, MHD_HTTP_BAD_GATEWAY,
                                  "control_unavailable",
                                  "Native API service is unavailable.");
        }
      g_free (pdf_request_target);
      gsad_credentials_free (credentials);

      if (pdf_response.status_code != MHD_HTTP_OK)
        {
          guint status_code = pdf_response.status_code;

          native_api_pdf_response_clear (&pdf_response);
          return send_json_error (connection, (int) status_code,
                                  "report_download_failed",
                                  "Native API report download failed.");
        }

      gsize pdf_length;
      const gchar *pdf = g_bytes_get_data (pdf_response.body, &pdf_length);
      ret = gsad_http_send_response_for_content (
        connection, pdf, MHD_HTTP_OK, NULL, GSAD_CONTENT_TYPE_APP_PDF,
        pdf_response.content_disposition, pdf_length);
      native_api_pdf_response_clear (&pdf_response);
      return ret;
    }

  if (!native_api_path_is_allowed (path))
    {
      gsad_credentials_free (credentials);
      return send_json_error (connection, MHD_HTTP_NOT_FOUND, "not_found",
                              "Native API path is not available.");
    }

  request_target = native_api_request_target (path, params);
  body = fetch_native_api_json ("GET", request_target, NULL, 0, NULL, NULL,
                                &status_code, &error_message,
                                &mutation_outcome_indeterminate);
  g_free (request_target);
  gsad_credentials_free (credentials);

  if (body == NULL)
    {
      g_warning ("%s: %s", __func__, error_message);
      g_free (error_message);
      return send_json_error (connection, MHD_HTTP_BAD_GATEWAY,
                              "control_unavailable",
                              "Native API service is unavailable.");
    }

  ret = gsad_http_send_response_for_content (connection, body, (int) status_code,
                                             NULL, GSAD_CONTENT_TYPE_APP_JSON,
                                             NULL, 0);
  g_free (body);
  return ret;
}

typedef gboolean (*native_api_write_path_check_t) (const gchar *path);

static gsad_http_result_t
handle_native_api_write (gsad_http_handler_t *handler_next, void *handler_data,
                         gsad_http_connection_t *connection,
                         gsad_connection_info_t *con_info, void *data,
                         const gchar *method,
                         native_api_write_path_check_t path_is_allowed)
{
  gsad_credentials_t *credentials = (gsad_credentials_t *) data;
  const gchar *path = gsad_connection_info_get_url (con_info);
  const gchar *secret = NULL;
  const gchar *operator_name = NULL;
  const gchar *request_body = NULL;
  gsize request_body_length = 0;
  gchar *body = NULL;
  gchar *error_message = NULL;
  guint status_code = MHD_HTTP_BAD_GATEWAY;
  gsad_http_result_t ret;
  gboolean mutation_outcome_indeterminate;

  (void) handler_next;
  (void) handler_data;

  if (!path_is_allowed (path))
    {
      gsad_credentials_free (credentials);
      return send_json_error (connection, MHD_HTTP_NOT_FOUND, "not_found",
                              "Native API path is not available.");
    }

  secret = browser_proxy_secret ();
  if (secret == NULL)
    {
      gsad_credentials_free (credentials);
      return send_json_error (connection, MHD_HTTP_SERVICE_UNAVAILABLE,
                              "control_unavailable",
                              "Native API browser write proxy is not configured.");
    }

  operator_name = browser_proxy_operator_name (credentials);
  if (operator_name == NULL)
    {
      gsad_credentials_free (credentials);
      return send_json_error (connection, MHD_HTTP_UNAUTHORIZED,
                              "unauthorized",
                              "Native API browser write proxy requires a session user.");
    }

  request_body = gsad_connection_info_get_raw_body (con_info,
                                                    &request_body_length);
  if (g_strcmp0 (method, "DELETE") == 0 && request_body_length != 0)
    {
      gsad_credentials_free (credentials);
      return send_json_error (connection, MHD_HTTP_NOT_ACCEPTABLE,
                              "request_body_not_allowed",
                              "Native API DELETE requests must not include a request body.");
    }
  body = fetch_native_api_json (method, path, request_body, request_body_length,
                                secret, operator_name, &status_code,
                                &error_message,
                                &mutation_outcome_indeterminate);
  gsad_credentials_free (credentials);

  if (body == NULL)
    {
      gsad_http_result_t error_ret;

      g_warning ("%s: %s", __func__, error_message);
      if (mutation_outcome_indeterminate)
        error_ret = send_json_error (
          connection, MHD_HTTP_BAD_GATEWAY, "mutation_outcome_indeterminate",
          "The mutation may have committed; verify current state before retrying.");
      else
        error_ret = send_json_error (
          connection, MHD_HTTP_SERVICE_UNAVAILABLE, "control_unavailable",
          "Native API service is unavailable.");
      g_free (error_message);
      return error_ret;
    }

  ret = gsad_http_send_response_for_content (connection, body, (int) status_code,
                                             NULL, GSAD_CONTENT_TYPE_APP_JSON,
                                             NULL, 0);
  g_free (body);
  return ret;
}

gsad_http_result_t
gsad_http_handle_native_api_post (gsad_http_handler_t *handler_next,
                                  void *handler_data,
                                  gsad_http_connection_t *connection,
                                  gsad_connection_info_t *con_info,
                                  void *data)
{
  return handle_native_api_write (handler_next, handler_data, connection,
                                  con_info, data, "POST",
                                  native_api_post_path_is_allowed);
}

gsad_http_result_t
gsad_http_handle_native_api_patch (gsad_http_handler_t *handler_next,
                                   void *handler_data,
                                   gsad_http_connection_t *connection,
                                   gsad_connection_info_t *con_info,
                                   void *data)
{
  return handle_native_api_write (handler_next, handler_data, connection,
                                  con_info, data, "PATCH",
                                  native_api_patch_path_is_allowed);
}

gsad_http_result_t
gsad_http_handle_native_api_delete (gsad_http_handler_t *handler_next,
                                    void *handler_data,
                                    gsad_http_connection_t *connection,
                                    gsad_connection_info_t *con_info,
                                    void *data)
{
  return handle_native_api_write (handler_next, handler_data, connection,
                                  con_info, data, "DELETE",
                                  native_api_delete_path_is_allowed);
}

#ifdef GSAD_NATIVE_API_TEST
gboolean
gsad_native_api_test_pdf_download_target (const gchar *path,
                                          const gchar *report_format_id,
                                          gchar **target)
{
  *target = native_api_pdf_download_target (path, report_format_id);
  return *target != NULL;
}

gboolean
gsad_native_api_test_parse_pdf_response (const guint8 *data, gsize length,
                                         guint *status_code, GBytes **body,
                                         gchar **content_disposition)
{
  native_api_pdf_response_t response = {0};
  gchar *error_message = NULL;
  gboolean parsed =
    parse_native_api_pdf_response (data, length, &response, &error_message);

  g_free (error_message);
  if (!parsed)
    return FALSE;

  *status_code = response.status_code;
  *body = g_steal_pointer (&response.body);
  *content_disposition = g_steal_pointer (&response.content_disposition);
  return TRUE;
}

gboolean
gsad_native_api_test_browser_credentials_are_session_bound (
  gsad_credentials_t *credentials)
{
  return browser_proxy_operator_name (credentials) != NULL;
}

gboolean
gsad_native_api_test_post_path_is_allowed (const gchar *path)
{
  return native_api_post_path_is_allowed (path);
}

gboolean
gsad_native_api_test_patch_path_is_allowed (const gchar *path)
{
  return native_api_patch_path_is_allowed (path);
}

gboolean
gsad_native_api_test_delete_path_is_allowed (const gchar *path)
{
  return native_api_delete_path_is_allowed (path);
}
#endif
