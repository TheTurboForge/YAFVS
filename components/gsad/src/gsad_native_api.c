/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_native_api.c
 * @brief Authenticated same-origin proxy for TurboVAS native API reads.
 */

#include "gsad_native_api.h"

#include "gsad_connection_info.h"
#include "gsad_credentials.h"
#include "gsad_http.h"
#include "gsad_params.h"

#include <errno.h>
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
    "dfn_cert_adv",  "host",          "nvt",          "os",
    "port_list",     "report_config", "report_format", "config",
    "target",        "task",          "tls_certificate"
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
native_api_path_is_allowed (const gchar *path)
{
  const gchar *raw_reports_path = "/api/v1/reports";
  const gchar *raw_report_prefix = "/api/v1/reports/";
  const gchar *results_path = "/api/v1/results";
  const gchar *result_export_suffix = "/export";
  const gchar *vulnerabilities_path = "/api/v1/vulnerabilities";
  const gchar *cpes_path = "/api/v1/cpes";
  const gchar *cpe_prefix = "/api/v1/cpes/";
  const gchar *cves_path = "/api/v1/cves";
  const gchar *cve_prefix = "/api/v1/cves/";
  const gchar *cert_bund_advisories_path = "/api/v1/cert-bund-advisories";
  const gchar *cert_bund_advisory_prefix = "/api/v1/cert-bund-advisories/";
  const gchar *dfn_cert_advisories_path = "/api/v1/dfn-cert-advisories";
  const gchar *dfn_cert_advisory_prefix = "/api/v1/dfn-cert-advisories/";
  const gchar *nvts_path = "/api/v1/nvts";
  const gchar *nvt_prefix = "/api/v1/nvts/";
  const gchar *operating_systems_path = "/api/v1/operating-systems";
  const gchar *operating_system_prefix = "/api/v1/operating-systems/";
  const gchar *hosts_path = "/api/v1/hosts";
  const gchar *host_prefix = "/api/v1/hosts/";
  const gchar *tls_certificates_path = "/api/v1/tls-certificates";
  const gchar *tls_certificate_prefix = "/api/v1/tls-certificates/";
  const gchar *scanners_path = "/api/v1/scanners";
  const gchar *scanner_prefix = "/api/v1/scanners/";
  const gchar *credentials_path = "/api/v1/credentials";
  const gchar *credential_prefix = "/api/v1/credentials/";
  const gchar *scan_configs_path = "/api/v1/scan-configs";
  const gchar *scan_config_prefix = "/api/v1/scan-configs/";
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
  const gchar *port_lists_path = "/api/v1/port-lists";
  const gchar *port_list_prefix = "/api/v1/port-lists/";
  const gchar *port_list_export_suffix = "/export";
  const gchar *schedules_path = "/api/v1/schedules";
  const gchar *schedule_prefix = "/api/v1/schedules/";
  const gchar *timezones_path = "/api/v1/timezones";
  const gchar *report_configs_path = "/api/v1/report-configs";
  const gchar *report_config_prefix = "/api/v1/report-configs/";
  const gchar *report_config_export_suffix = "/export";
  const gchar *report_formats_path = "/api/v1/report-formats";
  const gchar *report_format_prefix = "/api/v1/report-formats/";
  const gchar *trashcan_summary_path = "/api/v1/trashcan/summary";
  const gchar *scopes_path = "/api/v1/scopes";
  const gchar *targets_path = "/api/v1/targets";
  const gchar *target_prefix = "/api/v1/targets/";
  const gchar *tasks_path = "/api/v1/tasks";
  const gchar *task_prefix = "/api/v1/tasks/";
  const gchar *scope_reports_path = "/api/v1/scope-reports";
  const gchar *scope_report_prefix = "/api/v1/scope-reports/";
  const gchar *scope_prefix = "/api/v1/scopes/";
  const gchar *metrics_suffix = "/metrics";
  const gchar *results_suffix = "/results";
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
      return is_cve_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, cert_bund_advisories_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, cert_bund_advisory_prefix))
    {
      const gchar *id = path + strlen (cert_bund_advisory_prefix);
      return is_advisory_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, dfn_cert_advisories_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, dfn_cert_advisory_prefix))
    {
      const gchar *id = path + strlen (dfn_cert_advisory_prefix);
      return is_advisory_id_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, nvts_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, nvt_prefix))
    {
      const gchar *id = path + strlen (nvt_prefix);
      return is_nvt_oid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, operating_systems_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, operating_system_prefix))
    {
      const gchar *id = path + strlen (operating_system_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, hosts_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, host_prefix))
    {
      const gchar *id = path + strlen (host_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, tls_certificates_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, tls_certificate_prefix))
    {
      const gchar *id = path + strlen (tls_certificate_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, scanners_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, scanner_prefix))
    {
      const gchar *id = path + strlen (scanner_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, credentials_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, credential_prefix))
    {
      const gchar *id = path + strlen (credential_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, scan_configs_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, scan_config_prefix))
    {
      const gchar *id = path + strlen (scan_config_prefix);
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
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, report_configs_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, report_config_prefix))
    {
      const gchar *id = path + strlen (report_config_prefix);
      if (g_str_has_suffix (id, report_config_export_suffix))
        return is_uuid_segment (id,
                                strlen (id)
                                - strlen (report_config_export_suffix));
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, report_formats_path) == 0)
    return TRUE;

  if (g_str_has_prefix (path, report_format_prefix))
    {
      const gchar *id = path + strlen (report_format_prefix);
      return is_uuid_segment (id, strlen (id));
    }

  if (g_strcmp0 (path, trashcan_summary_path) == 0)
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

static gsad_http_result_t
send_json_error (gsad_http_connection_t *connection, int status_code,
                 const gchar *message)
{
  gchar *body = g_strdup_printf ("{\"error\":{\"message\":\"%s\"}}\n",
                                 message);
  gsad_http_result_t ret = gsad_http_send_response_for_content (
    connection, body, status_code, NULL, GSAD_CONTENT_TYPE_APP_JSON, NULL, 0);
  g_free (body);
  return ret;
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
fetch_native_api_json (const gchar *path, guint *status_code,
                       gchar **error_message)
{
  const gchar *host = g_getenv ("TURBOVAS_NATIVE_API_HOST");
  const gchar *port = g_getenv ("TURBOVAS_NATIVE_API_PORT");
  int fd;
  GString *request;
  GString *response;
  gchar buffer[8192];
  gchar *body;

  if (host == NULL || host[0] == 0)
    host = DEFAULT_NATIVE_API_HOST;
  if (port == NULL || port[0] == 0)
    port = DEFAULT_NATIVE_API_PORT;

  fd = connect_to_native_api (host, port);
  if (fd == -1)
    {
      *error_message = g_strdup ("Native API service is unavailable.");
      return NULL;
    }

  request = g_string_new (NULL);
  g_string_printf (request,
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s:%s\r\n"
                   "Accept: application/json\r\n"
                   "Connection: close\r\n"
                   "User-Agent: gsad-native-api-proxy\r\n\r\n",
                   path, host, port);

  if (!send_all (fd, request->str, request->len))
    {
      g_string_free (request, TRUE);
      close (fd);
      *error_message = g_strdup ("Native API request could not be sent.");
      return NULL;
    }
  g_string_free (request, TRUE);

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
          *error_message = g_strdup ("Native API response could not be read.");
          return NULL;
        }

      if (response->len + (gsize) count > NATIVE_API_MAX_RESPONSE_BYTES)
        {
          g_string_free (response, TRUE);
          close (fd);
          *error_message = g_strdup ("Native API response is too large.");
          return NULL;
        }

      g_string_append_len (response, buffer, count);
    }
  close (fd);

  body = extract_response_body (response, status_code, error_message);
  g_string_free (response, TRUE);
  return body;
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

  (void) handler_next;
  (void) handler_data;

  if (!native_api_path_is_allowed (path))
    {
      gsad_credentials_free (credentials);
      return send_json_error (connection, MHD_HTTP_NOT_FOUND,
                              "Native API path is not available.");
    }

  request_target = native_api_request_target (path, params);
  body = fetch_native_api_json (request_target, &status_code, &error_message);
  g_free (request_target);
  gsad_credentials_free (credentials);

  if (body == NULL)
    {
      g_warning ("%s: %s", __func__, error_message);
      g_free (error_message);
      return send_json_error (connection, MHD_HTTP_BAD_GATEWAY,
                              "Native API service is unavailable.");
    }

  ret = gsad_http_send_response_for_content (connection, body, (int) status_code,
                                             NULL, GSAD_CONTENT_TYPE_APP_JSON,
                                             NULL, 0);
  g_free (body);
  return ret;
}
