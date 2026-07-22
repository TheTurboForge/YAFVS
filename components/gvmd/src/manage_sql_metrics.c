/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for YAFVS report metrics.
 */

#include "manage_sql_metrics.h"
#include "manage_utils.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define METRIC_FINDING_CLAUSE                                              \
  "coalesce (r.severity, 0) > 0 AND coalesce (r.severity, 0) != "           \
  G_STRINGIFY (SEVERITY_ERROR)

static const char *
empty_if_null (const char *value)
{
  return value ? value : "";
}

static void
append_xml_text (GString *buffer, const char *element, const char *value)
{
  gchar *escaped;

  escaped = g_markup_escape_text (empty_if_null (value), -1);
  g_string_append_printf (buffer, "<%s>%s</%s>", element, escaped, element);
  g_free (escaped);
}

static void
append_xml_int64 (GString *buffer, const char *element, long long value)
{
  g_string_append_printf (buffer, "<%s>%lld</%s>", element, value, element);
}

static void
append_xml_double (GString *buffer, const char *element, double value)
{
  g_string_append_printf (buffer, "<%s>%.2f</%s>", element, value, element);
}

static void
append_xml_percent (GString *buffer, const char *element, double value)
{
  g_string_append_printf (buffer, "<%s>%.1f</%s>", element, value, element);
}

static resource_t
resource_id_by_uuid (const char *table, const char *uuid)
{
  gchar *uuid_literal;
  resource_t id;

  if (uuid == NULL || uuid[0] == '\0')
    return 0;

  uuid_literal = sql_insert (uuid);
  id = sql_int64_0 ("SELECT id FROM %s WHERE uuid = %s;", table,
                    uuid_literal);
  g_free (uuid_literal);

  return id;
}

static gchar *
scope_host_filter_clause (resource_t scope, int global, const char *host_expr)
{
  if (global)
    return g_strdup ("TRUE");

  return g_strdup_printf
    ("EXISTS (SELECT 1 FROM scope_hosts sh"
     " WHERE sh.scope = %llu"
     " AND lower (sh.host_name) = lower (%s))",
     scope, host_expr);
}

static const char *
auth_evidence_text_expr (void)
{
  return "lower (coalesce (rhd.name, '') || ' '"
         "       || coalesce (rhd.value, '') || ' '"
         "       || coalesce (rhd.source_name, ''))";
}

static gchar *
auth_success_clause (void)
{
  const char *text_expr;

  text_expr = auth_evidence_text_expr ();
  return g_strdup_printf
    ("EXISTS (SELECT 1 FROM report_host_details rhd"
     " WHERE rhd.report_host = rh.id"
     " AND (%s LIKE '%%auth%%'"
     "      OR %s LIKE '%%credential%%'"
     "      OR %s LIKE '%%login%%')"
     " AND (%s LIKE '%%success%%'"
     "      OR %s LIKE '%%succeeded%%'"
     "      OR %s LIKE '%%logged in%%'"
     "      OR %s LIKE '%%valid credential%%'))",
     text_expr, text_expr, text_expr, text_expr, text_expr, text_expr,
     text_expr);
}

static gchar *
auth_failure_clause (void)
{
  const char *text_expr;

  text_expr = auth_evidence_text_expr ();
  return g_strdup_printf
    ("EXISTS (SELECT 1 FROM report_host_details rhd"
     " WHERE rhd.report_host = rh.id"
     " AND (%s LIKE '%%auth%%'"
     "      OR %s LIKE '%%credential%%'"
     "      OR %s LIKE '%%login%%')"
     " AND (%s LIKE '%%fail%%'"
     "      OR %s LIKE '%%denied%%'"
     "      OR %s LIKE '%%invalid%%'"
     "      OR %s LIKE '%%refused%%'))",
     text_expr, text_expr, text_expr, text_expr, text_expr, text_expr,
     text_expr);
}

static gchar *
source_reports_cte_for_report (resource_t report)
{
  return g_strdup_printf
    ("source_reports AS ("
     " SELECT r.id AS source_report, t.target AS target"
     " FROM reports r JOIN tasks t ON t.id = r.task"
     " WHERE r.id = %llu)",
     report);
}

static gchar *
source_reports_cte_for_scope_report (resource_t scope_report)
{
  return g_strdup_printf
    ("source_reports AS ("
     " SELECT source_report, target FROM scope_report_sources"
     " WHERE scope_report = %llu)",
     scope_report);
}

static gchar *
system_rows_query (const char *source_reports_cte,
                   const char *alive_host_filter,
                   const char *result_host_filter)
{
  gchar *auth_success, *auth_failure, *query;

  auth_success = auth_success_clause ();
  auth_failure = auth_failure_clause ();
  query = g_strdup_printf
    ("WITH %s,"
     " alive AS ("
     "   SELECT lower (coalesce (nullif (rh.host, ''), rh.hostname, ''))"
     "            AS host_key,"
     "          min (coalesce (nullif (rh.host, ''), rh.hostname, '')) AS host,"
     "          count (DISTINCT rh.report) AS source_report_count,"
     "          bool_or (EXISTS (SELECT 1 FROM targets_login_data tld"
     "                           WHERE tld.target = sr.target"
     "                           AND coalesce (tld.credential, 0) > 0))"
     "            AS has_credential_path,"
     "          bool_or (%s) AS auth_success,"
     "          bool_or (%s) AS auth_failure"
     "   FROM report_hosts rh"
     "   JOIN source_reports sr ON sr.source_report = rh.report"
     "   WHERE coalesce (nullif (rh.host, ''), rh.hostname, '') <> ''"
     "     AND %s"
     "   GROUP BY lower (coalesce (nullif (rh.host, ''), rh.hostname, ''))"
     " ),"
     " vuln_by_system AS ("
     "   SELECT lower (coalesce (nullif (r.host, ''), r.hostname, ''))"
     "            AS host_key,"
     "          coalesce (nullif (r.nvt, ''), 'unknown') AS nvt_oid,"
     "          max (coalesce (r.severity, 0)) AS cvss_score"
     "   FROM results r"
     "   JOIN source_reports sr ON sr.source_report = r.report"
     "   WHERE " METRIC_FINDING_CLAUSE
     "     AND coalesce (nullif (r.host, ''), r.hostname, '') <> ''"
     "     AND %s"
     "   GROUP BY lower (coalesce (nullif (r.host, ''), r.hostname, '')),"
     "            coalesce (nullif (r.nvt, ''), 'unknown')"
     " ),"
     " system_load AS ("
     "   SELECT host_key, sum (cvss_score) AS cvss_load,"
     "          max (cvss_score) AS max_cvss,"
     "          count (*) AS vulnerability_count"
     "   FROM vuln_by_system GROUP BY host_key"
     " )"
     " SELECT alive.host, coalesce (system_load.cvss_load, 0),"
     "        coalesce (system_load.max_cvss, 0),"
     "        coalesce (system_load.vulnerability_count, 0),"
     "        CASE WHEN alive.auth_success THEN 'authenticated'"
     "             WHEN alive.auth_failure THEN 'authentication_failed'"
     "             WHEN alive.has_credential_path THEN 'unknown'"
     "             ELSE 'no_credential_path' END,"
     "        alive.source_report_count"
     " FROM alive LEFT JOIN system_load USING (host_key)"
     " ORDER BY coalesce (system_load.cvss_load, 0) DESC, alive.host ASC",
     source_reports_cte, auth_success, auth_failure, alive_host_filter,
     result_host_filter);

  g_free (auth_failure);
  g_free (auth_success);
  return query;
}

static gchar *
vulnerability_rows_query (const char *source_reports_cte,
                          const char *result_host_filter,
                          long long alive_system_count)
{
  return g_strdup_printf
    ("WITH %s,"
     " deduped_results AS ("
     "   SELECT lower (coalesce (nullif (r.host, ''), r.hostname, ''))"
     "            AS host_key,"
     "          coalesce (nullif (r.nvt, ''), 'unknown') AS nvt_oid,"
     "          max (coalesce (n.name, r.nvt, 'Unknown vulnerability'))"
     "            AS nvt_name,"
     "          max (coalesce (r.severity, 0)) AS cvss_score,"
     "          r.report AS source_report"
     "   FROM results r"
     "   JOIN source_reports sr ON sr.source_report = r.report"
     "   LEFT JOIN nvts n ON n.oid = r.nvt"
     "   WHERE " METRIC_FINDING_CLAUSE
     "     AND coalesce (nullif (r.host, ''), r.hostname, '') <> ''"
     "     AND %s"
     "   GROUP BY lower (coalesce (nullif (r.host, ''), r.hostname, '')),"
     "            coalesce (nullif (r.nvt, ''), 'unknown'), r.report"
     " ),"
     " vuln_by_system AS ("
     "   SELECT host_key, nvt_oid, max (nvt_name) AS nvt_name,"
     "          max (cvss_score) AS cvss_score"
     "   FROM deduped_results"
     "   GROUP BY host_key, nvt_oid"
     " ),"
     " vuln_sources AS ("
     "   SELECT nvt_oid, count (DISTINCT source_report) AS source_report_count"
     "   FROM deduped_results"
     "   GROUP BY nvt_oid"
     " )"
     " SELECT v.nvt_oid, max (v.nvt_name), max (v.cvss_score),"
     "        count (DISTINCT v.host_key),"
     "        max (v.cvss_score) * count (DISTINCT v.host_key),"
     "        CASE WHEN %lld > 0"
     "             THEN (max (v.cvss_score) * count (DISTINCT v.host_key))"
     "                  / %lld"
     "             ELSE 0 END,"
     "        coalesce (max (vs.source_report_count), 0)"
     " FROM vuln_by_system v"
     " LEFT JOIN vuln_sources vs ON vs.nvt_oid = v.nvt_oid"
     " GROUP BY v.nvt_oid"
     " ORDER BY (max (v.cvss_score) * count (DISTINCT v.host_key)) DESC,"
     "          max (v.cvss_score) DESC, max (v.nvt_name) ASC",
     source_reports_cte, result_host_filter, alive_system_count,
     alive_system_count);
}

static void
append_metric_summary_xml (GString *buffer, long long alive_system_count,
                           double total_cvss_load,
                           double average_system_cvss_load,
                           long long vulnerability_count,
                           long long authenticated_count,
                           long long auth_failed_count,
                           long long no_credential_path_count,
                           long long unknown_count)
{
  double coverage;

  coverage = alive_system_count > 0
             ? (100.0 * authenticated_count) / alive_system_count
             : 0.0;

  g_string_append (buffer, "<summary>");
  append_xml_int64 (buffer, "alive_system_count", alive_system_count);
  append_xml_double (buffer, "total_system_cvss_load", total_cvss_load);
  append_xml_double (buffer, "average_system_cvss_load",
                     average_system_cvss_load);
  append_xml_int64 (buffer, "vulnerability_count", vulnerability_count);
  append_xml_int64 (buffer, "authenticated_system_count",
                    authenticated_count);
  append_xml_int64 (buffer, "authentication_failed_system_count",
                    auth_failed_count);
  append_xml_int64 (buffer, "no_credential_path_system_count",
                    no_credential_path_count);
  append_xml_int64 (buffer, "unknown_authentication_system_count",
                    unknown_count);
  append_xml_percent (buffer, "authenticated_scan_coverage_percent",
                      coverage);
  g_string_append (buffer, "</summary>");
}

static void
append_system_rows_xml_from_query (GString *buffer, const char *query)
{
  iterator_t systems;

  g_string_append (buffer, "<systems>");
  init_iterator (&systems, "%s", query);
  while (next (&systems))
    {
      g_string_append (buffer, "<system>");
      append_xml_text (buffer, "host", iterator_string (&systems, 0));
      append_xml_double (buffer, "cvss_load", iterator_double (&systems, 1));
      append_xml_double (buffer, "max_cvss", iterator_double (&systems, 2));
      append_xml_int64 (buffer, "vulnerability_count",
                        iterator_int64 (&systems, 3));
      append_xml_text (buffer, "authentication_state",
                       iterator_string (&systems, 4));
      append_xml_int64 (buffer, "source_report_count",
                        iterator_int64 (&systems, 5));
      g_string_append (buffer, "</system>");
    }
  cleanup_iterator (&systems);
  g_string_append (buffer, "</systems>");
}

static void
append_vulnerability_rows_xml_from_query (GString *buffer, const char *query)
{
  iterator_t vulns;

  g_string_append (buffer, "<vulnerabilities>");
  init_iterator (&vulns, "%s", query);
  while (next (&vulns))
    {
      g_string_append (buffer, "<vulnerability>");
      append_xml_text (buffer, "nvt_oid", iterator_string (&vulns, 0));
      append_xml_text (buffer, "name", iterator_string (&vulns, 1));
      append_xml_double (buffer, "cvss_score", iterator_double (&vulns, 2));
      append_xml_int64 (buffer, "affected_system_count",
                        iterator_int64 (&vulns, 3));
      append_xml_double (buffer, "cvss_load", iterator_double (&vulns, 4));
      append_xml_double (buffer, "average_contribution",
                         iterator_double (&vulns, 5));
      append_xml_int64 (buffer, "source_report_count",
                        iterator_int64 (&vulns, 6));
      g_string_append (buffer, "</vulnerability>");
    }
  cleanup_iterator (&vulns);
  g_string_append (buffer, "</vulnerabilities>");
}

static void
append_summary_from_queries (GString *buffer, const char *system_query,
                             const char *vulnerability_query)
{
  iterator_t systems, vulnerabilities;
  long long alive_count = 0, vulnerability_count = 0;
  long long authenticated_count = 0, auth_failed_count = 0;
  long long no_credential_path_count = 0, unknown_count = 0;
  double total_load = 0.0;

  init_iterator (&systems, "%s", system_query);
  while (next (&systems))
    {
      const char *state;

      alive_count++;
      total_load += iterator_double (&systems, 1);
      state = iterator_string (&systems, 4);
      if (g_strcmp0 (state, "authenticated") == 0)
        authenticated_count++;
      else if (g_strcmp0 (state, "authentication_failed") == 0)
        auth_failed_count++;
      else if (g_strcmp0 (state, "no_credential_path") == 0)
        no_credential_path_count++;
      else
        unknown_count++;
    }
  cleanup_iterator (&systems);

  init_iterator (&vulnerabilities, "%s", vulnerability_query);
  while (next (&vulnerabilities))
    vulnerability_count++;
  cleanup_iterator (&vulnerabilities);

  append_metric_summary_xml (buffer, alive_count, total_load,
                             alive_count > 0 ? total_load / alive_count : 0,
                             vulnerability_count, authenticated_count,
                             auth_failed_count, no_credential_path_count,
                             unknown_count);
}

int
rebuild_scope_report_metrics (resource_t scope_report, resource_t scope,
                              int global)
{
  gchar *source_cte, *alive_host_filter, *result_host_filter;
  gchar *system_query, *vuln_query;
  long long alive_count;

  source_cte = source_reports_cte_for_scope_report (scope_report);
  alive_host_filter = scope_host_filter_clause
    (scope, global, "coalesce (nullif (rh.host, ''), rh.hostname, '')");
  result_host_filter = scope_host_filter_clause
    (scope, global, "coalesce (nullif (r.host, ''), r.hostname, '')");
  system_query = system_rows_query (source_cte, alive_host_filter,
                                    result_host_filter);

  sql ("DELETE FROM scope_report_system_metrics WHERE scope_report = %llu;",
       scope_report);
  sql ("DELETE FROM scope_report_vulnerability_metrics"
       " WHERE scope_report = %llu;",
       scope_report);

  sql ("INSERT INTO scope_report_system_metrics"
       " (scope_report, host, cvss_load, max_cvss, vulnerability_count,"
       "  authentication_state, source_report_count)"
       " SELECT %llu, host, cvss_load, max_cvss, vulnerability_count,"
       "        authentication_state, source_report_count"
       " FROM (%s) AS system_rows"
       " (host, cvss_load, max_cvss, vulnerability_count,"
       "  authentication_state, source_report_count);",
       scope_report, system_query);

  alive_count = sql_int64_0
    ("SELECT count (*) FROM scope_report_system_metrics"
     " WHERE scope_report = %llu;",
     scope_report);
  vuln_query = vulnerability_rows_query (source_cte, result_host_filter,
                                         alive_count);
  sql ("INSERT INTO scope_report_vulnerability_metrics"
       " (scope_report, nvt_oid, nvt_name, cvss_score, affected_system_count,"
       "  cvss_load, average_contribution, source_report_count)"
       " SELECT %llu, nvt_oid, name, cvss_score, affected_system_count,"
       "        cvss_load, average_contribution, source_report_count"
       " FROM (%s) AS vulnerability_rows"
       " (nvt_oid, name, cvss_score, affected_system_count, cvss_load,"
       "  average_contribution, source_report_count);",
       scope_report, vuln_query);

  sql ("UPDATE scope_reports"
       " SET metric_alive_system_count ="
       "       (SELECT count (*) FROM scope_report_system_metrics"
       "        WHERE scope_report = %llu),"
       "     metric_total_system_cvss_load ="
       "       coalesce ((SELECT sum (cvss_load)"
       "                  FROM scope_report_system_metrics"
       "                  WHERE scope_report = %llu), 0),"
       "     metric_average_system_cvss_load ="
       "       coalesce ((SELECT avg (cvss_load)"
       "                  FROM scope_report_system_metrics"
       "                  WHERE scope_report = %llu), 0),"
       "     metric_authenticated_system_count ="
       "       (SELECT count (*) FROM scope_report_system_metrics"
       "        WHERE scope_report = %llu"
       "          AND authentication_state = 'authenticated'),"
       "     metric_auth_failed_system_count ="
       "       (SELECT count (*) FROM scope_report_system_metrics"
       "        WHERE scope_report = %llu"
       "          AND authentication_state = 'authentication_failed'),"
       "     metric_no_credential_path_system_count ="
       "       (SELECT count (*) FROM scope_report_system_metrics"
       "        WHERE scope_report = %llu"
       "          AND authentication_state = 'no_credential_path'),"
       "     metric_unknown_authentication_system_count ="
       "       (SELECT count (*) FROM scope_report_system_metrics"
       "        WHERE scope_report = %llu"
       "          AND authentication_state = 'unknown'),"
       "     metric_authenticated_scan_coverage ="
       "       CASE WHEN (SELECT count (*)"
       "                  FROM scope_report_system_metrics"
       "                  WHERE scope_report = %llu) > 0"
       "            THEN (100.0 * (SELECT count (*)"
       "                           FROM scope_report_system_metrics"
       "                           WHERE scope_report = %llu"
       "                             AND authentication_state ="
       "                                 'authenticated')"
       "                  / (SELECT count (*)"
       "                     FROM scope_report_system_metrics"
       "                     WHERE scope_report = %llu))"
       "            ELSE 0 END"
       " WHERE id = %llu;",
       scope_report, scope_report, scope_report, scope_report, scope_report,
       scope_report, scope_report, scope_report, scope_report, scope_report,
       scope_report);

  g_free (vuln_query);
  g_free (system_query);
  g_free (result_host_filter);
  g_free (alive_host_filter);
  g_free (source_cte);

  return 0;
}
int
buffer_report_metrics_xml (GString *buffer, const char *report_uuid)
{
  resource_t report;
  gchar *source_cte, *system_query, *vuln_query;
  long long alive_count;

  report = resource_id_by_uuid ("reports", report_uuid);
  if (report == 0)
    return 2;

  source_cte = source_reports_cte_for_report (report);
  system_query = system_rows_query (source_cte, "TRUE", "TRUE");
  alive_count = sql_int64_0
    ("SELECT count (*) FROM report_hosts"
     " WHERE report = %llu"
     " AND coalesce (nullif (host, ''), hostname, '') <> '';",
     report);
  vuln_query = vulnerability_rows_query (source_cte, "TRUE", alive_count);

  g_string_append_printf (buffer, "<report_metrics id=\"%s\">",
                          report_uuid);
  append_summary_from_queries (buffer, system_query, vuln_query);
  append_system_rows_xml_from_query (buffer, system_query);
  append_vulnerability_rows_xml_from_query (buffer, vuln_query);
  g_string_append (buffer, "</report_metrics>");

  g_free (vuln_query);
  g_free (system_query);
  g_free (source_cte);

  return 0;
}
