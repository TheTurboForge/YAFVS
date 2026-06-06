/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for TurboVAS reporting scopes.
 */

#include "manage_sql_scopes.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define ORGANIZATION_SCOPE_NAME "Organization"

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
  g_string_append_printf (buffer, "<%s>%.1f</%s>", element, value, element);
}

static gchar *
xml_escape (const char *value)
{
  return g_markup_escape_text (empty_if_null (value), -1);
}

static gchar *
quoted (const char *value)
{
  gchar *escaped, *literal;

  escaped = sql_quote (empty_if_null (value));
  literal = g_strdup_printf ("'%s'", escaped);
  g_free (escaped);

  return literal;
}

static gchar *
normalize_protection_requirement (const char *value)
{
  gchar *lower, *cursor;

  if (value == NULL || value[0] == '\0')
    return g_strdup ("normal");

  lower = g_ascii_strdown (value, -1);
  for (cursor = lower; *cursor; cursor++)
    if (*cursor == ' ' || *cursor == '-')
      *cursor = '_';

  if (g_strcmp0 (lower, "normal") == 0
      || g_strcmp0 (lower, "high") == 0
      || g_strcmp0 (lower, "very_high") == 0)
    return lower;

  g_free (lower);
  return NULL;
}

static const char *
protection_requirement_label (const char *value)
{
  if (g_strcmp0 (value, "very_high") == 0)
    return "Very High";
  if (g_strcmp0 (value, "high") == 0)
    return "High";
  return "Normal";
}

static resource_t
current_user_id (void)
{
  if (current_credentials.uuid == NULL)
    return 0;

  return sql_int64_0 ("SELECT id FROM users WHERE uuid = '%s';",
                     current_credentials.uuid);
}

static resource_t
fallback_user_id (void)
{
  resource_t user_id;

  user_id = current_user_id ();
  if (user_id)
    return user_id;

  return sql_int64_0 ("SELECT id FROM users ORDER BY id LIMIT 1;");
}

static resource_t
resource_id_by_uuid (const char *table, const char *uuid)
{
  gchar *uuid_quoted;
  resource_t id;

  uuid_quoted = quoted (uuid);
  id = sql_int64_0 ("SELECT id FROM %s WHERE uuid = %s;", table,
                    uuid_quoted);
  g_free (uuid_quoted);

  return id;
}

static resource_t
scope_id_by_uuid (const char *uuid)
{
  return resource_id_by_uuid ("scopes", uuid);
}

static resource_t
scope_report_id_by_uuid (const char *uuid)
{
  return resource_id_by_uuid ("scope_reports", uuid);
}

static gboolean
scope_is_predefined (scope_t scope)
{
  return sql_int ("SELECT predefined FROM scopes WHERE id = %llu;", scope);
}

static gboolean
scope_is_global (scope_t scope)
{
  return sql_int ("SELECT is_global FROM scopes WHERE id = %llu;", scope);
}

static gboolean
uuid_list_is_valid (const char *uuid_list, const char *table)
{
  gchar **parts, **part;

  if (uuid_list == NULL || uuid_list[0] == '\0')
    return TRUE;

  parts = g_strsplit_set (uuid_list, ", \n\r\t", -1);
  for (part = parts; *part; part++)
    {
      gchar *candidate;

      candidate = g_strstrip (*part);
      if (candidate[0] == '\0')
        continue;

      if (resource_id_by_uuid (table, candidate) == 0)
        {
          g_strfreev (parts);
          return FALSE;
        }
    }

  g_strfreev (parts);
  return TRUE;
}

static void
replace_scope_targets (scope_t scope, const char *target_uuids)
{
  gchar **parts, **part;

  sql ("DELETE FROM scope_targets WHERE scope = %llu;", scope);
  if (target_uuids == NULL || target_uuids[0] == '\0')
    return;

  parts = g_strsplit_set (target_uuids, ", \n\r\t", -1);
  for (part = parts; *part; part++)
    {
      gchar *uuid, *uuid_quoted;
      resource_t target;

      uuid = g_strstrip (*part);
      if (uuid[0] == '\0')
        continue;

      uuid_quoted = quoted (uuid);
      target = sql_int64_0 ("SELECT id FROM targets WHERE uuid = %s;",
                            uuid_quoted);
      g_free (uuid_quoted);
      if (target == 0)
        continue;

      sql ("INSERT INTO scope_targets"
           " (scope, target, target_uuid, target_name, added_time)"
           " SELECT %llu, id, uuid, name, m_now () FROM targets"
           " WHERE id = %llu"
           " ON CONFLICT (scope, target) DO NOTHING;",
           scope, target);
    }

  g_strfreev (parts);
}

static void
replace_scope_hosts (scope_t scope, const char *host_uuids)
{
  gchar **parts, **part;

  sql ("DELETE FROM scope_hosts WHERE scope = %llu;", scope);
  if (host_uuids == NULL || host_uuids[0] == '\0')
    return;

  parts = g_strsplit_set (host_uuids, ", \n\r\t", -1);
  for (part = parts; *part; part++)
    {
      gchar *uuid, *uuid_quoted;
      resource_t host;

      uuid = g_strstrip (*part);
      if (uuid[0] == '\0')
        continue;

      uuid_quoted = quoted (uuid);
      host = sql_int64_0 ("SELECT id FROM hosts WHERE uuid = %s;",
                          uuid_quoted);
      g_free (uuid_quoted);
      if (host == 0)
        continue;

      sql ("INSERT INTO scope_hosts"
           " (scope, host, host_uuid, host_name, added_time)"
           " SELECT %llu, id, uuid, name, m_now () FROM hosts"
           " WHERE id = %llu"
           " ON CONFLICT (scope, host) DO NOTHING;",
           scope, host);
    }

  g_strfreev (parts);
}

int
ensure_organization_scope (void)
{
  resource_t owner;

  if (sql_int ("SELECT count (*) FROM scopes"
               " WHERE name = '%s' AND predefined = 1 AND is_global = 1;",
               ORGANIZATION_SCOPE_NAME))
    return 0;

  owner = fallback_user_id ();
  if (owner == 0)
    return 1;

  sql ("INSERT INTO scopes"
       " (uuid, owner, name, comment, protection_requirement, predefined,"
       "  is_global, creation_time, modification_time)"
       " VALUES (make_uuid (), %llu, '%s',"
       "         'Global reporting scope containing all active targets and known hosts.',"
       "         'normal', 1, 1, m_now (), m_now ())"
       " ON CONFLICT (name) DO NOTHING;",
       owner, ORGANIZATION_SCOPE_NAME);

  return 0;
}

int
create_scope (const char *name, const char *comment,
              const char *protection_requirement, const char *target_uuids,
              const char *host_uuids, char **scope_uuid)
{
  gchar *name_quoted, *comment_quoted, *normalized, *uuid;
  resource_t owner, scope;

  if (name == NULL || name[0] == '\0')
    return 1;

  normalized = normalize_protection_requirement (protection_requirement);
  if (normalized == NULL)
    return 3;

  if (!uuid_list_is_valid (target_uuids, "targets"))
    {
      g_free (normalized);
      return 4;
    }

  if (!uuid_list_is_valid (host_uuids, "hosts"))
    {
      g_free (normalized);
      return 5;
    }

  owner = current_user_id ();
  if (owner == 0)
    {
      g_free (normalized);
      return 99;
    }

  name_quoted = quoted (name);
  comment_quoted = quoted (comment);
  scope = sql_int64_0
    ("INSERT INTO scopes"
     " (uuid, owner, name, comment, protection_requirement, predefined,"
     "  is_global, creation_time, modification_time)"
     " VALUES (make_uuid (), %llu, %s, %s, '%s', 0, 0, m_now (), m_now ())"
     " RETURNING id;",
     owner, name_quoted, comment_quoted, normalized);
  g_free (name_quoted);
  g_free (comment_quoted);

  if (scope == 0)
    {
      g_free (normalized);
      return 99;
    }

  replace_scope_targets (scope, target_uuids);
  replace_scope_hosts (scope, host_uuids);

  uuid = sql_string ("SELECT uuid FROM scopes WHERE id = %llu;", scope);
  if (scope_uuid)
    *scope_uuid = uuid;
  else
    g_free (uuid);

  g_free (normalized);
  return 0;
}

int
modify_scope (const char *scope_uuid, const char *name, const char *comment,
              const char *protection_requirement, const char *target_uuids,
              const char *host_uuids)
{
  gchar *name_quoted = NULL, *comment_quoted = NULL, *normalized = NULL;
  gchar *normalized_quoted = NULL;
  scope_t scope;

  scope = scope_id_by_uuid (scope_uuid);
  if (scope == 0)
    return 2;

  if (name && name[0] && scope_is_predefined (scope))
    return 6;

  if (protection_requirement && protection_requirement[0])
    {
      normalized = normalize_protection_requirement (protection_requirement);
      if (normalized == NULL)
        return 3;
    }

  if (!uuid_list_is_valid (target_uuids, "targets"))
    {
      g_free (normalized);
      return 4;
    }

  if (!uuid_list_is_valid (host_uuids, "hosts"))
    {
      g_free (normalized);
      return 5;
    }

  if (name && name[0])
    name_quoted = quoted (name);
  if (comment)
    comment_quoted = quoted (comment);
  if (normalized)
    normalized_quoted = quoted (normalized);

  sql ("UPDATE scopes"
       " SET name = coalesce (%s, name),"
       "     comment = coalesce (%s, comment),"
       "     protection_requirement = coalesce (%s, protection_requirement),"
       "     modification_time = m_now ()"
       " WHERE id = %llu;",
       name_quoted ? name_quoted : "NULL",
       comment_quoted ? comment_quoted : "NULL",
       normalized_quoted ? normalized_quoted : "NULL",
       scope);

  if (!scope_is_global (scope))
    {
      if (target_uuids)
        replace_scope_targets (scope, target_uuids);
      if (host_uuids)
        replace_scope_hosts (scope, host_uuids);
    }

  g_free (name_quoted);
  g_free (comment_quoted);
  g_free (normalized_quoted);
  g_free (normalized);
  return 0;
}

int
delete_scope (const char *scope_uuid)
{
  scope_t scope;

  scope = scope_id_by_uuid (scope_uuid);
  if (scope == 0)
    return 2;
  if (scope_is_predefined (scope))
    return 3;

  sql ("DELETE FROM scope_targets WHERE scope = %llu;", scope);
  sql ("DELETE FROM scope_hosts WHERE scope = %llu;", scope);
  sql ("DELETE FROM scopes WHERE id = %llu;", scope);
  return 0;
}

static gchar *
scope_target_filter (scope_t scope, gboolean global)
{
  if (global)
    return g_strdup ("SELECT id AS target FROM targets");

  return g_strdup_printf ("SELECT target FROM scope_targets WHERE scope = %llu",
                          scope);
}

static gchar *
custom_host_match_clause (scope_t scope, gboolean global)
{
  if (global)
    return g_strdup ("TRUE");

  return g_strdup_printf
    ("EXISTS (SELECT 1 FROM scope_hosts sh"
     " JOIN hosts h ON h.id = sh.host"
     " WHERE sh.scope = %llu"
     " AND (lower (h.name) = lower (coalesce (nullif (r.host, ''), r.hostname))"
     "      OR lower (h.name) = lower (coalesce (nullif (r.hostname, ''), r.host))))",
     scope);
}

static void
update_scope_report_counts (scope_report_t scope_report, scope_t scope,
                            gboolean global)
{
  long long source_report_count, source_target_count, member_host_count;
  long long evidence_host_count, result_count, vulnerability_count;
  long long excluded_candidate_host_count, latest_evidence_time;
  double max_severity;
  gchar *host_clause;

  host_clause = custom_host_match_clause (scope, global);

  source_report_count = sql_int64_0
    ("SELECT count (*) FROM scope_report_sources WHERE scope_report = %llu;",
     scope_report);
  source_target_count = sql_int64_0
    ("SELECT count (DISTINCT target_uuid) FROM scope_report_sources"
     " WHERE scope_report = %llu;",
     scope_report);

  if (global)
    member_host_count = sql_int64_0 ("SELECT count (*) FROM hosts;");
  else
    member_host_count = sql_int64_0
      ("SELECT count (*) FROM scope_hosts WHERE scope = %llu;", scope);

  if (global)
    evidence_host_count = sql_int64_0
      ("SELECT count (DISTINCT lower (host)) FROM report_hosts rh"
       " JOIN scope_report_sources s ON s.source_report = rh.report"
       " WHERE s.scope_report = %llu AND coalesce (rh.host, '') <> '';",
       scope_report);
  else
    evidence_host_count = sql_int64_0
      ("SELECT count (DISTINCT lower (rh.host)) FROM report_hosts rh"
       " JOIN scope_report_sources s ON s.source_report = rh.report"
       " WHERE s.scope_report = %llu AND coalesce (rh.host, '') <> ''"
       " AND EXISTS (SELECT 1 FROM scope_hosts sh"
       "             JOIN hosts h ON h.id = sh.host"
       "             WHERE sh.scope = %llu"
       "             AND lower (h.name) = lower (rh.host));",
       scope_report, scope);

  result_count = sql_int64_0
    ("SELECT count (*) FROM ("
     " SELECT DISTINCT lower (coalesce (nullif (r.host, ''), r.hostname, '')) AS host_key,"
     "        coalesce (r.nvt, '') AS nvt_key, coalesce (r.port, '') AS port_key"
     " FROM results r"
     " JOIN scope_report_sources s ON s.source_report = r.report"
     " WHERE s.scope_report = %llu AND "
     "       %s"
     ") AS deduped;",
     scope_report, host_clause);

  vulnerability_count = sql_int64_0
    ("SELECT count (*) FROM ("
     " SELECT DISTINCT lower (coalesce (nullif (r.host, ''), r.hostname, '')) AS host_key,"
     "        coalesce (r.nvt, '') AS nvt_key, coalesce (r.port, '') AS port_key"
     " FROM results r"
     " JOIN scope_report_sources s ON s.source_report = r.report"
     " WHERE s.scope_report = %llu AND r.severity > 0 AND "
     "       %s"
     ") AS deduped;",
     scope_report, host_clause);

  max_severity = sql_double
    ("SELECT coalesce (max (r.severity), 0) FROM results r"
     " JOIN scope_report_sources s ON s.source_report = r.report"
     " WHERE s.scope_report = %llu AND %s;",
     scope_report, host_clause);

  latest_evidence_time = sql_int64_0
    ("SELECT coalesce (max (coalesce (r.end_time, r.creation_time)), 0)"
     " FROM reports r"
     " JOIN scope_report_sources s ON s.source_report = r.id"
     " WHERE s.scope_report = %llu;",
     scope_report);

  if (global)
    excluded_candidate_host_count = 0;
  else
    excluded_candidate_host_count = sql_int64_0
      ("SELECT count (*) FROM ("
       " SELECT DISTINCT lower (rh.host) AS host_key FROM report_hosts rh"
       " JOIN scope_report_sources s ON s.source_report = rh.report"
       " WHERE s.scope_report = %llu AND coalesce (rh.host, '') <> ''"
       " EXCEPT"
       " SELECT lower (h.name) FROM scope_hosts sh"
       " JOIN hosts h ON h.id = sh.host WHERE sh.scope = %llu"
       ") AS excluded;",
       scope_report, scope);

  sql ("UPDATE scope_reports"
       " SET source_report_count = %lld, source_target_count = %lld,"
       "     member_host_count = %lld, evidence_host_count = %lld,"
       "     missing_host_count = %lld, result_count = %lld,"
       "     vulnerability_count = %lld, max_severity = %f,"
       "     latest_evidence_time = %lld,"
       "     excluded_candidate_host_count = %lld,"
       "     modification_time = m_now ()"
       " WHERE id = %llu;",
       source_report_count, source_target_count, member_host_count,
       evidence_host_count,
       MAX (member_host_count - evidence_host_count, 0), result_count,
       vulnerability_count, max_severity, latest_evidence_time,
       excluded_candidate_host_count, scope_report);

  g_free (host_clause);
}

int
generate_scope_report (const char *scope_uuid, char **scope_report_uuid)
{
  scope_t scope;
  scope_report_t scope_report;
  gboolean global;
  gchar *target_filter, *uuid;

  scope = scope_id_by_uuid (scope_uuid);
  if (scope == 0)
    return 2;

  global = scope_is_global (scope);
  target_filter = scope_target_filter (scope, global);

  sql_begin_immediate ();
  scope_report = sql_int64_0
    ("INSERT INTO scope_reports"
     " (uuid, scope, scope_uuid, scope_name, protection_requirement,"
     "  generated_by, creation_time, modification_time)"
     " SELECT make_uuid (), id, uuid, name, protection_requirement,"
     "        (SELECT id FROM users WHERE uuid = '%s'), m_now (), m_now ()"
     " FROM scopes WHERE id = %llu"
     " RETURNING id;",
     current_credentials.uuid, scope);
  if (scope_report == 0)
    {
      sql_rollback ();
      g_free (target_filter);
      return 99;
    }

  sql ("INSERT INTO scope_report_sources"
       " (scope_report, target, target_uuid, target_name, source_report,"
       "  source_report_uuid, task, task_uuid, task_name, scan_start, scan_end,"
       "  selected_time)"
       " SELECT %llu, t.id, t.uuid, t.name, r.id, r.uuid, task.id, task.uuid,"
       "        task.name, r.start_time, r.end_time, m_now ()"
       " FROM targets t"
       " JOIN (%s) selected_targets ON selected_targets.target = t.id"
       " JOIN LATERAL ("
       "   SELECT reports.* FROM reports"
       "   JOIN tasks ON tasks.id = reports.task"
       "   WHERE tasks.target = t.id"
       "     AND coalesce (tasks.usage_type, 'scan') = 'scan'"
       "     AND reports.scan_run_status = %i"
       "   ORDER BY coalesce (reports.end_time, reports.creation_time) DESC,"
       "            reports.id DESC"
       "   LIMIT 1"
       " ) r ON TRUE"
       " JOIN tasks task ON task.id = r.task;",
       scope_report, target_filter, TASK_STATUS_DONE);

  update_scope_report_counts (scope_report, scope, global);
  sql_commit ();

  g_free (target_filter);
  uuid = sql_string ("SELECT uuid FROM scope_reports WHERE id = %llu;",
                     scope_report);
  if (scope_report_uuid)
    *scope_report_uuid = uuid;
  else
    g_free (uuid);

  return 0;
}

int
delete_scope_report (const char *scope_report_uuid)
{
  scope_report_t scope_report;

  scope_report = scope_report_id_by_uuid (scope_report_uuid);
  if (scope_report == 0)
    return 2;

  sql ("DELETE FROM scope_report_sources WHERE scope_report = %llu;",
       scope_report);
  sql ("DELETE FROM scope_reports WHERE id = %llu;", scope_report);
  return 0;
}

static void
append_scope_members_xml (GString *buffer, scope_t scope, gboolean global)
{
  iterator_t targets, hosts, candidates;

  g_string_append (buffer, "<targets>");
  if (global)
    init_iterator (&targets,
                   "SELECT uuid, name FROM targets ORDER BY name, uuid;");
  else
    init_iterator (&targets,
                   "SELECT target_uuid, target_name FROM scope_targets"
                   " WHERE scope = %llu ORDER BY target_name, target_uuid;",
                   scope);
  while (next (&targets))
    {
      gchar *uuid, *name;

      uuid = xml_escape (iterator_string (&targets, 0));
      name = xml_escape (iterator_string (&targets, 1));
      g_string_append_printf (buffer, "<target id=\"%s\"><name>%s</name></target>",
                              uuid, name);
      g_free (uuid);
      g_free (name);
    }
  cleanup_iterator (&targets);
  g_string_append (buffer, "</targets>");

  g_string_append (buffer, "<hosts>");
  if (global)
    init_iterator (&hosts, "SELECT uuid, name FROM hosts ORDER BY name, uuid;");
  else
    init_iterator (&hosts,
                   "SELECT host_uuid, host_name FROM scope_hosts"
                   " WHERE scope = %llu ORDER BY host_name, host_uuid;",
                   scope);
  while (next (&hosts))
    {
      gchar *uuid, *name;

      uuid = xml_escape (iterator_string (&hosts, 0));
      name = xml_escape (iterator_string (&hosts, 1));
      g_string_append_printf (buffer, "<host id=\"%s\"><name>%s</name></host>",
                              uuid, name);
      g_free (uuid);
      g_free (name);
    }
  cleanup_iterator (&hosts);
  g_string_append (buffer, "</hosts>");

  if (global)
    return;

  g_string_append (buffer, "<candidate_hosts>");
  init_iterator (&candidates,
                 "WITH newest_reports AS ("
                 " SELECT DISTINCT ON (t.id) t.id AS target, r.id AS report"
                 " FROM targets t"
                 " JOIN scope_targets st ON st.target = t.id"
                 " JOIN tasks task ON task.target = t.id"
                 " JOIN reports r ON r.task = task.id"
                 " WHERE st.scope = %llu"
                 "   AND coalesce (task.usage_type, 'scan') = 'scan'"
                 "   AND r.scan_run_status = %i"
                 " ORDER BY t.id, coalesce (r.end_time, r.creation_time) DESC, r.id DESC"
                 ")"
                 " SELECT DISTINCT rh.host FROM report_hosts rh"
                 " JOIN newest_reports nr ON nr.report = rh.report"
                 " WHERE coalesce (rh.host, '') <> ''"
                 "   AND NOT EXISTS (SELECT 1 FROM scope_hosts sh"
                 "                   JOIN hosts h ON h.id = sh.host"
                 "                   WHERE sh.scope = %llu"
                 "                   AND lower (h.name) = lower (rh.host))"
                 " ORDER BY rh.host;",
                 scope, TASK_STATUS_DONE, scope);
  while (next (&candidates))
    append_xml_text (buffer, "candidate_host", iterator_string (&candidates, 0));
  cleanup_iterator (&candidates);
  g_string_append (buffer, "</candidate_hosts>");
}

int
buffer_scopes_xml (GString *buffer, const char *scope_uuid, int details)
{
  iterator_t scopes;
  gchar *where;

  ensure_organization_scope ();

  if (scope_uuid && scope_uuid[0])
    {
      gchar *uuid_quoted;

      uuid_quoted = quoted (scope_uuid);
      where = g_strdup_printf ("WHERE uuid = %s", uuid_quoted);
      g_free (uuid_quoted);
    }
  else
    where = g_strdup ("");

  init_iterator (&scopes,
                 "SELECT id, uuid, name, comment, protection_requirement,"
                 "       predefined, is_global, creation_time, modification_time,"
                 "       CASE WHEN is_global = 1 THEN (SELECT count (*) FROM targets)"
                 "            ELSE (SELECT count (*) FROM scope_targets WHERE scope = scopes.id) END,"
                 "       CASE WHEN is_global = 1 THEN (SELECT count (*) FROM hosts)"
                 "            ELSE (SELECT count (*) FROM scope_hosts WHERE scope = scopes.id) END,"
                 "       (SELECT count (*) FROM scope_reports WHERE scope = scopes.id)"
                 " FROM scopes %s ORDER BY is_global DESC, name ASC, uuid ASC;",
                 where);
  g_free (where);

  while (next (&scopes))
    {
      scope_t scope;
      const char *uuid, *protection;
      gchar *escaped_uuid;
      gboolean global;

      scope = iterator_int64 (&scopes, 0);
      uuid = iterator_string (&scopes, 1);
      protection = iterator_string (&scopes, 4);
      escaped_uuid = xml_escape (uuid);
      global = iterator_int (&scopes, 6);

      g_string_append_printf (buffer, "<scope id=\"%s\">", escaped_uuid);
      append_xml_text (buffer, "id", uuid);
      append_xml_text (buffer, "name", iterator_string (&scopes, 2));
      append_xml_text (buffer, "comment", iterator_string (&scopes, 3));
      append_xml_text (buffer, "protection_requirement", protection);
      append_xml_text (buffer, "protection_requirement_label",
                       protection_requirement_label (protection));
      append_xml_int64 (buffer, "predefined", iterator_int (&scopes, 5));
      append_xml_int64 (buffer, "global", global);
      append_xml_int64 (buffer, "creation_time", iterator_int64 (&scopes, 7));
      append_xml_int64 (buffer, "modification_time", iterator_int64 (&scopes, 8));
      append_xml_int64 (buffer, "target_count", iterator_int64 (&scopes, 9));
      append_xml_int64 (buffer, "host_count", iterator_int64 (&scopes, 10));
      append_xml_int64 (buffer, "scope_report_count", iterator_int64 (&scopes, 11));

      if (details)
        append_scope_members_xml (buffer, scope, global);

      g_string_append (buffer, "</scope>");
      g_free (escaped_uuid);
    }
  cleanup_iterator (&scopes);

  return 0;
}

static void
append_scope_report_sources_xml (GString *buffer, scope_report_t scope_report)
{
  iterator_t sources;

  g_string_append (buffer, "<sources>");
  init_iterator (&sources,
                 "SELECT target_uuid, target_name, source_report_uuid,"
                 "       task_uuid, task_name, scan_start, scan_end"
                 " FROM scope_report_sources"
                 " WHERE scope_report = %llu"
                 " ORDER BY target_name, target_uuid;",
                 scope_report);
  while (next (&sources))
    {
      gchar *report_uuid, *target_uuid, *task_uuid;

      report_uuid = xml_escape (iterator_string (&sources, 2));
      target_uuid = xml_escape (iterator_string (&sources, 0));
      task_uuid = xml_escape (iterator_string (&sources, 3));
      g_string_append_printf (buffer,
                              "<source report_id=\"%s\" target_id=\"%s\" task_id=\"%s\">",
                              report_uuid, target_uuid, task_uuid);
      append_xml_text (buffer, "target_name", iterator_string (&sources, 1));
      append_xml_text (buffer, "task_name", iterator_string (&sources, 4));
      append_xml_int64 (buffer, "scan_start", iterator_int64 (&sources, 5));
      append_xml_int64 (buffer, "scan_end", iterator_int64 (&sources, 6));
      g_string_append (buffer, "</source>");
      g_free (report_uuid);
      g_free (target_uuid);
      g_free (task_uuid);
    }
  cleanup_iterator (&sources);
  g_string_append (buffer, "</sources>");
}

static long long
scope_report_severity_count (scope_report_t scope_report,
                             const char *host_clause,
                             const char *severity_clause)
{
  return sql_int64_0
    ("SELECT count (*) FROM ("
     " SELECT DISTINCT lower (coalesce (nullif (r.host, ''), r.hostname, '')) AS host_key,"
     "        coalesce (r.nvt, '') AS nvt_key, coalesce (r.port, '') AS port_key"
     " FROM results r"
     " JOIN scope_report_sources s ON s.source_report = r.report"
     " WHERE s.scope_report = %llu AND %s AND %s"
     ") AS deduped;",
     scope_report, host_clause, severity_clause);
}

static void
append_scope_report_severity_xml (GString *buffer, scope_report_t scope_report,
                                  gboolean global, scope_t scope)
{
  gchar *host_clause;

  host_clause = custom_host_match_clause (scope, global);
  g_string_append (buffer, "<severity>");
  append_xml_int64 (buffer, "high",
                    scope_report_severity_count (scope_report, host_clause,
                                                 "coalesce (r.severity, 0) >= 7.0"));
  append_xml_int64 (buffer, "medium",
                    scope_report_severity_count (scope_report, host_clause,
                                                 "coalesce (r.severity, 0) >= 4.0 AND coalesce (r.severity, 0) < 7.0"));
  append_xml_int64 (buffer, "low",
                    scope_report_severity_count (scope_report, host_clause,
                                                 "coalesce (r.severity, 0) > 0 AND coalesce (r.severity, 0) < 4.0"));
  append_xml_int64 (buffer, "log",
                    scope_report_severity_count (scope_report, host_clause,
                                                 "coalesce (r.severity, 0) = 0"));
  append_xml_int64 (buffer, "false_positive", 0);
  g_string_append (buffer, "</severity>");
  g_free (host_clause);
}

static void
append_scope_report_results_xml (GString *buffer, scope_report_t scope_report,
                                 gboolean global, scope_t scope)
{
  iterator_t results;
  gchar *host_clause;

  host_clause = custom_host_match_clause (scope, global);
  g_string_append (buffer, "<results max=\"100\">");
  init_iterator (&results,
                 "WITH ranked AS ("
                 " SELECT r.uuid, coalesce (nullif (r.host, ''), r.hostname, '') AS host,"
                 "        coalesce (r.port, '') AS port, coalesce (r.nvt, '') AS nvt,"
                 "        coalesce (r.severity, 0) AS severity, coalesce (r.qod, 0) AS qod,"
                 "        coalesce (r.date, 0) AS date, s.source_report_uuid, s.target_uuid,"
                 "        row_number () OVER ("
                 "          PARTITION BY lower (coalesce (nullif (r.host, ''), r.hostname, '')),"
                 "                       coalesce (r.nvt, ''), coalesce (r.port, '')"
                 "          ORDER BY coalesce (r.severity, 0) DESC, coalesce (r.date, 0) DESC, r.id DESC"
                 "        ) AS rn"
                 " FROM results r"
                 " JOIN scope_report_sources s ON s.source_report = r.report"
                 " WHERE s.scope_report = %llu AND %s"
                 ")"
                 " SELECT uuid, host, port, nvt, severity, qod, date,"
                 "        source_report_uuid, target_uuid"
                 " FROM ranked WHERE rn = 1"
                 " ORDER BY severity DESC, date DESC, host ASC LIMIT 100;",
                 scope_report, host_clause);
  while (next (&results))
    {
      gchar *result_uuid, *source_report_uuid, *target_uuid;

      result_uuid = xml_escape (iterator_string (&results, 0));
      source_report_uuid = xml_escape (iterator_string (&results, 7));
      target_uuid = xml_escape (iterator_string (&results, 8));
      g_string_append_printf (buffer,
                              "<result id=\"%s\" source_report_id=\"%s\" target_id=\"%s\">",
                              result_uuid, source_report_uuid, target_uuid);
      append_xml_text (buffer, "host", iterator_string (&results, 1));
      append_xml_text (buffer, "port", iterator_string (&results, 2));
      append_xml_text (buffer, "nvt", iterator_string (&results, 3));
      append_xml_double (buffer, "severity", iterator_double (&results, 4));
      append_xml_int64 (buffer, "qod", iterator_int64 (&results, 5));
      append_xml_int64 (buffer, "date", iterator_int64 (&results, 6));
      g_string_append (buffer, "</result>");
      g_free (result_uuid);
      g_free (source_report_uuid);
      g_free (target_uuid);
    }
  cleanup_iterator (&results);
  g_free (host_clause);
  g_string_append (buffer, "</results>");
}

int
buffer_scope_reports_xml (GString *buffer, const char *scope_report_uuid,
                          const char *scope_uuid, int details)
{
  iterator_t reports;
  gchar *where;

  if (scope_report_uuid && scope_report_uuid[0])
    {
      gchar *uuid_quoted;

      uuid_quoted = quoted (scope_report_uuid);
      where = g_strdup_printf ("WHERE sr.uuid = %s", uuid_quoted);
      g_free (uuid_quoted);
    }
  else if (scope_uuid && scope_uuid[0])
    {
      gchar *uuid_quoted;

      uuid_quoted = quoted (scope_uuid);
      where = g_strdup_printf ("WHERE sr.scope_uuid = %s", uuid_quoted);
      g_free (uuid_quoted);
    }
  else
    where = g_strdup ("");

  init_iterator (&reports,
                 "SELECT sr.id, sr.uuid, sr.scope, sr.scope_uuid, sr.scope_name,"
                 "       sr.protection_requirement, sr.source_report_count,"
                 "       sr.source_target_count, sr.member_host_count,"
                 "       sr.evidence_host_count, sr.missing_host_count,"
                 "       sr.result_count, sr.vulnerability_count, sr.max_severity,"
                 "       sr.latest_evidence_time, sr.excluded_candidate_host_count,"
                 "       sr.creation_time, sr.modification_time,"
                 "       coalesce (s.is_global, 0)"
                 " FROM scope_reports sr"
                 " LEFT JOIN scopes s ON s.id = sr.scope"
                 " %s ORDER BY sr.creation_time DESC, sr.id DESC;",
                 where);
  g_free (where);

  while (next (&reports))
    {
      scope_report_t scope_report;
      scope_t scope;
      const char *uuid, *protection;
      gchar *escaped_uuid;
      gboolean global;

      scope_report = iterator_int64 (&reports, 0);
      uuid = iterator_string (&reports, 1);
      scope = iterator_int64 (&reports, 2);
      protection = iterator_string (&reports, 5);
      escaped_uuid = xml_escape (uuid);
      global = iterator_int (&reports, 18);

      g_string_append_printf (buffer, "<scope_report id=\"%s\">",
                              escaped_uuid);
      append_xml_text (buffer, "id", uuid);
      g_string_append (buffer, "<scope>");
      append_xml_text (buffer, "id", iterator_string (&reports, 3));
      append_xml_text (buffer, "name", iterator_string (&reports, 4));
      g_string_append (buffer, "</scope>");
      append_xml_text (buffer, "protection_requirement", protection);
      append_xml_text (buffer, "protection_requirement_label",
                       protection_requirement_label (protection));
      append_xml_int64 (buffer, "source_report_count", iterator_int64 (&reports, 6));
      append_xml_int64 (buffer, "source_target_count", iterator_int64 (&reports, 7));
      append_xml_int64 (buffer, "member_host_count", iterator_int64 (&reports, 8));
      append_xml_int64 (buffer, "evidence_host_count", iterator_int64 (&reports, 9));
      append_xml_int64 (buffer, "missing_host_count", iterator_int64 (&reports, 10));
      append_xml_int64 (buffer, "result_count", iterator_int64 (&reports, 11));
      append_xml_int64 (buffer, "vulnerability_count", iterator_int64 (&reports, 12));
      append_xml_double (buffer, "max_severity", iterator_double (&reports, 13));
      append_xml_int64 (buffer, "latest_evidence_time", iterator_int64 (&reports, 14));
      append_xml_int64 (buffer, "excluded_candidate_host_count", iterator_int64 (&reports, 15));
      append_xml_int64 (buffer, "creation_time", iterator_int64 (&reports, 16));
      append_xml_int64 (buffer, "modification_time", iterator_int64 (&reports, 17));
      append_scope_report_severity_xml (buffer, scope_report, global, scope);

      if (details)
        {
          append_scope_report_sources_xml (buffer, scope_report);
          append_scope_report_results_xml (buffer, scope_report, global, scope);
        }

      g_string_append (buffer, "</scope_report>");
      g_free (escaped_uuid);
    }
  cleanup_iterator (&reports);

  return 0;
}

int
scope_count (const char *scope_uuid)
{
  if (scope_uuid && scope_uuid[0])
    {
      gchar *uuid_quoted;
      int count;

      uuid_quoted = quoted (scope_uuid);
      count = sql_int ("SELECT count (*) FROM scopes WHERE uuid = %s;",
                       uuid_quoted);
      g_free (uuid_quoted);
      return count;
    }

  return sql_int ("SELECT count (*) FROM scopes;");
}

int
scope_report_count (const char *scope_report_uuid, const char *scope_uuid)
{
  if (scope_report_uuid && scope_report_uuid[0])
    {
      gchar *uuid_quoted;
      int count;

      uuid_quoted = quoted (scope_report_uuid);
      count = sql_int ("SELECT count (*) FROM scope_reports WHERE uuid = %s;",
                       uuid_quoted);
      g_free (uuid_quoted);
      return count;
    }

  if (scope_uuid && scope_uuid[0])
    {
      gchar *uuid_quoted;
      int count;

      uuid_quoted = quoted (scope_uuid);
      count = sql_int ("SELECT count (*) FROM scope_reports"
                       " WHERE scope_uuid = %s;",
                       uuid_quoted);
      g_free (uuid_quoted);
      return count;
    }

  return sql_int ("SELECT count (*) FROM scope_reports;");
}
