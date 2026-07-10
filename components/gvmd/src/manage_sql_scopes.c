/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for TurboVAS reporting scopes.
 */

#include "manage_sql_scopes.h"
#include "manage_filters.h"
#include "manage_filter_utils.h"
#include "manage_sql_metrics.h"
#include "manage_utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define ORGANIZATION_SCOPE_NAME "Organization"
#define SCOPE_REPORT_FINDING_CLAUSE \
  "coalesce (r.severity, 0) != " G_STRINGIFY (SEVERITY_ERROR)

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
