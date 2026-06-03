/* Copyright (C) 2013-2022 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief The Greenbone Vulnerability Manager management library (Access
 * Control Layer).
 *
 * TurboVAS uses an operator-account model: authentication is the scanner
 * administration boundary, and every authenticated user has the same effective
 * access to scanner resources. Owner columns remain as attribution metadata.
 */

#include "manage_acl.h"
#include "manage_sql.h"
#include "sql.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

static int
strv_case_eq (gchar **strv, const gchar *string)
{
  if (string == NULL)
    return 0;

  while (*strv)
    if (strcasecmp (*strv, string) == 0)
      return 1;
    else
      strv++;

  return 0;
}

static int
authenticated_user_exists (const char *uuid)
{
  gchar *quoted_uuid;
  int ret;

  if (uuid == NULL)
    return 0;

  if (strlen (uuid) == 0)
    return 1;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT EXISTS (SELECT 1 FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

command_t *
acl_commands (gchar **disabled_commands)
{
  command_t *all, *commands;
  int index, length;

  length = 1;
  all = gmp_commands;
  while ((*all).name)
    {
      length++;
      all++;
    }

  commands = g_malloc0 (length * sizeof (*commands));
  all = gmp_commands;
  index = 0;
  while ((*all).name)
    {
      if (disabled_commands == NULL
          || strv_case_eq (disabled_commands, (*all).name) == 0)
        {
          commands[index].name = (*all).name;
          commands[index].summary = (*all).summary;
          index++;
        }
      all++;
    }

  return commands;
}

int
acl_user_may (const char *operation)
{
  (void) operation;
  return authenticated_user_exists (current_credentials.uuid);
}

int
acl_role_can_super_everyone (const char *role_id)
{
  (void) role_id;
  return 0;
}

int
acl_user_can_super_everyone (const char *uuid)
{
  return authenticated_user_exists (uuid);
}

int
acl_user_can_everything (const char *user_id)
{
  return authenticated_user_exists (user_id);
}

int
acl_user_has_super (const char *super_user_id, user_t other_user)
{
  (void) other_user;
  return authenticated_user_exists (super_user_id);
}

int
acl_user_is_admin (const char *uuid)
{
  return authenticated_user_exists (uuid);
}

int
acl_user_is_observer (const char *uuid)
{
  (void) uuid;
  return 0;
}

int
acl_user_is_super_admin (const char *uuid)
{
  return authenticated_user_exists (uuid);
}

int
acl_user_is_user (const char *uuid)
{
  return authenticated_user_exists (uuid);
}

int
acl_user_has_role (const char *user_uuid, const char *role_uuid)
{
  (void) user_uuid;
  (void) role_uuid;
  return 0;
}

int
acl_user_is_owner (const char *type, const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  assert (uuid && current_credentials.uuid);

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count(*) FROM %ss"
                 " WHERE uuid = '%s'"
                 " AND owner = (SELECT users.id FROM users"
                 "              WHERE users.uuid = '%s');",
                 type,
                 quoted_uuid,
                 current_credentials.uuid);
  g_free (quoted_uuid);

  return ret;
}

int
acl_user_owns_uuid (const char *type, const char *uuid, int trash)
{
  int ret;
  gchar *quoted_uuid;

  assert (current_credentials.uuid);

  if (authenticated_user_exists (current_credentials.uuid) == 0)
    return 0;

  if ((strcmp (type, "nvt") == 0)
      || (strcmp (type, "cve") == 0)
      || (strcmp (type, "cpe") == 0)
      || (strcmp (type, "cert_bund_adv") == 0)
      || (strcmp (type, "dfn_cert_adv") == 0))
    return 1;

  if (strcmp (type, "permission") == 0)
    return 0;

  quoted_uuid = sql_quote (uuid);
  if (strcmp (type, "result") == 0)
    ret = sql_int ("SELECT count(*) FROM results WHERE uuid = '%s';",
                   quoted_uuid);
  else if ((strcmp (type, "task") == 0) && trash)
    ret = sql_int ("SELECT count(*) FROM tasks"
                   " WHERE uuid = '%s' AND hidden = 2;",
                   quoted_uuid);
  else if (strcmp (type, "task") == 0)
    ret = sql_int ("SELECT count(*) FROM tasks"
                   " WHERE uuid = '%s' AND hidden < 2;",
                   quoted_uuid);
  else
    ret = sql_int ("SELECT count(*) FROM %ss%s WHERE uuid = '%s';",
                   type,
                   trash ? "_trash" : "",
                   quoted_uuid);
  g_free (quoted_uuid);

  return ret;
}

int
acl_user_owns (const char *type, resource_t resource, int trash)
{
  if (authenticated_user_exists (current_credentials.uuid) == 0)
    return 0;

  if ((strcmp (type, "nvt") == 0)
      || (strcmp (type, "cve") == 0)
      || (strcmp (type, "cpe") == 0)
      || (strcmp (type, "cert_bund_adv") == 0)
      || (strcmp (type, "dfn_cert_adv") == 0))
    return 1;

  if (strcmp (type, "permission") == 0)
    return 0;

  if (strcmp (type, "result") == 0)
    return sql_int ("SELECT count(*) FROM results WHERE id = %llu;",
                    resource);
  else if ((strcmp (type, "task") == 0) && trash)
    return sql_int ("SELECT count(*) FROM tasks"
                    " WHERE id = %llu AND hidden = 2;",
                    resource);
  else if (strcmp (type, "task") == 0)
    return sql_int ("SELECT count(*) FROM tasks"
                    " WHERE id = %llu AND hidden < 2;",
                    resource);

  return sql_int ("SELECT count(*) FROM %ss%s WHERE id = %llu;",
                  type,
                  trash ? "_trash" : "",
                  resource);
}

int
acl_user_owns_trash_uuid (const char *type, const char *uuid)
{
  return acl_user_owns_uuid (type, uuid, 1);
}

int
acl_user_has_access_uuid (const char *type, const char *uuid,
                          const char *permission, int trash)
{
  if (permission && (valid_gmp_command (permission) == 0))
    return 0;

  return acl_user_owns_uuid (type, uuid, trash);
}

gchar *
acl_where_owned (const char *type, const get_data_t *get, int owned,
                 const gchar *owner_filter, resource_t resource,
                 array_t *permissions, int with_optional, gchar **with)
{
  gchar *clause;

  (void) owned;
  (void) resource;
  (void) permissions;
  (void) with_optional;

  if (with)
    *with = NULL;

  if (owner_filter == NULL
      || (owner_filter && (strcmp (owner_filter, "any") == 0)))
    clause = g_strdup ("t ()");
  else if (owner_filter && strcmp (owner_filter, ""))
    {
      gchar *quoted;
      quoted = sql_quote (owner_filter);
      clause = g_strdup_printf ("owner = (SELECT id FROM users"
                                " WHERE name = '%s')",
                                quoted);
      g_free (quoted);
    }
  else if (current_credentials.uuid)
    clause = g_strdup_printf ("owner = (SELECT id FROM users"
                              " WHERE uuid = '%s')",
                              current_credentials.uuid);
  else
    clause = g_strdup ("NOT t ()");

  if (get && get->trash && (strcasecmp (type, "task") == 0))
    {
      gchar *task_clause;
      task_clause = g_strdup_printf ("(tasks.hidden = 2 AND %s)", clause);
      g_free (clause);
      clause = task_clause;
    }

  return clause;
}

gchar *
acl_where_owned_for_get (const char *type, const char *user_sql,
                         const char *with_prefix, gchar **with)
{
  (void) type;
  (void) user_sql;
  (void) with_prefix;

  if (with)
    *with = NULL;

  return g_strdup ("t ()");
}

gchar *
acl_users_with_access_sql (const char *type, const char *resource_id,
                           const char *users_where)
{
  (void) type;
  (void) resource_id;
  return g_strdup_printf ("(SELECT id FROM users WHERE %s)",
                          users_where ? users_where : "t ()");
}

gchar *
acl_users_with_access_where (const char *type, const char *resource_id,
                             const char *users_where, const char* user_expr)
{
  gchar *values, *ret;
  assert (user_expr);
  values = acl_users_with_access_sql (type, resource_id, users_where);
  ret = g_strdup_printf ("%s IN %s", user_expr, values);
  g_free (values);
  return ret;
}
