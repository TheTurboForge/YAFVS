/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief SQL handlers for YAFVS reporting scopes.
 */

#include "manage_sql_scopes.h"
#include "manage_utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#define ORGANIZATION_SCOPE_NAME "Organization"

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
