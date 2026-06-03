/* Copyright (C) 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: removed permission-cache compatibility hooks.
 */

#include "manage_sql_permissions_cache.h"

void
cache_permissions_for_resource (const char *type, resource_t resource,
                                GArray *users)
{
  (void) type;
  (void) resource;
  (void) users;
}

void
cache_all_permissions_for_users (GArray *users)
{
  (void) users;
}

void
delete_permissions_cache_for_resource (const char *type, resource_t resource)
{
  (void) type;
  (void) resource;
}

void
delete_permissions_cache_for_user (user_t user)
{
  (void) user;
}
