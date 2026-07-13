/* Copyright (C) 2013-2022 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Greenbone Vulnerability Manager: the Manage library.
 */

#ifndef _GVMD_MANAGE_ACL_H
#define _GVMD_MANAGE_ACL_H

#include "manage_commands.h"
#include "manage_sql.h"
#include <glib.h>

/**
 * @brief Generate SQL for user permission check.
 *
 * TurboVAS grants every authenticated operator effective access to scanner
 * resources. These macros keep the inherited SQL format-argument contracts so
 * older query construction sites stay mechanically safe while RBAC tables are
 * removed.
 */
#define ACL_USER_MAY_OPTS(resource) " (EXISTS (SELECT 1 FROM users WHERE id = opts.user_id))"

/**
 * @brief Generate SQL for user permission check.
 */
#define ACL_USER_MAY(resource)                                        \
  "SELECT EXISTS (SELECT 1 FROM users WHERE users.uuid = '%s')"       \
  " OR ('%s' IS NULL AND '%s' IS NULL AND '%s' IS NULL"               \
  "     AND '%s' IS NULL AND '%s' IS NULL AND '%s' IS NULL)"

/**
 * @brief Generate SQL for global resource check.
 */
#define ACL_IS_GLOBAL() "owner IS NULL"

/**
 * @brief Generate SQL for effective ownership check.
 */
#define ACL_USER_OWNS()                                    \
  " (EXISTS (SELECT 1 FROM users WHERE users.uuid = '%s'))"

/**
 * @brief Generate SQL for global or effective ownership check.
 */
#define ACL_GLOBAL_OR_USER_OWNS()                          \
  " ((" ACL_IS_GLOBAL () ")"                              \
  "  OR EXISTS (SELECT 1 FROM users WHERE users.uuid = '%s'))"

command_t *
acl_commands (gchar **);

int
acl_user_may (const char *);

int
acl_user_can_everything (const char *);

int
acl_role_can_super_everyone (const char *);

int
acl_user_can_super_everyone (const char *);

int
acl_user_has_super (const char *, user_t);

int
acl_user_is_admin (const char *);

int
acl_user_is_user (const char *);

int
acl_user_is_super_admin (const char *);

int
acl_user_is_observer (const char *);

int
acl_user_has_role (const char *, const char *);

int
acl_user_owns (const char *, resource_t, int);

int
acl_user_is_owner (const char *, const char *);

int
acl_user_owns_uuid (const char *, const char *, int);

int
acl_user_owns_trash_uuid (const char *resource, const char *uuid);

int
acl_user_has_access_uuid (const char *, const char *, const char *, int);

gchar *
acl_where_owned (const char *, const get_data_t *, int, const gchar *, resource_t,
                 array_t *, int, gchar **);

gchar *
acl_where_owned_for_get (const char *, const char *, const char *, gchar **);

gchar *
acl_users_with_access_sql (const char *, const char *, const char *);

gchar *
acl_users_with_access_where (const char *, const char *, const char *,
                             const char*);

#endif /* not _GVMD_MANAGE_ACL_H */
