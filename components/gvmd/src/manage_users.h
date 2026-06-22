/* Copyright (C) 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_USERS_H
#define _GVMD_MANAGE_USERS_H

#include "manage_get.h"
#include "manage_resources_types.h"
#include "sql.h" // Sadly, for db_conn_info_t

gchar *
user_name (const char *);

char *
user_uuid (user_t);

int
user_in_use (user_t);

int
trash_user_in_use (user_t);

int
user_writable (user_t);

int
trash_user_writable (user_t);

int
user_count (const get_data_t *);

int
init_user_iterator (iterator_t *, get_data_t *);

const char*
user_iterator_method (iterator_t *);

int
create_user (const gchar *, const gchar *, const gchar *, const array_t *,
             gchar **, user_t *);

int
delete_user (const char *, const char *, int, const char *, const char *);

int
copy_user (const char *, const char *, const char *, user_t *);

int
modify_user (const gchar *, gchar **, const gchar *, const gchar *,
             const gchar *, const array_t *, gchar **);

int
manage_create_user (GSList *, const db_conn_info_t *, const gchar *,
                    const gchar *, const gchar *);

int
manage_delete_user (GSList *, const db_conn_info_t *, const gchar *,
                    const gchar *);

int
manage_get_users (GSList *, const db_conn_info_t *, const gchar *, int);

int
manage_set_password (GSList *, const db_conn_info_t *, const gchar *,
                     const gchar *);

int
current_user_set_timezone (const gchar *);

#endif /* not _GVMD_MANAGE_USERS_H */
