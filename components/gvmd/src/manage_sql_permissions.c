/* Copyright (C) 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: SQL permission compatibility helpers.
 *
 * YAFVS removes inherited role/group/permission authorization. These
 * helpers remain as no-ops for legacy manager call sites while the live GMP,
 * schema, and UI surfaces are removed.
 */

#include "manage_sql_permissions.h"
#include "iterator.h"
#include "sql.h"

#include <stdlib.h>

resource_t
permission_resource (permission_t permission)
{
  (void) permission;
  return 0;
}

int
permission_is_predefined (permission_t permission)
{
  (void) permission;
  return 0;
}

char *
permission_resource_type (permission_t permission)
{
  (void) permission;
  return NULL;
}

resource_t
permission_subject (permission_t permission)
{
  (void) permission;
  return 0;
}

char *
permission_subject_type (permission_t permission)
{
  (void) permission;
  return NULL;
}

char *
permission_name (permission_t permission)
{
  (void) permission;
  return NULL;
}

void
permissions_set_locations (const char *type, resource_t old, resource_t new,
                           int to)
{
  (void) type;
  (void) old;
  (void) new;
  (void) to;
}

void
permissions_set_orphans (const char *type, resource_t resource, int location)
{
  (void) type;
  (void) resource;
  (void) location;
}

void
permissions_set_subjects (const char *type, resource_t old, resource_t new,
                          int to)
{
  (void) type;
  (void) old;
  (void) new;
  (void) to;
}

void
add_feed_role_permissions (const char *type, const char *type_cap,
                           int *permission_count, int *object_count)
{
  (void) type;
  (void) type_cap;
  if (permission_count)
    *permission_count = 0;
  if (object_count)
    *object_count = 0;
}

void
clean_feed_role_permissions (const char *type, const char *type_cap,
                             int *permission_count, int *object_count)
{
  (void) type;
  (void) type_cap;
  if (permission_count)
    *permission_count = 0;
  if (object_count)
    *object_count = 0;
}

gchar *
subject_where_clause (const char *subject_type, resource_t subject)
{
  (void) subject_type;
  (void) subject;
  return g_strdup ("FALSE");
}

int
permission_count (const get_data_t *get)
{
  (void) get;
  return 0;
}

int
init_permission_iterator (iterator_t *iterator, get_data_t *get)
{
  (void) get;
  init_iterator (iterator, "SELECT 1 WHERE FALSE;");
  return 0;
}

const char *
permission_iterator_resource_type (iterator_t *iterator)
{
  (void) iterator;
  return "";
}

const char *
permission_iterator_resource_uuid (iterator_t *iterator)
{
  (void) iterator;
  return "";
}

const char *
permission_iterator_resource_name (iterator_t *iterator)
{
  (void) iterator;
  return "";
}

int
permission_iterator_resource_in_trash (iterator_t *iterator)
{
  (void) iterator;
  return 0;
}

int
permission_iterator_resource_orphan (iterator_t *iterator)
{
  (void) iterator;
  return 0;
}

int
permission_iterator_resource_readable (iterator_t *iterator)
{
  (void) iterator;
  return 0;
}

const char *
permission_iterator_subject_type (iterator_t *iterator)
{
  (void) iterator;
  return "";
}

const char *
permission_iterator_subject_uuid (iterator_t *iterator)
{
  (void) iterator;
  return "";
}

const char *
permission_iterator_subject_name (iterator_t *iterator)
{
  (void) iterator;
  return "";
}

int
permission_iterator_subject_in_trash (iterator_t *iterator)
{
  (void) iterator;
  return 0;
}

int
permission_iterator_subject_readable (iterator_t *iterator)
{
  (void) iterator;
  return 0;
}

int
create_permission_internal (int check_access, const char *name_arg,
                            const char *comment, const char *resource_type,
                            const char *resource_id,
                            const char *subject_type,
                            const char *subject_id,
                            permission_t *permission)
{
  (void) check_access;
  (void) name_arg;
  (void) comment;
  (void) resource_type;
  (void) resource_id;
  (void) subject_type;
  (void) subject_id;
  if (permission)
    *permission = 0;
  return 99;
}

int
create_permission_no_acl (const char *name_arg, const char *comment,
                          const char *resource_type,
                          const char *resource_id,
                          const char *subject_type,
                          const char *subject_id,
                          permission_t *permission)
{
  return create_permission_internal (0, name_arg, comment, resource_type,
                                     resource_id, subject_type, subject_id,
                                     permission);
}

int
create_permission (const char *name_arg, const char *comment,
                   const char *resource_type, const char *resource_id,
                   const char *subject_type, const char *subject_id,
                   permission_t *permission)
{
  return create_permission_internal (1, name_arg, comment, resource_type,
                                     resource_id, subject_type, subject_id,
                                     permission);
}

int
copy_permission (const char *comment, const char *permission_id,
                 permission_t *permission)
{
  (void) comment;
  (void) permission_id;
  if (permission)
    *permission = 0;
  return 99;
}

int
delete_permission (const char *permission_id, int ultimate)
{
  (void) permission_id;
  (void) ultimate;
  return 99;
}

int
modify_permission (const char *permission_id, const char *name_arg,
                   const char *comment, const char *resource_type,
                   const char *resource_id, const char *subject_type,
                   const char *subject_id)
{
  (void) permission_id;
  (void) name_arg;
  (void) comment;
  (void) resource_type;
  (void) resource_id;
  (void) subject_type;
  (void) subject_id;
  return 99;
}

char *
permission_uuid (permission_t permission)
{
  (void) permission;
  return NULL;
}
