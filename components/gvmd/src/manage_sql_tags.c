/* Copyright (C) 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_tags.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_resources.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Tags SQL
 *
 * The Tags SQL for the GVM management layer.
 */

/**
 * @brief Remove a resource from tags.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource.
 * @param[in]  location  Location: table or trash.
 */
void
tags_remove_resource (const char *type, resource_t resource, int location)
{
  sql ("DELETE FROM tag_resources"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
}

/**
 * @brief Adjust location of resource in tags.
 *
 * @param[in]   type  Type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
tags_set_locations (const char *type, resource_t old, resource_t new,
                    int to)
{
  sql ("UPDATE tag_resources SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
  sql ("UPDATE tag_resources_trash SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
}

/**
 * @brief Initialise a iterator of tags attached to a resource.
 *
 * @param[in]  iterator         Iterator.
 * @param[in]  type             Resource type.
 * @param[in]  resource         Resource.
 * @param[in]  active_only      Whether to select only active tags.
 * @param[in]  sort_field       Field to sort by.
 * @param[in]  ascending        Whether to sort in ascending order.
 *
 * @return 0 success, -1 error.
 */
int
init_resource_tag_iterator (iterator_t* iterator, const char* type,
                            resource_t resource, int active_only,
                            const char* sort_field, int ascending)
{
  get_data_t get;
  gchar *owned_clause, *with_clause;
  const char *parent_type;

  assert (type);
  assert (resource);
  assert (current_credentials.uuid);

  get.trash = 0;
  owned_clause = acl_where_owned ("tag", &get, 1, "any", 0, NULL, 0,
                                  &with_clause);

  if (type_is_report_subtype (type))
    parent_type = "report";
  else if (type_is_task_subtype (type))
    parent_type = "task";
  else if (type_is_config_subtype (type))
    parent_type = "config";
  else
    parent_type = type;

  init_iterator (iterator,
                 "%s"
                 " SELECT id, uuid, name, value, comment"
                 " FROM tags"
                 " WHERE resource_type = '%s'"
                 " AND EXISTS"
                 "  (SELECT * FROM tag_resources"
                 "   WHERE resource_type = '%s'"
                 "   AND resource = %llu"
                 "   AND resource_location = %d"
                 "   AND tag = tags.id)"
                 "%s"
                 " AND %s"
                 " ORDER BY %s %s;",
                 with_clause ? with_clause : "",
                 type,
                 parent_type,
                 resource,
                 LOCATION_TABLE,
                 active_only ? " AND active=1" : "",
                 owned_clause,
                 sort_field ? sort_field : "active DESC, name",
                 ascending ? "ASC" : "DESC");

  g_free (with_clause);
  g_free (owned_clause);
  return 0;
}

/**
 * @brief Get the Tag UUID from a resource Tag iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the tag.
 */
DEF_ACCESS (resource_tag_iterator_uuid, 1);

/**
 * @brief Get the Tag name from a resource Tag iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the tag.
 */
DEF_ACCESS (resource_tag_iterator_name, 2);

/**
 * @brief Get the Tag value from a resource Tag iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the tag.
 */
DEF_ACCESS (resource_tag_iterator_value, 3);

/**
 * @brief Get the Tag comment from a resource Tag iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The comment of the tag.
 */
DEF_ACCESS (resource_tag_iterator_comment, 4);

/**
 * @brief Check if there are tags attached to a resource.
 *
 * @param[in]  type         Resource type.
 * @param[in]  resource     Resource.
 * @param[in]  active_only  Whether to count only active tags.
 *
 * @return 1 if resource has tags, else 0.
 */
int
resource_tag_exists (const char* type, resource_t resource, int active_only)
{
  int ret;

  assert (type);
  assert (resource);

  ret = sql_int ("SELECT EXISTS (SELECT *"
                 "               FROM tags"
                 "               WHERE resource_type = '%s'"
                 "               AND EXISTS"
                 "                   (SELECT * FROM tag_resources"
                 "                    WHERE tag = tags.id"
                 "                    AND resource = %llu"
                 "                    AND resource_location = %d"
                 "                    AND tags.resource_type"
                 "                        = tag_resources.resource_type)"
                 "               %s);",
                 type,
                 resource,
                 LOCATION_TABLE,
                 active_only ? "AND active=1": "");

  return ret;
}

/**
 * @brief Count number of tags attached to a resource.
 *
 * @param[in]  type         Resource type.
 * @param[in]  resource     Resource.
 * @param[in]  active_only  Whether to count only active tags.
 *
 * @return Total number of tags attached to the resource.
 */
int
resource_tag_count (const char* type, resource_t resource, int active_only)
{
  int ret;
  const char *parent_type;

  assert (type);
  assert (resource);

  if (type_is_report_subtype (type))
    parent_type = "report";
  else if (type_is_task_subtype (type))
    parent_type = "task";
  else if (type_is_config_subtype (type))
    parent_type = "config";
  else
    parent_type = type;

  ret = sql_int ("SELECT count (id)"
                " FROM tags"
                " WHERE resource_type = '%s'"
                "   AND EXISTS"
                "     (SELECT * FROM tag_resources"
                "      WHERE tag = tags.id"
                "        AND resource = %llu"
                "        AND resource_location = %d"
                "        AND tag_resources.resource_type = '%s')"
                "   %s;",
                type,
                resource,
                LOCATION_TABLE,
                parent_type,
                active_only ? "AND active=1": "");

  return ret;
}
