// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn port_list_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn port_list_create_metadata_sql() -> &'static str {
    "INSERT INTO port_lists
        (uuid, owner, name, comment, predefined, creation_time, modification_time)
     VALUES (coalesce($4, make_uuid()), $1, $2, $3, 0, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn port_list_create_range_sql() -> &'static str {
    "INSERT INTO port_ranges
        (uuid, port_list, type, start, \"end\", comment, exclude)
     VALUES (make_uuid(), $1, $2, $3, $4, $5, 0);"
}

pub(crate) fn port_list_clone_metadata_sql() -> &'static str {
    "INSERT INTO port_lists
        (uuid, owner, name, comment, predefined, creation_time, modification_time)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('port_list', name, $2, ' Clone')),
            coalesce($4, comment),
            0,
            m_now(),
            m_now()
       FROM port_lists
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn port_list_clone_ranges_sql() -> &'static str {
    "INSERT INTO port_ranges
        (uuid, port_list, type, start, \"end\", comment, exclude)
     SELECT make_uuid(), $2, type, start, \"end\", comment, exclude
       FROM port_ranges
      WHERE port_list = $1;"
}

pub(crate) fn port_list_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'port_list'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn port_list_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(predefined, 0)::integer
       FROM port_lists
      WHERE uuid = $1;"
}

pub(crate) fn port_list_range_write_state_sql() -> &'static str {
    "SELECT pr.id::integer,
            pr.port_list::integer,
            pl.owner::integer,
            coalesce(pl.predefined, 0)::integer
       FROM port_ranges pr
       JOIN port_lists pl ON pl.id = pr.port_list
      WHERE pl.uuid = $1
        AND pr.uuid = $2;"
}

pub(crate) fn port_list_trash_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text, name, owner::integer
       FROM port_lists_trash
      WHERE uuid = $1;"
}

pub(crate) fn port_list_unique_name_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM port_lists WHERE name = $1 AND id != $2)
        + (SELECT count(*) FROM port_lists_trash WHERE name = $1)
      )::bigint;"
}

pub(crate) fn port_list_unique_live_owner_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM port_lists
      WHERE name = $1
        AND owner = $2;"
}

pub(crate) fn port_list_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM port_lists
      WHERE uuid = $1;"
}

pub(crate) fn port_list_live_or_trash_uuid_conflict_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM port_lists WHERE uuid = $1)
        + (SELECT count(*) FROM port_lists_trash WHERE uuid = $1)
      )::bigint;"
}

pub(crate) fn port_list_update_metadata_sql() -> &'static str {
    "UPDATE port_lists
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn port_list_live_target_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets
      WHERE port_list = $1;"
}

pub(crate) fn port_list_live_location_trash_target_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets_trash
      WHERE port_list = $1
        AND port_list_location = 0;"
}

pub(crate) fn port_list_trash_target_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets_trash
      WHERE port_list = $1
        AND port_list_location = 1;"
}

pub(crate) fn port_list_trash_insert_sql() -> &'static str {
    "INSERT INTO port_lists_trash
        (uuid, owner, name, comment, predefined, creation_time, modification_time)
     SELECT uuid, owner, name, comment, predefined, creation_time, modification_time
       FROM port_lists
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn port_list_trash_ranges_insert_sql() -> &'static str {
    "INSERT INTO port_ranges_trash
        (uuid, port_list, type, start, \"end\", comment, exclude)
     SELECT uuid, $1, type, start, \"end\", comment, exclude
       FROM port_ranges
      WHERE port_list = $2;"
}

pub(crate) fn port_list_trash_target_relink_sql() -> &'static str {
    "UPDATE targets_trash
        SET port_list = $1,
            port_list_location = 1
      WHERE port_list = $2
        AND port_list_location = 0;"
}

pub(crate) fn port_list_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'port_list'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn port_list_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'port_list'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn port_list_delete_ranges_sql() -> &'static str {
    "DELETE FROM port_ranges WHERE port_list = $1;"
}

pub(crate) fn port_list_delete_range_sql() -> &'static str {
    "DELETE FROM port_ranges WHERE id = $1;"
}

pub(crate) fn port_list_delete_metadata_sql() -> &'static str {
    "DELETE FROM port_lists WHERE id = $1;"
}

pub(crate) fn port_list_restore_metadata_sql() -> &'static str {
    "INSERT INTO port_lists
        (uuid, owner, name, comment, predefined, creation_time, modification_time)
     SELECT uuid, owner, name, comment, predefined, creation_time, modification_time
       FROM port_lists_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn port_list_restore_ranges_sql() -> &'static str {
    "INSERT INTO port_ranges
        (uuid, port_list, type, start, \"end\", comment, exclude)
     SELECT uuid, $2, type, start, \"end\", comment, exclude
       FROM port_ranges_trash
      WHERE port_list = $1;"
}

pub(crate) fn port_list_restore_target_relink_sql() -> &'static str {
    "UPDATE targets_trash
        SET port_list = $2,
            port_list_location = 0
      WHERE port_list = $1
        AND port_list_location = 1;"
}

pub(crate) fn port_list_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'port_list'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn port_list_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'port_list'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn port_list_delete_trash_ranges_sql() -> &'static str {
    "DELETE FROM port_ranges_trash WHERE port_list = $1;"
}

pub(crate) fn port_list_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'port_list'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn port_list_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'port_list'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn port_list_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM port_lists_trash WHERE id = $1;"
}
