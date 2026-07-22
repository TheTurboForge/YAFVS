// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn scanner_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn scanner_trash_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer,
            name::text,
            credential::integer,
            coalesce(credential_location, 0)::integer
       FROM scanners_trash
      WHERE uuid = $1;"
}

pub(crate) fn scanner_write_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer
       FROM scanners
      WHERE uuid = $1;"
}

pub(crate) fn scanner_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM scanners
      WHERE name = $1
        AND id != $2;"
}

pub(crate) fn scanner_credential_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            type::text
       FROM credentials
      WHERE uuid = $1;"
}

pub(crate) fn scanner_live_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE scanner = $1
        AND coalesce(scanner_location, 0) = 0
        AND coalesce(hidden, 0) = 0;"
}

pub(crate) fn scanner_trash_task_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE scanner = $1
        AND scanner_location = 1;"
}

pub(crate) fn scanner_live_uuid_conflict_sql() -> &'static str {
    "SELECT count(*)::bigint FROM scanners WHERE uuid = $1;"
}

pub(crate) fn scanner_live_credential_count_sql() -> &'static str {
    "SELECT count(*)::bigint FROM credentials WHERE id = $1;"
}

pub(crate) fn scanner_create_configuration_sql() -> &'static str {
    "INSERT INTO scanners
        (uuid, owner, name, comment, host, port, type, ca_pub, credential,
         relay_host, relay_port, creation_time, modification_time)
     VALUES
        (make_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, m_now(), m_now())
     RETURNING uuid::text;"
}

pub(crate) fn scanner_clone_metadata_sql() -> &'static str {
    "INSERT INTO scanners
        (uuid, owner, name, comment, host, port, type, ca_pub, credential,
         relay_host, relay_port, creation_time, modification_time)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('scanner', name, $2, ' Clone')),
            coalesce($4, comment),
            host,
            port,
            type,
            ca_pub,
            credential,
            NULL,
            0,
            m_now(),
            m_now()
       FROM scanners
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scanner_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, 0
       FROM tag_resources
      WHERE resource_type = 'scanner'
        AND resource = $1
        AND resource_location = 0;"
}

pub(crate) fn scanner_trash_insert_sql() -> &'static str {
    "INSERT INTO scanners_trash
        (uuid, owner, name, comment, host, port, type, ca_pub, credential,
         credential_location, creation_time, modification_time, relay_host, relay_port)
     SELECT uuid, owner, name, comment, host, port, type, ca_pub, credential,
            0, creation_time, modification_time, relay_host, relay_port
       FROM scanners
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scanner_trash_task_relink_sql() -> &'static str {
    "UPDATE tasks
        SET scanner = $1,
            scanner_location = 1
      WHERE scanner = $2
        AND coalesce(scanner_location, 0) = 0;"
}

pub(crate) fn scanner_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'scanner'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn scanner_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'scanner'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn scanner_delete_live_metadata_sql() -> &'static str {
    "DELETE FROM scanners WHERE id = $1;"
}

pub(crate) fn scanner_restore_metadata_sql() -> &'static str {
    "INSERT INTO scanners
        (uuid, owner, name, comment, host, port, type, ca_pub, credential,
         creation_time, modification_time, relay_host, relay_port)
     SELECT uuid, owner, name, comment, host, port, type, ca_pub, credential,
            creation_time, modification_time, relay_host, relay_port
       FROM scanners_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn scanner_restore_task_relink_sql() -> &'static str {
    "UPDATE tasks
        SET scanner = $2,
            scanner_location = 0
      WHERE scanner = $1
        AND scanner_location = 1;"
}

pub(crate) fn scanner_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'scanner'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scanner_trash_tag_locations_to_live_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'scanner'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scanner_trash_tag_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'scanner'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scanner_trash_tag_trash_delete_sql() -> &'static str {
    "DELETE FROM tag_resources_trash
      WHERE resource_type = 'scanner'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn scanner_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM scanners_trash WHERE id = $1;"
}

pub(crate) fn scanner_replace_configuration_sql() -> &'static str {
    "UPDATE scanners
        SET name = $2,
            comment = $3,
            host = $4,
            port = $5,
            type = $6,
            ca_pub = $7,
            credential = $8,
            relay_host = $9,
            relay_port = $10,
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn scanner_update_metadata_sql() -> &'static str {
    "UPDATE scanners
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}
