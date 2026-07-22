// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn credential_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn credential_trash_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer,
            name::text
       FROM credentials_trash
      WHERE uuid = $1;"
}

pub(crate) fn credential_live_uuid_count_sql() -> &'static str {
    "SELECT count(*)::bigint FROM credentials WHERE uuid = $1;"
}

pub(crate) fn credential_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM credentials
      WHERE uuid = $1;"
}

pub(crate) fn credential_restore_metadata_sql() -> &'static str {
    "INSERT INTO credentials
        (uuid, owner, name, comment, creation_time, modification_time, type,
         allow_insecure)
     SELECT uuid, owner, name, comment, creation_time, modification_time, type,
            allow_insecure
       FROM credentials_trash
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn credential_restore_data_sql() -> &'static str {
    "INSERT INTO credentials_data (credential, type, value)
     SELECT $2, type, value
       FROM credentials_trash_data
      WHERE credential = $1;"
}

pub(crate) fn credential_restore_target_references_sql() -> &'static str {
    "UPDATE targets_trash_login_data
        SET credential_location = 0,
            credential = $2
      WHERE credential = $1
        AND credential_location = 1;"
}

pub(crate) fn credential_restore_scanner_references_sql() -> &'static str {
    "UPDATE scanners_trash
        SET credential_location = 0,
            credential = $2
      WHERE credential = $1
        AND credential_location = 1;"
}

pub(crate) fn credential_restore_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'credential'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn credential_restore_trash_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 0,
            resource = $2
      WHERE resource_type = 'credential'
        AND resource = $1
        AND resource_location = 1;"
}

pub(crate) fn credential_delete_trash_data_sql() -> &'static str {
    "DELETE FROM credentials_trash_data WHERE credential = $1;"
}

pub(crate) fn credential_delete_trash_metadata_sql() -> &'static str {
    "DELETE FROM credentials_trash
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn credential_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM credentials
      WHERE name = $1
        AND id != $2
        AND owner = $3;"
}

pub(crate) fn credential_update_metadata_sql() -> &'static str {
    "UPDATE credentials
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}
