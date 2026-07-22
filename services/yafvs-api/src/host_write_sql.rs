// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn host_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn host_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM hosts
      WHERE uuid = $1;"
}

pub(crate) fn host_identifier_write_state_sql() -> &'static str {
    "SELECT hi.id::integer,
            h.owner::integer
       FROM host_identifiers hi
       JOIN hosts h ON h.id = hi.host
      WHERE hi.uuid = $1;"
}

pub(crate) fn host_operating_system_write_state_sql() -> &'static str {
    "SELECT ho.id::integer,
            h.owner::integer
       FROM host_oss ho
       JOIN hosts h ON h.id = ho.host
      WHERE ho.uuid = $1;"
}

pub(crate) fn host_create_sql() -> &'static str {
    "INSERT INTO hosts
        (uuid, owner, name, comment, creation_time, modification_time)
     VALUES
        (make_uuid(), $1, $2, $3, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn host_create_ip_identifier_sql() -> &'static str {
    "INSERT INTO host_identifiers
        (uuid, host, owner, name, comment, value, source_type, source_id,
         source_data, creation_time, modification_time)
     VALUES
        (make_uuid(), $1, $2, 'ip', '', $3, 'User', $4, '', m_now(), m_now());"
}

pub(crate) fn host_update_comment_sql() -> &'static str {
    "UPDATE hosts
        SET comment = $2,
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn host_delete_identifiers_sql() -> &'static str {
    "DELETE FROM host_identifiers WHERE host = $1;"
}

pub(crate) fn host_delete_identifier_sql() -> &'static str {
    "DELETE FROM host_identifiers WHERE id = $1;"
}

pub(crate) fn host_delete_operating_system_link_sql() -> &'static str {
    "DELETE FROM host_oss WHERE id = $1;"
}

pub(crate) fn host_delete_operating_system_links_sql() -> &'static str {
    "DELETE FROM host_oss WHERE host = $1;"
}

pub(crate) fn host_delete_max_severities_sql() -> &'static str {
    "DELETE FROM host_max_severities WHERE host = $1;"
}

pub(crate) fn host_delete_details_sql() -> &'static str {
    "DELETE FROM host_details WHERE host = $1;"
}

pub(crate) fn host_delete_host_sql() -> &'static str {
    "DELETE FROM hosts WHERE id = $1;"
}

pub(crate) fn host_delete_tags_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE resource_type = 'host'
        AND resource = $1
        AND resource_location = 0;"
}
