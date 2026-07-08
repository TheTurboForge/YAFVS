// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn host_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn host_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM hosts
      WHERE uuid = $1;"
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
