// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scanner_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
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
        AND coalesce(hidden, 0) = 0;"
}

pub(crate) fn scanner_create_configuration_sql() -> &'static str {
    "INSERT INTO scanners
        (uuid, owner, name, comment, host, port, type, ca_pub, credential,
         relay_host, relay_port, creation_time, modification_time)
     VALUES
        (make_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NULL, 0, m_now(), m_now())
     RETURNING uuid::text;"
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
