// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn credential_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn credential_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM credentials
      WHERE uuid = $1;"
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
