// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn alert_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn alert_write_state_sql() -> &'static str {
    "SELECT id::integer, owner::integer
       FROM alerts
      WHERE uuid = $1;"
}

pub(crate) fn alert_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM alerts
      WHERE name = $1
        AND id != $2;"
}

pub(crate) fn alert_update_metadata_sql() -> &'static str {
    "UPDATE alerts
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}
