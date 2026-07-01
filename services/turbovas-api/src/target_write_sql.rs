// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn target_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn target_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM targets
      WHERE uuid = $1;"
}

pub(crate) fn target_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets
      WHERE name = $1
        AND id != $2
        AND owner = $3;"
}

pub(crate) fn target_in_use_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE target = $1
        AND target_location = 0
        AND hidden = 0;"
}

pub(crate) fn target_update_metadata_sql() -> &'static str {
    "UPDATE targets
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            alive_test = coalesce($4, alive_test),
            allow_simultaneous_ips = coalesce($5, allow_simultaneous_ips),
            reverse_lookup_only = coalesce($6, reverse_lookup_only),
            reverse_lookup_unify = coalesce($7, reverse_lookup_unify),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}
