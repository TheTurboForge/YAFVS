// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn report_format_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn report_format_write_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            owner::integer,
            coalesce(predefined, 0)::integer
       FROM report_formats
      WHERE uuid = $1;"
}

pub(crate) fn report_format_update_metadata_sql() -> &'static str {
    "UPDATE report_formats
        SET name = coalesce($2, name),
            summary = coalesce($3, summary),
            flags = CASE
                WHEN $4::boolean IS NULL THEN coalesce(flags, 0)
                WHEN $4::boolean THEN coalesce(flags, 0) | 1
                ELSE coalesce(flags, 0) & ~1
            END,
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}
