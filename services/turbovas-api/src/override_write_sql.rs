// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn override_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn override_write_state_sql() -> &'static str {
    "SELECT id::integer,
            coalesce(owner, 0)::integer,
            coalesce(nvt, '')::text,
            coalesce(task, 0)::integer,
            coalesce(result, 0)::integer
       FROM overrides
      WHERE uuid = $1
        FOR UPDATE;"
}

pub(crate) fn override_affected_reports_sql() -> &'static str {
    "SELECT DISTINCT report::integer
       FROM results
      WHERE nvt = $1
        AND (($3 <> 0 AND id = $3)
             OR ($3 = 0 AND $2 <> 0 AND task = $2)
             OR ($3 = 0 AND $2 = 0))
      ORDER BY report::integer;"
}

pub(crate) fn override_trash_insert_sql() -> &'static str {
    "INSERT INTO overrides_trash
        (uuid, owner, nvt, creation_time, modification_time, text, hosts,
         port, severity, new_severity, task, result, end_time, result_nvt)
     SELECT uuid, owner, nvt, creation_time, modification_time, text, hosts,
            port, severity, new_severity, task, result, end_time, result_nvt
       FROM overrides
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn override_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'override'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn override_trash_tag_locations_to_trash_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1,
            resource = $1
      WHERE resource_type = 'override'
        AND resource = $2
        AND resource_location = 0;"
}

pub(crate) fn override_delete_live_sql() -> &'static str {
    "DELETE FROM overrides WHERE id = $1;"
}

pub(crate) fn override_clear_overridden_report_counts_sql() -> &'static str {
    "DELETE FROM report_counts
      WHERE override = 1
        AND report = ANY($1::integer[]);"
}
