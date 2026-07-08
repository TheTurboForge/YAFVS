// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn task_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn task_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(run_status, 1)::integer
       FROM tasks
      WHERE uuid = $1
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn task_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE name = $1
        AND id != $2
        AND owner = $3
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn task_update_metadata_sql() -> &'static str {
    "UPDATE tasks
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan'
      RETURNING uuid::text;"
}

pub(crate) fn task_trash_result_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1
      WHERE resource_type = 'result'
        AND resource IN (SELECT id FROM results WHERE task = $1);"
}

pub(crate) fn task_trash_result_trash_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1
      WHERE resource_type = 'result'
        AND resource IN (SELECT id FROM results WHERE task = $1);"
}

pub(crate) fn task_trash_report_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1
      WHERE resource_type = 'report'
        AND resource IN (SELECT id FROM reports WHERE task = $1);"
}

pub(crate) fn task_trash_report_trash_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1
      WHERE resource_type = 'report'
        AND resource IN (SELECT id FROM reports WHERE task = $1);"
}

pub(crate) fn task_trash_task_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources
        SET resource_location = 1
      WHERE resource_type = 'task'
        AND resource = $1;"
}

pub(crate) fn task_trash_task_trash_tag_locations_sql() -> &'static str {
    "UPDATE tag_resources_trash
        SET resource_location = 1
      WHERE resource_type = 'task'
        AND resource = $1;"
}

pub(crate) fn task_trash_results_insert_sql() -> &'static str {
    "INSERT INTO results_trash
        (uuid, task, host, port, nvt, result_nvt, type, description, report,
         nvt_version, severity, qod, qod_type, owner, date, hostname, path)
     SELECT uuid, task, host, port, nvt, result_nvt, type, description, report,
            nvt_version, severity, qod, qod_type, owner, date, hostname, path
       FROM results
      WHERE report IN (SELECT id FROM reports WHERE task = $1);"
}

pub(crate) fn task_delete_live_results_sql() -> &'static str {
    "DELETE FROM results
      WHERE report IN (SELECT id FROM reports WHERE task = $1);"
}

pub(crate) fn task_delete_report_counts_sql() -> &'static str {
    "DELETE FROM report_counts
      WHERE report IN (SELECT id FROM reports WHERE task = $1);"
}

pub(crate) fn task_mark_hidden_trash_sql() -> &'static str {
    "UPDATE tasks
        SET hidden = 2,
            modification_time = m_now()
      WHERE id = $1
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan'
      RETURNING uuid::text;"
}
