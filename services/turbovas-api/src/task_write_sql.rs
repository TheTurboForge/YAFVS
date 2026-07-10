// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn task_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn task_assignable_schedule_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(next_time_ical(icalendar, m_now()::bigint,
                                    timezone), 0)::integer
       FROM schedules
      WHERE uuid = $1;"
}

pub(crate) fn task_assignable_alert_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM alerts
      WHERE uuid = $1;"
}

pub(crate) fn task_assignable_target_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM targets
      WHERE uuid = $1;"
}

pub(crate) fn task_assignable_config_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(predefined, 0)::integer
       FROM configs
      WHERE uuid = $1
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn task_assignable_scanner_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(type, 0)::integer
       FROM scanners
      WHERE uuid = $1;"
}

pub(crate) fn task_create_metadata_sql() -> &'static str {
    "INSERT INTO tasks
        (uuid, owner, name, hidden, comment, run_status, config, target,
         schedule, schedule_next_time, schedule_periods, scanner, config_location,
         target_location, schedule_location, scanner_location, alterable,
         creation_time, modification_time, usage_type)
     VALUES (make_uuid(), $1, $2, 0, coalesce($3, ''), 1, $4, $5,
             $7, $8, 0, $6, 0, 0, 0, 0, 1, m_now(), m_now(), 'scan')
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn task_insert_preference_sql() -> &'static str {
    "INSERT INTO task_preferences (task, name, value)
     VALUES ($1, $2, $3);"
}

pub(crate) fn task_insert_alert_sql() -> &'static str {
    "INSERT INTO task_alerts (task, alert, alert_location)
     VALUES ($1, $2, 0);"
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
