// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn task_start_state_sql() -> &'static str {
    "SELECT tasks.id::integer,
            tasks.owner::integer,
            coalesce(tasks.run_status, 1)::integer,
            targets.id::integer,
            (nullif(btrim(coalesce(targets.hosts, '')), '') IS NOT NULL)::boolean,
            configs.id::integer,
            scanners.id::integer,
            scanners.type::integer
       FROM tasks
       LEFT JOIN targets
              ON targets.id = tasks.target
             AND coalesce(tasks.target_location, 0) = 0
       LEFT JOIN configs
              ON configs.id = tasks.config
             AND coalesce(tasks.config_location, 0) = 0
             AND coalesce(configs.usage_type, 'scan') = 'scan'
       LEFT JOIN scanners
              ON scanners.id = tasks.scanner
             AND coalesce(tasks.scanner_location, 0) = 0
      WHERE tasks.uuid = $1
        AND coalesce(tasks.hidden, 0) = 0
        AND coalesce(tasks.usage_type, 'scan') = 'scan'
      FOR UPDATE OF tasks;"
}

pub(crate) fn task_start_scan_queue_exists_sql() -> &'static str {
    "SELECT EXISTS (
         SELECT 1
           FROM scan_queue
           JOIN reports ON reports.id = scan_queue.report
          WHERE reports.task = $1
     );"
}

pub(crate) fn task_start_insert_report_sql() -> &'static str {
    "INSERT INTO reports
        (uuid, owner, task, creation_time, modification_time, comment,
         scan_run_status, slave_progress, flags)
     VALUES (make_uuid(), $1, $2, m_now(), m_now(), '', 3, 0, 0)
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn task_start_insert_scan_queue_sql() -> &'static str {
    "WITH queue_time AS (SELECT clock_timestamp() AS value)
     INSERT INTO scan_queue
        (report, queued_time_secs, queued_time_nano, handler_pid, start_from)
     SELECT $1,
            floor(EXTRACT(EPOCH FROM value))::integer,
            floor((EXTRACT(EPOCH FROM value) - floor(EXTRACT(EPOCH FROM value))) * 1000000000)::integer,
            0,
            0
       FROM queue_time;"
}

pub(crate) fn task_start_mark_requested_sql() -> &'static str {
    "UPDATE tasks
        SET run_status = 3
      WHERE id = $1;"
}
