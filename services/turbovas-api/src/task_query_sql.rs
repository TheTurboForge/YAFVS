// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn task_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH report_rollup AS (
             SELECT r.task,
                    count(DISTINCT r.id)::bigint AS report_count_total,
                    count(DISTINCT r.id) FILTER (WHERE run_status_name(coalesce(r.scan_run_status, 0)) = 'Done')::bigint AS report_count_finished,
                    coalesce(max(res.severity) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity
               FROM reports r
               LEFT JOIN results res ON res.report = r.id
              GROUP BY r.task
         ),
         report_rows AS (
             SELECT r.task,
                    r.id AS report_pk,
                    r.uuid,
                    coalesce(r.creation_time, 0)::bigint AS timestamp,
                    coalesce(r.start_time, 0)::bigint AS scan_start,
                    coalesce(r.end_time, 0)::bigint AS scan_end,
                    coalesce(max(res.severity) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS severity,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 9.0)::bigint AS critical_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 7.0 AND coalesce(res.severity, 0) < 9.0)::bigint AS high_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 4.0 AND coalesce(res.severity, 0) < 7.0)::bigint AS medium_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) > 0 AND coalesce(res.severity, 0) < 4.0)::bigint AS low_count,
                    run_status_name(coalesce(r.scan_run_status, 0)) AS status,
                    row_number() OVER (PARTITION BY r.task ORDER BY coalesce(nullif(r.end_time, 0), nullif(r.start_time, 0), nullif(r.creation_time, 0), 0) DESC, r.id DESC) AS latest_rank,
                    CASE WHEN run_status_name(coalesce(r.scan_run_status, 0)) = 'Done' THEN 1 ELSE 0 END AS is_finished
               FROM reports r
               LEFT JOIN results res ON res.report = r.id
              GROUP BY r.task, r.id, r.uuid, r.creation_time, r.start_time, r.end_time, r.scan_run_status
         ),
         finished_report_rows AS (
             SELECT *, row_number() OVER (PARTITION BY task ORDER BY coalesce(nullif(scan_end, 0), nullif(scan_start, 0), nullif(timestamp, 0), 0) DESC, report_pk DESC) AS finished_rank
               FROM report_rows
              WHERE is_finished = 1
         ),
         latest_report AS (
             SELECT * FROM report_rows WHERE latest_rank = 1
         ),
         latest_finished_report AS (
             SELECT * FROM finished_report_rows WHERE finished_rank = 1
         ),
         second_latest_finished_report AS (
             SELECT * FROM finished_report_rows WHERE finished_rank = 2
         ),
         base AS (
             SELECT task.id AS task_pk,
                    task.uuid,
                    task.name,
                    coalesce(task.comment, '') AS comment,
                    run_status_name(coalesce(task.run_status, 0)) AS status,
                    CASE WHEN run_status_name(coalesce(task.run_status, 0)) = 'Done' THEN 100::bigint
                         WHEN latest_report.report_pk IS NOT NULL THEN coalesce(report_progress(latest_report.report_pk), 0)::bigint
                         ELSE 0::bigint END AS progress,
                    CASE
                      WHEN coalesce(report_rollup.report_count_finished, 0) <= 1 THEN ''
                      WHEN run_status_name(coalesce(task.run_status, 0)) = 'Running' OR target.id IS NULL THEN ''
                      WHEN latest_finished_report.severity > second_latest_finished_report.severity THEN 'up'
                      WHEN second_latest_finished_report.severity > latest_finished_report.severity THEN 'down'
                      WHEN (CASE WHEN latest_finished_report.critical_count > 0 THEN 5
                                 WHEN latest_finished_report.high_count > 0 THEN 4
                                 WHEN latest_finished_report.medium_count > 0 THEN 3
                                 WHEN latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END)
                         > (CASE WHEN second_latest_finished_report.critical_count > 0 THEN 5
                                 WHEN second_latest_finished_report.high_count > 0 THEN 4
                                 WHEN second_latest_finished_report.medium_count > 0 THEN 3
                                 WHEN second_latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END) THEN 'up'
                      WHEN (CASE WHEN second_latest_finished_report.critical_count > 0 THEN 5
                                 WHEN second_latest_finished_report.high_count > 0 THEN 4
                                 WHEN second_latest_finished_report.medium_count > 0 THEN 3
                                 WHEN second_latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END)
                         > (CASE WHEN latest_finished_report.critical_count > 0 THEN 5
                                 WHEN latest_finished_report.high_count > 0 THEN 4
                                 WHEN latest_finished_report.medium_count > 0 THEN 3
                                 WHEN latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END) THEN 'down'
                      WHEN latest_finished_report.critical_count > 0 THEN
                        CASE WHEN latest_finished_report.critical_count > second_latest_finished_report.critical_count THEN 'more'
                             WHEN latest_finished_report.critical_count < second_latest_finished_report.critical_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.high_count > 0 THEN
                        CASE WHEN latest_finished_report.high_count > second_latest_finished_report.high_count THEN 'more'
                             WHEN latest_finished_report.high_count < second_latest_finished_report.high_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.medium_count > 0 THEN
                        CASE WHEN latest_finished_report.medium_count > second_latest_finished_report.medium_count THEN 'more'
                             WHEN latest_finished_report.medium_count < second_latest_finished_report.medium_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.low_count > 0 THEN
                        CASE WHEN latest_finished_report.low_count > second_latest_finished_report.low_count THEN 'more'
                             WHEN latest_finished_report.low_count < second_latest_finished_report.low_count THEN 'less'
                             ELSE 'same' END
                      ELSE 'same'
                    END AS trend,
                    coalesce(task.usage_type, 'scan') AS usage_type,
                    target.uuid AS target_id,
                    target.name AS target_name,
                    config.uuid AS config_id,
                    config.name AS config_name,
                    scanner.uuid AS scanner_id,
                    scanner.name AS scanner_name,
                    scanner.type AS scanner_type,
                    schedule.uuid AS schedule_id,
                    schedule.name AS schedule_name,
                    coalesce(task.start_time, 0)::bigint AS start_time,
                    coalesce(task.end_time, 0)::bigint AS end_time,
                    coalesce(task.schedule_next_time, 0)::bigint AS schedule_next_time,
                    task.schedule_periods::bigint AS schedule_periods,
                    CASE WHEN task.alterable IS NULL THEN NULL
                         ELSE coalesce(task.alterable, 0) <> 0 END AS alterable,
                    coalesce(report_rollup.report_count_total, 0)::bigint AS report_count_total,
                    coalesce(report_rollup.report_count_finished, 0)::bigint AS report_count_finished,
                    latest_report.uuid AS current_report_id,
                    latest_report.timestamp AS current_report_timestamp,
                    latest_report.scan_start AS current_report_scan_start,
                    latest_report.scan_end AS current_report_scan_end,
                    latest_report.severity AS current_report_severity,
                    latest_finished_report.uuid AS last_report_id,
                    latest_finished_report.timestamp AS last_report_timestamp,
                    latest_finished_report.scan_start AS last_report_scan_start,
                    latest_finished_report.scan_end AS last_report_scan_end,
                    latest_finished_report.severity AS last_report_severity,
                    coalesce(report_rollup.max_severity, 0)::double precision AS max_severity,
                    coalesce(task.creation_time, 0)::bigint AS creation_time,
                    coalesce(task.modification_time, 0)::bigint AS modification_time
               FROM tasks task
               LEFT JOIN targets target ON target.id = task.target
               LEFT JOIN configs config ON config.id = task.config
               LEFT JOIN scanners scanner ON scanner.id = task.scanner
               LEFT JOIN schedules schedule ON schedule.id = task.schedule
               LEFT JOIN report_rollup ON report_rollup.task = task.id
               LEFT JOIN latest_report ON latest_report.task = task.id
               LEFT JOIN latest_finished_report ON latest_finished_report.task = task.id
               LEFT JOIN second_latest_finished_report ON second_latest_finished_report.task = task.id
              WHERE coalesce(task.hidden, 0) = 0
                AND coalesce(task.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total, *
           FROM filtered
          ORDER BY {sort_sql}, name ASC {limit_clause};"#
    )
}
