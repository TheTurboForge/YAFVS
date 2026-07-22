// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn schedule_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH schedule_rows AS (
             SELECT s.id AS internal_id,
                    s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.icalendar, '') AS icalendar,
                    coalesce(s.timezone, 'UTC') AS timezone,
                    coalesce(s.first_time, 0)::bigint AS first_run_unix,
                    coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                    coalesce(s.period, 0)::bigint AS period_seconds,
                    coalesce(s.duration, 0)::bigint AS duration_seconds,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM tasks t
                       WHERE t.schedule = s.id
                         AND t.hidden = 0
                    ), 0)::bigint AS task_count
               FROM schedules s
         ),
         filtered AS (
             SELECT * FROM schedule_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(timezone) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn schedule_asset_detail_sql() -> &'static str {
    r#"SELECT s.id AS internal_id,
              s.uuid AS id,
              coalesce(s.name, '') AS name,
              coalesce(s.comment, '') AS comment,
              coalesce(s.icalendar, '') AS icalendar,
              coalesce(s.timezone, 'UTC') AS timezone,
              coalesce(s.first_time, 0)::bigint AS first_run_unix,
              coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
              coalesce(s.period, 0)::bigint AS period_seconds,
              coalesce(s.duration, 0)::bigint AS duration_seconds,
              coalesce(s.creation_time, 0)::bigint AS created_at_unix,
              coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
              coalesce((
                SELECT count(*)::bigint
                  FROM tasks t
                 WHERE t.schedule = s.id
                   AND t.hidden = 0
              ), 0)::bigint AS task_count
         FROM schedules s
        WHERE s.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn schedule_tasks_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM tasks t
        WHERE t.schedule = $1
          AND t.hidden = 0
        ORDER BY name ASC, id ASC;"#
}
