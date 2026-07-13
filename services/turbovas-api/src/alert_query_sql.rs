// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn alert_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH alert_rows AS (
             SELECT a.uuid AS id,
                    coalesce(a.name, '') AS name,
                    coalesce(a.comment, '') AS comment,
                    u.uuid AS owner_id,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(a.active, 0)::integer AS active_int,
                    CASE coalesce(a.event, 0)::integer
                      WHEN 1 THEN 'Task run status changed'
                      WHEN 2 THEN 'New SecInfo arrived'
                      WHEN 3 THEN 'Updated SecInfo arrived'
                      ELSE 'Internal Error'
                    END AS event_type,
                    CASE coalesce(a.condition, 0)::integer
                      WHEN 1 THEN 'Always'
                      WHEN 2 THEN 'Severity at least'
                      WHEN 3 THEN 'Severity changed'
                      WHEN 4 THEN 'Filter count at least'
                      WHEN 5 THEN 'Filter count changed'
                      ELSE 'Internal Error'
                    END AS condition_type,
                    CASE coalesce(a.method, 0)::integer
                      WHEN 1 THEN 'Email'
                      WHEN 2 THEN 'HTTP Get'
                      WHEN 4 THEN 'Start Task'
                      WHEN 5 THEN 'Syslog'
                      WHEN 8 THEN 'SCP'
                      WHEN 9 THEN 'SNMP'
                      WHEN 10 THEN 'SMB'
                      WHEN 11 THEN 'TippingPoint SMS'
                      WHEN 12 THEN 'Alemba vFire'
                      ELSE 'Internal Error'
                    END AS method_type,
                    f.uuid AS filter_id,
                    coalesce(f.name, '') AS filter_name,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM task_alerts ta
                        JOIN tasks t ON t.id = ta.task
                       WHERE ta.alert = a.id
                         AND coalesce(t.hidden, 0) = 0
                    ), 0)::bigint AS task_count,
                    coalesce(a.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(a.modification_time, 0)::bigint AS modified_at_unix
               FROM alerts a
          LEFT JOIN users u ON u.id = a.owner
          LEFT JOIN filters f ON f.id = a.filter
         ),
         filtered AS (
             SELECT * FROM alert_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(event_type) LIKE '%' || lower($1) || '%'
                     OR lower(condition_type) LIKE '%' || lower($1) || '%'
                     OR lower(method_type) LIKE '%' || lower($1) || '%'
                     OR lower(filter_name) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn alert_asset_detail_sql() -> &'static str {
    r#"SELECT a.uuid AS id,
              coalesce(a.name, '') AS name,
              coalesce(a.comment, '') AS comment,
              u.uuid AS owner_id,
              coalesce(u.name, '') AS owner_name,
              coalesce(a.active, 0)::integer AS active_int,
              CASE coalesce(a.event, 0)::integer
                WHEN 1 THEN 'Task run status changed'
                WHEN 2 THEN 'New SecInfo arrived'
                WHEN 3 THEN 'Updated SecInfo arrived'
                ELSE 'Internal Error'
              END AS event_type,
              CASE coalesce(a.condition, 0)::integer
                WHEN 1 THEN 'Always'
                WHEN 2 THEN 'Severity at least'
                WHEN 3 THEN 'Severity changed'
                WHEN 4 THEN 'Filter count at least'
                WHEN 5 THEN 'Filter count changed'
                ELSE 'Internal Error'
              END AS condition_type,
              CASE coalesce(a.method, 0)::integer
                WHEN 1 THEN 'Email'
                WHEN 2 THEN 'HTTP Get'
                WHEN 4 THEN 'Start Task'
                WHEN 5 THEN 'Syslog'
                WHEN 8 THEN 'SCP'
                WHEN 9 THEN 'SNMP'
                WHEN 10 THEN 'SMB'
                WHEN 11 THEN 'TippingPoint SMS'
                WHEN 12 THEN 'Alemba vFire'
                ELSE 'Internal Error'
              END AS method_type,
              f.uuid AS filter_id,
              coalesce(f.name, '') AS filter_name,
              coalesce((
                SELECT count(*)::bigint
                  FROM task_alerts ta
                  JOIN tasks t ON t.id = ta.task
                 WHERE ta.alert = a.id
                   AND coalesce(t.hidden, 0) = 0
              ), 0)::bigint AS task_count,
              coalesce(a.creation_time, 0)::bigint AS created_at_unix,
              coalesce(a.modification_time, 0)::bigint AS modified_at_unix
         FROM alerts a
    LEFT JOIN users u ON u.id = a.owner
    LEFT JOIN filters f ON f.id = a.filter
        WHERE a.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn alert_asset_tasks_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name
         FROM alerts a
         JOIN task_alerts ta ON ta.alert = a.id
         JOIN tasks t ON t.id = ta.task
        WHERE a.uuid = $1
          AND coalesce(t.hidden, 0) = 0
        ORDER BY name ASC, id ASC;"#
}
