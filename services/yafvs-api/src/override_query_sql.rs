// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn override_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH override_rows AS (
             SELECT o.uuid AS id,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(o.nvt, '') AS nvt_id,
                    CASE
                      WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                      ELSE coalesce(n.name, o.nvt, '')
                    END AS nvt_name,
                    CASE
                      WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                      ELSE 'nvt'
                    END AS nvt_type,
                    coalesce(o.text, '') AS text,
                    coalesce(o.hosts, '') AS hosts,
                    coalesce(o.port, '') AS port,
                    o.severity::double precision AS severity,
                    coalesce(o.severity, -9999)::double precision AS severity_sort,
                    o.new_severity::double precision AS new_severity,
                    coalesce(o.new_severity, -9999)::double precision AS new_severity_sort,
                    coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(o.end_time, 0)::bigint AS end_time_unix,
                    CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int,
                    t.uuid AS task_id,
                    coalesce(t.name, '') AS task_name,
                    r.uuid AS result_id,
                    coalesce(r.uuid, '') AS result_name,
                    CASE
                      WHEN ((coalesce(o.task, 0) <> 0 AND t.uuid IS NULL)
                            OR (coalesce(o.result, 0) <> 0 AND r.uuid IS NULL))
                      THEN 1 ELSE 0
                    END AS orphan_int
               FROM overrides o
          LEFT JOIN users u ON u.id = o.owner
          LEFT JOIN nvts n ON n.oid = o.nvt
          LEFT JOIN tasks t ON t.id = o.task
          LEFT JOIN results r ON r.id = o.result
         ),
         filtered AS (
             SELECT * FROM override_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_id) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_name) LIKE '%' || lower($1) || '%'
                     OR lower(text) LIKE '%' || lower($1) || '%'
                     OR lower(hosts) LIKE '%' || lower($1) || '%'
                     OR lower(port) LIKE '%' || lower($1) || '%'
                     OR lower(task_name) LIKE '%' || lower($1) || '%')
                AND ($4 = '' OR lower(text) LIKE '%' || lower($4) || '%')
                AND ($5 = '' OR lower(task_name) LIKE '%' || lower($5) || '%')
                AND ($6 = ''
                     OR ($6 = '1' AND active_int = 1)
                     OR ($6 = '0' AND active_int = 0))
                AND ($7 = '' OR lower(coalesce(task_id, '')) = lower($7))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, text ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn override_asset_detail_sql() -> &'static str {
    r#"SELECT o.uuid AS id,
              coalesce(u.name, '') AS owner_name,
              coalesce(o.nvt, '') AS nvt_id,
              CASE
                WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                ELSE coalesce(n.name, o.nvt, '')
              END AS nvt_name,
              CASE
                WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                ELSE 'nvt'
              END AS nvt_type,
              coalesce(o.text, '') AS text,
              coalesce(o.hosts, '') AS hosts,
              coalesce(o.port, '') AS port,
              o.severity::double precision AS severity,
              o.new_severity::double precision AS new_severity,
              coalesce(o.creation_time, 0)::bigint AS created_at_unix,
              coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
              coalesce(o.end_time, 0)::bigint AS end_time_unix,
              CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int,
              t.uuid AS task_id,
              coalesce(t.name, '') AS task_name,
              r.uuid AS result_id,
              coalesce(r.uuid, '') AS result_name,
              CASE
                WHEN ((coalesce(o.task, 0) <> 0 AND t.uuid IS NULL)
                      OR (coalesce(o.result, 0) <> 0 AND r.uuid IS NULL))
                THEN 1 ELSE 0
              END AS orphan_int
         FROM overrides o
    LEFT JOIN users u ON u.id = o.owner
    LEFT JOIN nvts n ON n.oid = o.nvt
    LEFT JOIN tasks t ON t.id = o.task
    LEFT JOIN results r ON r.id = o.result
        WHERE o.uuid = $1
        LIMIT 1;"#
}
