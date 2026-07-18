// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn operating_system_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH latest_best_os AS (
             SELECT DISTINCT ON (hd.host)
                    hd.host, hd.value AS cpe
               FROM host_details hd
              WHERE hd.name = 'best_os_cpe'
              ORDER BY hd.host, hd.id DESC
         ),
         latest_host_severity AS (
             SELECT DISTINCT ON (hms.host)
                    hms.host,
                    round(CAST(hms.severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities hms
              ORDER BY hms.host, hms.creation_time DESC
         ),
         os_rows AS (
             SELECT oss.uuid AS id,
                    oss.name AS name,
                    coalesce(cpe_title(oss.name), '') AS title,
                    (
                      SELECT lhs.severity
                        FROM host_oss ho_latest
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_latest.host
                       WHERE ho_latest.os = oss.id
                       ORDER BY ho_latest.creation_time DESC
                       LIMIT 1
                    ) AS latest_severity,
                    (
                      SELECT max(lhs.severity)
                        FROM host_oss ho_highest
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_highest.host
                       WHERE ho_highest.os = oss.id
                    ) AS highest_severity,
                    (
                      SELECT round(CAST(avg(lhs.severity) AS numeric), 2)::double precision
                        FROM host_oss ho_average
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_average.host
                       WHERE ho_average.os = oss.id
                    ) AS average_severity,
                    (
                      SELECT count(DISTINCT lbo.host)::bigint
                        FROM latest_best_os lbo
                       WHERE lbo.cpe = oss.name
                    ) AS hosts,
                    (
                      SELECT count(DISTINCT ho_all.host)::bigint
                        FROM host_oss ho_all
                       WHERE ho_all.os = oss.id
                    ) AS all_hosts,
                    coalesce(oss.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(oss.modification_time, 0)::bigint AS modified_at_unix
               FROM oss
         ),
         filtered AS (
             SELECT * FROM os_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn operating_system_asset_detail_sql() -> &'static str {
    r#"WITH latest_best_os AS (
         SELECT DISTINCT ON (hd.host)
                hd.host, hd.value AS cpe
           FROM host_details hd
          WHERE hd.name = 'best_os_cpe'
          ORDER BY hd.host, hd.id DESC
     ),
     latest_host_severity AS (
         SELECT DISTINCT ON (hms.host)
                hms.host,
                round(CAST(hms.severity AS numeric), 1)::double precision AS severity
           FROM host_max_severities hms
          ORDER BY hms.host, hms.creation_time DESC
     )
     SELECT oss.uuid AS id,
            oss.name AS name,
            coalesce(cpe_title(oss.name), '') AS title,
            (
              SELECT lhs.severity
                FROM host_oss ho_latest
                LEFT JOIN latest_host_severity lhs ON lhs.host = ho_latest.host
               WHERE ho_latest.os = oss.id
               ORDER BY ho_latest.creation_time DESC
               LIMIT 1
            ) AS latest_severity,
            (
              SELECT max(lhs.severity)
                FROM host_oss ho_highest
                LEFT JOIN latest_host_severity lhs ON lhs.host = ho_highest.host
               WHERE ho_highest.os = oss.id
            ) AS highest_severity,
            (
              SELECT round(CAST(avg(lhs.severity) AS numeric), 2)::double precision
                FROM host_oss ho_average
                LEFT JOIN latest_host_severity lhs ON lhs.host = ho_average.host
               WHERE ho_average.os = oss.id
            ) AS average_severity,
            (
              SELECT count(DISTINCT lbo.host)::bigint
                FROM latest_best_os lbo
               WHERE lbo.cpe = oss.name
            ) AS hosts,
            (
              SELECT count(DISTINCT ho_all.host)::bigint
                FROM host_oss ho_all
               WHERE ho_all.os = oss.id
            ) AS all_hosts,
            coalesce(oss.creation_time, 0)::bigint AS created_at_unix,
            coalesce(oss.modification_time, 0)::bigint AS modified_at_unix
       FROM oss
      WHERE oss.uuid = $1
      LIMIT 1;"#
}
