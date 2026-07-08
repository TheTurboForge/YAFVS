// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scanner_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH scanner_rows AS (
             SELECT s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.host, '') AS host,
                    coalesce(s.port, 0)::bigint AS port,
                    coalesce(s.type, 0)::bigint AS scanner_type,
                    NULL::text AS ca_pub,
                    nullif(c.uuid, '') AS credential_id,
                    nullif(c.name, '') AS credential_name,
                    nullif(s.relay_host, '') AS relay_host,
                    coalesce(s.relay_port, 0)::bigint AS relay_port,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix
               FROM scanners s
               LEFT JOIN credentials c ON c.id = s.credential
         ),
         filtered AS (
             SELECT * FROM scanner_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(host) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(credential_name, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(relay_host, '')) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn scanner_asset_detail_sql() -> &'static str {
    r#"SELECT s.uuid AS id,
              coalesce(s.name, '') AS name,
              coalesce(s.comment, '') AS comment,
              coalesce(s.host, '') AS host,
              coalesce(s.port, 0)::bigint AS port,
              coalesce(s.type, 0)::bigint AS scanner_type,
              nullif(s.ca_pub, '') AS ca_pub,
              nullif(c.uuid, '') AS credential_id,
              nullif(c.name, '') AS credential_name,
              nullif(s.relay_host, '') AS relay_host,
              coalesce(s.relay_port, 0)::bigint AS relay_port,
              coalesce(s.creation_time, 0)::bigint AS created_at_unix,
              coalesce(s.modification_time, 0)::bigint AS modified_at_unix
         FROM scanners s
    LEFT JOIN credentials c ON c.id = s.credential
        WHERE s.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn scanner_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM scanners s
         JOIN tasks t ON t.scanner = s.id
        WHERE lower(s.uuid) = lower($1)
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}
