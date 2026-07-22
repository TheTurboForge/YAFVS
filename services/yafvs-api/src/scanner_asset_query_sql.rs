// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
              WHERE {}
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
        scanner_collection_predicate_sql(
            "scanner_rows.id",
            "scanner_rows.name",
            "scanner_rows.comment",
            "scanner_rows.host",
            "scanner_rows.credential_name",
            "scanner_rows.relay_host",
            "$1",
        ),
    )
}

/// Shared with the typed scanner tag selector. Search remains literal data
/// across UUID, name, comment, host, credential name, and relay host.
pub(crate) fn scanner_collection_predicate_sql(
    id_expression: &str,
    name_expression: &str,
    comment_expression: &str,
    host_expression: &str,
    credential_name_expression: &str,
    relay_host_expression: &str,
    search_parameter: &str,
) -> String {
    format!(
        "({search_parameter} = ''\n             OR strpos(lower({id_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({name_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({comment_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({host_expression}), lower({search_parameter})) > 0\n             OR strpos(lower(coalesce({credential_name_expression}, '')), lower({search_parameter})) > 0\n             OR strpos(lower(coalesce({relay_host_expression}, '')), lower({search_parameter})) > 0)"
    )
}

pub(crate) fn tag_scanner_selection_sql() -> String {
    format!(
        "SELECT s.id::integer, s.uuid::text, s.owner::integer\n           FROM scanners s\n      LEFT JOIN credentials c ON c.id = s.credential\n          WHERE {}\n          ORDER BY s.id ASC\n          LIMIT $2\n          FOR UPDATE OF s;",
        scanner_collection_predicate_sql(
            "s.uuid",
            "coalesce(s.name, '')",
            "coalesce(s.comment, '')",
            "coalesce(s.host, '')",
            "c.name",
            "coalesce(s.relay_host, '')",
            "$1",
        )
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
