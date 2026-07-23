// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn credential_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH credential_rows AS (
             SELECT c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    u.uuid AS owner_id,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.type, '') AS credential_type,
                    (coalesce(c.type, '') = 'up'
                     AND (SELECT count(*)
                            FROM credentials_data cd
                           WHERE cd.credential = c.id
                             AND cd.type = 'username') = 1
                     AND EXISTS (
                         SELECT 1
                           FROM credentials_data cd
                          WHERE cd.credential = c.id
                            AND cd.type = 'username'
                            AND cd.value <> ''
                            AND strpos(cd.value, '@') = 0
                            AND strpos(cd.value, ':') = 0
                     )) AS smb_compatible,
                    coalesce(c.allow_insecure, 0)::integer AS allow_insecure_int,
                    coalesce((SELECT count(DISTINCT tld.target)::bigint
                                FROM targets_login_data tld
                               WHERE tld.credential = c.id), 0)::bigint AS target_count,
                    coalesce((SELECT count(DISTINCT s.id)::bigint
                                FROM scanners s
                               WHERE s.credential = c.id), 0)::bigint AS scanner_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM credentials c
          LEFT JOIN users u ON u.id = c.owner
         ),
         filtered AS (
             SELECT * FROM credential_rows
              WHERE {}
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
        credential_collection_predicate_sql(
            "credential_rows.id",
            "credential_rows.name",
            "credential_rows.comment",
            "credential_rows.owner_name",
            "credential_rows.credential_type",
            "$1",
            "$4",
        ),
    )
}

pub(crate) fn credential_certificate_sql() -> &'static str {
    r#"WITH matching AS (
           SELECT cd.value
             FROM credentials c
             JOIN credentials_data cd ON cd.credential = c.id
            WHERE c.uuid = $1
              AND c.type = 'cc'
              AND cd.type = 'certificate'
       )
       SELECT value AS certificate
         FROM matching
        WHERE octet_length(value) BETWEEN 1 AND $2
          AND (SELECT count(*) FROM matching) = 1;"#
}

/// Shared with typed credential tag selection. Search remains literal data
/// across UUID, name, comment, owner name, and credential type.
pub(crate) fn credential_collection_predicate_sql(
    id_expression: &str,
    name_expression: &str,
    comment_expression: &str,
    owner_name_expression: &str,
    credential_type_expression: &str,
    search_parameter: &str,
    credential_type_parameter: &str,
) -> String {
    format!(
        "({search_parameter} = ''\n             OR strpos(lower({id_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({name_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({comment_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({owner_name_expression}), lower({search_parameter})) > 0\n             OR strpos(lower({credential_type_expression}), lower({search_parameter})) > 0)\n        AND ({credential_type_parameter} = '' OR {credential_type_expression} = {credential_type_parameter})"
    )
}

pub(crate) fn tag_credential_selection_sql() -> String {
    format!(
        "SELECT c.id::integer, c.uuid::text, c.owner::integer\n           FROM credentials c\n      LEFT JOIN users u ON u.id = c.owner\n          WHERE {}\n          ORDER BY c.id ASC\n          LIMIT $3\n          FOR UPDATE OF c;",
        credential_collection_predicate_sql(
            "c.uuid",
            "coalesce(c.name, '')",
            "coalesce(c.comment, '')",
            "coalesce(u.name, '')",
            "coalesce(c.type, '')",
            "$1",
            "$2",
        )
    )
}

pub(crate) fn credential_asset_detail_sql() -> &'static str {
    r#"SELECT c.uuid AS id,
              coalesce(c.name, '') AS name,
              coalesce(c.comment, '') AS comment,
              u.uuid AS owner_id,
              coalesce(u.name, '') AS owner_name,
              coalesce(c.type, '') AS credential_type,
              (coalesce(c.type, '') = 'up'
               AND (SELECT count(*)
                      FROM credentials_data cd
                     WHERE cd.credential = c.id
                       AND cd.type = 'username') = 1
               AND EXISTS (
                   SELECT 1
                     FROM credentials_data cd
                    WHERE cd.credential = c.id
                      AND cd.type = 'username'
                      AND cd.value <> ''
                      AND strpos(cd.value, '@') = 0
                      AND strpos(cd.value, ':') = 0
               )) AS smb_compatible,
              coalesce(c.allow_insecure, 0)::integer AS allow_insecure_int,
              coalesce((SELECT count(DISTINCT tld.target)::bigint
                          FROM targets_login_data tld
                         WHERE tld.credential = c.id), 0)::bigint AS target_count,
              coalesce((SELECT count(DISTINCT s.id)::bigint
                          FROM scanners s
                         WHERE s.credential = c.id), 0)::bigint AS scanner_count,
              coalesce(c.creation_time, 0)::bigint AS created_at_unix,
              coalesce(c.modification_time, 0)::bigint AS modified_at_unix
         FROM credentials c
    LEFT JOIN users u ON u.id = c.owner
        WHERE c.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn credential_target_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(tld.type, '') AS use_type,
              NULLIF(tld.port, 0)::bigint AS port
         FROM credentials c
         JOIN targets_login_data tld ON tld.credential = c.id
         JOIN targets t ON t.id = tld.target
        WHERE c.uuid = $1
        ORDER BY name ASC, id ASC, use_type ASC;"#
}

pub(crate) fn credential_scanner_references_sql() -> &'static str {
    r#"SELECT s.uuid AS id,
              coalesce(s.name, '') AS name,
              'scanner'::text AS use_type,
              NULL::bigint AS port
         FROM credentials c
         JOIN scanners s ON s.credential = c.id
        WHERE c.uuid = $1
        ORDER BY name ASC, id ASC;"#
}
