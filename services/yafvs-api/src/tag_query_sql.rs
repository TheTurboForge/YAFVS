// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn tag_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH tag_rows AS (
             SELECT t.uuid AS id,
                    coalesce(t.name, '') AS name,
                    coalesce(t.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    (t.owner IS NOT NULL) AS human_owned,
                    coalesce(t.resource_type, '') AS resource_type,
                    coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
                    coalesce(t.active, 0)::integer AS active_int,
                    coalesce(t.value, '') AS value,
                    coalesce(t.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(t.modification_time, 0)::bigint AS modified_at_unix
               FROM tags t
          LEFT JOIN users u ON u.id = t.owner
         ),
         filtered AS (
             SELECT * FROM tag_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(resource_type) LIKE '%' || lower($1) || '%'
                     OR lower(value) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND active_int = 1)
                     OR ($4 = '0' AND active_int = 0))
                AND ($5 = '' OR lower(resource_type) = lower($5))
                AND ($6 = '' OR lower(value) LIKE '%' || lower($6) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn tag_asset_detail_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              (t.owner IS NOT NULL) AS human_owned,
              coalesce(t.resource_type, '') AS resource_type,
              coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
              coalesce(t.active, 0)::integer AS active_int,
              coalesce(t.value, '') AS value,
              coalesce(t.creation_time, 0)::bigint AS created_at_unix,
              coalesce(t.modification_time, 0)::bigint AS modified_at_unix
         FROM tags t
    LEFT JOIN users u ON u.id = t.owner
        WHERE t.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn tag_resource_lookup_sql() -> &'static str {
    r#"SELECT id, uuid, coalesce(resource_type, '') AS resource_type
         FROM tags
        WHERE uuid = $1
        LIMIT 1;"#
}
