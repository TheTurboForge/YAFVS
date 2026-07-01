// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scan_config_asset_list_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH scan_config_rows AS (
             SELECT c.id AS internal_id,
                    c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.family_count, 0)::bigint AS family_count,
                    coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                    coalesce(c.families_growing, 0)::integer AS families_growing,
                    coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                    coalesce(c.predefined, 0)::integer AS predefined_int,
                    coalesce(c.usage_type, 'scan') AS usage_type,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM tasks t
                        WHERE t.config = c.id
                          AND t.config_location = 0
                          AND t.hidden = 0
                    ) THEN 1 ELSE 0 END AS in_use_int,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM deprecated_feed_data d
                        WHERE d.type = 'config' AND d.uuid = c.uuid
                    ) THEN 1 ELSE 0 END AS deprecated_int,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM configs c
          LEFT JOIN users u ON u.id = c.owner
              WHERE coalesce(c.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM scan_config_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND predefined_int = 1)
                     OR ($4 = '0' AND predefined_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn scan_config_asset_detail_sql() -> &'static str {
    r#"SELECT c.id AS internal_id,
              c.uuid AS id,
              coalesce(c.name, '') AS name,
              coalesce(c.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              coalesce(c.family_count, 0)::bigint AS family_count,
              coalesce(c.nvt_count, 0)::bigint AS nvt_count,
              coalesce(c.families_growing, 0)::integer AS families_growing,
              coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
              coalesce(c.predefined, 0)::integer AS predefined_int,
              coalesce(c.usage_type, 'scan') AS usage_type,
              CASE WHEN EXISTS (
                 SELECT 1 FROM tasks t
                  WHERE t.config = c.id
                    AND t.config_location = 0
                    AND t.hidden = 0
              ) THEN 1 ELSE 0 END AS in_use_int,
              CASE WHEN EXISTS (
                 SELECT 1 FROM deprecated_feed_data d
                  WHERE d.type = 'config' AND d.uuid = c.uuid
              ) THEN 1 ELSE 0 END AS deprecated_int,
              coalesce(c.creation_time, 0)::bigint AS created_at_unix,
              coalesce(c.modification_time, 0)::bigint AS modified_at_unix
         FROM configs c
    LEFT JOIN users u ON u.id = c.owner
        WHERE c.uuid = $1
          AND coalesce(c.usage_type, 'scan') = 'scan'
        LIMIT 1;"#
}

pub(crate) fn scan_config_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM configs c
         JOIN tasks t ON t.config = c.id
        WHERE lower(c.uuid) = lower($1)
          AND t.config_location = 0
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}
