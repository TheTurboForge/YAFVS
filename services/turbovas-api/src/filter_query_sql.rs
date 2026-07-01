// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn filter_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH filter_rows AS (
             SELECT f.uuid AS id,
                    coalesce(f.name, '') AS name,
                    coalesce(f.comment, '') AS comment,
                    coalesce(f.type, '') AS filter_type,
                    coalesce(f.term, '') AS term,
                    coalesce(f.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(f.modification_time, 0)::bigint AS modified_at_unix,
                    (
                      SELECT count(DISTINCT alert_id)::bigint
                        FROM (
                          SELECT a.id AS alert_id
                            FROM alerts a
                           WHERE a.filter = f.id
                          UNION
                          SELECT acd.alert AS alert_id
                            FROM alert_condition_data acd
                           WHERE acd.name = 'filter_id'
                             AND acd.data = f.uuid
                        ) alert_refs
                    ) AS alert_count
               FROM filters f
         ),
         filtered AS (
             SELECT * FROM filter_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(filter_type) LIKE '%' || lower($1) || '%'
                     OR lower(term) LIKE '%' || lower($1) || '%')
                AND ($2 = '' OR lower(filter_type) = lower($2))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $3 OFFSET $4;"#,
    )
}

pub(crate) fn filter_asset_detail_sql() -> &'static str {
    r#"SELECT f.id AS internal_id,
              f.uuid AS id,
              coalesce(f.name, '') AS name,
              coalesce(f.comment, '') AS comment,
              coalesce(f.type, '') AS filter_type,
              coalesce(f.term, '') AS term,
              coalesce(f.creation_time, 0)::bigint AS created_at_unix,
              coalesce(f.modification_time, 0)::bigint AS modified_at_unix,
              (
                SELECT count(DISTINCT alert_id)::bigint
                  FROM (
                    SELECT a.id AS alert_id
                      FROM alerts a
                     WHERE a.filter = f.id
                    UNION
                    SELECT acd.alert AS alert_id
                      FROM alert_condition_data acd
                     WHERE acd.name = 'filter_id'
                       AND acd.data = f.uuid
                  ) alert_refs
              ) AS alert_count
         FROM filters f
        WHERE f.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn filter_alert_backlinks_sql() -> &'static str {
    r#"SELECT DISTINCT a.uuid AS id,
              coalesce(a.name, '') AS name
         FROM alerts a
        WHERE a.filter = $1
        UNION
       SELECT DISTINCT a.uuid AS id,
              coalesce(a.name, '') AS name
         FROM alert_condition_data acd
         JOIN alerts a ON a.id = acd.alert
        WHERE acd.name = 'filter_id'
          AND acd.data = $2
        ORDER BY name ASC, id ASC;"#
}
