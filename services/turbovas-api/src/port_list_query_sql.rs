// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn port_list_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH port_list_rows AS (
             SELECT pl.id AS internal_id,
                    pl.uuid AS id,
                    coalesce(pl.name, '') AS name,
                    coalesce(pl.comment, '') AS comment,
                    coalesce(pl.predefined, 0)::integer AS predefined_int,
                    0::integer AS deprecated_int,
                    coalesce(pl.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(pl.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                    ), 0)::bigint AS port_count_all,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                         AND pr.type = 0
                    ), 0)::bigint AS port_count_tcp,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                         AND pr.type = 1
                    ), 0)::bigint AS port_count_udp
               FROM port_lists pl
         ),
         filtered AS (
             SELECT * FROM port_list_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn port_list_asset_detail_sql() -> &'static str {
    r#"SELECT pl.id AS internal_id,
              pl.uuid AS id,
              coalesce(pl.name, '') AS name,
              coalesce(pl.comment, '') AS comment,
              coalesce(pl.predefined, 0)::integer AS predefined_int,
              0::integer AS deprecated_int,
              coalesce(pl.creation_time, 0)::bigint AS created_at_unix,
              coalesce(pl.modification_time, 0)::bigint AS modified_at_unix,
              coalesce((
                SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                  FROM port_ranges pr
                 WHERE pr.port_list = pl.id
              ), 0)::bigint AS port_count_all,
              coalesce((
                SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                  FROM port_ranges pr
                 WHERE pr.port_list = pl.id
                   AND pr.type = 0
              ), 0)::bigint AS port_count_tcp,
              coalesce((
                SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                  FROM port_ranges pr
                 WHERE pr.port_list = pl.id
                   AND pr.type = 1
              ), 0)::bigint AS port_count_udp
         FROM port_lists pl
        WHERE pl.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn port_list_ranges_sql() -> &'static str {
    r#"SELECT pr.uuid AS id,
              CASE WHEN pr.type = 1 THEN 'udp' ELSE 'tcp' END AS protocol,
              coalesce(pr.start, 0)::bigint AS start,
              coalesce(pr."end", pr.start, 0)::bigint AS "end",
              coalesce(pr.comment, '') AS comment
         FROM port_ranges pr
        WHERE pr.port_list = $1
        ORDER BY pr.type ASC, pr.start ASC, pr."end" ASC, pr.uuid ASC;"#
}

pub(crate) fn port_list_targets_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name
         FROM targets t
        WHERE t.port_list = $1
        ORDER BY name ASC, id ASC;"#
}
