// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub(crate) fn report_format_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH report_format_rows AS (
             SELECT rf.id AS internal_id,
                    rf.uuid AS id,
                    coalesce(rf.name, '') AS name,
                    coalesce(rf.summary, '') AS summary,
                    coalesce(rf.description, '') AS description,
                    coalesce(rf.extension, '') AS extension,
                    coalesce(rf.content_type, '') AS content_type,
                    coalesce(rf.report_type, '') AS report_type,
                    coalesce(rf.trust, 3)::integer AS trust_int,
                    coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                    coalesce(rf.flags & 1, 0)::integer AS active_int,
                    coalesce(rf.predefined, 0)::integer AS predefined_int,
                    (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                    (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                    coalesce((SELECT count(DISTINCT a.id)::bigint
                                FROM alerts a
                                JOIN alert_method_data amd ON amd.alert = a.id
                               WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                    coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
               FROM report_formats rf
         ),
         filtered AS (
             SELECT * FROM report_format_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR lower(extension) LIKE '%' || lower($1) || '%'
                     OR lower(content_type) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND predefined_int = 1)
                     OR ($4 = '0' AND predefined_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn report_format_asset_detail_sql() -> &'static str {
    r#"SELECT rf.id AS internal_id,
              rf.uuid AS id,
              coalesce(rf.name, '') AS name,
              coalesce(rf.summary, '') AS summary,
              coalesce(rf.description, '') AS description,
              coalesce(rf.extension, '') AS extension,
              coalesce(rf.content_type, '') AS content_type,
              coalesce(rf.report_type, '') AS report_type,
              coalesce(rf.trust, 3)::integer AS trust_int,
              coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
              coalesce(rf.flags & 1, 0)::integer AS active_int,
              coalesce(rf.predefined, 0)::integer AS predefined_int,
              (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
              (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
              coalesce((SELECT count(DISTINCT a.id)::bigint
                          FROM alerts a
                          JOIN alert_method_data amd ON amd.alert = a.id
                         WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
              coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
              coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
         FROM report_formats rf
        WHERE rf.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn report_format_alert_backlinks_sql() -> &'static str {
    r#"SELECT a.uuid AS id,
              coalesce(a.name, '') AS name
         FROM alerts a
         JOIN alert_method_data amd ON amd.alert = a.id
        WHERE amd.data = $1
        ORDER BY name ASC, id ASC;"#
}

pub(crate) fn report_format_params_sql() -> &'static str {
    r#"SELECT rfp.id AS internal_id,
              coalesce(rfp.name, '') AS name,
              coalesce(rfp.type, 100)::integer AS type_int,
              coalesce(rfp.value, '') AS value,
              coalesce(rfp.fallback, '') AS fallback,
              rfp.type_min AS min,
              rfp.type_max AS max
         FROM report_format_params rfp
        WHERE rfp.report_format = $1
        ORDER BY name ASC, internal_id ASC;"#
}

pub(crate) fn report_format_param_options_sql() -> &'static str {
    r#"SELECT coalesce(value, '') AS value
         FROM report_format_param_options
        WHERE report_format_param = $1
        ORDER BY value ASC;"#
}
