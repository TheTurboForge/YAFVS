// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCOPE_REPORT_APPLICATION_DEFAULT_SORT, SCOPE_REPORT_APPLICATION_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{ApplicationItem, application_from_row},
    scope_report_lookup::scope_report_exists,
};

pub(crate) async fn scope_report_applications(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ApplicationItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_APPLICATION_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_APPLICATION_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         app_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    rh.id AS report_host,\n\
                    rhd.source_name AS detection_oid,\n\
                    rhd.value AS name\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(rh.host)\n\
               JOIN report_host_details rhd ON rhd.report_host = rh.id\n\
              WHERE rhd.name = 'App'\n\
                AND coalesce(rhd.value, '') <> ''\n\
                AND coalesce(rhd.source_name, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, srs.source_report_uuid,\n\
                       rh.id, rhd.source_name, rhd.value\n\
         ),\n\
         result_detection AS (\n\
             SELECT r.uuid AS result_id,\n\
                    r.report AS source_report,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(nullif(by_location.value, ''), by_generic.value, '') AS detection_oid,\n\
                    coalesce(nullif(r.path, ''),\n\
                             CASE WHEN coalesce(r.port, '') <> ''\n\
                                    AND coalesce(r.port, '') NOT LIKE 'general/%'\n\
                                  THEN r.port ELSE NULL END,\n\
                             detected_at.value, '') AS detection_location\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN report_hosts rh\n\
                 ON rh.report = r.report\n\
                AND lower(rh.host) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
               JOIN selected_hosts sh ON sh.host_key = lower(rh.host)\n\
               LEFT JOIN report_host_details detected_at\n\
                 ON detected_at.report_host = rh.id\n\
                AND detected_at.source_name = r.nvt\n\
                AND detected_at.name = 'detected_at'\n\
               LEFT JOIN report_host_details by_location\n\
                 ON by_location.report_host = rh.id\n\
                AND by_location.source_name = r.nvt\n\
                AND by_location.name = 'detected_by@' || coalesce(nullif(r.path, ''),\n\
                     CASE WHEN coalesce(r.port, '') <> ''\n\
                            AND coalesce(r.port, '') NOT LIKE 'general/%'\n\
                          THEN r.port ELSE NULL END,\n\
                     detected_at.value, '')\n\
               LEFT JOIN report_host_details by_generic\n\
                 ON by_generic.report_host = rh.id\n\
                AND by_generic.source_name = r.nvt\n\
                AND by_generic.name = 'detected_by'\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         app_result_matches AS (\n\
             SELECT ai.name,\n\
                    ai.host_key,\n\
                    ai.source_report_id,\n\
                    rd.result_id,\n\
                    rd.nvt_oid,\n\
                    rd.severity\n\
               FROM app_instances ai\n\
               LEFT JOIN result_detection rd\n\
                 ON rd.source_report = ai.source_report\n\
                AND rd.host_key = ai.host_key\n\
                AND rd.detection_oid = ai.detection_oid\n\
               LEFT JOIN report_host_details app_location\n\
                 ON app_location.report_host = ai.report_host\n\
                AND app_location.source_name = ai.detection_oid\n\
                AND app_location.name = ai.name\n\
                AND app_location.value = rd.detection_location\n\
              WHERE rd.result_id IS NULL OR app_location.id IS NOT NULL\n\
         ),\n\
         application_rows AS (\n\
             SELECT ai.name,\n\
                    ''::text AS version,\n\
                    CASE WHEN lower(ai.name) LIKE 'cpe:%' THEN ai.name ELSE '' END AS cpe,\n\
                    count(DISTINCT ai.host_key)::bigint AS host_count,\n\
                    count(DISTINCT arm.result_id)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(arm.nvt_oid, ''), arm.result_id))\n\
                      FILTER (WHERE coalesce(arm.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(arm.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT ai.source_report_id), NULL) AS source_report_ids\n\
               FROM app_instances ai\n\
               LEFT JOIN app_result_matches arm\n\
                 ON arm.name = ai.name\n\
                AND arm.host_key = ai.host_key\n\
                AND arm.source_report_id = ai.source_report_id\n\
              GROUP BY ai.name\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM application_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(name) LIKE '%' || lower($3) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report application query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[
            &scope_report_id,
            &scope_id,
            &params.filter,
            &probe_page_size,
            &probe_offset,
        ],
        "scope report application list",
    )
    .await?;
    let items = rows.iter().map(application_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
