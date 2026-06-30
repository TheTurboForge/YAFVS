// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{
        REPORT_APPLICATION_DEFAULT_SORT, REPORT_APPLICATION_SORT_FIELDS, REPORT_HOST_DEFAULT_SORT,
        REPORT_HOST_SORT_FIELDS, REPORT_OPERATING_SYSTEM_DEFAULT_SORT,
        REPORT_OPERATING_SYSTEM_SORT_FIELDS,
    },
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    report_evidence_payloads::{
        ApplicationItem, OperatingSystemItem, ReportHostItem, application_from_row,
        operating_system_from_row, report_host_from_row,
    },
    report_helpers::raw_report_exists,
};

pub(crate) async fn report_applications(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ApplicationItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_APPLICATION_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_APPLICATION_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         app_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    sr.uuid AS source_report_id,\n\
                    rh.id AS report_host,\n\
                    rhd.source_name AS detection_oid,\n\
                    rhd.value AS name\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
               JOIN report_host_details rhd ON rhd.report_host = rh.id\n\
              WHERE rhd.name = 'App'\n\
                AND coalesce(rhd.value, '') <> ''\n\
                AND coalesce(rhd.source_name, '') <> ''\n\
                AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, sr.uuid,\n\
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
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               JOIN report_hosts rh\n\
                 ON rh.report = r.report\n\
                AND lower(rh.host) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
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
              WHERE ($2 = ''\n\
                     OR lower(name) LIKE '%' || lower($2) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report application query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(application_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_operating_systems(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_OPERATING_SYSTEM_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_OPERATING_SYSTEM_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         os_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    sr.uuid AS source_report_id,\n\
                    coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown') AS name,\n\
                    coalesce(os_cpe.value, '') AS cpe\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
               LEFT JOIN report_host_details os_cpe\n\
                 ON os_cpe.report_host = rh.id AND os_cpe.name = 'best_os_cpe'\n\
               LEFT JOIN report_host_details os_txt\n\
                 ON os_txt.report_host = rh.id AND os_txt.name = 'best_os_txt'\n\
              WHERE coalesce(os_txt.value, os_cpe.value, '') <> ''\n\
                AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, sr.uuid,\n\
                       coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown'),\n\
                       coalesce(os_cpe.value, '')\n\
         ),\n\
         operating_system_rows AS (\n\
             SELECT oi.name,\n\
                    oi.cpe,\n\
                    count(DISTINCT oi.host_key)::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(r.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT oi.source_report_id), NULL) AS source_report_ids\n\
               FROM os_instances oi\n\
               LEFT JOIN results r\n\
                 ON r.report = oi.source_report\n\
                AND lower(coalesce(nullif(r.host, ''), r.hostname, '')) = oi.host_key\n\
                AND coalesce(r.severity, 0) != -3.0\n\
              GROUP BY oi.name, oi.cpe\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM operating_system_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(name) LIKE '%' || lower($2) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report operating-system query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(operating_system_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_hosts(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportHostItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_HOST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_HOST_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH selected_report AS (
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)
         ),
         host_base AS (
             SELECT rh.id AS report_host_id,
                    lower(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host_key,
                    coalesce(nullif(rh.host, ''), rh.hostname, '') AS host,
                    nullif(rh.hostname, '') AS hostname,
                    coalesce(rh.start_time, 0)::bigint AS start_time_unix,
                    coalesce(rh.end_time, 0)::bigint AS end_time_unix,
                    sr.uuid AS source_report_id
               FROM selected_report sr
               JOIN report_hosts rh ON rh.report = sr.id
              WHERE coalesce(nullif(rh.host, ''), rh.hostname, '') <> ''
         ),
         detail_rows AS (
             SELECT hb.report_host_id,
                    nullif(max(rhd.value) FILTER (WHERE rhd.name = 'best_os_cpe'), '') AS best_os_cpe,
                    nullif(max(rhd.value) FILTER (WHERE rhd.name = 'best_os_txt'), '') AS best_os_txt,
                    count(*) FILTER (WHERE rhd.name = 'App')::bigint AS applications_count,
                    max(CASE WHEN rhd.name = 'distance' AND rhd.value ~ '^[0-9]+$' THEN rhd.value::bigint ELSE NULL END) AS distance,
                    bool_or((lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                            AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%success%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%succeeded%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%logged in%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%valid credential%')) AS auth_success,
                    bool_or((lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                            AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%fail%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%denied%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%invalid%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%refused%')) AS auth_failure,
                    bool_or(lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                            OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                            OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%') AS has_credential_path
               FROM host_base hb
               LEFT JOIN report_host_details rhd ON rhd.report_host = hb.report_host_id
              GROUP BY hb.report_host_id
         ),
         result_counts AS (
             SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,
                    count(*)::bigint AS result_count,
                    count(DISTINCT nullif(r.nvt, '')) FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,
                    count(DISTINCT nullif(r.port, ''))::bigint AS ports_count,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 9.0)::bigint AS severity_critical,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 7.0 AND coalesce(r.severity, 0) < 9.0)::bigint AS severity_high,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 4.0 AND coalesce(r.severity, 0) < 7.0)::bigint AS severity_medium,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) > 0.0 AND coalesce(r.severity, 0) < 4.0)::bigint AS severity_low,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) = 0.0)::bigint AS severity_log,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) = -1.0)::bigint AS severity_false_positive,
                    coalesce(max(r.severity) FILTER (WHERE coalesce(r.severity, 0) > 0), 0)::double precision AS max_severity
               FROM selected_report sr
               JOIN results r ON r.report = sr.id
              WHERE coalesce(r.severity, 0) != -3.0
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
              GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))
         ),
         rows AS (
             SELECT hb.host, hb.hostname, dr.best_os_cpe, dr.best_os_txt,
                    coalesce(rc.ports_count, 0)::bigint AS ports_count,
                    coalesce(dr.applications_count, 0)::bigint AS applications_count,
                    dr.distance,
                    CASE WHEN coalesce(dr.auth_success, false) THEN 'authenticated'
                         WHEN coalesce(dr.auth_failure, false) THEN 'authentication_failed'
                         WHEN coalesce(dr.has_credential_path, false) THEN 'unknown'
                         ELSE 'no_credential_path' END AS authentication_state,
                    hb.start_time_unix, hb.end_time_unix,
                    coalesce(rc.result_count, 0)::bigint AS result_count,
                    coalesce(rc.vulnerability_count, 0)::bigint AS vulnerability_count,
                    coalesce(rc.severity_critical, 0)::bigint AS severity_critical,
                    coalesce(rc.severity_high, 0)::bigint AS severity_high,
                    coalesce(rc.severity_medium, 0)::bigint AS severity_medium,
                    coalesce(rc.severity_low, 0)::bigint AS severity_low,
                    coalesce(rc.severity_log, 0)::bigint AS severity_log,
                    coalesce(rc.severity_false_positive, 0)::bigint AS severity_false_positive,
                    coalesce(rc.max_severity, 0)::double precision AS max_severity,
                    hb.source_report_id
               FROM host_base hb
               LEFT JOIN detail_rows dr ON dr.report_host_id = hb.report_host_id
               LEFT JOIN result_counts rc ON rc.host_key = hb.host_key
         ),
         filtered AS (
             SELECT * FROM rows
              WHERE ($2 = ''
                     OR lower(host) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(best_os_cpe, '')) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(best_os_txt, '')) LIKE '%' || lower($2) || '%'
                     OR lower(authentication_state) LIKE '%' || lower($2) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, host ASC LIMIT $3 OFFSET $4;"#
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report host query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(report_host_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
