// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use tokio_postgres::Client;

use crate::{
    app_state::AppState,
    collections::*,
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    report_evidence_payloads::*,
    scope_payloads::*,
};

pub(crate) async fn scope_reports(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScopeReportItem>>, ApiError> {
    let params = normalize_collection_query(query, SCOPE_REPORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_SORT_FIELDS)?;
    let sql = format!(
        "WITH filtered AS (\n\
           SELECT sr.id, sr.scope, sr.uuid, sr.scope_uuid, sr.scope_name, sr.protection_requirement,\n\
                  sr.source_report_count::bigint, sr.source_target_count::bigint,\n\
                  sr.member_host_count::bigint, sr.evidence_host_count::bigint,\n\
                  sr.missing_host_count::bigint, sr.result_count::bigint,\n\
                  sr.vulnerability_count::bigint, sr.max_severity::double precision,\n\
                  sr.latest_evidence_time::bigint, sr.excluded_candidate_host_count::bigint,\n\
                  sr.creation_time::bigint, sr.modification_time::bigint,\n\
                  coalesce(s.is_global, 0)::int AS is_global\n\
             FROM scope_reports sr\n\
             JOIN scopes s ON s.id = sr.scope\n\
            WHERE ($1 = '' OR lower(sr.uuid) = lower($1)\n\
                   OR lower(sr.scope_uuid) = lower($1)\n\
                   OR lower(sr.scope_name) LIKE '%' || lower($1) || '%')\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT f.id AS scope_report_id, lower(rh.host) AS host_key\n\
               FROM filtered f\n\
               JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE f.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY f.id, lower(rh.host)\n\
             UNION\n\
             SELECT f.id AS scope_report_id, lower(h.name) AS host_key\n\
               FROM filtered f\n\
               JOIN scope_hosts sh ON sh.scope = f.scope AND f.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY f.id, lower(h.name)\n\
         ),\n\
         ranked_results AS (\n\
             SELECT f.id AS scope_report_id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    row_number () OVER (\n\
                      PARTITION BY f.id, lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                                   coalesce(r.nvt, ''), coalesce(r.port, '')\n\
                      ORDER BY coalesce(r.severity, 0) DESC, coalesce(r.date, 0) DESC, r.id DESC\n\
                    ) AS rn\n\
               FROM filtered f\n\
               JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.scope_report_id = f.id\n\
                                      AND sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         severity_counts AS (\n\
             SELECT scope_report_id,\n\
                    count(*) FILTER (WHERE severity >= 7.0)::bigint AS severity_high,\n\
                    count(*) FILTER (WHERE severity >= 4.0 AND severity < 7.0)::bigint AS severity_medium,\n\
                    count(*) FILTER (WHERE severity > 0.0 AND severity < 4.0)::bigint AS severity_low,\n\
                    count(*) FILTER (WHERE severity = 0.0)::bigint AS severity_log,\n\
                    count(*) FILTER (WHERE severity = -1.0)::bigint AS severity_false_positive\n\
               FROM ranked_results\n\
              WHERE rn = 1\n\
              GROUP BY scope_report_id\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total,\n\
                f.uuid, f.scope_uuid, f.scope_name, f.protection_requirement,\n\
                f.source_report_count, f.source_target_count, f.member_host_count,\n\
                f.evidence_host_count, f.missing_host_count, f.result_count,\n\
                f.vulnerability_count, f.max_severity, f.latest_evidence_time,\n\
                f.excluded_candidate_host_count, f.creation_time, f.modification_time,\n\
                coalesce(sc.severity_high, 0)::bigint,\n\
                coalesce(sc.severity_medium, 0)::bigint,\n\
                coalesce(sc.severity_low, 0)::bigint,\n\
                coalesce(sc.severity_log, 0)::bigint,\n\
                coalesce(sc.severity_false_positive, 0)::bigint\n\
           FROM filtered f\n\
           LEFT JOIN severity_counts sc ON sc.scope_report_id = f.id\n\
          ORDER BY {sort_sql}, uuid DESC LIMIT $2 OFFSET $3;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report query failed");
            ApiError::Database
        })?;
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(scope_report_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scope_report_detail(
    State(state): State<AppState>,
    Path(scope_report_id): Path<String>,
) -> Result<Json<ScopeReportDetail>, ApiError> {
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            "WITH selected_scope_report AS (\n\
               SELECT sr.id, sr.scope, sr.uuid, sr.scope_uuid, sr.scope_name, sr.protection_requirement,\n\
                      sr.source_report_count::bigint, sr.source_target_count::bigint,\n\
                      sr.member_host_count::bigint, sr.evidence_host_count::bigint,\n\
                      sr.missing_host_count::bigint, sr.result_count::bigint,\n\
                      sr.vulnerability_count::bigint, sr.max_severity::double precision,\n\
                      sr.latest_evidence_time::bigint, sr.excluded_candidate_host_count::bigint,\n\
                      sr.creation_time::bigint, sr.modification_time::bigint,\n\
                      coalesce(s.is_global, 0)::int AS is_global\n\
                 FROM scope_reports sr\n\
                 JOIN scopes s ON s.id = sr.scope\n\
                WHERE lower(sr.uuid) = lower($1)\n\
             ),\n\
             selected_hosts AS (\n\
                 SELECT f.id AS scope_report_id, lower(rh.host) AS host_key\n\
                   FROM selected_scope_report f\n\
                   JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
                   JOIN report_hosts rh ON rh.report = srs.source_report\n\
                  WHERE f.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
                  GROUP BY f.id, lower(rh.host)\n\
                 UNION\n\
                 SELECT f.id AS scope_report_id, lower(h.name) AS host_key\n\
                   FROM selected_scope_report f\n\
                   JOIN scope_hosts sh ON sh.scope = f.scope AND f.is_global = 0\n\
                   JOIN hosts h ON h.id = sh.host\n\
                  WHERE coalesce(h.name, '') <> ''\n\
                  GROUP BY f.id, lower(h.name)\n\
             ),\n\
             ranked_results AS (\n\
                 SELECT f.id AS scope_report_id,\n\
                        lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                        coalesce(r.nvt, '') AS nvt_oid,\n\
                        coalesce(r.port, '') AS port,\n\
                        coalesce(r.severity, 0)::double precision AS severity,\n\
                        row_number () OVER (\n\
                          PARTITION BY f.id, lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                                       coalesce(r.nvt, ''), coalesce(r.port, '')\n\
                          ORDER BY coalesce(r.severity, 0) DESC, coalesce(r.date, 0) DESC, r.id DESC\n\
                        ) AS rn\n\
                   FROM selected_scope_report f\n\
                   JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
                   JOIN results r ON r.report = srs.source_report\n\
                   JOIN selected_hosts sh ON sh.scope_report_id = f.id\n\
                                          AND sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
                  WHERE coalesce(r.severity, 0) != -3.0\n\
                    AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
             ),\n\
             severity_counts AS (\n\
                 SELECT scope_report_id,\n\
                        count(*) FILTER (WHERE severity >= 7.0)::bigint AS severity_high,\n\
                        count(*) FILTER (WHERE severity >= 4.0 AND severity < 7.0)::bigint AS severity_medium,\n\
                        count(*) FILTER (WHERE severity > 0.0 AND severity < 4.0)::bigint AS severity_low,\n\
                        count(*) FILTER (WHERE severity = 0.0)::bigint AS severity_log,\n\
                        count(*) FILTER (WHERE severity = -1.0)::bigint AS severity_false_positive\n\
                   FROM ranked_results\n\
                  WHERE rn = 1\n\
                  GROUP BY scope_report_id\n\
             )\n\
             SELECT 1::bigint AS total,\n\
                    f.uuid, f.scope_uuid, f.scope_name, f.protection_requirement,\n\
                    f.source_report_count, f.source_target_count, f.member_host_count,\n\
                    f.evidence_host_count, f.missing_host_count, f.result_count,\n\
                    f.vulnerability_count, f.max_severity, f.latest_evidence_time,\n\
                    f.excluded_candidate_host_count, f.creation_time, f.modification_time,\n\
                    coalesce(sc.severity_high, 0)::bigint,\n\
                    coalesce(sc.severity_medium, 0)::bigint,\n\
                    coalesce(sc.severity_low, 0)::bigint,\n\
                    coalesce(sc.severity_log, 0)::bigint,\n\
                    coalesce(sc.severity_false_positive, 0)::bigint\n\
               FROM selected_scope_report f\n\
               LEFT JOIN severity_counts sc ON sc.scope_report_id = f.id;",
            &[&scope_report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let sources = client
        .query(
            "SELECT srs.id::bigint AS id,\n\
                    coalesce(srs.source_report_uuid, '') AS source_report_id,\n\
                    coalesce(srs.target_uuid, '') AS target_id,\n\
                    coalesce(srs.target_name, '') AS target_name,\n\
                    coalesce(srs.task_uuid, '') AS task_id,\n\
                    coalesce(srs.task_name, '') AS task_name,\n\
                    srs.scan_end::bigint AS scan_end\n\
               FROM scope_report_sources srs\n\
               JOIN scope_reports sr ON sr.id = srs.scope_report\n\
              WHERE lower(sr.uuid) = lower($1)\n\
              ORDER BY lower(coalesce(srs.target_name, '')), srs.target_uuid, srs.source_report_uuid;",
            &[&scope_report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report source query failed");
            ApiError::Database
        })?;

    Ok(Json(ScopeReportDetail {
        report: scope_report_from_row(&row),
        sources: sources.iter().map(scope_report_source_from_row).collect(),
    }))
}

pub(crate) async fn scope_report_hosts(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<HostItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_HOST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_HOST_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         member_hosts AS (\n\
             SELECT lower(h.name) AS host_key, min(h.name) AS host\n\
               FROM selected_scope_report sr\n\
               JOIN hosts h ON sr.is_global = 1\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key, min(h.name) AS host\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         evidence_hosts AS (\n\
             SELECT lower(rh.host) AS host_key, min(rh.host) AS host,\n\
                    count(DISTINCT srs.source_report)::bigint AS source_report_count,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
         ),\n\
         result_counts AS (\n\
             SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    count(DISTINCT (coalesce(r.nvt, ''), coalesce(r.port, '')))::bigint AS result_count\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
         ),\n\
         host_rows AS (\n\
             SELECT coalesce(m.host_key, e.host_key) AS host_key,\n\
                    coalesce(m.host, e.host) AS host,\n\
                    m.host_key IS NOT NULL AS is_member,\n\
                    e.host_key IS NOT NULL AS has_evidence,\n\
                    coalesce(e.source_report_count, 0)::bigint AS source_report_count,\n\
                    coalesce(e.source_report_ids, ARRAY[]::text[]) AS source_report_ids\n\
               FROM member_hosts m\n\
               FULL OUTER JOIN evidence_hosts e ON e.host_key = m.host_key\n\
         ),\n\
         rows AS (\n\
             SELECT hr.host,\n\
                    CASE\n\
                      WHEN sr.is_global = 1 THEN 'organization'\n\
                      WHEN hr.is_member THEN 'member'\n\
                      ELSE 'candidate'\n\
                    END AS scope_membership,\n\
                    hr.source_report_count,\n\
                    coalesce(rc.result_count, 0)::bigint AS result_count,\n\
                    coalesce(srm.vulnerability_count, 0)::bigint AS vulnerability_count,\n\
                    coalesce(nullif(srm.authentication_state, ''), 'unknown') AS authenticated_scan_state,\n\
                    hr.source_report_ids\n\
               FROM selected_scope_report sr\n\
               CROSS JOIN host_rows hr\n\
               LEFT JOIN result_counts rc ON rc.host_key = hr.host_key\n\
               LEFT JOIN scope_report_system_metrics srm\n\
                 ON srm.scope_report = sr.id AND lower(srm.host) = hr.host_key\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM rows\n\
              WHERE ($3 = '' OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(scope_membership) LIKE '%' || lower($3) || '%'\n\
                     OR lower(authenticated_scan_state) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, host ASC LIMIT $4 OFFSET $5;"
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
            tracing::warn!(%error, "scope report host query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(host_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scope_report_ports(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_PORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_PORT_SORT_FIELDS)?;
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
         port_rows AS (\n\
             SELECT coalesce(r.port, '') AS port,\n\
                    CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                         THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                         ELSE '' END AS protocol,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                AND coalesce(r.port, '') <> ''\n\
              GROUP BY coalesce(r.port, ''),\n\
                       CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                            THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                            ELSE '' END\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM port_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(protocol) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, port ASC LIMIT $4 OFFSET $5;"
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
            tracing::warn!(%error, "scope report port query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(port_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

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
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(application_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scope_report_operating_systems(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_OPERATING_SYSTEM_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_OPERATING_SYSTEM_SORT_FIELDS)?;
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
         os_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown') AS name,\n\
                    coalesce(os_cpe.value, '') AS cpe\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(rh.host)\n\
               LEFT JOIN report_host_details os_cpe\n\
                 ON os_cpe.report_host = rh.id AND os_cpe.name = 'best_os_cpe'\n\
               LEFT JOIN report_host_details os_txt\n\
                 ON os_txt.report_host = rh.id AND os_txt.name = 'best_os_txt'\n\
              WHERE coalesce(os_txt.value, os_cpe.value, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, srs.source_report_uuid,\n\
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
            tracing::warn!(%error, "scope report operating-system query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(operating_system_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scope_report_tls_certificates(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_TLS_CERTIFICATE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS)?;
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
         tls_rows AS (\n\
             SELECT c.uuid AS id,\n\
                    coalesce(c.sha256_fingerprint, '') AS fingerprint_sha256,\n\
                    coalesce(c.subject_dn, '') AS subject,\n\
                    coalesce(c.issuer_dn, '') AS issuer,\n\
                    coalesce(c.serial, '') AS serial,\n\
                    coalesce(c.activation_time, 0)::bigint AS not_before_unix,\n\
                    coalesce(c.expiration_time, 0)::bigint AS not_after_unix,\n\
                    count(DISTINCT lower(loc.host_ip))::bigint AS host_count,\n\
                    count(DISTINCT loc.port)::bigint AS port_count,\n\
                    count(DISTINCT src.uuid)::bigint AS result_count,\n\
                    array_remove(array_agg(DISTINCT origin.origin_id), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN tls_certificate_origins origin\n\
                 ON origin.origin_type = 'Report'\n\
                AND origin.origin_id = srs.source_report_uuid\n\
               JOIN tls_certificate_sources src ON src.origin = origin.id\n\
               JOIN tls_certificates c ON c.id = src.tls_certificate\n\
               JOIN tls_certificate_locations loc ON loc.id = src.location\n\
               JOIN selected_hosts sh ON sh.host_key = lower(loc.host_ip)\n\
              GROUP BY c.uuid, c.sha256_fingerprint, c.subject_dn, c.issuer_dn,\n\
                       c.serial, c.activation_time, c.expiration_time\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM tls_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(fingerprint_sha256) LIKE '%' || lower($3) || '%'\n\
                     OR lower(subject) LIKE '%' || lower($3) || '%'\n\
                     OR lower(issuer) LIKE '%' || lower($3) || '%'\n\
                     OR lower(serial) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $4 OFFSET $5;"
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
            tracing::warn!(%error, "scope report TLS certificate query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(tls_certificate_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scope_report_exists(
    client: &Client,
    scope_report_id: &str,
    scope_id: &str,
) -> Result<bool, ApiError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM scope_reports WHERE uuid = $1 AND scope_uuid = $2);",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(row.get::<_, bool>(0))
}
