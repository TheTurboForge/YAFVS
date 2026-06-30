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
