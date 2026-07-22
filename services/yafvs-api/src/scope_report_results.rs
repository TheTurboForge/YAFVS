// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use deadpool_postgres::Client;

use crate::{
    app_state::AppState,
    collections::{REPORT_RESULT_DEFAULT_SORT, REPORT_RESULT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    result_payload_rows::{ResultItem, result_from_row},
    scope_report_lookup::{scope_report_exists, scope_report_scope_uuid},
};

pub(crate) async fn scope_report_results(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    scope_report_results_for_ids(&client, scope_id, scope_report_id, query).await
}

pub(crate) async fn scope_report_results_by_report(
    State(state): State<AppState>,
    Path(scope_report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let scope_id = scope_report_scope_uuid(&client, &scope_report_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    scope_report_results_for_ids(&client, scope_id, scope_report_id, query).await
}

async fn scope_report_results_for_ids(
    client: &Client,
    scope_id: String,
    scope_report_id: String,
    query: CollectionQuery,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_RESULT_SORT_FIELDS)?;
    let sql = scope_report_results_sql(&sort_sql);
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
            tracing::warn!(%error, "scope report result query failed");
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
        "scope report result list",
    )
    .await?;
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) fn scope_report_results_sql(sort_sql: &str) -> String {
    format!(
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
             SELECT lower(srh.host_name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_hosts srh ON srh.scope_report = sr.id AND sr.is_global = 0\n\
              WHERE coalesce(srh.host_name, '') <> ''\n\
              GROUP BY lower(srh.host_name)\n\
         ),\n\
         ranked AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    nullif(r.hostname, '') AS hostname,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
                    nullif(n.family, '') AS nvt_family,\n\
                    n.cve AS cve_text,\n\
                    n.epss_score::double precision AS epss_score,\n\
                    n.epss_percentile::double precision AS epss_percentile,\n\
                    n.epss_cve AS epss_cve,\n\
                    n.epss_severity::double precision AS epss_severity,\n\
                    n.max_epss_score::double precision AS max_epss_score,\n\
                    n.max_epss_percentile::double precision AS max_epss_percentile,\n\
                    n.max_epss_cve AS max_epss_cve,\n\
                    n.max_epss_severity::double precision AS max_epss_severity,\n\
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(r.qod, 0)::bigint AS qod,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    row_number () OVER (\n\
                      PARTITION BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                                   coalesce(r.nvt, ''), coalesce(r.port, '')\n\
                      ORDER BY coalesce(r.severity, 0) DESC, coalesce(r.date, 0) DESC, r.id DESC\n\
                    ) AS rn\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
               LEFT JOIN nvts n ON n.oid = r.nvt\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         result_rows AS (\n\
             SELECT id, host, hostname, port, nvt_oid, name, nvt_family, cve_text, epss_score, epss_percentile, epss_cve, epss_severity, max_epss_score, max_epss_percentile, max_epss_cve, max_epss_severity, description_excerpt, severity, qod, created_at_unix, source_report_id\n\
               FROM ranked WHERE rn = 1\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM result_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($3) || '%'\n\
                     OR lower(name) LIKE '%' || lower($3) || '%')\n\
         ),\n\
         page_rows AS (\n\
             SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $4 OFFSET $5\n\
         ),\n\
         page_with_refs AS (\n\
             SELECT p.*,\n\
                    CASE\n\
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0\n\
                      THEN refs.cves\n\
                      WHEN coalesce(p.cve_text, '') <> ''\n\
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')\n\
                      ELSE ARRAY[]::text[]\n\
                    END AS cves,\n\
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,\n\
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs\n\
               FROM page_rows p\n\
               LEFT JOIN LATERAL (\n\
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs\n\
                     FROM vt_refs vr\n\
                    WHERE vr.vt_oid = p.nvt_oid\n\
               ) refs ON true\n\
         )\n\
         SELECT * FROM page_with_refs;"
    )
}
