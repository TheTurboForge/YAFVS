// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCOPE_REPORT_ERROR_DEFAULT_SORT, SCOPE_REPORT_ERROR_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{ErrorMessageItem, error_message_from_row},
    scope_report_lookup::scope_report_exists,
};

pub(crate) async fn scope_report_errors(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ErrorMessageItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_ERROR_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_ERROR_SORT_FIELDS)?;
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
             SELECT lower(srh.host_name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_hosts srh ON srh.scope_report = sr.id AND sr.is_global = 0\n\
              WHERE coalesce(srh.host_name, '') <> ''\n\
              GROUP BY lower(srh.host_name)\n\
         ),\n\
         error_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    coalesce(r.port, '') AS port,\n\
                    r.nvt AS nvt_oid,\n\
                    coalesce(r.description, '') AS description,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE (r.type = 'Error Message' OR coalesce(r.severity, 0) = -3)\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM error_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($3) || '%'\n\
                     OR lower(description) LIKE '%' || lower($3) || '%')\n\
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
            tracing::warn!(%error, "scope report error-message query failed");
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
        "scope report error-message list",
    )
    .await?;
    let items = rows.iter().map(error_message_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
