// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    collections::{REPORT_RAW_RESULT_DEFAULT_SORT, REPORT_RAW_RESULT_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_helpers::raw_report_exists,
    report_raw_result_query_sql::report_raw_results_sql,
};

#[derive(Debug, Serialize)]
pub(crate) struct RawResultEvidenceItem {
    id: String,
    source_report_id: String,
    task_id: Option<String>,
    owner_id: Option<String>,
    host: Option<String>,
    hostname: Option<String>,
    port: Option<String>,
    nvt_oid: Option<String>,
    result_type: Option<String>,
    description: Option<String>,
    scan_nvt_version: Option<String>,
    severity: Option<f64>,
    qod: Option<i64>,
    qod_type: Option<String>,
    created_at: Option<String>,
    path: Option<String>,
    hash_value: Option<String>,
}

fn raw_result_evidence_from_row(row: &Row) -> RawResultEvidenceItem {
    RawResultEvidenceItem {
        id: row.get("id"),
        source_report_id: row.get("source_report_id"),
        task_id: row.get("task_id"),
        owner_id: row.get("owner_id"),
        host: row.get("host"),
        hostname: row.get("hostname"),
        port: row.get("port"),
        nvt_oid: row.get("nvt_oid"),
        result_type: row.get("result_type"),
        description: row.get("description"),
        scan_nvt_version: row.get("scan_nvt_version"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        qod_type: row.get("qod_type"),
        created_at: row
            .get::<_, Option<i64>>("created_at_unix")
            .and_then(unix_ts_to_rfc3339),
        path: row.get("path"),
        hash_value: row.get("hash_value"),
    }
}

pub(crate) async fn report_raw_results(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<RawResultEvidenceItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_RAW_RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_RAW_RESULT_SORT_FIELDS)?;
    let sql = report_raw_results_sql(&sort_sql);
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
            tracing::warn!(%error, "raw report lossless result query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&report_id, &params.filter, &probe_page_size, &probe_offset],
        "raw report lossless result list",
    )
    .await?;
    let items = rows.iter().map(raw_result_evidence_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
