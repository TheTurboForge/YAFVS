// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{REPORT_OPERATING_SYSTEM_DEFAULT_SORT, REPORT_OPERATING_SYSTEM_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{OperatingSystemItem, operating_system_from_row},
    report_helpers::raw_report_exists,
    report_operating_system_query_sql::report_operating_systems_sql,
};

pub(crate) async fn report_operating_systems(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_OPERATING_SYSTEM_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_OPERATING_SYSTEM_SORT_FIELDS)?;
    let sql = report_operating_systems_sql(&sort_sql);
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
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&report_id, &params.filter, &probe_page_size, &probe_offset],
        "raw report operating-system list",
    )
    .await?;
    let items = rows.iter().map(operating_system_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
