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
    collections::{OVERRIDE_ASSET_DEFAULT_SORT, OVERRIDE_ASSET_SORT_FIELDS},
    errors::ApiError,
    override_payloads::{OverrideAssetItem, override_asset_from_row},
    override_query_sql::{override_asset_detail_sql, override_assets_sql},
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) async fn override_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OverrideAssetItem>>, ApiError> {
    let active_filter = query.active.clone().unwrap_or_default();
    let text_filter = query.text.clone().unwrap_or_default();
    let task_name_filter = query.task_name.clone().unwrap_or_default();
    let params = normalize_collection_query(query, OVERRIDE_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, OVERRIDE_ASSET_SORT_FIELDS)?;
    let sql = override_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &text_filter,
                &task_name_filter,
                &active_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "override asset list query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[
            &params.filter,
            &probe_page_size,
            &probe_offset,
            &text_filter,
            &task_name_filter,
            &active_filter,
        ],
        "override asset list",
    )
    .await?;
    let items = rows.iter().map(override_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn override_asset_detail(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    parse_uuid(&override_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_override_asset_detail(&client, &override_id).await?,
    ))
}

pub(crate) async fn load_override_asset_detail(
    client: &Client,
    override_id: &str,
) -> Result<OverrideAssetItem, ApiError> {
    let row = client
        .query_opt(override_asset_detail_sql(), &[&override_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "override asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(override_asset_from_row(&row))
}

pub(crate) async fn override_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    override_asset_detail(state, path).await
}
