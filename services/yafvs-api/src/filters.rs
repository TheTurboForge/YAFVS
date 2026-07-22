// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Client;

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{FILTER_ASSET_DEFAULT_SORT, FILTER_ASSET_SORT_FIELDS},
    errors::ApiError,
    filter_payloads::{FilterAssetItem, filter_alert_from_row, filter_asset_from_row},
    filter_query_sql::{filter_alert_backlinks_sql, filter_asset_detail_sql, filter_assets_sql},
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) async fn filter_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<FilterAssetItem>>, ApiError> {
    let filter_type = query
        .filter_type
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let params = normalize_collection_query(query, FILTER_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, FILTER_ASSET_SORT_FIELDS)?;
    let sql = filter_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &filter_type,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter asset list query failed");
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
            &filter_type,
            &probe_page_size,
            &probe_offset,
        ],
        "filter asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| filter_asset_from_row(row, Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn filter_asset_detail(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_filter_asset_detail(&client, &filter_id).await?))
}

pub(crate) async fn export_filter_metadata(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_filter_asset_detail(&client, &filter_id).await?))
}

pub(crate) async fn load_filter_asset_detail(
    client: &Client,
    filter_id: &str,
) -> Result<FilterAssetItem, ApiError> {
    parse_uuid(&filter_id)?;
    let row = client
        .query_opt(filter_asset_detail_sql(), &[&filter_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let alerts = client
        .query(
            filter_alert_backlinks_sql(),
            &[&row.get::<_, i32>("internal_id"), &filter_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(filter_alert_from_row)
        .collect();
    Ok(filter_asset_from_row(&row, alerts))
}
