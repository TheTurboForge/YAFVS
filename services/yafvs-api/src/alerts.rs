// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    alert_payloads::{AlertAssetItem, AlertReference, alert_asset_from_row},
    alert_query_sql::{alert_asset_detail_sql, alert_asset_tasks_sql, alert_assets_sql},
    app_state::AppState,
    collections::{ALERT_DEFAULT_SORT, ALERT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) async fn alert_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<AlertAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, ALERT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, ALERT_SORT_FIELDS)?;
    let sql = alert_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "alert asset list")
            .await?;
    let items = rows.iter().map(alert_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn alert_asset_detail(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_alert_asset_detail(&client, &alert_id).await?))
}

pub(crate) async fn export_alert_metadata(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_alert_asset_detail(&client, &alert_id).await?))
}

pub(crate) async fn load_alert_asset_detail(
    client: &tokio_postgres::Client,
    alert_id: &str,
) -> Result<AlertAssetItem, ApiError> {
    let alert_id = parse_uuid(alert_id)?.to_string();
    let row = client
        .query_opt(alert_asset_detail_sql(), &[&alert_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let task_rows = client
        .query(alert_asset_tasks_sql(), &[&alert_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset task reference query failed");
            ApiError::Database
        })?;
    let tasks = task_rows
        .iter()
        .map(|row| AlertReference {
            id: row.get("id"),
            name: row.get("name"),
        })
        .collect();
    let mut item = alert_asset_from_row(&row);
    item.tasks = tasks;
    Ok(item)
}
