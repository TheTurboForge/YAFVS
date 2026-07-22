// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::scanner_user_tags_sql,
    collections::{SCANNER_ASSET_DEFAULT_SORT, SCANNER_ASSET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    scanner_asset_payloads::{
        ScannerAssetDetail, ScannerAssetItem, ScannerTaskReference, scanner_asset_from_row,
    },
    scanner_asset_query_sql::{
        scanner_asset_detail_sql, scanner_assets_sql, scanner_task_references_sql,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn scanner_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScannerAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCANNER_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCANNER_ASSET_SORT_FIELDS)?;
    let sql = scanner_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner asset list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "scanner asset list")
            .await?;
    let items = rows.iter().map(scanner_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scanner_asset_detail(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let scanner_id = parse_uuid(&scanner_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(scanner_asset_detail_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let tasks = scanner_task_references(&client, &scanner_id).await?;
    let user_tags = scanner_user_tags(&client, &scanner_id).await?;
    Ok(Json(ScannerAssetDetail {
        asset: scanner_asset_from_row(&row),
        tasks,
        user_tags,
    }))
}

pub(crate) async fn scanner_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    scanner_asset_detail(state, path).await
}

async fn scanner_task_references(
    client: &tokio_postgres::Client,
    scanner_id: &str,
) -> Result<Vec<ScannerTaskReference>, ApiError> {
    let rows = client
        .query(scanner_task_references_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ScannerTaskReference {
            id: row.get("id"),
            name: row.get("name"),
            usage_type: row.get("usage_type"),
        })
        .collect())
}

async fn scanner_user_tags(
    client: &tokio_postgres::Client,
    scanner_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scanner_user_tags_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}
