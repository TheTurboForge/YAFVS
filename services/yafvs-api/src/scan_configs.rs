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
    asset_user_tag_query_sql::scan_config_user_tags_sql,
    collections::{SCAN_CONFIG_ASSET_DEFAULT_SORT, SCAN_CONFIG_ASSET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    scan_config_payloads::{
        ScanConfigAssetDetail, ScanConfigAssetItem, ScanConfigPreferences, ScanConfigTaskReference,
        scan_config_asset_from_row, scan_config_preferences_payload_from_rows,
        scan_config_task_reference_from_row,
    },
    scan_config_query_sql::{
        scan_config_asset_detail_sql, scan_config_asset_list_sql, scan_config_preferences_sql,
        scan_config_task_references_sql,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn scan_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScanConfigAssetItem>>, ApiError> {
    let predefined_filter = query.predefined.clone().unwrap_or_default();
    if !matches!(predefined_filter.as_str(), "" | "0" | "1") {
        return Err(ApiError::BadRequest("invalid predefined filter".into()));
    }
    let params = normalize_collection_query(query, SCAN_CONFIG_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCAN_CONFIG_ASSET_SORT_FIELDS)?;
    let sql = scan_config_asset_list_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &predefined_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset list query failed");
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
            &predefined_filter,
        ],
        "scan config asset list",
    )
    .await?;
    let items = rows.iter().map(scan_config_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scan_config_asset_detail(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &scan_config_id).await?,
    ))
}

pub(crate) async fn export_scan_config_metadata(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &scan_config_id).await?,
    ))
}

pub(crate) async fn load_scan_config_asset_detail(
    client: &Client,
    scan_config_id: &str,
) -> Result<ScanConfigAssetDetail, ApiError> {
    parse_uuid(scan_config_id)?;
    let row = client
        .query_opt(scan_config_asset_detail_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    let tasks = scan_config_task_references(&client, &scan_config_id).await?;
    let user_tags = scan_config_user_tags(&client, &scan_config_id).await?;
    let preferences = scan_config_preferences(&client, &scan_config_id).await?;
    Ok(ScanConfigAssetDetail {
        asset: scan_config_asset_from_row(&row),
        preferences,
        tasks,
        user_tags,
    })
}

async fn scan_config_preferences(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<ScanConfigPreferences, ApiError> {
    let rows = client
        .query(scan_config_preferences_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config preference query failed");
            ApiError::Database
        })?;
    Ok(scan_config_preferences_payload_from_rows(&rows))
}

async fn scan_config_task_references(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ScanConfigTaskReference>, ApiError> {
    let rows = client
        .query(scan_config_task_references_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(scan_config_task_reference_from_row)
        .collect())
}

async fn scan_config_user_tags(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scan_config_user_tags_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config user-tag query failed");
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
