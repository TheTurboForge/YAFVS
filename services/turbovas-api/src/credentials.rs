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
    collections::{CREDENTIAL_ASSET_DEFAULT_SORT, CREDENTIAL_ASSET_SORT_FIELDS},
    credential_payloads::{
        CredentialAssetItem, credential_asset_from_row, credential_usage_reference_from_row,
    },
    credential_query_sql::{
        credential_asset_detail_sql, credential_assets_sql, credential_scanner_references_sql,
        credential_target_references_sql,
    },
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) async fn credential_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CredentialAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, CREDENTIAL_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CREDENTIAL_ASSET_SORT_FIELDS)?;
    let sql = credential_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "credential asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| credential_asset_from_row(row, Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn credential_asset_detail(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    let credential_id = parse_uuid(&credential_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_credential_asset_detail(&client, &credential_id).await?,
    ))
}

pub(crate) async fn load_credential_asset_detail(
    client: &Client,
    credential_id: &str,
) -> Result<CredentialAssetItem, ApiError> {
    let row = client
        .query_opt(credential_asset_detail_sql(), &[&credential_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let targets = client
        .query(credential_target_references_sql(), &[&credential_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential target-reference query failed");
            ApiError::Database
        })?
        .iter()
        .map(credential_usage_reference_from_row)
        .collect();
    let scanners = client
        .query(credential_scanner_references_sql(), &[&credential_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential scanner-reference query failed");
            ApiError::Database
        })?
        .iter()
        .map(credential_usage_reference_from_row)
        .collect();
    Ok(credential_asset_from_row(&row, targets, scanners))
}
