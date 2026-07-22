// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
};

#[derive(Debug, serde::Deserialize)]
pub(crate) struct CredentialCollectionQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    sort: Option<String>,
    filter: Option<String>,
    filter_type: Option<String>,
    active: Option<String>,
    predefined: Option<String>,
    resource_type: Option<String>,
    text: Option<String>,
    task_name: Option<String>,
    value: Option<String>,
    credential_type: Option<String>,
}

impl CredentialCollectionQuery {
    fn collection_query(&self) -> CollectionQuery {
        CollectionQuery {
            page: self.page,
            page_size: self.page_size,
            sort: self.sort.clone(),
            filter: self.filter.clone(),
            filter_type: self.filter_type.clone(),
            active: self.active.clone(),
            name: None,
            nvt_oid: None,
            predefined: self.predefined.clone(),
            resource_type: self.resource_type.clone(),
            schedules_only: None,
            scope_id: None,
            text: self.text.clone(),
            task_name: self.task_name.clone(),
            task_id: None,
            value: self.value.clone(),
            vulnerability_id: None,
        }
    }
}

pub(crate) async fn credential_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CredentialCollectionQuery>,
) -> Result<Json<Collection<CredentialAssetItem>>, ApiError> {
    let credential_type = query.credential_type.clone().unwrap_or_default();
    let params =
        normalize_collection_query(query.collection_query(), CREDENTIAL_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CREDENTIAL_ASSET_SORT_FIELDS)?;
    let sql = credential_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &credential_type,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&params.filter, &1_i64, &0_i64, &credential_type],
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

pub(crate) async fn credential_asset_export(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    credential_asset_detail(State(state), Path(credential_id)).await
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
