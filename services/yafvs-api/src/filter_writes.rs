// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::{ApiError, mutation_committed_response_unavailable},
    filter_payloads::FilterAssetItem,
    filter_write_db::*,
    filter_write_transactions::*,
    filter_write_validation::{
        FilterCloneRequest, FilterCreateRequest, FilterPatchRequest, validate_filter_clone_request,
        validate_filter_create_request, validate_filter_patch_request,
    },
    filters::load_filter_asset_detail,
    path_ids::parse_uuid,
};

pub(crate) async fn create_filter(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<FilterCreateRequest>,
) -> Result<(StatusCode, Json<FilterAssetItem>), ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let request = validate_filter_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin create filter transaction"))?;
    let owner_id = resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE filters, filters_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_filter_write_db_error(error, "lock filters for create"))?;
    ensure_unique_filter_name(&tx, &request.name, -1).await?;
    let record = execute_filter_create_transaction(&tx, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit create filter transaction"))?;
    Ok((
        StatusCode::CREATED,
        Json(
            load_filter_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(error, "create filter response reload")
                })?,
        ),
    ))
}

pub(crate) async fn delete_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let filter_uuid = parse_uuid(&filter_id)?.to_string();
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin delete filter transaction"))?;
    let operator_owner_id = resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE filters, filters_trash, settings, alerts, alerts_trash, alert_condition_data, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_filter_write_db_error(error, "lock filter tables for delete"))?;
    let state = load_filter_write_state(&tx, &filter_uuid).await?;
    ensure_filter_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_filter_not_in_use_by_alerts(&tx, state.internal_id).await?;
    execute_filter_trash_transaction(&tx, state.internal_id, &filter_uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit delete filter transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn clone_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<FilterCloneRequest>,
) -> Result<(StatusCode, Json<FilterAssetItem>), ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let request = validate_filter_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin clone filter transaction"))?;
    let owner_id = resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE filters, filters_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_filter_write_db_error(error, "lock filter tables for clone"))?;
    let source = load_filter_write_state(&tx, &filter_id).await?;
    ensure_filter_owner_matches_operator(source.owner_id, owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_filter_name(&tx, name, -1).await?;
    }
    let record =
        execute_filter_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit clone filter transaction"))?;
    Ok((
        StatusCode::CREATED,
        Json(
            load_filter_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(error, "clone filter response reload")
                })?,
        ),
    ))
}

pub(crate) async fn restore_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin restore filter transaction"))?;
    let operator_owner_id = resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE filters, filters_trash, alerts_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_filter_write_db_error(error, "lock filter tables for restore"))?;
    let trash = load_filter_trash_state(&tx, &filter_id).await?;
    ensure_filter_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_unique_live_filter_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_filter_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_filter_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit restore filter transaction"))?;

    Ok(Json(
        load_filter_asset_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "restore filter response reload")
            })?,
    ))
}

pub(crate) async fn hard_delete_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_filter_write_db_error(error, "begin hard-delete filter transaction")
    })?;
    let operator_owner_id = resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE filters_trash, alerts_trash, alert_condition_data_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_filter_write_db_error(error, "lock filter trash tables for hard delete"))?;
    let trash = load_filter_trash_state(&tx, &filter_id).await?;
    ensure_filter_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_filter_not_in_use_by_trash_alerts(&tx, trash.internal_id).await?;
    execute_filter_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_filter_write_db_error(error, "commit hard-delete filter transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn patch_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<FilterPatchRequest>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let request = validate_filter_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin patch filter transaction"))?;
    let operator_owner_id = resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE filters, filters_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_filter_write_db_error(error, "lock filters for patch"))?;
    let state = load_filter_write_state(&tx, &filter_id).await?;
    ensure_filter_owner_matches_operator(state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_filter_name(&tx, name, state.internal_id).await?;
    }
    if request.changes_alert_linked_type() {
        ensure_filter_not_in_use_by_alerts(&tx, state.internal_id).await?;
    }
    let record = execute_filter_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit patch filter transaction"))?;
    Ok(Json(
        load_filter_asset_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "patch filter response reload")
            })?,
    ))
}

#[cfg(test)]
#[path = "filter_writes_tests.rs"]
mod filter_writes_tests;
