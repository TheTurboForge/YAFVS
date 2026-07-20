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
    host_asset_payloads::HostAssetDetail,
    host_assets::host_asset_detail,
    host_write_db::*,
    host_write_transactions::{
        execute_host_create_transaction, execute_host_delete_transaction,
        execute_host_identifier_delete_transaction,
        execute_host_operating_system_delete_transaction, execute_host_patch_transaction,
    },
    host_write_validation::{
        HostCreateRequest, HostPatchRequest, validate_host_create_request,
        validate_host_patch_request,
    },
};

pub(crate) async fn create_host(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<HostCreateRequest>,
) -> Result<(StatusCode, Json<HostAssetDetail>), ApiError> {
    let operator = require_host_write_operator(operator)?;
    let request = validate_host_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_host_write_db_error(error, "begin create host transaction"))?;
    let owner_id = resolve_host_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE hosts, host_identifiers IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_host_write_db_error(error, "lock host tables for create"))?;
    let record =
        execute_host_create_transaction(&tx, owner_id, operator.user_uuid(), &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_host_write_db_error(error, "commit create host transaction"))?;
    Ok((
        StatusCode::CREATED,
        host_asset_detail(State(state), Path(record.uuid))
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "create host response reload")
            })?,
    ))
}

pub(crate) async fn patch_host(
    State(state): State<AppState>,
    Path(host_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<HostPatchRequest>,
) -> Result<Json<HostAssetDetail>, ApiError> {
    let operator = require_host_write_operator(operator)?;
    let request = validate_host_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_host_write_db_error(error, "begin patch host transaction"))?;
    let operator_owner_id = resolve_host_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE hosts IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_host_write_db_error(error, "lock hosts for patch"))?;
    let host_state = load_host_write_state(&tx, &host_id).await?;
    ensure_host_owner_matches_operator(host_state.owner_id, operator_owner_id)?;
    let record = execute_host_patch_transaction(&tx, host_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_host_write_db_error(error, "commit patch host transaction"))?;
    host_asset_detail(State(state), Path(record.uuid))
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "patch host response reload")
        })
}

pub(crate) async fn delete_host(
    State(state): State<AppState>,
    Path(host_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_host_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_host_write_db_error(error, "begin delete host transaction"))?;
    let operator_owner_id = resolve_host_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE hosts, host_identifiers, host_oss, host_max_severities, host_details, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_host_write_db_error(error, "lock host tables for delete"))?;
    let host_state = load_host_write_state(&tx, &host_id).await?;
    ensure_host_owner_matches_operator(host_state.owner_id, operator_owner_id)?;
    execute_host_delete_transaction(&tx, host_state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_host_write_db_error(error, "commit delete host transaction"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_host_identifier(
    State(state): State<AppState>,
    Path(identifier_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_host_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_host_write_db_error(error, "begin delete host identifier transaction")
    })?;
    let operator_owner_id = resolve_host_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE hosts, host_identifiers IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_host_write_db_error(error, "lock host identifier tables"))?;
    let identifier_state = load_host_identifier_write_state(&tx, &identifier_id).await?;
    ensure_host_owner_matches_operator(identifier_state.owner_id, operator_owner_id)?;
    execute_host_identifier_delete_transaction(&tx, identifier_state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_host_write_db_error(error, "commit delete host identifier transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_host_operating_system(
    State(state): State<AppState>,
    Path(host_operating_system_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_host_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_host_write_db_error(error, "begin delete host operating system transaction")
    })?;
    let operator_owner_id = resolve_host_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE hosts, host_oss IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_host_write_db_error(error, "lock host operating system tables"))?;
    let host_operating_system_state =
        load_host_operating_system_write_state(&tx, &host_operating_system_id).await?;
    ensure_host_owner_matches_operator(host_operating_system_state.owner_id, operator_owner_id)?;
    execute_host_operating_system_delete_transaction(&tx, host_operating_system_state.internal_id)
        .await?;
    tx.commit().await.map_err(|error| {
        map_host_write_db_error(error, "commit delete host operating system transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}
