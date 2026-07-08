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
    errors::ApiError,
    host_asset_payloads::HostAssetDetail,
    host_assets::host_asset_detail,
    host_write_db::*,
    host_write_transactions::{execute_host_create_transaction, execute_host_patch_transaction},
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
        host_asset_detail(State(state), Path(record.uuid)).await?,
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
    host_asset_detail(State(state), Path(record.uuid)).await
}
