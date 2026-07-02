// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    scan_config_payloads::ScanConfigAssetDetail,
    scan_config_write_db::*,
    scan_config_write_transactions::*,
    scan_config_write_validation::{
        ScanConfigCloneRequest, ScanConfigCreateRequest, ScanConfigPatchRequest,
        validate_scan_config_clone_request, validate_scan_config_create_request,
        validate_scan_config_patch_request,
    },
    scan_configs::load_scan_config_asset_detail,
};

pub(crate) async fn create_scan_config(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScanConfigCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScanConfigAssetDetail>), ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let request = validate_scan_config_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin create scan-config transaction")
    })?;
    let operator_owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, config_preferences, nvt_selectors, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for create"))?;
    let config_state = load_scan_config_write_state(&tx, &request.base_scan_config_id).await?;
    ensure_scan_config_clone_source_allowed(&config_state, operator_owner_id)?;
    ensure_unique_scan_config_name(&tx, &request.name, 0).await?;
    let record = execute_scan_config_create_from_base_transaction(
        &tx,
        config_state.internal_id,
        operator_owner_id,
        &request,
    )
    .await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit create scan-config transaction")
    })?;

    Ok((
        StatusCode::CREATED,
        scan_config_write_location_headers(&record.uuid)?,
        Json(load_scan_config_asset_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn clone_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScanConfigCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScanConfigAssetDetail>), ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let request = validate_scan_config_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin clone scan-config transaction")
    })?;
    let operator_owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, config_preferences, nvt_selectors, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for clone"))?;
    let config_state = load_scan_config_write_state(&tx, &scan_config_id).await?;
    ensure_scan_config_clone_source_allowed(&config_state, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scan_config_name(&tx, name, 0).await?;
    }
    let record = execute_scan_config_clone_transaction(
        &tx,
        config_state.internal_id,
        operator_owner_id,
        &request,
    )
    .await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit clone scan-config transaction")
    })?;

    Ok((
        StatusCode::CREATED,
        scan_config_write_location_headers(&record.uuid)?,
        Json(load_scan_config_asset_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn delete_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin delete scan-config transaction")
    })?;
    let operator_owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, configs_trash, config_preferences, config_preferences_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for delete"))?;
    let config_state = load_scan_config_write_state(&tx, &scan_config_id).await?;
    ensure_scan_config_owner_matches_operator(config_state.owner_id, operator_owner_id)?;
    ensure_scan_config_not_predefined(&config_state)?;
    ensure_scan_config_not_in_use_by_live_tasks(&tx, config_state.internal_id).await?;
    execute_scan_config_trash_transaction(&tx, config_state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit delete scan-config transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin hard-delete scan-config transaction")
    })?;
    let operator_owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs_trash, config_preferences_trash, nvt_selectors, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| {
        map_scan_config_write_db_error(error, "lock scan-config trash tables for hard delete")
    })?;
    let trash = load_scan_config_trash_state(&tx, &scan_config_id).await?;
    ensure_scan_config_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_scan_config_not_in_use_by_trash_tasks(&tx, trash.internal_id).await?;
    execute_scan_config_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit hard-delete scan-config transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin restore scan-config transaction")
    })?;
    let operator_owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, configs_trash, config_preferences, config_preferences_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for restore"))?;
    let trash = load_scan_config_trash_state(&tx, &scan_config_id).await?;
    ensure_scan_config_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_scan_config_trash_scanner_is_live(&trash)?;
    ensure_unique_live_scan_config_name(&tx, &trash.name).await?;
    ensure_scan_config_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_scan_config_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit restore scan-config transaction")
    })?;

    Ok(Json(
        load_scan_config_asset_detail(&client, &record.uuid).await?,
    ))
}

fn scan_config_write_location_headers(scan_config_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/scan-configs/{scan_config_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}

pub(crate) async fn patch_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScanConfigPatchRequest>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let request = validate_scan_config_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin patch scan-config transaction")
    })?;
    let operator_owner_id = resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE configs, configs_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "lock scan-config tables for patch")
        })?;
    let config_state = load_scan_config_write_state(&tx, &scan_config_id).await?;
    ensure_scan_config_owner_matches_operator(config_state.owner_id, operator_owner_id)?;
    ensure_scan_config_not_predefined(&config_state)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scan_config_name(&tx, name, config_state.internal_id).await?;
    }
    let record =
        execute_scan_config_metadata_patch_transaction(&tx, config_state.internal_id, &request)
            .await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit patch scan-config transaction")
    })?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &record.uuid).await?,
    ))
}
