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
    report_config_payloads::ReportConfigAssetItem,
    report_config_write_db::*,
    report_config_write_validation::{
        ReportConfigCloneRequest, ReportConfigCreateRequest, ReportConfigPatchRequest,
        validate_report_config_clone_request, validate_report_config_create_request,
        validate_report_config_param_values, validate_report_config_patch_request,
    },
    report_configs::load_report_config_asset_detail,
};

pub(crate) async fn create_report_config(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ReportConfigCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ReportConfigAssetItem>), ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let request = validate_report_config_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin create report config transaction")
    })?;
    let owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_configs IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "lock report configs for create")
        })?;
    ensure_unique_live_report_config_name(&tx, &request.name, None).await?;
    let format = load_report_config_format_state(&tx, &request.report_format_id).await?;
    validate_report_config_param_values(&request.params, &format)?;
    let record = execute_report_config_create_transaction(&tx, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit create report config transaction")
    })?;

    let report_config = load_report_config_asset_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        report_config_write_location_headers(&record.uuid)?,
        Json(report_config),
    ))
}

pub(crate) async fn hard_delete_report_config(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin hard-delete report config transaction")
    })?;
    let operator_owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE report_configs_trash, report_config_params_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| {
        map_report_config_write_db_error(error, "lock report config trash tables for hard delete")
    })?;
    let trash = load_report_config_trash_state(&tx, &report_config_id).await?;
    ensure_report_config_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_trash_report_config_not_in_use_by_alerts(&tx, trash.internal_id).await?;
    execute_report_config_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit hard-delete report config transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn clone_report_config(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ReportConfigCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ReportConfigAssetItem>), ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let request = validate_report_config_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin clone report config transaction")
    })?;
    let owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_configs IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "lock report configs for clone")
        })?;
    let source = load_report_config_write_state(&tx, &report_config_id).await?;
    ensure_report_config_owner_matches_operator(source.owner_id, owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_live_report_config_name(&tx, name, None).await?;
    }
    let record =
        execute_report_config_clone_transaction(&tx, source.internal_id, owner_id, &request)
            .await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit clone report config transaction")
    })?;

    let report_config = load_report_config_asset_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        report_config_write_location_headers(&record.uuid)?,
        Json(report_config),
    ))
}

pub(crate) async fn delete_report_config(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin delete report config transaction")
    })?;
    let operator_owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_configs IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "lock report configs for delete")
        })?;
    let state = load_report_config_write_state(&tx, &report_config_id).await?;
    ensure_report_config_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_report_config_not_in_use_by_alerts(&tx, state.internal_id).await?;
    execute_report_config_trash_transaction(&tx, state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit delete report config transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_report_config(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin restore report config transaction")
    })?;
    let operator_owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE report_configs, report_configs_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_report_config_write_db_error(error, "lock report configs for restore"))?;
    let trash = load_report_config_trash_state(&tx, &report_config_id).await?;
    ensure_report_config_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_unique_live_report_config_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_report_config_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_report_config_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit restore report config transaction")
    })?;

    Ok(Json(
        load_report_config_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn patch_report_config(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ReportConfigPatchRequest>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let request = validate_report_config_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin patch report config transaction")
    })?;
    let operator_owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_configs IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "lock report configs for patch")
        })?;
    let state = load_report_config_write_state(&tx, &report_config_id).await?;
    ensure_report_config_owner_matches_operator(state.owner_id, operator_owner_id)?;
    if let Some(params) = request.params.as_ref() {
        let format = load_report_config_format_state(&tx, &state.report_format_id).await?;
        validate_report_config_param_values(params, &format)?;
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_live_report_config_name(&tx, name, Some(state.internal_id)).await?;
    }
    let record = execute_report_config_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit patch report config transaction")
    })?;

    Ok(Json(
        load_report_config_asset_detail(&client, &record.uuid).await?,
    ))
}

fn report_config_write_location_headers(report_config_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/report-configs/{report_config_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

#[cfg(test)]
#[path = "report_config_writes_tests.rs"]
mod report_config_writes_tests;
