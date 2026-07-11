// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    gvmd_control::{
        gvmd_control_secret, gvmd_control_socket_path, map_control_socket_error,
        request_gvmd_control_response,
    },
    schedule_payloads::ScheduleAssetDetail,
    schedule_write_db::*,
    schedule_write_transactions::*,
    schedule_write_validation::{
        ScheduleCloneRequest, ScheduleCreateRequest, SchedulePatchRequest, ValidatedScheduleCreate,
        validate_schedule_clone_request, validate_schedule_create_request,
        validate_schedule_patch_request,
    },
    schedules::load_schedule_asset_detail,
};

pub(crate) async fn create_schedule(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScheduleCreateRequest>,
) -> Result<(StatusCode, Json<ScheduleAssetDetail>), ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let request = validate_schedule_create_request(request)?;
    let control_secret = gvmd_control_secret()?;
    let schedule_id = request_schedule_create(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &request,
    )
    .await?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok((
        StatusCode::CREATED,
        Json(load_schedule_asset_detail(&client, &schedule_id).await?),
    ))
}

pub(crate) async fn request_schedule_create(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedScheduleCreate,
) -> Result<String, ApiError> {
    let response = request_gvmd_control_response(
        socket_path,
        control_secret,
        &schedule_create_command(control_secret, operator_uuid, request),
    )
    .await
    .map_err(map_control_socket_error)?;
    parse_schedule_create_response(&response)
}

pub(crate) fn schedule_create_command(
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedScheduleCreate,
) -> String {
    format!(
        "schedule-create {control_secret} {operator_uuid} {} {} {} {}\n",
        STANDARD.encode(&request.name),
        STANDARD.encode(&request.comment),
        STANDARD.encode(&request.timezone),
        STANDARD.encode(&request.icalendar),
    )
}

pub(crate) fn parse_schedule_create_response(response: &[u8]) -> Result<String, ApiError> {
    match response {
        b"1 exists" => Err(ApiError::Conflict(
            "A schedule with this name already exists.".to_string(),
        )),
        b"3 invalid_ical" => Err(ApiError::BadRequest(
            "The iCalendar data is invalid.".to_string(),
        )),
        b"4 invalid_timezone" => Err(ApiError::BadRequest("The timezone is invalid.".to_string())),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-1 internal" => Err(ApiError::ControlFailure),
        _ => parse_created_schedule_id(response),
    }
}

fn parse_created_schedule_id(response: &[u8]) -> Result<String, ApiError> {
    let Some(uuid) = response.strip_prefix(b"0 created ") else {
        return Err(ApiError::ControlFailure);
    };
    let uuid = std::str::from_utf8(uuid).map_err(|_| ApiError::ControlFailure)?;
    if uuid.len() != 36 {
        return Err(ApiError::ControlFailure);
    }
    let uuid = Uuid::parse_str(uuid).map_err(|_| ApiError::ControlFailure)?;
    Ok(uuid.to_string())
}

pub(crate) async fn clone_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScheduleCloneRequest>,
) -> Result<(StatusCode, Json<ScheduleAssetDetail>), ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let request = validate_schedule_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "begin clone schedule transaction"))?;
    let owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for clone"))?;
    let source = load_schedule_write_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(source.owner_id, owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_schedule_name(&tx, name, -1).await?;
    }
    let record =
        execute_schedule_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "commit clone schedule transaction"))?;
    Ok((
        StatusCode::CREATED,
        Json(load_schedule_asset_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn delete_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "begin delete schedule transaction"))?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for delete"))?;
    let state = load_schedule_write_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_schedule_not_in_use_by_live_tasks(&tx, state.internal_id).await?;
    execute_schedule_trash_transaction(&tx, state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_schedule_write_db_error(error, "commit delete schedule transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_schedule_write_db_error(error, "begin hard-delete schedule transaction")
    })?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule trash tables for hard delete"))?;
    let trash = load_schedule_trash_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_schedule_not_in_use_by_trash_tasks(&tx, trash.internal_id).await?;
    execute_schedule_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_schedule_write_db_error(error, "commit hard-delete schedule transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_schedule_write_db_error(error, "begin restore schedule transaction")
    })?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for restore"))?;
    let trash = load_schedule_trash_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_unique_live_schedule_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_schedule_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_schedule_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_schedule_write_db_error(error, "commit restore schedule transaction")
    })?;

    Ok(Json(
        load_schedule_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn patch_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<SchedulePatchRequest>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let request = validate_schedule_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "begin patch schedule transaction"))?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE schedules, schedules_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_schedule_write_db_error(error, "lock schedules for patch"))?;
    let state = load_schedule_write_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_schedule_name(&tx, name, state.internal_id).await?;
    }
    let record = execute_schedule_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "commit patch schedule transaction"))?;
    Ok(Json(
        load_schedule_asset_detail(&client, &record.uuid).await?,
    ))
}

#[cfg(test)]
#[path = "schedule_writes_tests.rs"]
mod schedule_writes_tests;
