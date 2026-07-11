// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    gvmd_control::{
        ControlSocketError, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response,
    },
    schedule_payloads::ScheduleAssetDetail,
    schedule_write_db::*,
    schedule_write_transactions::*,
    schedule_write_validation::{
        ScheduleCloneRequest, ScheduleCreateRequest, SchedulePatchRequest, ValidatedScheduleCreate,
        ValidatedSchedulePatch, validate_schedule_clone_request, validate_schedule_create_request,
        validate_schedule_patch_request,
    },
    schedules::load_schedule_asset_detail,
};

#[derive(Debug)]
pub(crate) enum SchedulePatchError {
    Api(ApiError),
    Unprocessable(String),
    ControlFailure,
}

impl From<ApiError> for SchedulePatchError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl IntoResponse for SchedulePatchError {
    fn into_response(self) -> Response {
        match self {
            Self::Api(error) => error.into_response(),
            Self::Unprocessable(message) => schedule_patch_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unprocessable_entity",
                message,
            ),
            Self::ControlFailure => schedule_patch_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "control_failure",
                "The schedule control operation failed.".to_string(),
            ),
        }
    }
}

#[derive(Serialize)]
struct SchedulePatchErrorBody {
    error: SchedulePatchErrorPayload,
}

#[derive(Serialize)]
struct SchedulePatchErrorPayload {
    code: &'static str,
    message: String,
}

fn schedule_patch_error_response(
    status: StatusCode,
    code: &'static str,
    message: String,
) -> Response {
    (
        status,
        Json(SchedulePatchErrorBody {
            error: SchedulePatchErrorPayload { code, message },
        }),
    )
        .into_response()
}

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
) -> Result<Json<ScheduleAssetDetail>, SchedulePatchError> {
    let operator = require_schedule_write_operator(operator)?;
    let request = validate_schedule_patch_request(request)?;
    let control_secret = gvmd_control_secret()?;
    request_schedule_patch(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &schedule_id,
        &request,
    )
    .await?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_schedule_asset_detail(&client, &schedule_id).await?,
    ))
}

pub(crate) async fn request_schedule_patch(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    schedule_uuid: &str,
    request: &ValidatedSchedulePatch,
) -> Result<(), SchedulePatchError> {
    let response = request_gvmd_control_response(
        socket_path,
        control_secret,
        &schedule_patch_command(control_secret, operator_uuid, schedule_uuid, request),
    )
    .await
    .map_err(map_schedule_patch_control_socket_error)?;
    parse_schedule_patch_response(&response)
}

pub(crate) fn schedule_patch_command(
    control_secret: &str,
    operator_uuid: &str,
    schedule_uuid: &str,
    request: &ValidatedSchedulePatch,
) -> String {
    format!(
        "schedule-modify {control_secret} {operator_uuid} {schedule_uuid} {} {} {} {}\n",
        schedule_patch_token(request.name.as_deref()),
        schedule_patch_token(request.comment.as_deref()),
        schedule_patch_token(request.timezone.as_deref()),
        schedule_patch_token(request.icalendar.as_deref()),
    )
}

fn schedule_patch_token(value: Option<&str>) -> String {
    value
        .map(|value| format!("+{}", STANDARD.encode(value)))
        .unwrap_or_else(|| "-".to_string())
}

pub(crate) fn parse_schedule_patch_response(response: &[u8]) -> Result<(), SchedulePatchError> {
    match response {
        b"0 modified" => Ok(()),
        b"1 not_found" => Err(SchedulePatchError::Api(ApiError::NotFound)),
        b"2 duplicate" => Err(SchedulePatchError::Api(ApiError::Conflict(
            "A schedule with this name already exists.".to_string(),
        ))),
        b"6 invalid_ical" => Err(SchedulePatchError::Unprocessable(
            "The iCalendar data is invalid.".to_string(),
        )),
        b"7 invalid_timezone" => Err(SchedulePatchError::Unprocessable(
            "The timezone is invalid.".to_string(),
        )),
        b"99 forbidden" => Err(SchedulePatchError::Api(ApiError::Forbidden)),
        b"-2 malformed" => Err(SchedulePatchError::Api(ApiError::BadRequest(
            "The schedule control request was rejected.".to_string(),
        ))),
        b"-1 internal" => Err(SchedulePatchError::ControlFailure),
        _ => Err(SchedulePatchError::ControlFailure),
    }
}

fn map_schedule_patch_control_socket_error(error: ControlSocketError) -> SchedulePatchError {
    match error {
        ControlSocketError::Configuration => SchedulePatchError::Api(ApiError::Config),
        ControlSocketError::Forbidden => SchedulePatchError::Api(ApiError::Forbidden),
        ControlSocketError::NotFound => SchedulePatchError::Api(ApiError::NotFound),
        ControlSocketError::Unavailable => SchedulePatchError::Api(ApiError::ControlUnavailable),
        ControlSocketError::Requested
        | ControlSocketError::ScannerUnverified
        | ControlSocketError::Failure => SchedulePatchError::ControlFailure,
    }
}

#[cfg(test)]
#[path = "schedule_writes_tests.rs"]
mod schedule_writes_tests;
