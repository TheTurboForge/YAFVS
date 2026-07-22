// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    gvmd_control::{gvmd_control_secret, gvmd_control_socket_path, request_gvmd_control_response},
    path_ids::parse_uuid,
    task_write_db::require_task_write_operator,
};
use axum::{
    Json,
    extract::{Extension, Path},
    http::StatusCode,
};
use serde::Serialize;

#[cfg(test)]
pub(crate) use crate::gvmd_control::gvmd_control_secret_from_source;
pub(crate) use crate::gvmd_control::{ControlSocketError, map_control_socket_error};

#[derive(Debug, Serialize)]
pub(crate) struct TaskStopResult {
    task_id: String,
    status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskStopOutcome {
    Stopped,
}

pub(crate) async fn stop_task(
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<(StatusCode, Json<TaskStopResult>), ApiError> {
    let operator = require_task_write_operator(operator)?;
    let task_id = parse_uuid(&task_id)?.to_string();
    let control_secret = gvmd_control_secret()?;
    let outcome = request_task_stop(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &task_id,
    )
    .await
    .map_err(map_control_socket_error)?;

    match outcome {
        TaskStopOutcome::Stopped => Ok((
            StatusCode::OK,
            Json(TaskStopResult {
                task_id,
                status: "stopped",
            }),
        )),
    }
}

pub(crate) async fn request_task_stop(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    task_uuid: &str,
) -> Result<TaskStopOutcome, ControlSocketError> {
    let response = request_gvmd_control_response(
        socket_path,
        control_secret,
        &task_stop_command(control_secret, operator_uuid, task_uuid),
    )
    .await?;
    parse_task_stop_response(&response)
}

pub(crate) fn task_stop_command(
    control_secret: &str,
    operator_uuid: &str,
    task_uuid: &str,
) -> String {
    format!("stop {control_secret} {operator_uuid} {task_uuid}\n")
}

pub(crate) fn parse_task_stop_response(
    response: &[u8],
) -> Result<TaskStopOutcome, ControlSocketError> {
    match response {
        b"0 stopped" | b"2 inactive" => Ok(TaskStopOutcome::Stopped),
        b"1 requested" => Err(ControlSocketError::Requested),
        b"3 not_found" => Err(ControlSocketError::NotFound),
        b"99 forbidden" => Err(ControlSocketError::Forbidden),
        b"-1 internal" => Err(ControlSocketError::Failure),
        b"-2 scanner_status" | b"-3 scanner_stop" | b"-4 scanner_delete" | b"-5 scanner_verify" => {
            Err(ControlSocketError::ScannerUnverified)
        }
        _ => Err(ControlSocketError::Failure),
    }
}
