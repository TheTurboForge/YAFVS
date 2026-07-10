// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, time::Duration};

use axum::{
    Json,
    extract::{Extension, Path},
    http::StatusCode,
};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid,
    task_write_db::require_task_write_operator,
};

const GVMD_CONTROL_SOCKET_ENV: &str = "TURBOVAS_API_GVMD_CONTROL_SOCKET";
const GVMD_CONTROL_SECRET_ENV: &str = "TURBOVAS_GVMD_CONTROL_SECRET";
const DEFAULT_GVMD_CONTROL_SOCKET: &str = "/runtime/run/gvmd/turbovas-control.sock";
const MIN_CONTROL_SECRET_BYTES: usize = 32;
const MAX_CONTROL_SECRET_BYTES: usize = 128;
const CONTROL_SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONTROL_RESPONSE_BYTES: usize = 256;

#[derive(Debug, Serialize)]
pub(crate) struct TaskStopResult {
    task_id: String,
    status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskStopOutcome {
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlSocketError {
    Configuration,
    Forbidden,
    NotFound,
    Requested,
    ScannerUnverified,
    Unavailable,
    Failure,
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

fn gvmd_control_socket_path() -> String {
    env::var(GVMD_CONTROL_SOCKET_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_GVMD_CONTROL_SOCKET.to_string())
}

fn gvmd_control_secret() -> Result<String, ApiError> {
    gvmd_control_secret_from_source(env::var(GVMD_CONTROL_SECRET_ENV).ok())
}

pub(crate) fn gvmd_control_secret_from_source(secret: Option<String>) -> Result<String, ApiError> {
    let secret = secret.ok_or(ApiError::Config)?;
    if !control_secret_is_acceptable(&secret) {
        return Err(ApiError::Config);
    }
    Ok(secret)
}

fn control_secret_is_acceptable(secret: &str) -> bool {
    (MIN_CONTROL_SECRET_BYTES..=MAX_CONTROL_SECRET_BYTES).contains(&secret.len())
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) async fn request_task_stop(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    task_uuid: &str,
) -> Result<TaskStopOutcome, ControlSocketError> {
    if !control_secret_is_acceptable(control_secret) {
        return Err(ControlSocketError::Configuration);
    }
    let mut stream = timeout(CONTROL_SOCKET_IO_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .map_err(|_| ControlSocketError::Unavailable)?
        .map_err(|_| ControlSocketError::Unavailable)?;
    timeout(
        CONTROL_SOCKET_IO_TIMEOUT,
        stream.write_all(task_stop_command(control_secret, operator_uuid, task_uuid).as_bytes()),
    )
    .await
    .map_err(|_| ControlSocketError::Unavailable)?
    .map_err(|_| ControlSocketError::Unavailable)?;
    timeout(
        CONTROL_RESPONSE_TIMEOUT,
        read_task_stop_response(&mut stream),
    )
    .await
    .map_err(|_| ControlSocketError::Unavailable)?
}

pub(crate) fn task_stop_command(
    control_secret: &str,
    operator_uuid: &str,
    task_uuid: &str,
) -> String {
    format!("stop {control_secret} {operator_uuid} {task_uuid}\n")
}

async fn read_task_stop_response(
    stream: &mut UnixStream,
) -> Result<TaskStopOutcome, ControlSocketError> {
    let mut response = Vec::with_capacity(32);
    let mut chunk = [0_u8; 64];
    let mut newline_seen = false;
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|_| ControlSocketError::Unavailable)?;
        if count == 0 {
            break;
        }
        if response.len() + count > MAX_CONTROL_RESPONSE_BYTES || newline_seen {
            return Err(ControlSocketError::Failure);
        }
        response.extend_from_slice(&chunk[..count]);
        let newline_count = response.iter().filter(|byte| **byte == b'\n').count();
        if newline_count > 1 || (newline_count == 1 && response.last() != Some(&b'\n')) {
            return Err(ControlSocketError::Failure);
        }
        newline_seen = newline_count == 1;
    }
    if !newline_seen {
        return Err(ControlSocketError::Failure);
    }
    parse_task_stop_response(&response[..response.len() - 1])
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

pub(crate) fn map_control_socket_error(error: ControlSocketError) -> ApiError {
    match error {
        ControlSocketError::Configuration => ApiError::Config,
        ControlSocketError::Forbidden => ApiError::Forbidden,
        ControlSocketError::NotFound => ApiError::NotFound,
        ControlSocketError::Requested => ApiError::TaskStopRequested,
        ControlSocketError::ScannerUnverified => ApiError::ScannerUnverified,
        ControlSocketError::Unavailable => ApiError::ControlUnavailable,
        ControlSocketError::Failure => ApiError::ControlFailure,
    }
}
