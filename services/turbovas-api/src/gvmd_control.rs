// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

use crate::errors::ApiError;

const GVMD_CONTROL_SOCKET_ENV: &str = "TURBOVAS_API_GVMD_CONTROL_SOCKET";
const GVMD_CONTROL_SECRET_ENV: &str = "TURBOVAS_GVMD_CONTROL_SECRET";
const DEFAULT_GVMD_CONTROL_SOCKET: &str = "/runtime/run/gvmd/turbovas-control.sock";
const MIN_CONTROL_SECRET_BYTES: usize = 32;
const MAX_CONTROL_SECRET_BYTES: usize = 128;
const CONTROL_SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONTROL_RESPONSE_BYTES: usize = 256;

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

pub(crate) fn gvmd_control_socket_path() -> String {
    env::var(GVMD_CONTROL_SOCKET_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_GVMD_CONTROL_SOCKET.to_string())
}

pub(crate) fn gvmd_control_secret() -> Result<String, ApiError> {
    gvmd_control_secret_from_source(env::var(GVMD_CONTROL_SECRET_ENV).ok())
}

pub(crate) fn gvmd_control_secret_from_source(secret: Option<String>) -> Result<String, ApiError> {
    let secret = secret.ok_or(ApiError::Config)?;
    if !control_secret_is_acceptable(&secret) {
        return Err(ApiError::Config);
    }
    Ok(secret)
}

pub(crate) async fn request_gvmd_control_response(
    socket_path: &str,
    control_secret: &str,
    command: &str,
) -> Result<Vec<u8>, ControlSocketError> {
    request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes()).await
}

pub(crate) async fn request_gvmd_control_response_bytes(
    socket_path: &str,
    control_secret: &str,
    command: &[u8],
) -> Result<Vec<u8>, ControlSocketError> {
    if !control_secret_is_acceptable(control_secret) {
        return Err(ControlSocketError::Configuration);
    }
    let mut stream = timeout(CONTROL_SOCKET_IO_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .map_err(|_| ControlSocketError::Unavailable)?
        .map_err(|_| ControlSocketError::Unavailable)?;
    timeout(CONTROL_SOCKET_IO_TIMEOUT, stream.write_all(command))
        .await
        .map_err(|_| ControlSocketError::Unavailable)?
        .map_err(|_| ControlSocketError::Unavailable)?;
    timeout(
        CONTROL_RESPONSE_TIMEOUT,
        read_gvmd_control_response(&mut stream),
    )
    .await
    .map_err(|_| ControlSocketError::Unavailable)?
}

async fn read_gvmd_control_response(
    stream: &mut UnixStream,
) -> Result<Vec<u8>, ControlSocketError> {
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
    response.pop();
    Ok(response)
}

fn control_secret_is_acceptable(secret: &str) -> bool {
    (MIN_CONTROL_SECRET_BYTES..=MAX_CONTROL_SECRET_BYTES).contains(&secret.len())
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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
