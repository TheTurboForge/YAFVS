// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    errors::ApiError,
    gvmd_control::{
        MAX_CONTROL_REQUEST_BYTES, ScrubbedControlFrame, map_control_socket_error,
        request_gvmd_control_response_bytes, validate_gvmd_control_secret,
    },
};
use uuid::Uuid;

const UUID_TEXT_BYTES: usize = 36;

pub(crate) async fn request_task_clone(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    source_task_uuid: &str,
) -> Result<String, ApiError> {
    let command = task_clone_command(control_secret, operator_uuid, source_task_uuid)?;
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_task_clone_response(&response)
}

pub(crate) fn task_clone_command(
    control_secret: &str,
    operator_uuid: &str,
    source_task_uuid: &str,
) -> Result<ScrubbedControlFrame, ApiError> {
    validate_gvmd_control_secret(control_secret)?;
    let operator_uuid = canonical_task_clone_uuid(operator_uuid)?;
    let source_task_uuid = canonical_task_clone_uuid(source_task_uuid)?;

    let mut command = Vec::with_capacity(256);
    command.extend_from_slice(b"task-clone ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.extend_from_slice(source_task_uuid.as_bytes());
    command.push(b'\n');
    if command.len() >= MAX_CONTROL_REQUEST_BYTES {
        return Err(ApiError::RequestTooLarge);
    }
    Ok(ScrubbedControlFrame::new(command))
}

pub(crate) fn parse_task_clone_response(response: &[u8]) -> Result<String, ApiError> {
    if let Some(uuid) = response.strip_prefix(b"0 created ") {
        return parse_created_task_clone_id(uuid);
    }
    match response {
        b"1 duplicate" => Err(ApiError::Conflict(
            "A task with this name already exists.".to_string(),
        )),
        b"2 not_found" => Err(ApiError::NotFound),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The task clone control request was rejected.".to_string(),
        )),
        b"-3 committed_indeterminate" => Err(ApiError::MutationCommittedResponseUnavailable),
        b"-1 internal" => Err(ApiError::ControlFailure),
        _ => Err(ApiError::MutationOutcomeIndeterminate),
    }
}

fn canonical_task_clone_uuid(value: &str) -> Result<String, ApiError> {
    if value.len() != UUID_TEXT_BYTES {
        return Err(ApiError::BadRequest(
            "Task clone identifiers must be canonical UUIDs.".to_string(),
        ));
    }
    Uuid::parse_str(value)
        .map(|uuid| uuid.to_string())
        .map_err(|_| ApiError::BadRequest("Task clone identifiers must be UUIDs.".to_string()))
}

fn parse_created_task_clone_id(value: &[u8]) -> Result<String, ApiError> {
    let value = std::str::from_utf8(value).map_err(|_| ApiError::MutationOutcomeIndeterminate)?;
    if value.len() != UUID_TEXT_BYTES {
        return Err(ApiError::MutationOutcomeIndeterminate);
    }
    Uuid::parse_str(value)
        .map(|uuid| uuid.to_string())
        .map_err(|_| ApiError::MutationOutcomeIndeterminate)
}

#[cfg(test)]
#[path = "task_clone_control_tests.rs"]
mod task_clone_control_tests;
