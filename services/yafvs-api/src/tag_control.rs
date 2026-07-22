// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    errors::ApiError,
    gvmd_control::{
        MAX_CONTROL_REQUEST_BYTES, ScrubbedControlFrame, map_control_socket_error,
        request_gvmd_control_response_bytes,
    },
    path_ids::parse_uuid,
    tag_write_validation::{
        TagResourceUpdateAction, ValidatedTagPatch, ValidatedTagResourceUpdate,
    },
};

pub(crate) async fn request_tag_modify(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    tag_uuid: &str,
    request: &ValidatedTagPatch,
) -> Result<(), ApiError> {
    let command = tag_modify_command(control_secret, operator_uuid, tag_uuid, request)?;
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_tag_modify_response(&response)
}

pub(crate) async fn request_tag_resource_update(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    tag_uuid: &str,
    request: &ValidatedTagResourceUpdate,
) -> Result<(), ApiError> {
    let patch = ValidatedTagPatch {
        name: None,
        comment: None,
        value: None,
        active: None,
        resource_type: None,
        resources: Some(ValidatedTagResourceUpdate {
            action: request.action,
            resource_ids: request.resource_ids.clone(),
            resource_filter: request.resource_filter.clone(),
        }),
    };
    request_tag_modify(socket_path, control_secret, operator_uuid, tag_uuid, &patch).await
}

pub(crate) fn tag_modify_command(
    control_secret: &str,
    operator_uuid: &str,
    tag_uuid: &str,
    request: &ValidatedTagPatch,
) -> Result<ScrubbedControlFrame, ApiError> {
    let mut command = Vec::with_capacity(1024);
    command.extend_from_slice(b"tag-modify ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.extend_from_slice(parse_uuid(tag_uuid)?.to_string().as_bytes());
    for value in [
        request.name.as_deref(),
        request.comment.as_deref(),
        request.value.as_deref(),
    ] {
        command.push(b' ');
        append_optional_base64(&mut command, value.map(str::as_bytes));
    }
    command.push(b' ');
    match request.active {
        Some(true) => command.push(b'1'),
        Some(false) => command.push(b'0'),
        None => command.push(b'-'),
    }
    command.push(b' ');
    append_optional_base64(
        &mut command,
        request.resource_type.as_deref().map(str::as_bytes),
    );
    command.push(b' ');
    match request.resources.as_ref().map(|value| value.action) {
        Some(TagResourceUpdateAction::Add) => command.extend_from_slice(b"add"),
        Some(TagResourceUpdateAction::Remove) => command.extend_from_slice(b"remove"),
        Some(TagResourceUpdateAction::Set) => command.extend_from_slice(b"set"),
        None => command.push(b'-'),
    }
    command.push(b' ');
    append_optional_base64(
        &mut command,
        request
            .resources
            .as_ref()
            .map(|value| joined_resource_ids(&value.resource_ids))
            .as_deref()
            .map(str::as_bytes),
    );
    command.push(b' ');
    append_optional_base64(
        &mut command,
        request
            .resources
            .as_ref()
            .and_then(|value| value.resource_filter.as_deref())
            .map(str::as_bytes),
    );
    command.push(b'\n');
    bounded_tag_control_frame(command)
}

fn append_optional_base64(command: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            command.push(b'+');
            command.extend_from_slice(STANDARD.encode(value).as_bytes());
        }
        None => command.push(b'-'),
    }
}

fn joined_resource_ids(resource_ids: &[String]) -> String {
    resource_ids.join("\n")
}

fn bounded_tag_control_frame(command: Vec<u8>) -> Result<ScrubbedControlFrame, ApiError> {
    if command.len() >= MAX_CONTROL_REQUEST_BYTES {
        Err(ApiError::RequestTooLarge)
    } else {
        Ok(ScrubbedControlFrame::new(command))
    }
}

pub(crate) fn parse_tag_modify_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 modified" => Ok(()),
        b"1 tag_not_found" | b"4 resource_not_found" | b"5 no_resources" => Err(ApiError::NotFound),
        b"3 invalid_action" => Err(ApiError::BadRequest(
            "The tag resource action is invalid.".to_string(),
        )),
        b"6 too_many_resources" => Err(ApiError::BadRequest(
            "The tag resource selection is too large.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The tag control request was rejected.".to_string(),
        )),
        b"-1 internal" => Err(ApiError::ControlFailure),
        _ => Err(ApiError::MutationOutcomeIndeterminate),
    }
}

#[cfg(test)]
#[path = "tag_control_tests.rs"]
mod tag_control_tests;
