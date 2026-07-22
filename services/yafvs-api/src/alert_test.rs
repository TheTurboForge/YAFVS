// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
};

use crate::{
    alert_write_db::require_alert_write_operator,
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    gvmd_control::{
        MAX_CONTROL_REQUEST_BYTES, ScrubbedControlFrame, gvmd_control_secret,
        gvmd_control_socket_path, map_control_socket_error, request_gvmd_control_response_bytes,
        validate_gvmd_control_secret,
    },
    path_ids::parse_uuid,
};

pub(crate) async fn test_alert(
    State(_state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let alert_id = parse_uuid(&alert_id)?.to_string();
    let control_secret = gvmd_control_secret()?;
    request_alert_test(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &alert_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn request_alert_test(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    alert_uuid: &str,
) -> Result<(), ApiError> {
    let command = alert_test_command(control_secret, operator_uuid, alert_uuid)?;
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_alert_test_response(&response)
}

pub(crate) fn alert_test_command(
    control_secret: &str,
    operator_uuid: &str,
    alert_uuid: &str,
) -> Result<ScrubbedControlFrame, ApiError> {
    validate_gvmd_control_secret(control_secret)?;
    let operator_uuid = parse_uuid(operator_uuid)?.to_string();
    let alert_uuid = parse_uuid(alert_uuid)?.to_string();

    let mut command = Vec::with_capacity(256);
    command.extend_from_slice(b"alert-test ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.extend_from_slice(alert_uuid.as_bytes());
    command.push(b'\n');
    if command.len() >= MAX_CONTROL_REQUEST_BYTES {
        return Err(ApiError::RequestTooLarge);
    }
    Ok(ScrubbedControlFrame::new(command))
}

pub(crate) fn parse_alert_test_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 tested" => Ok(()),
        b"1 not_found" => Err(ApiError::NotFound),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 report_format_not_found" => Err(ApiError::Conflict(
            "The alert test cannot run because its report format is unavailable.".to_string(),
        )),
        b"-3 filter_not_found" => Err(ApiError::Conflict(
            "The alert test cannot run because its filter is unavailable.".to_string(),
        )),
        b"-4 credential_not_found" => Err(ApiError::Conflict(
            "The alert test cannot run because its credential is unavailable.".to_string(),
        )),
        b"-5 delivery_failed" => Err(ApiError::ControlFailure),
        _ => Err(ApiError::ControlFailure),
    }
}
