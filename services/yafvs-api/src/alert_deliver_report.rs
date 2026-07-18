// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::{
    alert_write_db::require_alert_write_operator,
    app_state::AppState,
    auth::DirectApiOperator,
    collections::MAX_COLLECTION_FILTER_LENGTH,
    errors::ApiError,
    gvmd_control::{
        MAX_CONTROL_REQUEST_BYTES, ScrubbedControlFrame, gvmd_control_secret,
        gvmd_control_socket_path, map_control_socket_error, request_gvmd_control_response_bytes,
        validate_gvmd_control_secret,
    },
    path_ids::parse_uuid,
};

pub(crate) const MAX_ALERT_DELIVER_REPORT_FILTER_BYTES: usize = MAX_COLLECTION_FILTER_LENGTH;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertDeliverReportRequest {
    pub(crate) report_id: String,
    #[serde(default)]
    pub(crate) filter: Option<String>,
    #[serde(default)]
    pub(crate) filter_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedAlertDeliverReport {
    report_id: String,
    filter: Option<String>,
    filter_id: Option<String>,
}

pub(crate) async fn deliver_alert_report(
    State(_state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<AlertDeliverReportRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let alert_id = parse_uuid(&alert_id)?.to_string();
    let request = parse_alert_deliver_report_payload(payload)?;
    let request = validate_alert_deliver_report_request(request)?;
    let control_secret = gvmd_control_secret()?;
    request_alert_deliver_report(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &alert_id,
        &request,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn parse_alert_deliver_report_payload(
    payload: Result<Json<AlertDeliverReportRequest>, JsonRejection>,
) -> Result<AlertDeliverReportRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|_| {
        ApiError::BadRequest(
            "request body must be application/json matching AlertDeliverReportRequest".to_string(),
        )
    })
}

pub(crate) fn validate_alert_deliver_report_request(
    request: AlertDeliverReportRequest,
) -> Result<ValidatedAlertDeliverReport, ApiError> {
    let report_id = parse_uuid(&request.report_id)?.to_string();
    let filter = request
        .filter
        .map(normalize_alert_deliver_report_filter)
        .transpose()?;
    let filter_id = request
        .filter_id
        .map(|value| parse_uuid(&value).map(|uuid| uuid.to_string()))
        .transpose()?;
    if filter.is_some() && filter_id.is_some() {
        return Err(ApiError::BadRequest(
            "filter and filter_id are mutually exclusive".to_string(),
        ));
    }
    Ok(ValidatedAlertDeliverReport {
        report_id,
        filter,
        filter_id,
    })
}

fn normalize_alert_deliver_report_filter(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.is_empty()
        || value.len() > MAX_ALERT_DELIVER_REPORT_FILTER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "filter must be printable text up to {MAX_ALERT_DELIVER_REPORT_FILTER_BYTES} bytes"
        )));
    }
    Ok(value)
}

pub(crate) async fn request_alert_deliver_report(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    alert_uuid: &str,
    request: &ValidatedAlertDeliverReport,
) -> Result<(), ApiError> {
    let command = alert_deliver_report_command(control_secret, operator_uuid, alert_uuid, request)?;
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_alert_deliver_report_response(&response)
}

pub(crate) fn alert_deliver_report_command(
    control_secret: &str,
    operator_uuid: &str,
    alert_uuid: &str,
    request: &ValidatedAlertDeliverReport,
) -> Result<ScrubbedControlFrame, ApiError> {
    validate_gvmd_control_secret(control_secret)?;
    let operator_uuid = parse_uuid(operator_uuid)?.to_string();
    let alert_uuid = parse_uuid(alert_uuid)?.to_string();
    let filter = request
        .filter
        .as_deref()
        .map(|value| STANDARD.encode(value.as_bytes()))
        .unwrap_or_else(|| "-".to_string());
    let filter_id = request.filter_id.as_deref().unwrap_or("-");

    let mut command = Vec::with_capacity(512 + filter.len());
    for field in [
        b"alert-deliver-report ".as_slice(),
        control_secret.as_bytes(),
        b" ",
        operator_uuid.as_bytes(),
        b" ",
        alert_uuid.as_bytes(),
        b" ",
        request.report_id.as_bytes(),
        b" ",
        filter.as_bytes(),
        b" ",
        filter_id.as_bytes(),
        b"\n",
    ] {
        command.extend_from_slice(field);
    }
    if command.len() >= MAX_CONTROL_REQUEST_BYTES {
        return Err(ApiError::RequestTooLarge);
    }
    Ok(ScrubbedControlFrame::new(command))
}

pub(crate) fn parse_alert_deliver_report_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 delivered" => Ok(()),
        b"1 alert_not_found" | b"2 report_not_found" | b"3 filter_not_found" => {
            Err(ApiError::NotFound)
        }
        b"-2 report_format_not_found" => Err(ApiError::Conflict(
            "The alert delivery cannot run because its configured report format is unavailable."
                .to_string(),
        )),
        b"-3 delivery_failed" => Err(ApiError::ControlFailure),
        b"99 forbidden" => Err(ApiError::Forbidden),
        _ => Err(ApiError::ControlFailure),
    }
}
