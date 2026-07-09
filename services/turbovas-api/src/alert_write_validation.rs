// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::errors::ApiError;

pub(crate) const MAX_ALERT_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedAlertPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedAlertClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_alert_patch_request(
    request: AlertPatchRequest,
) -> Result<ValidatedAlertPatch, ApiError> {
    let validated = ValidatedAlertPatch {
        name: normalize_optional_required_alert_text(request.name, "name")?,
        comment: normalize_optional_alert_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "alert patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_alert_clone_request(
    request: AlertCloneRequest,
) -> Result<ValidatedAlertClone, ApiError> {
    Ok(ValidatedAlertClone {
        name: normalize_optional_required_alert_text(request.name, "name")?,
        comment: normalize_optional_alert_text(request.comment, "comment")?,
    })
}

fn normalize_optional_required_alert_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_alert_text(value, field_name))
        .transpose()
}

fn normalize_required_alert_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_alert_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_alert_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_alert_text_value(value, field_name))
        .transpose()
}

fn normalize_alert_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_ALERT_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_ALERT_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
