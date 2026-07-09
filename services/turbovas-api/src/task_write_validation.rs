// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::parse_uuid};

pub(crate) const MAX_TASK_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) target_id: String,
    pub(crate) config_id: String,
    pub(crate) scanner_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTaskPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTaskCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) target_id: String,
    pub(crate) config_id: String,
    pub(crate) scanner_id: String,
}

pub(crate) fn validate_task_create_request(
    request: TaskCreateRequest,
) -> Result<ValidatedTaskCreate, ApiError> {
    Ok(ValidatedTaskCreate {
        name: normalize_required_task_text(request.name, "name")?,
        comment: normalize_optional_task_text(request.comment, "comment")?,
        target_id: normalize_task_uuid(request.target_id, "target_id")?,
        config_id: normalize_task_uuid(request.config_id, "config_id")?,
        scanner_id: normalize_task_uuid(request.scanner_id, "scanner_id")?,
    })
}

pub(crate) fn validate_task_patch_request(
    request: TaskPatchRequest,
) -> Result<ValidatedTaskPatch, ApiError> {
    let validated = ValidatedTaskPatch {
        name: normalize_optional_required_task_text(request.name, "name")?,
        comment: normalize_optional_task_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "task patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_optional_required_task_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_task_text(value, field_name))
        .transpose()
}

fn normalize_required_task_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_task_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_task_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_task_text_value(value, field_name))
        .transpose()
}

fn normalize_task_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_TASK_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_TASK_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_task_uuid(value: String, field_name: &str) -> Result<String, ApiError> {
    parse_uuid(value.trim())
        .map(|uuid| uuid.to_string())
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be a UUID")))
}
