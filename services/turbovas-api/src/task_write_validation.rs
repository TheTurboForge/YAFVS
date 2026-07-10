// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::parse_uuid};

pub(crate) const MAX_TASK_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_TASK_ALERTS: usize = 5;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskHostsOrdering {
    Random,
    Sequential,
    Reverse,
}

impl TaskHostsOrdering {
    fn preference_value(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Sequential => "sequential",
            Self::Reverse => "reverse",
        }
    }
}

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
    #[serde(default)]
    pub(crate) schedule_id: Option<String>,
    #[serde(default)]
    pub(crate) alert_ids: Vec<String>,
    #[serde(default)]
    pub(crate) hosts_ordering: Option<TaskHostsOrdering>,
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
    pub(crate) schedule_id: Option<String>,
    pub(crate) alert_ids: Vec<String>,
    pub(crate) hosts_ordering: Option<String>,
}

pub(crate) fn validate_task_create_request(
    request: TaskCreateRequest,
) -> Result<ValidatedTaskCreate, ApiError> {
    if request.alert_ids.len() > MAX_TASK_ALERTS {
        return Err(ApiError::BadRequest(format!(
            "alert_ids must contain at most {MAX_TASK_ALERTS} entries"
        )));
    }

    let schedule_id = request
        .schedule_id
        .map(|value| normalize_task_uuid(value, "schedule_id"))
        .transpose()?;
    let mut alert_ids = Vec::with_capacity(request.alert_ids.len());
    let mut unique_alert_ids = HashSet::with_capacity(request.alert_ids.len());
    for alert_id in request.alert_ids {
        let alert_id = normalize_task_uuid(alert_id, "alert_ids")?;
        if !unique_alert_ids.insert(alert_id.clone()) {
            return Err(ApiError::BadRequest(
                "alert_ids must not contain duplicates".to_string(),
            ));
        }
        alert_ids.push(alert_id);
    }

    Ok(ValidatedTaskCreate {
        name: normalize_required_task_text(request.name, "name")?,
        comment: normalize_optional_task_text(request.comment, "comment")?,
        target_id: normalize_task_uuid(request.target_id, "target_id")?,
        config_id: normalize_task_uuid(request.config_id, "config_id")?,
        scanner_id: normalize_task_uuid(request.scanner_id, "scanner_id")?,
        schedule_id,
        alert_ids,
        hosts_ordering: request
            .hosts_ordering
            .map(|ordering| ordering.preference_value().to_string()),
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
