// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::errors::ApiError;

pub(crate) const MAX_SCHEDULE_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_SCHEDULE_TIMEZONE_BYTES: usize = 256;
pub(crate) const MAX_SCHEDULE_ICALENDAR_BYTES: usize = 32768;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScheduleCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) timezone: Option<String>,
    pub(crate) icalendar: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchedulePatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScheduleCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) timezone: String,
    pub(crate) icalendar: String,
}

pub(crate) fn validate_schedule_create_request(
    request: ScheduleCreateRequest,
) -> Result<ValidatedScheduleCreate, ApiError> {
    Ok(ValidatedScheduleCreate {
        name: normalize_required_schedule_text(request.name, "name")?,
        comment: normalize_optional_schedule_text(request.comment, "comment")?.unwrap_or_default(),
        timezone: normalize_schedule_timezone(request.timezone)?.unwrap_or_default(),
        icalendar: normalize_schedule_icalendar(request.icalendar)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScheduleCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

fn normalize_schedule_timezone(value: Option<String>) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            let value = value.trim().to_string();
            if value.len() > MAX_SCHEDULE_TIMEZONE_BYTES || value.chars().any(char::is_control) {
                return Err(ApiError::BadRequest(format!(
                    "timezone must be printable text up to {MAX_SCHEDULE_TIMEZONE_BYTES} bytes"
                )));
            }
            Ok(value)
        })
        .transpose()
}

fn normalize_schedule_icalendar(value: String) -> Result<String, ApiError> {
    if value.trim().is_empty() {
        return Err(ApiError::BadRequest("icalendar is required".to_string()));
    }
    if value.len() > MAX_SCHEDULE_ICALENDAR_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(ApiError::BadRequest(format!(
            "icalendar must be calendar text up to {MAX_SCHEDULE_ICALENDAR_BYTES} bytes without unsupported control characters"
        )));
    }
    Ok(value)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedSchedulePatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScheduleClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_schedule_patch_request(
    request: SchedulePatchRequest,
) -> Result<ValidatedSchedulePatch, ApiError> {
    let validated = ValidatedSchedulePatch {
        name: normalize_optional_required_schedule_text(request.name, "name")?,
        comment: normalize_optional_schedule_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "schedule patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_schedule_clone_request(
    request: ScheduleCloneRequest,
) -> Result<ValidatedScheduleClone, ApiError> {
    Ok(ValidatedScheduleClone {
        name: normalize_optional_required_schedule_text(request.name, "name")?,
        comment: normalize_optional_schedule_text(request.comment, "comment")?,
    })
}

fn normalize_optional_required_schedule_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_schedule_text(value, field_name))
        .transpose()
}

fn normalize_required_schedule_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_schedule_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_schedule_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_schedule_text_value(value, field_name))
        .transpose()
}

fn normalize_schedule_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCHEDULE_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCHEDULE_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
