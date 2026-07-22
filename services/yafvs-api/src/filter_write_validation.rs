// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Deserialize;

use crate::errors::ApiError;

pub(crate) const MAX_FILTER_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) filter_type: Option<String>,
    #[serde(default)]
    pub(crate) term: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) filter_type: Option<String>,
    #[serde(default)]
    pub(crate) term: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedFilterPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) filter_type: Option<String>,
    pub(crate) term: Option<String>,
}

impl ValidatedFilterPatch {
    pub(crate) fn changes_alert_linked_type(&self) -> bool {
        self.filter_type.is_some()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedFilterCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) filter_type: String,
    pub(crate) term: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedFilterClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_filter_create_request(
    request: FilterCreateRequest,
) -> Result<ValidatedFilterCreate, ApiError> {
    Ok(ValidatedFilterCreate {
        name: normalize_required_filter_text(request.name, "name")?,
        comment: normalize_optional_filter_text(request.comment, "comment")?.unwrap_or_default(),
        filter_type: normalize_filter_type(request.filter_type)?,
        term: normalize_optional_filter_text(request.term, "term")?.unwrap_or_default(),
    })
}

pub(crate) fn validate_filter_patch_request(
    request: FilterPatchRequest,
) -> Result<ValidatedFilterPatch, ApiError> {
    let validated = ValidatedFilterPatch {
        name: normalize_optional_required_filter_text(request.name, "name")?,
        comment: normalize_optional_filter_text(request.comment, "comment")?,
        filter_type: normalize_optional_filter_type(request.filter_type)?,
        term: normalize_optional_filter_text(request.term, "term")?,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.filter_type.is_none()
        && validated.term.is_none()
    {
        return Err(ApiError::BadRequest(
            "filter patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_filter_clone_request(
    request: FilterCloneRequest,
) -> Result<ValidatedFilterClone, ApiError> {
    Ok(ValidatedFilterClone {
        name: normalize_optional_required_filter_text(request.name, "name")?,
        comment: normalize_optional_filter_text(request.comment, "comment")?,
    })
}

fn normalize_optional_required_filter_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_filter_text(value, field_name))
        .transpose()
}

fn normalize_required_filter_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_filter_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_filter_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_filter_text_value(value, field_name))
        .transpose()
}

fn normalize_filter_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_FILTER_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_FILTER_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_filter_type(value: Option<String>) -> Result<String, ApiError> {
    let Some(value) = value else {
        return Ok(String::new());
    };
    let value = normalize_filter_text_value(value, "filter_type")?;
    if value.is_empty() {
        return Ok(String::new());
    }
    let normalized = match value.to_ascii_lowercase().as_str() {
        "alert" => "alert",
        "asset" => "asset",
        "config" | "scan config" => "config",
        "credential" => "credential",
        "filter" => "filter",
        "group" => "group",
        "host" => "host",
        "info" | "secinfo" => "info",
        "os" => "os",
        "override" => "override",
        "permission" => "permission",
        "port_list" | "port list" => "port_list",
        "report" => "report",
        "report_format" | "report format" => "report_format",
        "result" => "result",
        "role" => "role",
        "scope" => "scope",
        "scope_report" | "scope report" => "scope_report",
        "scanner" => "scanner",
        "schedule" => "schedule",
        "tag" => "tag",
        "target" => "target",
        "task" => "task",
        "tls_certificate" | "tls certificate" => "tls_certificate",
        "user" => "user",
        "vuln" => "vuln",
        _ => {
            return Err(ApiError::BadRequest(
                "filter_type is not a supported saved-filter resource type".to_string(),
            ));
        }
    };
    Ok(normalized.to_string())
}

fn normalize_optional_filter_type(value: Option<String>) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_filter_type(Some(value)))
        .transpose()
}
