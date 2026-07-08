// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;
use std::collections::BTreeSet;

use crate::{errors::ApiError, tag_resource_helpers::tag_resource_type_is_supported};

pub(crate) const MAX_TAG_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_TAG_RESOURCE_ID_BYTES: usize = 4096;
pub(crate) const MAX_TAG_RESOURCE_WRITE_IDS: usize = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagCreateRequest {
    pub(crate) name: String,
    pub(crate) resource_type: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<String>,
    #[serde(default = "default_tag_active")]
    pub(crate) active: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<String>,
    #[serde(default)]
    pub(crate) active: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TagResourceUpdateAction {
    Add,
    Remove,
    Set,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagResourceUpdateRequest {
    pub(crate) action: TagResourceUpdateAction,
    pub(crate) resource_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagCreate {
    pub(crate) name: String,
    pub(crate) resource_type: String,
    pub(crate) comment: Option<String>,
    pub(crate) value: Option<String>,
    pub(crate) active: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) value: Option<String>,
    pub(crate) active: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagResourceUpdate {
    pub(crate) action: TagResourceUpdateAction,
    pub(crate) resource_ids: Vec<String>,
}

pub(crate) fn default_tag_active() -> bool {
    true
}

pub(crate) fn validate_tag_resource_update_request(
    request: TagResourceUpdateRequest,
) -> Result<ValidatedTagResourceUpdate, ApiError> {
    if request.resource_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "resource_ids must contain at least one resource id".to_string(),
        ));
    }

    if request.resource_ids.len() > MAX_TAG_RESOURCE_WRITE_IDS {
        return Err(ApiError::BadRequest(format!(
            "resource_ids must contain at most {MAX_TAG_RESOURCE_WRITE_IDS} ids"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut resource_ids = Vec::new();
    for resource_id in request.resource_ids {
        let normalized = normalize_tag_resource_id(resource_id)?;
        if seen.insert(normalized.clone()) {
            resource_ids.push(normalized);
        }
    }
    Ok(ValidatedTagResourceUpdate {
        action: request.action,
        resource_ids,
    })
}

fn normalize_tag_resource_id(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(ApiError::BadRequest("resource id is required".to_string()));
    }
    if value.len() > MAX_TAG_RESOURCE_ID_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "resource id must be printable text up to {MAX_TAG_RESOURCE_ID_BYTES} bytes"
        )));
    }
    Ok(value)
}

pub(crate) fn validate_tag_create_request(
    request: TagCreateRequest,
) -> Result<ValidatedTagCreate, ApiError> {
    Ok(ValidatedTagCreate {
        name: normalize_required_tag_text(request.name, "name")?,
        resource_type: normalize_tag_write_resource_type(request.resource_type)?,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
        value: normalize_optional_tag_text(request.value, "value")?,
        active: request.active,
    })
}

pub(crate) fn validate_tag_patch_request(
    request: TagPatchRequest,
) -> Result<ValidatedTagPatch, ApiError> {
    let validated = ValidatedTagPatch {
        name: normalize_optional_required_tag_text(request.name, "name")?,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
        value: normalize_optional_tag_text(request.value, "value")?,
        active: request.active,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.value.is_none()
        && validated.active.is_none()
    {
        Err(ApiError::BadRequest(
            "at least one tag metadata field must be provided".to_string(),
        ))
    } else {
        Ok(validated)
    }
}

pub(crate) fn validate_tag_clone_request(
    request: TagCloneRequest,
) -> Result<ValidatedTagClone, ApiError> {
    Ok(ValidatedTagClone {
        name: normalize_optional_required_tag_text(request.name, "name")?,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
    })
}

fn normalize_required_tag_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_tag_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_tag_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_tag_text_value(value, field_name))
        .transpose()
}

fn normalize_optional_required_tag_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_tag_text(value, field_name))
        .transpose()
}

fn normalize_tag_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_TAG_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_TAG_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_tag_write_resource_type(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(ApiError::BadRequest(
            "resource_type is required".to_string(),
        ));
    }
    if tag_resource_type_is_supported(&value) {
        Ok(value)
    } else {
        Err(ApiError::BadRequest(format!(
            "unsupported tag resource type: {value}"
        )))
    }
}
