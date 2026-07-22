// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;
use std::collections::BTreeSet;

use crate::{
    collections::MAX_COLLECTION_FILTER_LENGTH, errors::ApiError,
    tag_resource_helpers::tag_resource_type_is_supported,
};

pub(crate) const MAX_TAG_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_TAG_RESOURCE_ID_BYTES: usize = 4096;
pub(crate) const MAX_TAG_RESOURCE_WRITE_IDS: usize = 200;
pub(crate) const MAX_TAG_RESOURCE_FILTER_BYTES: usize = 16_384;
pub(crate) const MAX_TAG_RESOURCE_SELECTION_MATCHES: u32 = 100_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagCreateRequest {
    pub(crate) name: String,
    pub(crate) resource_type: String,
    #[serde(default)]
    pub(crate) resource_ids: Vec<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<String>,
    #[serde(default = "default_tag_active")]
    pub(crate) active: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "resource_type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TagResourceSelectionRequest {
    PortList {
        #[serde(default)]
        search: Option<String>,
        #[serde(default)]
        predefined: Option<bool>,
        expected_count: u32,
    },
    Scanner {
        #[serde(default)]
        search: Option<String>,
        expected_count: u32,
    },
    Target {
        #[serde(default)]
        search: Option<String>,
        expected_count: u32,
    },
    Credential {
        #[serde(default)]
        search: Option<String>,
        #[serde(default)]
        credential_type: Option<String>,
        expected_count: u32,
    },
    User {
        #[serde(default)]
        search: Option<String>,
        expected_count: u32,
    },
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
    #[serde(default)]
    pub(crate) resource_type: Option<String>,
    #[serde(default)]
    pub(crate) resources: Option<TagResourceUpdateRequest>,
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
    #[serde(default)]
    pub(crate) resource_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) resource_filter: Option<String>,
    #[serde(default)]
    pub(crate) resource_selection: Option<TagResourceSelectionRequest>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagCreate {
    pub(crate) name: String,
    pub(crate) resource_type: String,
    pub(crate) resource_ids: Vec<String>,
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
    pub(crate) resource_type: Option<String>,
    pub(crate) resources: Option<ValidatedTagResourceUpdate>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagResourceUpdate {
    pub(crate) action: TagResourceUpdateAction,
    pub(crate) resource_ids: Vec<String>,
    pub(crate) resource_filter: Option<String>,
    pub(crate) resource_selection: Option<ValidatedTagResourceSelection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidatedTagResourceSelection {
    PortList {
        search: Option<String>,
        predefined: Option<bool>,
        expected_count: i64,
    },
    Scanner {
        search: Option<String>,
        expected_count: i64,
    },
    Target {
        search: Option<String>,
        expected_count: i64,
    },
    Credential {
        search: Option<String>,
        credential_type: Option<String>,
        expected_count: i64,
    },
    User {
        search: Option<String>,
        expected_count: i64,
    },
}

impl ValidatedTagResourceSelection {
    pub(crate) fn resource_type(&self) -> &'static str {
        match self {
            Self::PortList { .. } => "port_list",
            Self::Credential { .. } => "credential",
            Self::Scanner { .. } => "scanner",
            Self::Target { .. } => "target",
            Self::User { .. } => "user",
        }
    }
}

pub(crate) fn default_tag_active() -> bool {
    true
}

pub(crate) fn validate_tag_resource_update_request(
    request: TagResourceUpdateRequest,
) -> Result<ValidatedTagResourceUpdate, ApiError> {
    let resource_ids_present = request.resource_ids.is_some();
    let resource_ids = validate_tag_resource_ids(request.resource_ids.unwrap_or_default(), true)?;
    let resource_filter = normalize_tag_resource_filter(request.resource_filter)?;
    let resource_selection = validate_tag_resource_selection_request(request.resource_selection)?;
    validate_tag_resource_selection(
        request.action,
        resource_ids_present,
        !resource_ids.is_empty(),
        resource_filter.as_deref(),
        resource_selection.as_ref(),
    )?;
    Ok(ValidatedTagResourceUpdate {
        action: request.action,
        resource_ids,
        resource_filter,
        resource_selection,
    })
}

fn validate_tag_resource_selection(
    action: TagResourceUpdateAction,
    resource_ids_present: bool,
    resource_ids_nonempty: bool,
    resource_filter: Option<&str>,
    resource_selection: Option<&ValidatedTagResourceSelection>,
) -> Result<(), ApiError> {
    let selection_count = resource_ids_present as usize
        + resource_filter.is_some() as usize
        + resource_selection.is_some() as usize;
    if selection_count > 1 {
        return Err(ApiError::BadRequest(
            "resource_ids, resource_filter, and resource_selection are mutually exclusive"
                .to_string(),
        ));
    }
    if resource_selection.is_some() && action != TagResourceUpdateAction::Add {
        return Err(ApiError::BadRequest(
            "resource_selection currently supports only the add action".to_string(),
        ));
    }
    if action != TagResourceUpdateAction::Set
        && !resource_ids_nonempty
        && resource_filter.is_none()
        && resource_selection.is_none()
    {
        return Err(ApiError::BadRequest(
            "add and remove require resource_ids, resource_filter, or resource_selection"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_tag_resource_selection_request(
    value: Option<TagResourceSelectionRequest>,
) -> Result<Option<ValidatedTagResourceSelection>, ApiError> {
    value
        .map(|value| {
            let validate_expected_count = |expected_count: u32| {
                if expected_count == 0 || expected_count > MAX_TAG_RESOURCE_SELECTION_MATCHES {
                    Err(ApiError::BadRequest(format!(
                        "resource_selection.expected_count must be between 1 and {MAX_TAG_RESOURCE_SELECTION_MATCHES}"
                    )))
                } else {
                    Ok(i64::from(expected_count))
                }
            };
            match value {
                TagResourceSelectionRequest::PortList {
                    search,
                    predefined,
                    expected_count,
                } => Ok(ValidatedTagResourceSelection::PortList {
                    search: validate_tag_selection_text(search, "search")?,
                    predefined,
                    expected_count: validate_expected_count(expected_count)?,
                }),
                TagResourceSelectionRequest::Scanner {
                    search,
                    expected_count,
                } => Ok(ValidatedTagResourceSelection::Scanner {
                    search: validate_tag_selection_text(search, "search")?,
                    expected_count: validate_expected_count(expected_count)?,
                }),
                TagResourceSelectionRequest::Target {
                    search,
                    expected_count,
                } => Ok(ValidatedTagResourceSelection::Target {
                    search: validate_tag_selection_text(search, "search")?,
                    expected_count: validate_expected_count(expected_count)?,
                }),
                TagResourceSelectionRequest::Credential {
                    search,
                    credential_type,
                    expected_count,
                } => Ok(ValidatedTagResourceSelection::Credential {
                    search: validate_tag_selection_text(search, "search")?,
                    credential_type: validate_tag_selection_text(
                        credential_type,
                        "credential_type",
                    )?,
                    expected_count: validate_expected_count(expected_count)?,
                }),
                TagResourceSelectionRequest::User {
                    search,
                    expected_count,
                } => Ok(ValidatedTagResourceSelection::User {
                    search: validate_tag_selection_text(search, "search")?,
                    expected_count: validate_expected_count(expected_count)?,
                }),
            }
        })
        .transpose()
}

fn validate_tag_selection_text(
    value: Option<String>,
    field: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            if value.len() > MAX_COLLECTION_FILTER_LENGTH || value.chars().any(char::is_control) {
                return Err(ApiError::BadRequest(format!(
                    "resource_selection.{field} must be printable text up to {MAX_COLLECTION_FILTER_LENGTH} bytes"
                )));
            }
            Ok(value)
        })
        .transpose()
}

fn validate_tag_resource_ids(
    resource_ids: Vec<String>,
    allow_empty: bool,
) -> Result<Vec<String>, ApiError> {
    if !allow_empty && resource_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "resource_ids must contain at least one resource id".to_string(),
        ));
    }

    if resource_ids.len() > MAX_TAG_RESOURCE_WRITE_IDS {
        return Err(ApiError::BadRequest(format!(
            "resource_ids must contain at most {MAX_TAG_RESOURCE_WRITE_IDS} ids"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut normalized_resource_ids = Vec::new();
    for resource_id in resource_ids {
        let normalized = normalize_tag_resource_id(resource_id)?;
        if seen.insert(normalized.clone()) {
            normalized_resource_ids.push(normalized);
        }
    }
    Ok(normalized_resource_ids)
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
    let resource_ids = validate_tag_resource_ids(request.resource_ids, true)?;
    Ok(ValidatedTagCreate {
        name: normalize_required_tag_text(request.name, "name")?,
        resource_type: normalize_tag_write_resource_type(request.resource_type)?,
        resource_ids,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
        value: normalize_optional_tag_text(request.value, "value")?,
        active: request.active,
    })
}

pub(crate) fn validate_tag_patch_request(
    request: TagPatchRequest,
) -> Result<ValidatedTagPatch, ApiError> {
    let resource_type = request
        .resource_type
        .map(normalize_tag_write_resource_type)
        .transpose()?;
    let resources = request
        .resources
        .map(validate_tag_resource_update_request)
        .transpose()?;
    if resource_type.is_some()
        && resources.as_ref().map(|value| value.action) != Some(TagResourceUpdateAction::Set)
    {
        return Err(ApiError::BadRequest(
            "resource_type changes require an atomic resources set operation".to_string(),
        ));
    }
    let validated = ValidatedTagPatch {
        name: normalize_optional_required_tag_text(request.name, "name")?,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
        value: normalize_optional_tag_text(request.value, "value")?,
        active: request.active,
        resource_type,
        resources,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.value.is_none()
        && validated.active.is_none()
        && validated.resource_type.is_none()
        && validated.resources.is_none()
    {
        Err(ApiError::BadRequest(
            "at least one tag metadata field must be provided".to_string(),
        ))
    } else {
        Ok(validated)
    }
}

fn normalize_tag_resource_filter(value: Option<String>) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(ApiError::BadRequest(
                    "resource_filter must not be empty when provided".to_string(),
                ));
            }
            if value.len() > MAX_TAG_RESOURCE_FILTER_BYTES || value.chars().any(char::is_control) {
                return Err(ApiError::BadRequest(format!(
                    "resource_filter must be printable text up to {MAX_TAG_RESOURCE_FILTER_BYTES} bytes"
                )));
            }
            Ok(value)
        })
        .transpose()
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
