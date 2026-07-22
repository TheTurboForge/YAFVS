// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashSet;

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::parse_uuid};

pub(crate) const MAX_SCOPE_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) protection_requirement: Option<String>,
    #[serde(default)]
    pub(crate) target_ids: Vec<String>,
    #[serde(default)]
    pub(crate) host_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopePatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) protection_requirement: Option<String>,
    #[serde(default)]
    pub(crate) target_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) host_ids: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScopeCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) protection_requirement: String,
    pub(crate) target_ids: Vec<String>,
    pub(crate) host_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScopePatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) protection_requirement: Option<String>,
    pub(crate) target_ids: Option<Vec<String>>,
    pub(crate) host_ids: Option<Vec<String>>,
}

pub(crate) fn validate_scope_create_request(
    request: ScopeCreateRequest,
) -> Result<ValidatedScopeCreate, ApiError> {
    Ok(ValidatedScopeCreate {
        name: normalize_required_scope_text(request.name, "name")?,
        comment: normalize_optional_scope_text(request.comment, "comment")?,
        protection_requirement: normalize_protection_requirement(
            request.protection_requirement.as_deref(),
        )?
        .unwrap_or_else(|| "normal".to_string()),
        target_ids: normalize_membership_ids(request.target_ids, "target_ids")?,
        host_ids: normalize_membership_ids(request.host_ids, "host_ids")?,
    })
}

pub(crate) fn validate_scope_patch_request(
    request: ScopePatchRequest,
) -> Result<ValidatedScopePatch, ApiError> {
    Ok(ValidatedScopePatch {
        name: normalize_optional_scope_text(request.name, "name")?,
        comment: normalize_optional_scope_text(request.comment, "comment")?,
        protection_requirement: normalize_protection_requirement(
            request.protection_requirement.as_deref(),
        )?,
        target_ids: normalize_optional_membership_ids(request.target_ids, "target_ids")?,
        host_ids: normalize_optional_membership_ids(request.host_ids, "host_ids")?,
    })
}

fn normalize_required_scope_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_scope_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_scope_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_scope_text_value(value, field_name))
        .transpose()
}

fn normalize_scope_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCOPE_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCOPE_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_protection_requirement(value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    match normalized.as_str() {
        "" => Ok(None),
        "normal" | "high" | "very_high" => Ok(Some(normalized)),
        _ => Err(ApiError::BadRequest(
            "protection_requirement must be normal, high, or very_high".to_string(),
        )),
    }
}

fn normalize_optional_membership_ids(
    values: Option<Vec<String>>,
    field_name: &str,
) -> Result<Option<Vec<String>>, ApiError> {
    values
        .map(|values| normalize_membership_ids(values, field_name))
        .transpose()
}

fn normalize_membership_ids(
    values: Vec<String>,
    field_name: &str,
) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let parsed = parse_uuid(value.trim())?.to_string();
        if !seen.insert(parsed.clone()) {
            return Err(ApiError::Conflict(format!(
                "{field_name} contains duplicate ids"
            )));
        }
        normalized.push(parsed);
    }
    Ok(normalized)
}
