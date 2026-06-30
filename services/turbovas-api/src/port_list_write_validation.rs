// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::errors::ApiError;

pub(crate) const MAX_PORT_LIST_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_PORT_LIST_CREATE_RANGES: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) port_ranges: Option<Vec<PortListCreateRangeRequest>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) port_ranges: Vec<PortListCreateRangeRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCreateRangeRequest {
    pub(crate) protocol: String,
    pub(crate) start: i32,
    pub(crate) end: i32,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) port_ranges: Option<Vec<ValidatedPortListCreateRange>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) port_ranges: Vec<ValidatedPortListCreateRange>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedPortListCreateRange {
    pub(crate) protocol_id: i32,
    pub(crate) start: i32,
    pub(crate) end: i32,
    pub(crate) comment: String,
}

pub(crate) fn validate_port_list_create_request(
    request: PortListCreateRequest,
) -> Result<ValidatedPortListCreate, ApiError> {
    let name = normalize_required_port_list_text(request.name, "name")?;
    let comment =
        normalize_optional_port_list_text(request.comment, "comment")?.unwrap_or_default();
    let port_ranges = validate_port_list_ranges(request.port_ranges, "port list create request")?;
    Ok(ValidatedPortListCreate {
        name,
        comment,
        port_ranges,
    })
}

fn validate_port_list_create_range(
    range: PortListCreateRangeRequest,
) -> Result<ValidatedPortListCreateRange, ApiError> {
    let protocol_id = match range.protocol.trim().to_ascii_lowercase().as_str() {
        "tcp" => 0,
        "udp" => 1,
        _ => {
            return Err(ApiError::BadRequest(
                "port range protocol must be tcp or udp".to_string(),
            ));
        }
    };
    if !(1..=65535).contains(&range.start) || !(1..=65535).contains(&range.end) {
        return Err(ApiError::BadRequest(
            "port range start and end must be between 1 and 65535".to_string(),
        ));
    }
    if range.end < range.start {
        return Err(ApiError::BadRequest(
            "port range end must be greater than or equal to start".to_string(),
        ));
    }
    Ok(ValidatedPortListCreateRange {
        protocol_id,
        start: range.start,
        end: range.end,
        comment: normalize_optional_port_list_text(range.comment, "port range comment")?
            .unwrap_or_default(),
    })
}

pub(crate) fn validate_port_list_patch_request(
    request: PortListPatchRequest,
) -> Result<ValidatedPortListPatch, ApiError> {
    let port_ranges = request
        .port_ranges
        .map(|ranges| validate_port_list_ranges(ranges, "port list patch request"))
        .transpose()?;
    let validated = ValidatedPortListPatch {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
        port_ranges,
    };
    if validated.name.is_none() && validated.comment.is_none() && validated.port_ranges.is_none() {
        return Err(ApiError::BadRequest(
            "port list patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_port_list_clone_request(
    request: PortListCloneRequest,
) -> Result<ValidatedPortListClone, ApiError> {
    Ok(ValidatedPortListClone {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
    })
}

fn validate_port_list_ranges(
    ranges: Vec<PortListCreateRangeRequest>,
    request_name: &str,
) -> Result<Vec<ValidatedPortListCreateRange>, ApiError> {
    if ranges.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{request_name} must include at least one port range"
        )));
    }
    if ranges.len() > MAX_PORT_LIST_CREATE_RANGES {
        return Err(ApiError::BadRequest(format!(
            "{request_name} may include at most {MAX_PORT_LIST_CREATE_RANGES} ranges"
        )));
    }
    let mut ranges = ranges
        .into_iter()
        .map(validate_port_list_create_range)
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_by_key(|range| (range.protocol_id, range.start, range.end));
    for pair in ranges.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.protocol_id == current.protocol_id && previous.end >= current.start {
            return Err(ApiError::BadRequest(format!(
                "{request_name} contains overlapping ranges"
            )));
        }
    }
    Ok(ranges)
}

fn normalize_optional_required_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_port_list_text(value, field_name))
        .transpose()
}

fn normalize_required_port_list_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_port_list_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_port_list_text_value(value, field_name))
        .transpose()
}

fn normalize_port_list_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_PORT_LIST_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_PORT_LIST_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
