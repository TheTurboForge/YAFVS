// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::parse_uuid};

pub(crate) const MAX_TARGET_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) alive_tests: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allow_simultaneous_ips: Option<bool>,
    #[serde(default)]
    pub(crate) reverse_lookup_only: Option<bool>,
    #[serde(default)]
    pub(crate) reverse_lookup_unify: Option<bool>,
    #[serde(default)]
    pub(crate) port_list_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTargetPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) alive_test: Option<i32>,
    pub(crate) allow_simultaneous_ips: Option<i32>,
    pub(crate) reverse_lookup_only: Option<i32>,
    pub(crate) reverse_lookup_unify: Option<i32>,
    pub(crate) port_list_id: Option<String>,
}

impl ValidatedTargetPatch {
    pub(crate) fn changes_task_in_use_guarded_scan_settings(&self) -> bool {
        self.allow_simultaneous_ips.is_some()
            || self.reverse_lookup_only.is_some()
            || self.reverse_lookup_unify.is_some()
            || self.port_list_id.is_some()
    }
}

pub(crate) fn validate_target_patch_request(
    request: TargetPatchRequest,
) -> Result<ValidatedTargetPatch, ApiError> {
    let validated = ValidatedTargetPatch {
        name: normalize_optional_required_target_text(request.name, "name")?,
        comment: normalize_optional_target_text(request.comment, "comment")?,
        alive_test: validate_alive_tests(request.alive_tests)?,
        allow_simultaneous_ips: bool_option_to_int(request.allow_simultaneous_ips),
        reverse_lookup_only: bool_option_to_int(request.reverse_lookup_only),
        reverse_lookup_unify: bool_option_to_int(request.reverse_lookup_unify),
        port_list_id: validate_optional_uuid(request.port_list_id, "port_list_id")?,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.alive_test.is_none()
        && validated.allow_simultaneous_ips.is_none()
        && validated.reverse_lookup_only.is_none()
        && validated.reverse_lookup_unify.is_none()
        && validated.port_list_id.is_none()
    {
        return Err(ApiError::BadRequest(
            "target patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn bool_option_to_int(value: Option<bool>) -> Option<i32> {
    value.map(i32::from)
}

fn validate_optional_uuid(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                return Err(ApiError::BadRequest(format!("{field_name} is required")));
            }
            Ok(parse_uuid(value)?.to_string())
        })
        .transpose()
}

fn normalize_optional_required_target_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_target_text(value, field_name))
        .transpose()
}

fn normalize_required_target_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_target_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_target_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_target_text_value(value, field_name))
        .transpose()
}

fn normalize_target_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_TARGET_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_TARGET_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

pub(crate) fn validate_alive_tests(value: Option<Vec<String>>) -> Result<Option<i32>, ApiError> {
    let Some(values) = value else {
        return Ok(None);
    };
    if values.is_empty() {
        return Ok(Some(0));
    }
    let mut bitfield = 0;
    let mut saw_default = false;
    let mut saw_consider_alive = false;
    for value in values {
        match value.as_str() {
            "Scan Config Default" => saw_default = true,
            "Consider Alive" => saw_consider_alive = true,
            "TCP-ACK Service Ping" => bitfield |= 1,
            "ICMP Ping" => bitfield |= 2,
            "ARP Ping" => bitfield |= 4,
            "TCP-SYN Service Ping" => bitfield |= 16,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "unsupported alive_tests value: {value}"
                )));
            }
        }
    }
    if saw_default && (saw_consider_alive || bitfield != 0) {
        return Err(ApiError::BadRequest(
            "Scan Config Default cannot be combined with other alive_tests values".to_string(),
        ));
    }
    if saw_consider_alive && bitfield != 0 {
        return Err(ApiError::BadRequest(
            "Consider Alive cannot be combined with probe alive_tests values".to_string(),
        ));
    }
    if saw_default {
        Ok(Some(0))
    } else if saw_consider_alive {
        Ok(Some(8))
    } else {
        Ok(Some(bitfield))
    }
}
