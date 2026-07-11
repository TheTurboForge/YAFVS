// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::validate_nvt_oid};

pub(crate) const MAX_SCAN_CONFIG_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigCreateRequest {
    pub(crate) name: String,
    pub(crate) base_scan_config_id: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticNvtSelectionRequest {
    pub(crate) nvt_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedDiagnosticNvtSelection {
    pub(crate) nvt_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_diagnostic_nvt_selection_request(
    request: DiagnosticNvtSelectionRequest,
) -> Result<ValidatedDiagnosticNvtSelection, ApiError> {
    validate_nvt_oid(&request.nvt_id).map_err(|_| {
        ApiError::BadRequest("nvt_id must be a numeric dotted NVT OID up to 128 bytes".to_string())
    })?;
    Ok(ValidatedDiagnosticNvtSelection {
        nvt_id: request.nvt_id,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigCreate {
    pub(crate) name: String,
    pub(crate) base_scan_config_id: String,
    pub(crate) comment: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_scan_config_create_request(
    request: ScanConfigCreateRequest,
) -> Result<ValidatedScanConfigCreate, ApiError> {
    Ok(ValidatedScanConfigCreate {
        name: normalize_required_scan_config_text(request.name, "name")?,
        base_scan_config_id: crate::path_ids::parse_uuid(request.base_scan_config_id.trim())?
            .to_string(),
        comment: normalize_optional_scan_config_text(request.comment, "comment")?
            .unwrap_or_default(),
    })
}

pub(crate) fn validate_scan_config_clone_request(
    request: ScanConfigCloneRequest,
) -> Result<ValidatedScanConfigClone, ApiError> {
    Ok(ValidatedScanConfigClone {
        name: normalize_optional_required_scan_config_text(request.name, "name")?,
        comment: normalize_optional_scan_config_text(request.comment, "comment")?,
    })
}

pub(crate) fn validate_scan_config_patch_request(
    request: ScanConfigPatchRequest,
) -> Result<ValidatedScanConfigPatch, ApiError> {
    let validated = ValidatedScanConfigPatch {
        name: normalize_optional_required_scan_config_text(request.name, "name")?,
        comment: normalize_optional_scan_config_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "scan-config patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_optional_required_scan_config_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_scan_config_text(value, field_name))
        .transpose()
}

fn normalize_required_scan_config_text(
    value: String,
    field_name: &str,
) -> Result<String, ApiError> {
    let value = normalize_scan_config_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_scan_config_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_scan_config_text_value(value, field_name))
        .transpose()
}

fn normalize_scan_config_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCAN_CONFIG_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCAN_CONFIG_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
