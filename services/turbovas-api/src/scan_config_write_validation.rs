// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::validate_nvt_oid};

pub(crate) const MAX_SCAN_CONFIG_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES: usize = 1024;

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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigFamilyNvtSelectionChange {
    pub(crate) oid: String,
    pub(crate) selected: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigFamilyNvtsPatchRequest {
    pub(crate) changes: Vec<ScanConfigFamilyNvtSelectionChange>,
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigFamilyNvtSelectionChange {
    pub(crate) oid: String,
    pub(crate) selected: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigFamilyNvtsPatch {
    pub(crate) changes: Vec<ValidatedScanConfigFamilyNvtSelectionChange>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_scan_config_family_nvts_patch_request(
    request: ScanConfigFamilyNvtsPatchRequest,
) -> Result<ValidatedScanConfigFamilyNvtsPatch, ApiError> {
    if request.changes.is_empty() {
        return Err(ApiError::BadRequest(
            "changes must contain at least one NVT selection".to_string(),
        ));
    }
    if request.changes.len() > MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES {
        return Err(ApiError::BadRequest(format!(
            "changes must contain at most {MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES} NVT selections"
        )));
    }

    let mut seen_oids = HashSet::with_capacity(request.changes.len());
    let mut changes = Vec::with_capacity(request.changes.len());
    for change in request.changes {
        validate_nvt_oid(&change.oid).map_err(|_| {
            ApiError::BadRequest(
                "changes[].oid must be a numeric dotted NVT OID up to 128 bytes".to_string(),
            )
        })?;
        if !seen_oids.insert(change.oid.clone()) {
            return Err(ApiError::BadRequest(
                "changes must not contain duplicate NVT OIDs".to_string(),
            ));
        }
        changes.push(ValidatedScanConfigFamilyNvtSelectionChange {
            oid: change.oid,
            selected: change.selected,
        });
    }

    Ok(ValidatedScanConfigFamilyNvtsPatch { changes })
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
