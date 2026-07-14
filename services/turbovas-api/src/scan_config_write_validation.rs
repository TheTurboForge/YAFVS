// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use serde::Deserialize;

use crate::{
    errors::ApiError,
    path_ids::{validate_nvt_oid, validate_scan_config_family},
};

pub(crate) const MAX_SCAN_CONFIG_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_SCAN_CONFIG_FAMILY_SELECTIONS: usize = 512;
pub(crate) const MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES: usize = 1024;
pub(crate) const WHOLE_ONLY_SCAN_CONFIG_FAMILIES: &[&str] = &[
    "AIX Local Security Checks",
    "AlmaLinux Local Security Checks",
    "Amazon Linux Local Security Checks",
    "Arch Linux Local Security Checks",
    "CentOS Local Security Checks",
    "Debian Local Security Checks",
    "Fedora Local Security Checks",
    "FreeBSD Local Security Checks",
    "Gentoo Local Security Checks",
    "HCE Local Security Checks",
    "HP-UX Local Security Checks",
    "Huawei EulerOS Local Security Checks",
    "Mageia Linux Local Security Checks",
    "Mandrake Local Security Checks",
    "openEuler Local Security Checks",
    "openSUSE Local Security Checks",
    "Oracle Linux Local Security Checks",
    "Red Hat Local Security Checks",
    "Rocky Linux Local Security Checks",
    "Slackware Local Security Checks",
    "Solaris Local Security Checks",
    "SuSE Local Security Checks",
    "Ubuntu Local Security Checks",
    "VMware Local Security Checks",
    "Windows : Microsoft Bulletins",
    "Windows Local Security Checks",
];

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
pub(crate) struct ScanConfigFamilySelectionRequest {
    pub(crate) families_growing: bool,
    pub(crate) families: Vec<ScanConfigFamilySelectionItem>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigFamilySelectionItem {
    pub(crate) name: String,
    pub(crate) growing: bool,
    pub(crate) selected: bool,
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
    #[serde(default)]
    pub(crate) family_selection: Option<ScanConfigFamilySelectionRequest>,
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
    pub(crate) family_selection: Option<ValidatedScanConfigFamilySelection>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigFamilySelection {
    pub(crate) families_growing: bool,
    pub(crate) families: Vec<ScanConfigFamilySelectionItem>,
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
        family_selection: request
            .family_selection
            .map(validate_scan_config_family_selection_request)
            .transpose()?,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.family_selection.is_none()
    {
        return Err(ApiError::BadRequest(
            "scan-config patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_scan_config_family_selection_request(
    request: ScanConfigFamilySelectionRequest,
) -> Result<ValidatedScanConfigFamilySelection, ApiError> {
    if request.families.len() > MAX_SCAN_CONFIG_FAMILY_SELECTIONS {
        return Err(ApiError::BadRequest(format!(
            "family_selection.families must contain at most {MAX_SCAN_CONFIG_FAMILY_SELECTIONS} families"
        )));
    }

    let mut seen = HashSet::with_capacity(request.families.len());
    for family in &request.families {
        validate_scan_config_family(&family.name)?;
        if !seen.insert(family.name.as_str()) {
            return Err(ApiError::BadRequest(
                "family_selection.families must not contain duplicate family names".to_string(),
            ));
        }
        let whole_only_state_is_valid =
            (family.growing && family.selected) || (!family.growing && !family.selected);
        if WHOLE_ONLY_SCAN_CONFIG_FAMILIES.contains(&family.name.as_str())
            && !whole_only_state_is_valid
        {
            return Err(ApiError::Conflict(format!(
                "whole-only family '{}' must be growing-all or static-empty",
                family.name
            )));
        }
    }

    Ok(ValidatedScanConfigFamilySelection {
        families_growing: request.families_growing,
        families: request.families,
    })
}

pub(crate) fn ensure_scan_config_family_selection_is_complete(
    request: &ValidatedScanConfigFamilySelection,
    known_families: &[String],
) -> Result<(), ApiError> {
    let requested = request
        .families
        .iter()
        .map(|family| family.name.as_str())
        .collect::<HashSet<_>>();
    let known = known_families
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if requested == known {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scan-config family inventory changed; reload the editor and retry".to_string(),
        ))
    }
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
