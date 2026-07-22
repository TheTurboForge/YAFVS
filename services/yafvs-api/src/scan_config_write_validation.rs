// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashSet;

use serde::{Deserialize, Deserializer};

use crate::{
    errors::ApiError,
    path_ids::{validate_nvt_oid, validate_scan_config_family},
};

pub(crate) const MAX_SCAN_CONFIG_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_SCAN_CONFIG_FAMILY_SELECTIONS: usize = 512;
pub(crate) const MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES: usize = 1024;
pub(crate) const MAX_SCAN_CONFIG_PREFERENCE_MUTATIONS: usize = 512;
pub(crate) const MAX_SCAN_CONFIG_PREFERENCE_VALUE_BYTES: usize = 192 * 1024;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) family_selection: Option<ScanConfigFamilySelectionRequest>,
    #[serde(default)]
    pub(crate) preferences: Option<Vec<ScanConfigPreferenceMutationRequest>>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanConfigPreferenceScope {
    Scanner,
    Nvt,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanConfigPreferenceAction {
    Set,
    Reset,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigPreferenceNvtIdentityRequest {
    pub(crate) oid: String,
    pub(crate) id: i32,
    #[serde(rename = "type")]
    pub(crate) preference_type: String,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfigPreferenceMutationRequest {
    pub(crate) scope: ScanConfigPreferenceScope,
    pub(crate) name: String,
    pub(crate) action: ScanConfigPreferenceAction,
    #[serde(default)]
    pub(crate) value: Option<SensitiveScanConfigPreferenceValue>,
    #[serde(default)]
    pub(crate) nvt: Option<ScanConfigPreferenceNvtIdentityRequest>,
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

#[derive(PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) family_selection: Option<ValidatedScanConfigFamilySelection>,
    pub(crate) preferences: Option<Vec<ValidatedScanConfigPreferenceMutation>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigPreferenceNvtIdentity {
    pub(crate) oid: String,
    pub(crate) id: i32,
    pub(crate) preference_type: String,
}

#[derive(PartialEq, Eq)]
pub(crate) struct ValidatedScanConfigPreferenceMutation {
    pub(crate) scope: ScanConfigPreferenceScope,
    pub(crate) name: String,
    pub(crate) action: ScanConfigPreferenceAction,
    pub(crate) value: Option<SensitiveScanConfigPreferenceValue>,
    pub(crate) nvt: Option<ValidatedScanConfigPreferenceNvtIdentity>,
}

#[derive(PartialEq, Eq)]
pub(crate) struct SensitiveScanConfigPreferenceValue(Vec<u8>);

impl SensitiveScanConfigPreferenceValue {
    pub(crate) fn from_string(value: String) -> Self {
        Self(value.into_bytes())
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("JSON preference values are valid UTF-8")
    }
}

impl<'de> Deserialize<'de> for SensitiveScanConfigPreferenceValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from_string)
    }
}

impl Drop for SensitiveScanConfigPreferenceValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
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
        preferences: request
            .preferences
            .map(validate_scan_config_preference_mutations)
            .transpose()?,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.family_selection.is_none()
        && validated.preferences.is_none()
    {
        return Err(ApiError::BadRequest(
            "scan-config patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_scan_config_preference_mutations(
    mutations: Vec<ScanConfigPreferenceMutationRequest>,
) -> Result<Vec<ValidatedScanConfigPreferenceMutation>, ApiError> {
    if mutations.is_empty() {
        return Err(ApiError::BadRequest(
            "preferences must contain at least one mutation".to_string(),
        ));
    }
    if mutations.len() > MAX_SCAN_CONFIG_PREFERENCE_MUTATIONS {
        return Err(ApiError::BadRequest(format!(
            "preferences must contain at most {MAX_SCAN_CONFIG_PREFERENCE_MUTATIONS} mutations"
        )));
    }

    let mut seen = HashSet::with_capacity(mutations.len());
    let mut validated = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        validate_scan_config_preference_text(&mutation.name, "preferences[].name", 4096, false)?;
        let nvt = match (mutation.scope, mutation.nvt) {
            (ScanConfigPreferenceScope::Scanner, None) => None,
            (ScanConfigPreferenceScope::Scanner, Some(_)) => {
                return Err(ApiError::BadRequest(
                    "scanner preference mutations must not include nvt".to_string(),
                ));
            }
            (ScanConfigPreferenceScope::Nvt, None) => {
                return Err(ApiError::BadRequest(
                    "NVT preference mutations must include nvt".to_string(),
                ));
            }
            (ScanConfigPreferenceScope::Nvt, Some(nvt)) => {
                validate_nvt_oid(&nvt.oid).map_err(|_| {
                    ApiError::BadRequest(
                        "preferences[].nvt.oid must be a numeric dotted NVT OID up to 128 bytes"
                            .to_string(),
                    )
                })?;
                if nvt.id < 0 {
                    return Err(ApiError::BadRequest(
                        "preferences[].nvt.id must be zero or greater".to_string(),
                    ));
                }
                validate_scan_config_preference_text(
                    &nvt.preference_type,
                    "preferences[].nvt.type",
                    128,
                    false,
                )?;
                Some(ValidatedScanConfigPreferenceNvtIdentity {
                    oid: nvt.oid,
                    id: nvt.id,
                    preference_type: nvt.preference_type,
                })
            }
        };

        match mutation.action {
            ScanConfigPreferenceAction::Set => {
                let value = mutation.value.as_ref().ok_or_else(|| {
                    ApiError::BadRequest("set preference mutations must include value".to_string())
                })?;
                validate_scan_config_preference_text(
                    value.as_str(),
                    "preferences[].value",
                    MAX_SCAN_CONFIG_PREFERENCE_VALUE_BYTES,
                    true,
                )?;
                if nvt
                    .as_ref()
                    .is_some_and(|nvt| nvt.preference_type.eq_ignore_ascii_case("radio"))
                    && value.as_str().is_empty()
                {
                    return Err(ApiError::BadRequest(
                        "radio preference values must not be empty".to_string(),
                    ));
                }
            }
            ScanConfigPreferenceAction::Reset if mutation.value.is_some() => {
                return Err(ApiError::BadRequest(
                    "reset preference mutations must not include value".to_string(),
                ));
            }
            ScanConfigPreferenceAction::Reset => {}
        }

        let key = (
            match mutation.scope {
                ScanConfigPreferenceScope::Scanner => "scanner".to_string(),
                ScanConfigPreferenceScope::Nvt => "nvt".to_string(),
            },
            mutation.name.clone(),
            nvt.as_ref().map(|identity| identity.oid.clone()),
            nvt.as_ref().map(|identity| identity.id),
            nvt.as_ref()
                .map(|identity| identity.preference_type.clone()),
        );
        if !seen.insert(key) {
            return Err(ApiError::BadRequest(
                "preferences must not contain duplicate mutations".to_string(),
            ));
        }

        validated.push(ValidatedScanConfigPreferenceMutation {
            scope: mutation.scope,
            name: mutation.name,
            action: mutation.action,
            value: mutation.value,
            nvt,
        });
    }
    Ok(validated)
}

fn validate_scan_config_preference_text(
    value: &str,
    field: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), ApiError> {
    if (!allow_empty && value.is_empty()) || value.len() > max_bytes || value.contains('\0') {
        return Err(ApiError::BadRequest(format!(
            "{field} must {}contain no NUL bytes and be at most {max_bytes} bytes",
            if allow_empty { "" } else { "not be empty, " }
        )));
    }
    Ok(())
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
