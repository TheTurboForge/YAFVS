// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Deserializer};

use crate::{errors::ApiError, path_ids::parse_uuid};

const MAX_NVT_ID_BYTES: usize = 255;
const MAX_OVERRIDE_TEXT_BYTES: usize = 8192;
const MAX_OVERRIDE_HOSTS_BYTES: usize = 4096;
const MAX_OVERRIDE_PORT_BYTES: usize = 512;
const MAX_ACTIVE_DAYS: u32 = 36_500;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum OverrideActivation {
    Always,
    Inactive,
    ForDays { days: u32 },
}

impl Default for OverrideActivation {
    fn default() -> Self {
        Self::Always
    }
}

impl OverrideActivation {
    pub(crate) fn database_days(&self) -> Result<i32, ApiError> {
        match self {
            Self::Always => Ok(-1),
            Self::Inactive => Ok(0),
            Self::ForDays { days } if (1..=MAX_ACTIVE_DAYS).contains(days) => Ok(*days as i32),
            Self::ForDays { .. } => Err(ApiError::BadRequest(format!(
                "activation days must be between 1 and {MAX_ACTIVE_DAYS}"
            ))),
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub(crate) enum PatchField<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<'de, T> Deserialize<'de> for PatchField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OverrideCreateRequest {
    pub(crate) nvt_id: String,
    pub(crate) text: String,
    #[serde(default)]
    pub(crate) hosts: Option<String>,
    #[serde(default)]
    pub(crate) port: Option<String>,
    #[serde(default)]
    pub(crate) severity: Option<f64>,
    pub(crate) new_severity: f64,
    #[serde(default)]
    pub(crate) task_id: Option<String>,
    #[serde(default)]
    pub(crate) result_id: Option<String>,
    #[serde(default)]
    pub(crate) activation: OverrideActivation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OverridePatchRequest {
    #[serde(default)]
    pub(crate) nvt_id: Option<String>,
    #[serde(default)]
    pub(crate) text: Option<String>,
    #[serde(default)]
    pub(crate) hosts: PatchField<String>,
    #[serde(default)]
    pub(crate) port: PatchField<String>,
    #[serde(default)]
    pub(crate) severity: PatchField<f64>,
    #[serde(default)]
    pub(crate) new_severity: Option<f64>,
    #[serde(default)]
    pub(crate) task_id: PatchField<String>,
    #[serde(default)]
    pub(crate) result_id: PatchField<String>,
    #[serde(default)]
    pub(crate) activation: Option<OverrideActivation>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OverrideCloneRequest {}

#[derive(Debug, PartialEq)]
pub(crate) struct ValidatedOverrideCreate {
    pub(crate) nvt_id: String,
    pub(crate) text: String,
    pub(crate) hosts: Option<String>,
    pub(crate) port: Option<String>,
    pub(crate) severity: Option<f64>,
    pub(crate) new_severity: f64,
    pub(crate) task_id: Option<String>,
    pub(crate) result_id: Option<String>,
    pub(crate) active_days: i32,
}

#[derive(Debug, PartialEq)]
pub(crate) struct ValidatedOverridePatch {
    pub(crate) nvt_id: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) hosts: PatchField<String>,
    pub(crate) port: PatchField<String>,
    pub(crate) severity: PatchField<f64>,
    pub(crate) new_severity: Option<f64>,
    pub(crate) task_id: PatchField<String>,
    pub(crate) result_id: PatchField<String>,
    pub(crate) active_days: Option<i32>,
}

pub(crate) fn validate_override_create_request(
    request: OverrideCreateRequest,
) -> Result<ValidatedOverrideCreate, ApiError> {
    Ok(ValidatedOverrideCreate {
        nvt_id: normalize_nvt_id(request.nvt_id)?,
        text: normalize_override_text(request.text)?,
        hosts: normalize_optional_text(request.hosts, "hosts", MAX_OVERRIDE_HOSTS_BYTES)?,
        port: normalize_port(request.port)?,
        severity: validate_optional_severity(request.severity, false)?,
        new_severity: validate_severity(request.new_severity, true, "new_severity")?,
        task_id: normalize_optional_uuid(request.task_id, "task_id")?,
        result_id: normalize_optional_uuid(request.result_id, "result_id")?,
        active_days: request.activation.database_days()?,
    })
}

pub(crate) fn validate_override_patch_request(
    request: OverridePatchRequest,
) -> Result<ValidatedOverridePatch, ApiError> {
    let patch = ValidatedOverridePatch {
        nvt_id: request.nvt_id.map(normalize_nvt_id).transpose()?,
        text: request.text.map(normalize_override_text).transpose()?,
        hosts: normalize_patch_text(request.hosts, "hosts", MAX_OVERRIDE_HOSTS_BYTES)?,
        port: normalize_patch_port(request.port)?,
        severity: validate_patch_severity(request.severity, false, "severity")?,
        new_severity: request
            .new_severity
            .map(|value| validate_severity(value, true, "new_severity"))
            .transpose()?,
        task_id: normalize_patch_uuid(request.task_id, "task_id")?,
        result_id: normalize_patch_uuid(request.result_id, "result_id")?,
        active_days: request
            .activation
            .map(|activation| activation.database_days())
            .transpose()?,
    };
    if patch.nvt_id.is_none()
        && patch.text.is_none()
        && patch.hosts == PatchField::Missing
        && patch.port == PatchField::Missing
        && patch.severity == PatchField::Missing
        && patch.new_severity.is_none()
        && patch.task_id == PatchField::Missing
        && patch.result_id == PatchField::Missing
        && patch.active_days.is_none()
    {
        return Err(ApiError::BadRequest(
            "override patch request must include at least one field".to_string(),
        ));
    }
    Ok(patch)
}

fn normalize_nvt_id(value: String) -> Result<String, ApiError> {
    let value = normalize_bounded_text(value, "nvt_id", MAX_NVT_ID_BYTES, false)?;
    if value.is_empty() || value == "0" {
        Err(ApiError::BadRequest("nvt_id is required".to_string()))
    } else {
        Ok(value)
    }
}

fn normalize_override_text(value: String) -> Result<String, ApiError> {
    normalize_bounded_text(value, "text", MAX_OVERRIDE_TEXT_BYTES, true)
}

fn normalize_optional_text(
    value: Option<String>,
    field_name: &str,
    max_bytes: usize,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_bounded_text(value, field_name, max_bytes, false))
        .transpose()
        .map(|value| value.filter(|value| !value.is_empty()))
}

fn normalize_patch_text(
    value: PatchField<String>,
    field_name: &str,
    max_bytes: usize,
) -> Result<PatchField<String>, ApiError> {
    match value {
        PatchField::Missing => Ok(PatchField::Missing),
        PatchField::Null => Ok(PatchField::Null),
        PatchField::Value(value) => {
            let value = normalize_bounded_text(value, field_name, max_bytes, false)?;
            if value.is_empty() {
                Ok(PatchField::Null)
            } else {
                Ok(PatchField::Value(value))
            }
        }
    }
}

fn normalize_bounded_text(
    value: String,
    field_name: &str,
    max_bytes: usize,
    allow_line_controls: bool,
) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    let forbidden_control = value.chars().any(|character| {
        character.is_control() && !(allow_line_controls && matches!(character, '\n' | '\r' | '\t'))
    });
    if value.len() > max_bytes || forbidden_control {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be bounded printable text up to {max_bytes} bytes"
        )));
    }
    Ok(value)
}

fn normalize_port(value: Option<String>) -> Result<Option<String>, ApiError> {
    let value = normalize_optional_text(value, "port", MAX_OVERRIDE_PORT_BYTES)?;
    if let Some(value) = value.as_ref() {
        validate_port(value)?;
    }
    Ok(value)
}

fn normalize_patch_port(value: PatchField<String>) -> Result<PatchField<String>, ApiError> {
    let value = normalize_patch_text(value, "port", MAX_OVERRIDE_PORT_BYTES)?;
    if let PatchField::Value(value) = &value {
        validate_port(value)?;
    }
    Ok(value)
}

fn validate_port(value: &str) -> Result<(), ApiError> {
    let valid = if value == "package" {
        true
    } else if let Some(cpe) = value.strip_prefix("cpe:") {
        !cpe.is_empty() && !cpe.chars().any(char::is_whitespace)
    } else if let Some(general) = value.strip_prefix("general/") {
        !general.is_empty()
            && !general
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, ',' | ';'))
    } else if let Some((port, protocol)) = value.split_once('/') {
        port.parse::<u16>().is_ok_and(|port| port > 0)
            && !protocol.is_empty()
            && protocol.chars().all(char::is_alphanumeric)
    } else {
        false
    };
    if valid {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "port must be package, cpe:..., general/..., or 1-65535/protocol".to_string(),
        ))
    }
}

fn validate_optional_severity(
    value: Option<f64>,
    allow_false_positive: bool,
) -> Result<Option<f64>, ApiError> {
    value
        .map(|value| validate_severity(value, allow_false_positive, "severity"))
        .transpose()
}

fn validate_patch_severity(
    value: PatchField<f64>,
    allow_false_positive: bool,
    field_name: &str,
) -> Result<PatchField<f64>, ApiError> {
    match value {
        PatchField::Missing => Ok(PatchField::Missing),
        PatchField::Null => Ok(PatchField::Null),
        PatchField::Value(value) => Ok(PatchField::Value(validate_severity(
            value,
            allow_false_positive,
            field_name,
        )?)),
    }
}

fn validate_severity(
    value: f64,
    allow_false_positive: bool,
    field_name: &str,
) -> Result<f64, ApiError> {
    if value.is_finite()
        && ((0.0..=10.0).contains(&value) || (allow_false_positive && value == -1.0))
    {
        Ok(value)
    } else {
        Err(ApiError::BadRequest(format!(
            "{field_name} must be between 0.0 and 10.0{}",
            if allow_false_positive {
                " or -1.0 for false positive"
            } else {
                ""
            }
        )))
    }
}

fn normalize_optional_uuid(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            parse_uuid(value.trim())
                .map(|uuid| uuid.to_string())
                .map_err(|_| ApiError::BadRequest(format!("{field_name} must be a UUID")))
        })
        .transpose()
}

fn normalize_patch_uuid(
    value: PatchField<String>,
    field_name: &str,
) -> Result<PatchField<String>, ApiError> {
    match value {
        PatchField::Missing => Ok(PatchField::Missing),
        PatchField::Null => Ok(PatchField::Null),
        PatchField::Value(value) if value.trim().is_empty() => Ok(PatchField::Null),
        PatchField::Value(value) => parse_uuid(value.trim())
            .map(|uuid| PatchField::Value(uuid.to_string()))
            .map_err(|_| ApiError::BadRequest(format!("{field_name} must be a UUID"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_validates_typed_scope() {
        let request: OverrideCreateRequest = serde_json::from_str(
            r#"{"nvt_id":"1.3.6.1.4.1.25623.1.0.1","text":"accepted risk","port":"443/tcp","new_severity":-1.0,"activation":{"mode":"for_days","days":30}}"#,
        )
        .unwrap();
        let validated = validate_override_create_request(request).unwrap();
        assert_eq!(validated.port.as_deref(), Some("443/tcp"));
        assert_eq!(validated.new_severity, -1.0);
        assert_eq!(validated.active_days, 30);
    }

    #[test]
    fn patch_distinguishes_missing_and_null_scope() {
        let request: OverridePatchRequest =
            serde_json::from_str(r#"{"hosts":null,"task_id":"","severity":null,"text":"updated"}"#)
                .unwrap();
        let validated = validate_override_patch_request(request).unwrap();
        assert_eq!(validated.hosts, PatchField::Null);
        assert_eq!(validated.task_id, PatchField::Null);
        assert_eq!(validated.severity, PatchField::Null);
        assert_eq!(validated.port, PatchField::Missing);
    }

    #[test]
    fn port_and_activation_validation_match_retained_contract() {
        for port in [
            "package",
            "cpe:/a:vendor:product",
            "general/Host_Details",
            "65535/tcp",
        ] {
            validate_port(port).unwrap();
        }
        for port in [
            "0/tcp",
            "65536/tcp",
            "22/",
            "22/tcp,udp",
            "general/bad value",
        ] {
            assert!(validate_port(port).is_err(), "{port} must be rejected");
        }
        assert!(
            OverrideActivation::ForDays { days: 0 }
                .database_days()
                .is_err()
        );
        assert!(
            OverrideActivation::ForDays {
                days: MAX_ACTIVE_DAYS + 1
            }
            .database_days()
            .is_err()
        );
    }

    #[test]
    fn empty_patch_and_unknown_fields_are_rejected() {
        let empty: OverridePatchRequest = serde_json::from_str("{}").unwrap();
        assert!(validate_override_patch_request(empty).is_err());
        assert!(
            serde_json::from_str::<OverrideCreateRequest>(
                r#"{"nvt_id":"1.2.3","text":"x","new_severity":1.0,"secret":"no"}"#
            )
            .is_err()
        );
    }
}
