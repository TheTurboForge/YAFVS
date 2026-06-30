// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;
use std::collections::BTreeSet;

use crate::{errors::ApiError, path_ids::parse_uuid};

const MAX_REPORT_CONFIG_TEXT_BYTES: usize = 4096;
const MAX_REPORT_CONFIG_PARAM_VALUE_BYTES: usize = 65_536;
const MAX_REPORT_CONFIG_PARAMS: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigParamWriteRequest {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigCreateRequest {
    name: String,
    report_format_id: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    params: Vec<ReportConfigParamWriteRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigPatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    report_format_id: Option<String>,
    #[serde(default)]
    params: Option<Vec<ReportConfigParamWriteRequest>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportConfigParamWrite {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportConfigCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) report_format_id: String,
    pub(crate) params: Vec<ValidatedReportConfigParamWrite>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportConfigPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) report_format_id: Option<String>,
    pub(crate) params: Option<Vec<ValidatedReportConfigParamWrite>>,
}

pub(crate) fn validate_report_config_create_request(
    request: ReportConfigCreateRequest,
) -> Result<ValidatedReportConfigCreate, ApiError> {
    Ok(ValidatedReportConfigCreate {
        name: normalize_required_report_config_text(request.name, "name")?,
        comment: normalize_optional_report_config_text(request.comment, "comment")?,
        report_format_id: normalize_report_format_id(request.report_format_id)?,
        params: normalize_report_config_params(request.params)?,
    })
}

pub(crate) fn validate_report_config_patch_request(
    request: ReportConfigPatchRequest,
) -> Result<ValidatedReportConfigPatch, ApiError> {
    let validated = ValidatedReportConfigPatch {
        name: normalize_optional_required_report_config_text(request.name, "name")?,
        comment: normalize_optional_report_config_text(request.comment, "comment")?,
        report_format_id: request
            .report_format_id
            .map(normalize_report_format_id)
            .transpose()?,
        params: request
            .params
            .map(normalize_report_config_params)
            .transpose()?,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.report_format_id.is_none()
        && validated.params.is_none()
    {
        return Err(ApiError::BadRequest(
            "report config patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_required_report_config_text(
    value: String,
    field_name: &str,
) -> Result<String, ApiError> {
    let value = normalize_report_config_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_required_report_config_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_report_config_text(value, field_name))
        .transpose()
}

fn normalize_optional_report_config_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_report_config_text_value(value, field_name))
        .transpose()
}

fn normalize_report_config_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_REPORT_CONFIG_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_REPORT_CONFIG_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_report_format_id(value: String) -> Result<String, ApiError> {
    parse_uuid(value.trim()).map(|uuid| uuid.to_string())
}

fn normalize_report_config_params(
    params: Vec<ReportConfigParamWriteRequest>,
) -> Result<Vec<ValidatedReportConfigParamWrite>, ApiError> {
    if params.len() > MAX_REPORT_CONFIG_PARAMS {
        return Err(ApiError::BadRequest(format!(
            "params must contain at most {MAX_REPORT_CONFIG_PARAMS} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(params.len());
    for param in params {
        let name = normalize_required_report_config_text(param.name, "param.name")?;
        if !seen.insert(name.clone()) {
            return Err(ApiError::Conflict(format!(
                "params contains duplicate name: {name}"
            )));
        }
        let value = normalize_report_config_param_value(param.value)?;
        normalized.push(ValidatedReportConfigParamWrite { name, value });
    }
    Ok(normalized)
}

fn normalize_report_config_param_value(value: String) -> Result<String, ApiError> {
    if value.len() > MAX_REPORT_CONFIG_PARAM_VALUE_BYTES || value.contains('\0') {
        return Err(ApiError::BadRequest(format!(
            "param.value must be text up to {MAX_REPORT_CONFIG_PARAM_VALUE_BYTES} bytes without NUL bytes"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_config_create_request_normalizes_metadata_and_params() {
        let request: ReportConfigCreateRequest = serde_json::from_str(
            r#"{
                "name": "  PDF summary  ",
                "comment": "  operator default  ",
                "report_format_id": "12345678-1234-1234-1234-123456789ABC",
                "params": [
                    {"name":"  timezone ","value":"UTC"},
                    {"name":"notes","value":"line one\nline two"}
                ]
            }"#,
        )
        .expect("valid create DTO");

        let validated = validate_report_config_create_request(request).expect("valid create");

        assert_eq!(validated.name, "PDF summary");
        assert_eq!(validated.comment.as_deref(), Some("operator default"));
        assert_eq!(
            validated.report_format_id,
            "12345678-1234-1234-1234-123456789abc"
        );
        assert_eq!(validated.params[0].name, "timezone");
        assert_eq!(validated.params[1].value, "line one\nline two");
    }

    #[test]
    fn report_config_create_rejects_unknown_fields_bad_ids_and_duplicate_params() {
        assert!(
            serde_json::from_str::<ReportConfigCreateRequest>(
                r#"{"name":"x","report_format_id":"12345678-1234-1234-1234-123456789abc","owner":"admin"}"#,
            )
            .is_err()
        );

        let bad_id = ReportConfigCreateRequest {
            name: "config".to_string(),
            comment: None,
            report_format_id: "not-a-uuid".to_string(),
            params: Vec::new(),
        };
        assert!(matches!(
            validate_report_config_create_request(bad_id),
            Err(ApiError::BadRequest(_))
        ));

        let duplicate_param = ReportConfigCreateRequest {
            name: "config".to_string(),
            comment: None,
            report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
            params: vec![
                ReportConfigParamWriteRequest {
                    name: "timezone".to_string(),
                    value: "UTC".to_string(),
                },
                ReportConfigParamWriteRequest {
                    name: " timezone ".to_string(),
                    value: "CET".to_string(),
                },
            ],
        };
        assert!(matches!(
            validate_report_config_create_request(duplicate_param),
            Err(ApiError::Conflict(_))
        ));
    }

    #[test]
    fn report_config_patch_request_requires_explicit_field_and_preserves_param_value() {
        let empty = ReportConfigPatchRequest {
            name: None,
            comment: None,
            report_format_id: None,
            params: None,
        };
        assert!(matches!(
            validate_report_config_patch_request(empty),
            Err(ApiError::BadRequest(_))
        ));

        let patch: ReportConfigPatchRequest = serde_json::from_str(
            r#"{
                "name":" Renamed ",
                "params":[{"name":"body","value":"  keep outer spaces  "}]
            }"#,
        )
        .expect("valid patch DTO");
        let validated = validate_report_config_patch_request(patch).expect("valid patch");

        assert_eq!(validated.name.as_deref(), Some("Renamed"));
        assert_eq!(validated.report_format_id, None);
        assert_eq!(
            validated.params.expect("params replacement")[0].value,
            "  keep outer spaces  "
        );
    }

    #[test]
    fn report_config_param_values_are_size_capped_and_reject_nul() {
        let nul = ReportConfigCreateRequest {
            name: "config".to_string(),
            comment: None,
            report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
            params: vec![ReportConfigParamWriteRequest {
                name: "body".to_string(),
                value: "bad\0value".to_string(),
            }],
        };
        assert!(matches!(
            validate_report_config_create_request(nul),
            Err(ApiError::BadRequest(_))
        ));

        let too_many = ReportConfigCreateRequest {
            name: "config".to_string(),
            comment: None,
            report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
            params: (0..=MAX_REPORT_CONFIG_PARAMS)
                .map(|index| ReportConfigParamWriteRequest {
                    name: format!("param{index}"),
                    value: "value".to_string(),
                })
                .collect(),
        };
        assert!(matches!(
            validate_report_config_create_request(too_many),
            Err(ApiError::BadRequest(_))
        ));
    }
}
