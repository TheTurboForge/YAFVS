// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::{errors::ApiError, path_ids::parse_uuid};

pub(crate) const MAX_REPORT_CONFIG_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_REPORT_CONFIG_PARAM_VALUE_BYTES: usize = 65_536;
pub(crate) const MAX_REPORT_CONFIG_PARAMS: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigParamWriteRequest {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigCreateRequest {
    pub(crate) name: String,
    pub(crate) report_format_id: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) params: Vec<ReportConfigParamWriteRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) params: Option<Vec<ReportConfigParamWriteRequest>>,
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
    pub(crate) params: Option<Vec<ValidatedReportConfigParamWrite>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigFormatState {
    pub(crate) params: BTreeMap<String, ReportConfigFormatParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigFormatParam {
    pub(crate) param_type: i32,
    pub(crate) min: i64,
    pub(crate) max: i64,
    pub(crate) options: BTreeSet<String>,
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
        params: request
            .params
            .map(normalize_report_config_params)
            .transpose()?,
    };
    if validated.name.is_none() && validated.comment.is_none() && validated.params.is_none() {
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

pub(crate) fn validate_report_config_param_values(
    params: &[ValidatedReportConfigParamWrite],
    format: &ReportConfigFormatState,
) -> Result<(), ApiError> {
    for param in params {
        let Some(format_param) = format.params.get(&param.name) else {
            return Err(ApiError::BadRequest(format!(
                "report format has no parameter named {}",
                param.name
            )));
        };
        validate_report_config_param_value(param, format_param)?;
    }
    Ok(())
}

fn validate_report_config_param_value(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    match format_param.param_type {
        1 => validate_report_config_integer_param(param, format_param),
        2 => validate_report_config_selection_param(param, format_param),
        3 | 4 => validate_report_config_text_param(param, format_param),
        5 => validate_report_config_report_format_list_param(param),
        6 => validate_report_config_multi_selection_param(param, format_param),
        _ => Ok(()),
    }
}

fn validate_report_config_integer_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    let actual = param.value.parse::<i64>().map_err(|_| {
        ApiError::BadRequest(format!("value of param {} must be an integer", param.name))
    })?;
    if actual < format_param.min {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is below minimum",
            param.name
        )));
    }
    if actual > format_param.max {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is above maximum",
            param.name
        )));
    }
    Ok(())
}

fn validate_report_config_selection_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    if format_param.options.contains(&param.value) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "value of param {} is not a valid selection option",
            param.name
        )))
    }
}

fn validate_report_config_text_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    let actual = param.value.len() as i64;
    if actual < format_param.min {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is too short",
            param.name
        )));
    }
    if actual > format_param.max {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is too long",
            param.name
        )));
    }
    Ok(())
}

fn validate_report_config_report_format_list_param(
    param: &ValidatedReportConfigParamWrite,
) -> Result<(), ApiError> {
    if param.value.is_empty()
        || param.value.split(',').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "value of param {} is not a valid UUID list",
            param.name
        )))
    }
}

fn validate_report_config_multi_selection_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    let values = serde_json::from_str::<Vec<String>>(&param.value).map_err(|_| {
        ApiError::BadRequest(format!(
            "value of param {} is not a valid JSON string array",
            param.name
        ))
    })?;
    let count = values.len() as i64;
    if count < format_param.min {
        return Err(ApiError::BadRequest(format!(
            "value of param {} has too few options",
            param.name
        )));
    }
    if count > format_param.max {
        return Err(ApiError::BadRequest(format!(
            "value of param {} has too many options",
            param.name
        )));
    }
    for value in values {
        if !format_param.options.contains(&value) {
            return Err(ApiError::BadRequest(format!(
                "value of param {} contains an invalid selection option",
                param.name
            )));
        }
    }
    Ok(())
}
