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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportConfigWriteOperation {
    Create,
    Patch,
    Delete,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportConfigWriteStep {
    ResolveOperatorOwner,
    VerifyReportFormatVisible,
    VerifyReportFormatParams,
    VerifyUniqueLiveName,
    VerifyExistingReportConfigMutable,
    InsertReportConfig,
    UpdateReportConfigMetadata,
    ReplaceReportConfigParams,
    MoveReportConfigToTrash,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteTransactionPlan {
    pub(crate) operation: ReportConfigWriteOperation,
    pub(crate) steps: Vec<ReportConfigWriteStep>,
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

#[cfg(test)]
pub(crate) fn report_config_create_transaction_plan(
    _request: &ValidatedReportConfigCreate,
) -> ReportConfigWriteTransactionPlan {
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Create,
        steps: vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyReportFormatVisible,
            ReportConfigWriteStep::VerifyReportFormatParams,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::InsertReportConfig,
            ReportConfigWriteStep::ReplaceReportConfigParams,
        ],
    }
}

#[cfg(test)]
pub(crate) fn report_config_patch_transaction_plan(
    request: &ValidatedReportConfigPatch,
) -> ReportConfigWriteTransactionPlan {
    let mut steps = vec![
        ReportConfigWriteStep::ResolveOperatorOwner,
        ReportConfigWriteStep::VerifyExistingReportConfigMutable,
    ];
    if request.report_format_id.is_some() || request.params.is_some() {
        steps.push(ReportConfigWriteStep::VerifyReportFormatVisible);
        steps.push(ReportConfigWriteStep::VerifyReportFormatParams);
    }
    if request.name.is_some() {
        steps.push(ReportConfigWriteStep::VerifyUniqueLiveName);
    }
    steps.push(ReportConfigWriteStep::UpdateReportConfigMetadata);
    if request.params.is_some() {
        steps.push(ReportConfigWriteStep::ReplaceReportConfigParams);
    }
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Patch,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn report_config_delete_transaction_plan() -> ReportConfigWriteTransactionPlan {
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Delete,
        steps: vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::MoveReportConfigToTrash,
        ],
    }
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
#[path = "report_config_writes_tests.rs"]
mod report_config_writes_tests;
