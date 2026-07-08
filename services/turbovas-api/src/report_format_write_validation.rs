// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::errors::ApiError;

pub(crate) const MAX_REPORT_FORMAT_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportFormatPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) summary: Option<String>,
    #[serde(default)]
    pub(crate) active: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportFormatPatch {
    pub(crate) name: Option<String>,
    pub(crate) summary: Option<String>,
    pub(crate) active: Option<bool>,
}

pub(crate) fn validate_report_format_patch_request(
    request: ReportFormatPatchRequest,
) -> Result<ValidatedReportFormatPatch, ApiError> {
    let validated = ValidatedReportFormatPatch {
        name: normalize_optional_required_report_format_text(request.name, "name")?,
        summary: normalize_optional_report_format_text(request.summary, "summary")?,
        active: request.active,
    };
    if validated.name.is_none() && validated.summary.is_none() && validated.active.is_none() {
        return Err(ApiError::BadRequest(
            "report format patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_optional_required_report_format_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_report_format_text(value, field_name))
        .transpose()
}

fn normalize_required_report_format_text(
    value: String,
    field_name: &str,
) -> Result<String, ApiError> {
    let value = normalize_report_format_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_report_format_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_report_format_text_value(value, field_name))
        .transpose()
}

fn normalize_report_format_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_REPORT_FORMAT_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_REPORT_FORMAT_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
