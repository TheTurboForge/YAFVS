// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::errors::ApiError;

pub(crate) const MAX_TARGET_TEXT_BYTES: usize = 4096;

pub(crate) fn normalize_optional_required_target_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_target_text(value, field_name))
        .transpose()
}

pub(crate) fn normalize_required_target_text(
    value: String,
    field_name: &str,
) -> Result<String, ApiError> {
    let value = normalize_target_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

pub(crate) fn normalize_optional_target_text(
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
