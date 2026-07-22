// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{errors::ApiError, path_ids::parse_uuid};

pub(crate) fn validate_uuid(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest(format!("{field_name} is required")));
    }
    Ok(parse_uuid(value)?.to_string())
}

pub(crate) fn validate_optional_uuid(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| validate_uuid(value, field_name))
        .transpose()
}
