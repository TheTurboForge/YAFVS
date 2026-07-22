// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::net::IpAddr;

use serde::Deserialize;

use crate::errors::ApiError;

const MAX_HOST_COMMENT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPatchRequest {
    pub(crate) comment: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedHostCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedHostPatch {
    pub(crate) comment: String,
}

pub(crate) fn validate_host_create_request(
    request: HostCreateRequest,
) -> Result<ValidatedHostCreate, ApiError> {
    let name = request.name.trim().to_string();
    if name.is_empty() || name.parse::<IpAddr>().is_err() {
        return Err(ApiError::BadRequest(
            "host name must be an IPv4 or IPv6 address".to_string(),
        ));
    }
    Ok(ValidatedHostCreate {
        name,
        comment: normalize_host_comment(request.comment.unwrap_or_default())?,
    })
}

pub(crate) fn validate_host_patch_request(
    request: HostPatchRequest,
) -> Result<ValidatedHostPatch, ApiError> {
    Ok(ValidatedHostPatch {
        comment: normalize_host_comment(request.comment)?,
    })
}

fn normalize_host_comment(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_HOST_COMMENT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "comment must be printable text up to {MAX_HOST_COMMENT_BYTES} bytes"
        )));
    }
    Ok(value)
}
