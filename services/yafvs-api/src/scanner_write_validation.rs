// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{net::IpAddr, path::Component};
use yafvs_domain::ScannerType;

use crate::errors::ApiError;

pub(crate) const MAX_SCANNER_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_SCANNER_CA_PUB_BYTES: usize = 65_536;
const MAX_NETWORK_HOST_BYTES: usize = 253;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScannerPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScannerCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScannerConfigurationRequest {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) host: String,
    pub(crate) port: i64,
    pub(crate) scanner_type: i64,
    #[serde(default)]
    pub(crate) ca_pub: Option<String>,
    #[serde(default)]
    pub(crate) credential_id: Option<String>,
    #[serde(default)]
    pub(crate) relay_host: Option<String>,
    #[serde(default)]
    pub(crate) relay_port: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScannerClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_scanner_clone_request(
    request: ScannerCloneRequest,
) -> Result<ValidatedScannerClone, ApiError> {
    Ok(ValidatedScannerClone {
        name: normalize_optional_required_scanner_text(request.name, "name")?,
        comment: normalize_optional_scanner_text(request.comment, "comment")?,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScannerConfiguration {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) host: String,
    pub(crate) port: i32,
    pub(crate) scanner_type: i32,
    pub(crate) ca_pub: Option<String>,
    pub(crate) credential_id: Option<String>,
    pub(crate) unix_socket: bool,
    pub(crate) relay_host: Option<String>,
    pub(crate) relay_port: i32,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScannerPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_scanner_patch_request(
    request: ScannerPatchRequest,
) -> Result<ValidatedScannerPatch, ApiError> {
    let validated = ValidatedScannerPatch {
        name: normalize_optional_required_scanner_text(request.name, "name")?,
        comment: normalize_optional_scanner_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "scanner patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_scanner_configuration_request(
    request: ScannerConfigurationRequest,
) -> Result<ValidatedScannerConfiguration, ApiError> {
    let name = normalize_required_scanner_text(request.name, "name")?;
    let comment = normalize_scanner_text_value(request.comment, "comment")?;
    let host = normalize_required_scanner_text(request.host, "host")?;
    let scanner_type = ScannerType::try_from(request.scanner_type)
        .ok()
        .filter(|scanner_type| scanner_type.is_operator_configurable())
        .ok_or_else(|| {
            ApiError::BadRequest("scanner_type must be one of 2, 5, 6, or 8".to_string())
        })?;

    let unix_socket = host.starts_with('/');
    let port = if unix_socket {
        validate_unix_socket_host(&host)?;
        if request.port != 0 {
            return Err(ApiError::BadRequest(
                "port must be 0 for a Unix socket scanner".to_string(),
            ));
        }
        0
    } else {
        validate_network_host(&host)?;
        i32::try_from(request.port)
            .ok()
            .filter(|port| (1..=65_535).contains(port))
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "port must be between 1 and 65535 for a network scanner".to_string(),
                )
            })?
    };

    let ca_pub = if unix_socket {
        None
    } else {
        request.ca_pub.map(validate_ca_pub).transpose()?
    };
    let credential_id = if unix_socket {
        None
    } else {
        request.credential_id
    };
    let relay_host = request
        .relay_host
        .map(|relay_host| normalize_scanner_text_value(relay_host, "relay_host"))
        .transpose()?
        .filter(|relay_host| !relay_host.is_empty());
    let relay_port = match relay_host.as_deref() {
        None => {
            if request.relay_port != 0 {
                return Err(ApiError::BadRequest(
                    "relay_port must be 0 when relay_host is empty".to_string(),
                ));
            }
            0
        }
        Some(relay_host) if relay_host.starts_with('/') => {
            validate_unix_socket_host(relay_host)?;
            if request.relay_port != 0 {
                return Err(ApiError::BadRequest(
                    "relay_port must be 0 for a Unix socket relay".to_string(),
                ));
            }
            0
        }
        Some(relay_host) => {
            validate_network_host(relay_host)?;
            i32::try_from(request.relay_port)
                .ok()
                .filter(|relay_port| (1..=65_535).contains(relay_port))
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "relay_port must be between 1 and 65535 for a network relay".to_string(),
                    )
                })?
        }
    };

    Ok(ValidatedScannerConfiguration {
        name,
        comment,
        host,
        port,
        scanner_type: scanner_type.database_value(),
        ca_pub,
        credential_id,
        unix_socket,
        relay_host,
        relay_port,
    })
}

fn normalize_optional_required_scanner_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_scanner_text(value, field_name))
        .transpose()
}

fn normalize_required_scanner_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_scanner_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_scanner_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_scanner_text_value(value, field_name))
        .transpose()
}

fn normalize_scanner_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCANNER_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCANNER_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn validate_unix_socket_host(host: &str) -> Result<(), ApiError> {
    let mut components = std::path::Path::new(host).components();
    let normalized_segments = host.strip_prefix('/').unwrap_or_default().split('/');
    if host == "/"
        || normalized_segments
            .clone()
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ApiError::BadRequest(
            "host must be a normalized absolute Unix socket path".to_string(),
        ));
    }
    Ok(())
}

fn validate_network_host(host: &str) -> Result<(), ApiError> {
    if host.len() > MAX_NETWORK_HOST_BYTES {
        return Err(ApiError::BadRequest(format!(
            "host must be at most {MAX_NETWORK_HOST_BYTES} bytes"
        )));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let dns_host = host.strip_suffix('.').unwrap_or(host);
    if dns_host.is_empty()
        || dns_host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ApiError::BadRequest(
            "host must be an IPv4 address, IPv6 address, or valid DNS name".to_string(),
        ));
    }
    Ok(())
}

fn validate_ca_pub(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > MAX_SCANNER_CA_PUB_BYTES {
        return Err(ApiError::BadRequest(format!(
            "ca_pub must be a PEM certificate up to {MAX_SCANNER_CA_PUB_BYTES} bytes"
        )));
    }
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut remaining = value.as_str();
    let mut certificates = 0usize;
    loop {
        remaining = remaining.trim_start_matches(char::is_whitespace);
        let Some(encoded_and_tail) = remaining.strip_prefix(BEGIN) else {
            return Err(invalid_ca_pub());
        };
        let Some(end_index) = encoded_and_tail.find(END) else {
            return Err(invalid_ca_pub());
        };
        let encoded = &encoded_and_tail[..end_index];
        validate_certificate_block(encoded)?;
        certificates += 1;
        remaining = &encoded_and_tail[end_index + END.len()..];
        if remaining.trim().is_empty() {
            break;
        }
    }
    if certificates == 0 {
        return Err(invalid_ca_pub());
    }
    Ok(value)
}

fn validate_certificate_block(encoded: &str) -> Result<(), ApiError> {
    if encoded.contains("-----BEGIN") || encoded.contains("-----END") {
        return Err(invalid_ca_pub());
    }
    let compact = encoded
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.is_empty()
        || encoded
            .chars()
            .any(|character| !character.is_ascii_whitespace() && !character.is_ascii_graphic())
    {
        return Err(invalid_ca_pub());
    }
    let der = STANDARD.decode(compact).map_err(|_| invalid_ca_pub())?;
    if !certificate_der_is_shaped(&der) {
        return Err(invalid_ca_pub());
    }
    Ok(())
}

fn invalid_ca_pub() -> ApiError {
    ApiError::BadRequest(
        "ca_pub must contain only valid PEM-encoded certificate blocks".to_string(),
    )
}

fn certificate_der_is_shaped(der: &[u8]) -> bool {
    let Some((0x30, certificate, rest)) = der_tlv(der) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    let Some((0x30, _, after_tbs)) = der_tlv(certificate) else {
        return false;
    };
    let Some((0x30, _, after_algorithm)) = der_tlv(after_tbs) else {
        return false;
    };
    let Some((0x03, signature, after_signature)) = der_tlv(after_algorithm) else {
        return false;
    };
    after_signature.is_empty() && signature.len() > 1 && signature[0] <= 7
}

fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, tail) = input.split_first()?;
    let (&first_length, tail) = tail.split_first()?;
    let (length, tail) = if first_length & 0x80 == 0 {
        (usize::from(first_length), tail)
    } else {
        let width = usize::from(first_length & 0x7f);
        if width == 0 || width > std::mem::size_of::<usize>() || tail.len() < width {
            return None;
        }
        let mut length = 0usize;
        for byte in &tail[..width] {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        (length, &tail[width..])
    };
    let content = tail.get(..length)?;
    Some((tag, content, &tail[length..]))
}
