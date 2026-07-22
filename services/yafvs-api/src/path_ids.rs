// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use uuid::Uuid;

use crate::errors::ApiError;

pub(crate) fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::BadRequest("path id must be a UUID".to_string()))
}

pub(crate) fn validate_cve_id(value: &str) -> Result<(), ApiError> {
    let upper = value.to_ascii_uppercase();
    let parts: Vec<&str> = upper.split('-').collect();
    if parts.len() != 3
        || parts[0] != "CVE"
        || parts[1].len() != 4
        || parts[2].len() < 4
        || !parts[1].chars().all(|ch| ch.is_ascii_digit())
        || !parts[2].chars().all(|ch| ch.is_ascii_digit())
    {
        return Err(ApiError::BadRequest(
            "path id must be a CVE identifier".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_cpe_id(value: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.len() > 2048 || !value.starts_with("cpe:") {
        return Err(ApiError::BadRequest(
            "path id must be a CPE identifier".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_advisory_id(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/'))
    {
        return Err(ApiError::BadRequest(
            "path id must be an advisory identifier".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_nvt_oid(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 128
        || value.split('.').count() < 2
        || !value
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(ApiError::BadRequest(
            "path id must be a numeric dotted NVT OID".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_scan_config_family(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 256
        || value.bytes().all(|byte| byte == b'.')
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || matches!(byte, b'/' | b'\\' | b'?' | b'#'))
    {
        return Err(ApiError::BadRequest(
            "path family must be a bounded family name".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parser_rejects_non_uuid_path_ids() {
        assert!(parse_uuid("12345678-1234-1234-1234-123456789abc").is_ok());
        assert!(parse_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn cve_id_validator_requires_cve_shape() {
        assert!(validate_cve_id("CVE-2026-0001").is_ok());
        assert!(validate_cve_id("cve-2026-0001").is_ok());
        assert!(validate_cve_id("CVE-26-0001").is_err());
        assert!(validate_cve_id("CVE-2026-abc").is_err());
        assert!(validate_cve_id("GHSA-2026-0001").is_err());
    }

    #[test]
    fn cpe_id_validator_requires_bounded_cpe_prefix() {
        assert!(validate_cpe_id("cpe:/a:vendor:product:1.0").is_ok());
        assert!(validate_cpe_id("").is_err());
        assert!(validate_cpe_id("not-cpe").is_err());
        assert!(validate_cpe_id(&format!("cpe:{}", "x".repeat(2048))).is_err());
    }

    #[test]
    fn advisory_id_validator_allows_feed_ids_but_rejects_unsafe_text() {
        assert!(validate_advisory_id("DFN-CERT-2026-2178").is_ok());
        assert!(validate_advisory_id("WID-SEC-2022-1384").is_ok());
        assert!(validate_advisory_id("CB-K14/0001").is_ok());
        assert!(validate_advisory_id("").is_err());
        assert!(validate_advisory_id("CB-K14/0001?download=true").is_err());
        assert!(validate_advisory_id("CB-K14/0001;drop").is_err());
    }

    #[test]
    fn nvt_oid_validator_requires_bounded_numeric_dotted_oid() {
        assert!(validate_nvt_oid("1.3.6.1.4.1.25623.1.0.100001").is_ok());
        assert!(validate_nvt_oid("").is_err());
        assert!(validate_nvt_oid("1").is_err());
        assert!(validate_nvt_oid("1.3.6.").is_err());
        assert!(validate_nvt_oid("1.3..6").is_err());
        assert!(validate_nvt_oid("1.3.6.a").is_err());
        assert!(validate_nvt_oid("1.3.6/1").is_err());
        assert!(validate_nvt_oid("1.3.6?download=true").is_err());
        assert!(validate_nvt_oid("1.3.6;drop").is_err());
        assert!(validate_nvt_oid(&format!("1.{}", "2".repeat(128))).is_err());
    }

    #[test]
    fn scan_config_family_validator_matches_proxy_path_boundary() {
        assert!(validate_scan_config_family("Port scanners").is_ok());
        assert!(validate_scan_config_family("Web Servers").is_ok());
        assert!(validate_scan_config_family("").is_err());
        assert!(validate_scan_config_family(".").is_err());
        assert!(validate_scan_config_family("..").is_err());
        assert!(validate_scan_config_family("Port/scanners").is_err());
        assert!(validate_scan_config_family("Port\\scanners").is_err());
        assert!(validate_scan_config_family("Port?scanners").is_err());
        assert!(validate_scan_config_family("Port#scanners").is_err());
        assert!(validate_scan_config_family("Port\nscanners").is_err());
        assert!(validate_scan_config_family(&"x".repeat(257)).is_err());
    }
}
