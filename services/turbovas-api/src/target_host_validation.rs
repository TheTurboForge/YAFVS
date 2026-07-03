// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use crate::{errors::ApiError, target_write_validation::MAX_TARGET_TEXT_BYTES};

pub(crate) const MAX_TARGET_HOSTS: usize = 4095;

pub(crate) fn validate_target_host_lists(
    hosts: Option<Vec<String>>,
    exclude_hosts: Option<Vec<String>>,
) -> Result<(Option<String>, Option<String>), ApiError> {
    match (hosts, exclude_hosts) {
        (None, None) => Ok((None, None)),
        (None, Some(_)) => Err(ApiError::BadRequest(
            "exclude_hosts requires hosts in the same patch request".to_string(),
        )),
        (Some(hosts), exclude_hosts) => {
            let normalized_hosts = normalize_simple_host_list(hosts, "hosts")?;
            if normalized_hosts.is_empty() {
                return Err(ApiError::BadRequest("hosts is required".to_string()));
            }
            if normalized_hosts.len() > MAX_TARGET_HOSTS {
                return Err(ApiError::BadRequest(format!(
                    "hosts may contain at most {MAX_TARGET_HOSTS} entries"
                )));
            }
            let normalized_excludes =
                normalize_simple_host_list(exclude_hosts.unwrap_or_default(), "exclude_hosts")?;
            let host_set: HashSet<&str> = normalized_hosts.iter().map(String::as_str).collect();
            let excluded_count = normalized_excludes
                .iter()
                .filter(|entry| host_set.contains(entry.as_str()))
                .count();
            if normalized_hosts.len().saturating_sub(excluded_count) == 0 {
                return Err(ApiError::BadRequest(
                    "hosts cannot be fully excluded".to_string(),
                ));
            }
            Ok((
                Some(normalized_hosts.join(", ")),
                Some(normalized_excludes.join(", ")),
            ))
        }
    }
}

fn normalize_simple_host_list(
    values: Vec<String>,
    field_name: &str,
) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let value = normalize_simple_host_entry(value, field_name)?;
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn normalize_simple_host_entry(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.len() > MAX_TARGET_TEXT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "{field_name} entries must be at most {MAX_TARGET_TEXT_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) || value.contains(',') {
        return Err(ApiError::BadRequest(format!(
            "{field_name} entries must be simple host strings without separators or control characters"
        )));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':'))
    {
        return Err(ApiError::BadRequest(format!(
            "{field_name} entries contain unsupported host characters"
        )));
    }
    if value.contains('/') || looks_like_ipv4_range(value) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} entries currently support only explicit hosts, not CIDR or range syntax"
        )));
    }
    Ok(normalize_ipv4_address(value).unwrap_or_else(|| value.to_string()))
}

fn looks_like_ipv4_range(value: &str) -> bool {
    let Some((left, right)) = value.split_once('-') else {
        return false;
    };
    is_dotted_ipv4_candidate(left) && right.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

fn is_dotted_ipv4_candidate(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn normalize_ipv4_address(value: &str) -> Option<String> {
    if !is_dotted_ipv4_candidate(value) {
        return None;
    }
    let mut octets = Vec::new();
    for part in value.split('.') {
        let octet = part.parse::<u16>().ok()?;
        if octet > 255 {
            return None;
        }
        octets.push(octet.to_string());
    }
    Some(octets.join("."))
}
