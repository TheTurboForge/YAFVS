// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: components/gvm-libs/base/hosts.c and hosts_tests.c (GPL-2.0-or-later); components/gvmd/src/manage_utils.c, manage_utils_tests.c, and manage_sql_targets.c (AGPL-3.0-or-later)

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{errors::ApiError, target_text_validation::MAX_TARGET_TEXT_BYTES};

pub(crate) const MAX_TARGET_HOSTS: usize = 4095;

#[derive(Debug)]
enum Expansion {
    One(String),
    V4(u32, u32),
    V6(u128, u128),
}

#[derive(Debug)]
pub(crate) struct ParsedHost {
    pub(crate) canonical: String,
    expansion: Expansion,
}

fn bad(field: &str, message: &str) -> ApiError {
    ApiError::BadRequest(format!("{field} {message}"))
}

fn parse_v4(value: &str) -> Option<u32> {
    let mut out = 0u32;
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let octet = part.parse::<u16>().ok()?;
        if octet > 255 {
            return None;
        }
        out = (out << 8) | u32::from(octet);
    }
    Some(out)
}

fn v4_string(value: u32) -> String {
    Ipv4Addr::from(value).to_string()
}
fn v6_string(value: u128) -> String {
    Ipv6Addr::from(value).to_string()
}

fn parse_prefix(value: &str, max: u8) -> Option<u8> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let prefix = value.parse::<u16>().ok()?;
    (prefix > 0 && prefix <= u16::from(max)).then_some(prefix as u8)
}

fn hostname(value: &str) -> Option<String> {
    let canonical = value.to_ascii_lowercase();
    let value = canonical.strip_suffix('.').unwrap_or(&canonical);
    if value.is_empty() || value.len() > 253 {
        return None;
    }
    let labels: Vec<_> = value.split('.').collect();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }) {
        return None;
    }
    if labels
        .last()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(canonical)
}

pub(crate) fn parse_host(value: &str, field: &str) -> Result<ParsedHost, ApiError> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_control() || c == ' ' || c == '\t')
    {
        return Err(bad(field, "entries contain malformed host syntax"));
    }

    if let Some((left, right)) = value.split_once('/') {
        if value.matches('/').count() != 1 {
            return Err(bad(field, "entries contain malformed host syntax"));
        }
        if let Some(address) = parse_v4(left) {
            let prefix = parse_prefix(right, 30)
                .ok_or_else(|| bad(field, "contains an invalid IPv4 CIDR prefix"))?;
            let host_bits = u32::from(32 - prefix);
            let size = 1u32 << host_bits;
            let network = address & !(size - 1);
            return Ok(ParsedHost {
                canonical: format!("{}/{}", v4_string(address), prefix),
                expansion: Expansion::V4(network + 1, network + (size - 2)),
            });
        }
        if let Ok(address) = Ipv6Addr::from_str(left) {
            let prefix = parse_prefix(right, 128)
                .ok_or_else(|| bad(field, "contains an invalid IPv6 CIDR prefix"))?;
            let address = u128::from(address);
            let host_bits = u32::from(128 - prefix);
            let mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            let network = address & !mask;
            let (first, last) = match prefix {
                128 => (network, network),
                127 => (network, network + 1),
                _ => (network + 1, network + mask - 1),
            };
            return Ok(ParsedHost {
                canonical: format!("{}/{}", v6_string(address), prefix),
                expansion: Expansion::V6(first, last),
            });
        }
        return Err(bad(field, "contains an invalid CIDR address"));
    }

    if let Some(address) = parse_v4(value) {
        return Ok(ParsedHost {
            canonical: v4_string(address),
            expansion: Expansion::One(v4_string(address)),
        });
    }
    if let Ok(address) = Ipv6Addr::from_str(value) {
        let canonical = address.to_string();
        return Ok(ParsedHost {
            canonical: canonical.clone(),
            expansion: Expansion::One(canonical),
        });
    }

    if let Some((left, right)) = value.split_once('-') {
        if let Some(first) = parse_v4(left) {
            if value.matches('-').count() != 1 || right.is_empty() {
                return Err(bad(field, "entries contain malformed range syntax"));
            }
            let (last, canonical_right) = if right.bytes().all(|b| b.is_ascii_digit()) {
                let suffix = right
                    .parse::<u16>()
                    .ok()
                    .filter(|v| *v <= 255)
                    .ok_or_else(|| bad(field, "contains an invalid IPv4 short range"))?;
                let last = (first & !255) | u32::from(suffix);
                (last, suffix.to_string())
            } else {
                let last =
                    parse_v4(right).ok_or_else(|| bad(field, "contains an invalid IPv4 range"))?;
                (last, v4_string(last))
            };
            if first > last {
                return Err(bad(field, "contains a reversed range"));
            }
            return Ok(ParsedHost {
                canonical: format!("{}-{}", v4_string(first), canonical_right),
                expansion: Expansion::V4(first, last),
            });
        }
        if let Ok(first_address) = Ipv6Addr::from_str(left) {
            if value.matches('-').count() != 1 || right.is_empty() {
                return Err(bad(field, "entries contain malformed range syntax"));
            }
            let first = u128::from(first_address);
            let (last, right_canonical) = if right.len() <= 4
                && !right.is_empty()
                && right.bytes().all(|b| b.is_ascii_hexdigit())
            {
                let suffix = u16::from_str_radix(right, 16)
                    .map_err(|_| bad(field, "contains an invalid IPv6 short range"))?;
                (
                    (first & !0xffff) | u128::from(suffix),
                    format!("{:x}", suffix),
                )
            } else {
                let last = Ipv6Addr::from_str(right)
                    .map(u128::from)
                    .map_err(|_| bad(field, "contains an invalid IPv6 range"))?;
                (last, v6_string(last))
            };
            if first > last {
                return Err(bad(field, "contains a reversed range"));
            }
            return Ok(ParsedHost {
                canonical: format!("{}-{}", v6_string(first), right_canonical),
                expansion: Expansion::V6(first, last),
            });
        }
    }

    let name = hostname(value).ok_or_else(|| bad(field, "contains malformed host syntax"))?;
    Ok(ParsedHost {
        canonical: name.clone(),
        expansion: Expansion::One(name),
    })
}

pub(crate) fn parse_list(
    values: Vec<String>,
    field: &str,
) -> Result<(Vec<ParsedHost>, HashSet<String>), ApiError> {
    let mut parsed = Vec::new();
    let mut seen_expressions = HashSet::new();
    let mut identities = HashSet::new();
    for raw in values {
        if raw.len() > MAX_TARGET_TEXT_BYTES {
            return Err(bad(
                field,
                &format!("entries must be at most {MAX_TARGET_TEXT_BYTES} bytes"),
            ));
        }
        for token in raw.split([',', '\n']) {
            let token = token.trim_matches([' ', '\t', '\r']);
            if token.is_empty() {
                continue;
            }
            let host = parse_host(token, field)?;
            if !seen_expressions.insert(host.canonical.clone()) {
                continue;
            }
            expand(&host.expansion, &mut identities, field)?;
            parsed.push(host);
        }
    }
    Ok((parsed, identities))
}

pub(crate) fn effective_host_count(hosts: &str, exclude_hosts: &str) -> Result<usize, ApiError> {
    let (_, host_identities) = parse_list(vec![hosts.to_string()], "hosts")?;
    let (_, exclude_identities) = parse_list(vec![exclude_hosts.to_string()], "exclude_hosts")?;
    Ok(host_identities.difference(&exclude_identities).count())
}

fn insert(identity: String, identities: &mut HashSet<String>, field: &str) -> Result<(), ApiError> {
    if identities.insert(identity) && identities.len() > MAX_TARGET_HOSTS {
        return Err(bad(field, "expands to more than 4095 unique hosts"));
    }
    Ok(())
}

fn expand(
    expansion: &Expansion,
    identities: &mut HashSet<String>,
    field: &str,
) -> Result<(), ApiError> {
    match expansion {
        Expansion::One(value) => insert(value.clone(), identities, field),
        Expansion::V4(first, last) => {
            let mut current = *first;
            loop {
                insert(v4_string(current), identities, field)?;
                if current == *last {
                    break;
                }
                current += 1;
            }
            Ok(())
        }
        Expansion::V6(first, last) => {
            let mut current = *first;
            loop {
                insert(v6_string(current), identities, field)?;
                if current == *last {
                    break;
                }
                current = current
                    .checked_add(1)
                    .ok_or_else(|| bad(field, "contains an overflowing IPv6 range"))?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(value: &str) -> (Vec<ParsedHost>, HashSet<String>) {
        parse_list(vec![value.into()], "hosts").unwrap()
    }
    fn bad_value(value: &str) {
        assert!(parse_list(vec![value.into()], "hosts").is_err(), "{value}");
    }

    #[test]
    fn mirrors_clean_hosts_whitespace_newlines_and_zeroes() {
        let (hosts, _) = ok(" 000.001.002.003,\nhost1\n host2 ");
        assert_eq!(
            hosts
                .iter()
                .map(|h| h.canonical.as_str())
                .collect::<Vec<_>>(),
            ["0.1.2.3", "host1", "host2"]
        );
        let (hosts, _) = ok("host1\n host1, HOST1");
        assert_eq!(
            hosts
                .iter()
                .map(|h| h.canonical.as_str())
                .collect::<Vec<_>>(),
            ["host1"]
        );
    }

    #[test]
    fn canonicalizes_ranges_and_preserves_hostname_identity() {
        assert_eq!(ok("000.001.002.003-004").0[0].canonical, "0.1.2.3-4");
        assert_eq!(ok("EXAMPLE.com.").0[0].canonical, "example.com.");
        assert_eq!(
            ok("example.com, example.com.").1.len(),
            2,
            "the inherited host identity retains a final dot"
        );
        assert_eq!(ok("multi-hyphen-host.example").1.len(), 1);
    }

    #[test]
    fn parses_all_expression_families() {
        for value in [
            "192.0.2.1",
            "2001:db8::1",
            "192.0.2.0/30",
            "2001:db8::/127",
            "192.0.2.1-3",
            "192.0.2.1-192.0.2.3",
            "2001:db8::1-3",
            "2001:db8::1-2001:db8::3",
            "example.COM",
        ] {
            let _ = ok(value);
        }
    }

    #[test]
    fn matches_inherited_cidr_endpoint_rules() {
        assert_eq!(ok("192.0.2.0/30").1.len(), 2);
        assert_eq!(ok("192.0.2.3/29").1.len(), 6);
        assert_eq!(ok("255.255.255.255/30").1.len(), 2);
        bad_value("255.255.255.255/1");
        assert_eq!(ok("2001:db8::/128").1.len(), 1);
        assert_eq!(ok("2001:db8::/127").1.len(), 2);
        assert_eq!(ok("2001:db8::3/126").1.len(), 2);
    }

    #[test]
    fn rejects_malformed_and_reversed_expressions() {
        for value in [
            "bad..example",
            "-bad.example",
            "bad-.example",
            "example.123",
            "192.0.2.1/31",
            "2001:db8::/129",
            "192.0.2.5-3",
            "2001:db8::5-3",
            "192.0.2.1-192.0.2.0",
            "2001:db8::1-2001:db8::0",
        ] {
            bad_value(value);
        }
    }

    #[test]
    fn deduplicates_expansions_and_enforces_boundaries() {
        let (_, identities) = ok("192.0.2.1-192.0.2.4,192.0.2.3-192.0.2.5");
        assert_eq!(identities.len(), 5);
        assert_eq!(ok("192.0.2.0/20").1.len(), 4094);
        bad_value("192.0.2.0/19");
        assert_eq!(ok("2001:db8::/116").1.len(), 4094);
        bad_value("2001:db8::/115");
    }

    #[test]
    fn enforces_exact_unique_identity_limit() {
        let exactly_max = (0..MAX_TARGET_HOSTS)
            .map(|index| format!("host-{index}.example"))
            .collect();
        assert_eq!(
            parse_list(exactly_max, "hosts").unwrap().1.len(),
            MAX_TARGET_HOSTS
        );
        let over_max = (0..=MAX_TARGET_HOSTS)
            .map(|index| format!("host-{index}.example"))
            .collect();
        assert!(parse_list(over_max, "hosts").is_err());
    }

    #[test]
    fn reports_effective_count_after_expanded_exclusions() {
        assert_eq!(
            effective_host_count("192.0.2.0/29", "192.0.2.1-3").unwrap(),
            3
        );
        assert_eq!(effective_host_count("host.example", "").unwrap(), 1);
    }
}
