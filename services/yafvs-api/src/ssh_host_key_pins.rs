// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{collections::HashSet, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;

const MAX_SSH_HOST_KEY_PINS: usize = 4095;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshHostKeyPin {
    pub(crate) host: String,
    pub(crate) fingerprint: String,
}

pub(crate) fn validate_ssh_host_key_pins(
    pins: Vec<SshHostKeyPin>,
    field_name: &str,
) -> Result<Vec<SshHostKeyPin>, ApiError> {
    if pins.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{field_name}.host_key_pins must contain at least one SSH host key pin"
        )));
    }
    if pins.len() > MAX_SSH_HOST_KEY_PINS {
        return Err(ApiError::BadRequest(format!(
            "{field_name}.host_key_pins must contain at most {MAX_SSH_HOST_KEY_PINS} entries"
        )));
    }

    let mut normalized = Vec::with_capacity(pins.len());
    let mut seen = HashSet::with_capacity(pins.len());
    for (index, pin) in pins.into_iter().enumerate() {
        let host = pin.host.parse::<IpAddr>().map_err(|_| {
            ApiError::BadRequest(format!(
                "{field_name}.host_key_pins[{index}].host must be an IPv4 or IPv6 address"
            ))
        })?;
        let encoded = pin.fingerprint.strip_prefix("SHA256:").ok_or_else(|| {
            ApiError::BadRequest(format!(
                "{field_name}.host_key_pins[{index}].fingerprint must use the OpenSSH SHA256: format"
            ))
        })?;
        let digest = STANDARD_NO_PAD.decode(encoded).map_err(|_| {
            ApiError::BadRequest(format!(
                "{field_name}.host_key_pins[{index}].fingerprint must contain an unpadded SHA-256 digest"
            ))
        })?;
        if digest.len() != 32 {
            return Err(ApiError::BadRequest(format!(
                "{field_name}.host_key_pins[{index}].fingerprint must contain a 32-byte SHA-256 digest"
            )));
        }

        let pin = SshHostKeyPin {
            host: host.to_string(),
            fingerprint: format!("SHA256:{encoded}"),
        };
        if !seen.insert((pin.host.clone(), pin.fingerprint.clone())) {
            return Err(ApiError::BadRequest(format!(
                "{field_name}.host_key_pins contains a duplicate host and fingerprint"
            )));
        }
        normalized.push(pin);
    }
    normalized.sort_unstable();
    Ok(normalized)
}

pub(crate) fn parse_stored_ssh_host_key_pins(value: &str) -> Vec<SshHostKeyPin> {
    serde_json::from_str(value)
        .ok()
        .and_then(|pins| validate_ssh_host_key_pins(pins, "stored credentials.ssh").ok())
        .unwrap_or_else(|| {
            tracing::warn!(
                "stored SSH host-key pin data is invalid; returning an empty fail-closed policy"
            );
            Vec::new()
        })
}

#[cfg(test)]
mod tests {
    use super::{SshHostKeyPin, validate_ssh_host_key_pins};

    const FINGERPRINT_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FINGERPRINT_B: &str = "SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn pin(host: &str, fingerprint: &str) -> SshHostKeyPin {
        SshHostKeyPin {
            host: host.to_string(),
            fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn normalizes_and_sorts_ipv4_and_ipv6_pins() {
        let pins = validate_ssh_host_key_pins(
            vec![
                pin("2001:0db8::1", FINGERPRINT_B),
                pin("192.0.2.1", FINGERPRINT_A),
            ],
            "credentials.ssh",
        )
        .unwrap();
        assert_eq!(pins[0].host, "192.0.2.1");
        assert_eq!(pins[1].host, "2001:db8::1");
    }

    #[test]
    fn rejects_empty_duplicate_and_non_sha256_pins() {
        assert!(validate_ssh_host_key_pins(Vec::new(), "credentials.ssh").is_err());
        assert!(
            validate_ssh_host_key_pins(
                vec![
                    pin("192.0.2.1", FINGERPRINT_A),
                    pin("192.0.2.1", FINGERPRINT_A),
                ],
                "credentials.ssh",
            )
            .is_err()
        );
        assert!(
            validate_ssh_host_key_pins(vec![pin("192.0.2.1", "MD5:00:11")], "credentials.ssh",)
                .is_err()
        );
    }
}
