// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashSet, net::IpAddr};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::Deserialize;

use super::error::{Result, SshErrorKind};

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_HOST_KEY_PINS: usize = 4095;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePin {
    host: String,
    fingerprint: String,
}

#[derive(Clone, Debug)]
pub(crate) struct HostKeyPolicy {
    accepted_digests: Vec<[u8; 32]>,
}

impl HostKeyPolicy {
    pub(super) fn from_preferences(
        require_value: Option<&str>,
        pins_b64: Option<&str>,
        host: IpAddr,
    ) -> Result<Option<Self>> {
        let required = match require_value {
            None => pins_b64.is_some(),
            Some("1" | "yes" | "true") => true,
            Some("0" | "no" | "false") => pins_b64.is_some(),
            Some(_) => return Err(SshErrorKind::HostKeyPolicyInvalid.into()),
        };
        if !required {
            return Ok(None);
        }
        let pins_b64 = pins_b64.ok_or(SshErrorKind::HostKeyPinMissing)?;
        if pins_b64.len() > MAX_POLICY_BYTES * 2 {
            return Err(SshErrorKind::HostKeyPolicyInvalid.into());
        }
        let raw = STANDARD
            .decode(pins_b64)
            .map_err(|_| SshErrorKind::HostKeyPolicyInvalid)?;
        if raw.len() > MAX_POLICY_BYTES {
            return Err(SshErrorKind::HostKeyPolicyInvalid.into());
        }
        let pins: Vec<WirePin> =
            serde_json::from_slice(&raw).map_err(|_| SshErrorKind::HostKeyPolicyInvalid)?;
        if pins.is_empty() || pins.len() > MAX_HOST_KEY_PINS {
            return Err(SshErrorKind::HostKeyPolicyInvalid.into());
        }

        let mut accepted_digests = Vec::new();
        let mut seen = HashSet::with_capacity(pins.len());
        for pin in pins {
            let pin_host = pin
                .host
                .parse::<IpAddr>()
                .map_err(|_| SshErrorKind::HostKeyPolicyInvalid)?;
            let encoded = pin
                .fingerprint
                .strip_prefix("SHA256:")
                .ok_or(SshErrorKind::HostKeyPolicyInvalid)?;
            let digest = STANDARD_NO_PAD
                .decode(encoded)
                .map_err(|_| SshErrorKind::HostKeyPolicyInvalid)?;
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| SshErrorKind::HostKeyPolicyInvalid)?;
            if !seen.insert((pin_host, digest)) {
                return Err(SshErrorKind::HostKeyPolicyInvalid.into());
            }
            if pin_host == host {
                accepted_digests.push(digest);
            }
        }
        if accepted_digests.is_empty() {
            return Err(SshErrorKind::HostKeyPinMissing.into());
        }
        Ok(Some(Self { accepted_digests }))
    }

    pub(super) fn accepts_digest(&self, digest: &[u8]) -> bool {
        self.accepted_digests
            .iter()
            .any(|accepted| accepted.as_slice() == digest)
    }
}

#[cfg(test)]
mod tests {
    use super::HostKeyPolicy;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::net::{IpAddr, Ipv4Addr};

    const FINGERPRINT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn encoded_policy(host: &str, fingerprint: &str) -> String {
        STANDARD.encode(serde_json::json!([{"host": host, "fingerprint": fingerprint}]).to_string())
    }

    #[test]
    fn permits_discovery_without_credential_policy() {
        assert!(
            HostKeyPolicy::from_preferences(None, None, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn accepts_only_the_pinned_host_and_digest() {
        let encoded = encoded_policy("192.0.2.1", FINGERPRINT);
        let policy = HostKeyPolicy::from_preferences(
            Some("1"),
            Some(&encoded),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap()
        .unwrap();
        assert!(policy.accepts_digest(&[0; 32]));
        assert!(!policy.accepts_digest(&[1; 32]));
    }

    #[test]
    fn rejects_missing_host_invalid_policy_and_duplicates() {
        let encoded = encoded_policy("192.0.2.2", FINGERPRINT);
        assert!(
            HostKeyPolicy::from_preferences(
                Some("1"),
                Some(&encoded),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            )
            .is_err()
        );
        assert!(
            HostKeyPolicy::from_preferences(
                Some("1"),
                Some("not-base64"),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            )
            .is_err()
        );
        let duplicate = STANDARD.encode(
            serde_json::json!([
                {"host": "192.0.2.1", "fingerprint": FINGERPRINT},
                {"host": "192.0.2.1", "fingerprint": FINGERPRINT}
            ])
            .to_string(),
        );
        assert!(
            HostKeyPolicy::from_preferences(
                Some("1"),
                Some(&duplicate),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            )
            .is_err()
        );
    }
}
