// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) fn normalize_protection_requirement(value: &str) -> String {
    match value {
        "normal" | "Normal" => "Normal".to_string(),
        "high" | "High" => "High".to_string(),
        "very_high" | "very high" | "Very High" => "Very High".to_string(),
        _ => value.to_string(),
    }
}

pub(crate) fn normalize_authentication_state(state: &str) -> String {
    match state {
        "authenticated" | "Authenticated" => "Authenticated".to_string(),
        "authentication_failed" | "Authentication Failed" => "Authentication Failed".to_string(),
        "no_credential_path" | "No Credential Path" => "No Credential Path".to_string(),
        _ => "Unknown".to_string(),
    }
}

pub(crate) fn unix_ts_to_rfc3339(value: i64) -> Option<String> {
    if value <= 0 {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(value)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_state_is_public_contract_shape() {
        assert_eq!(
            normalize_authentication_state("authenticated"),
            "Authenticated"
        );
        assert_eq!(
            normalize_authentication_state("authentication_failed"),
            "Authentication Failed"
        );
        assert_eq!(
            normalize_authentication_state("no_credential_path"),
            "No Credential Path"
        );
        assert_eq!(normalize_authentication_state("ambiguous"), "Unknown");
    }

    #[test]
    fn protection_requirement_is_public_contract_shape() {
        assert_eq!(normalize_protection_requirement("normal"), "Normal");
        assert_eq!(normalize_protection_requirement("high"), "High");
        assert_eq!(normalize_protection_requirement("very_high"), "Very High");
        assert_eq!(normalize_protection_requirement("Very High"), "Very High");
    }

    #[test]
    fn unix_timestamp_formats_as_rfc3339() {
        assert_eq!(unix_ts_to_rfc3339(0), None);
        assert_eq!(unix_ts_to_rfc3339(1).unwrap(), "1970-01-01T00:00:01Z");
    }
}
