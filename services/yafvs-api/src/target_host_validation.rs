// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{errors::ApiError, target_host_syntax::parse_list};

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
            let (normalized_hosts, host_identities) = parse_list(hosts, "hosts")?;
            if normalized_hosts.is_empty() {
                return Err(ApiError::BadRequest("hosts is required".to_string()));
            }
            let (normalized_excludes, exclude_identities) =
                parse_list(exclude_hosts.unwrap_or_default(), "exclude_hosts")?;
            if host_identities.is_subset(&exclude_identities) {
                return Err(ApiError::BadRequest(
                    "hosts cannot be fully excluded".to_string(),
                ));
            }
            Ok((
                Some(
                    normalized_hosts
                        .iter()
                        .map(|host| host.canonical.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                Some(
                    normalized_excludes
                        .iter()
                        .map(|host| host.canonical.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusions_apply_to_expanded_canonical_identities() {
        let (hosts, excludes) = validate_target_host_lists(
            Some(vec!["192.0.2.0/29".to_string()]),
            Some(vec!["192.0.2.1-3".to_string()]),
        )
        .expect("partially excluded range remains valid");
        assert_eq!(hosts.as_deref(), Some("192.0.2.0/29"));
        assert_eq!(excludes.as_deref(), Some("192.0.2.1-3"));
    }

    #[test]
    fn exclusions_outside_the_include_set_do_not_change_validity() {
        assert!(
            validate_target_host_lists(
                Some(vec!["host.example".to_string()]),
                Some(vec!["other.example".to_string()]),
            )
            .is_ok()
        );
    }

    #[test]
    fn fully_excluded_expansions_are_rejected() {
        assert!(matches!(
            validate_target_host_lists(
                Some(vec!["192.0.2.0/30".to_string()]),
                Some(vec!["192.0.2.1-2".to_string()]),
            ),
            Err(ApiError::BadRequest(message)) if message == "hosts cannot be fully excluded"
        ));
    }
}
