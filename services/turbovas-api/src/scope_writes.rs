// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use serde::Deserialize;

use crate::{errors::ApiError, path_ids::parse_uuid};

const MAX_SCOPE_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeCreateRequest {
    name: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    protection_requirement: Option<String>,
    #[serde(default)]
    target_ids: Vec<String>,
    #[serde(default)]
    host_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopePatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    protection_requirement: Option<String>,
    #[serde(default)]
    target_ids: Option<Vec<String>>,
    #[serde(default)]
    host_ids: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScopeCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) protection_requirement: String,
    pub(crate) target_ids: Vec<String>,
    pub(crate) host_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScopePatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) protection_requirement: Option<String>,
    pub(crate) target_ids: Option<Vec<String>>,
    pub(crate) host_ids: Option<Vec<String>>,
}

pub(crate) fn validate_scope_create_request(
    request: ScopeCreateRequest,
) -> Result<ValidatedScopeCreate, ApiError> {
    Ok(ValidatedScopeCreate {
        name: normalize_required_scope_text(request.name, "name")?,
        comment: normalize_optional_scope_text(request.comment, "comment")?,
        protection_requirement: normalize_protection_requirement(
            request.protection_requirement.as_deref(),
        )?
        .unwrap_or_else(|| "normal".to_string()),
        target_ids: normalize_membership_ids(request.target_ids, "target_ids")?,
        host_ids: normalize_membership_ids(request.host_ids, "host_ids")?,
    })
}

pub(crate) fn validate_scope_patch_request(
    request: ScopePatchRequest,
) -> Result<ValidatedScopePatch, ApiError> {
    Ok(ValidatedScopePatch {
        name: normalize_optional_scope_text(request.name, "name")?,
        comment: normalize_optional_scope_text(request.comment, "comment")?,
        protection_requirement: normalize_protection_requirement(
            request.protection_requirement.as_deref(),
        )?,
        target_ids: normalize_optional_membership_ids(request.target_ids, "target_ids")?,
        host_ids: normalize_optional_membership_ids(request.host_ids, "host_ids")?,
    })
}

pub(crate) fn ensure_scope_is_mutable(is_global: bool, predefined: bool) -> Result<(), ApiError> {
    if is_global || predefined {
        Err(ApiError::Conflict("scope is immutable".to_string()))
    } else {
        Ok(())
    }
}

pub(crate) fn scope_write_operator_owner_sql() -> &'static str {
    "SELECT id::bigint, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_mutability_sql() -> &'static str {
    "SELECT id::bigint, coalesce(predefined, 0)::integer, coalesce(is_global, 0)::integer
       FROM scopes
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_report_history_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM scope_reports
      WHERE scope_uuid = $1;"
}

pub(crate) fn scope_write_visible_targets_sql() -> &'static str {
    "SELECT uuid::text
       FROM targets
      WHERE uuid = ANY($1);"
}

pub(crate) fn scope_write_visible_hosts_sql() -> &'static str {
    "SELECT uuid::text
       FROM hosts
      WHERE uuid = ANY($1);"
}

fn normalize_required_scope_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_scope_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_scope_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_scope_text_value(value, field_name))
        .transpose()
}

fn normalize_scope_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCOPE_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCOPE_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_protection_requirement(value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    match normalized.as_str() {
        "" => Ok(None),
        "normal" | "high" | "very_high" => Ok(Some(normalized)),
        _ => Err(ApiError::BadRequest(
            "protection_requirement must be normal, high, or very_high".to_string(),
        )),
    }
}

fn normalize_optional_membership_ids(
    values: Option<Vec<String>>,
    field_name: &str,
) -> Result<Option<Vec<String>>, ApiError> {
    values
        .map(|values| normalize_membership_ids(values, field_name))
        .transpose()
}

fn normalize_membership_ids(
    values: Vec<String>,
    field_name: &str,
) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let parsed = parse_uuid(value.trim())?.to_string();
        if !seen.insert(parsed.clone()) {
            return Err(ApiError::Conflict(format!(
                "{field_name} contains duplicate ids"
            )));
        }
        normalized.push(parsed);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_create_request_normalizes_defaults_and_membership_ids() {
        let request: ScopeCreateRequest = serde_json::from_str(
            r#"{
                "name": "  Example scope  ",
                "comment": "  retained  ",
                "protection_requirement": "Very High",
                "target_ids": ["12345678-1234-1234-1234-123456789ABC"],
                "host_ids": []
            }"#,
        )
        .expect("valid create DTO");

        let validated = validate_scope_create_request(request).expect("valid create request");

        assert_eq!(validated.name, "Example scope");
        assert_eq!(validated.comment.as_deref(), Some("retained"));
        assert_eq!(validated.protection_requirement, "very_high");
        assert_eq!(
            validated.target_ids,
            vec!["12345678-1234-1234-1234-123456789abc"]
        );
        assert!(validated.host_ids.is_empty());

        let defaulted = validate_scope_create_request(ScopeCreateRequest {
            name: "Defaulted".to_string(),
            comment: None,
            protection_requirement: None,
            target_ids: vec![],
            host_ids: vec![],
        })
        .expect("defaulted create request");
        assert_eq!(defaulted.protection_requirement, "normal");
    }

    #[test]
    fn scope_write_dtos_reject_unknown_fields_bad_text_and_bad_enums() {
        assert!(serde_json::from_str::<ScopeCreateRequest>(r#"{"name":"x","extra":1}"#).is_err());

        let empty_name = ScopeCreateRequest {
            name: "   ".to_string(),
            comment: None,
            protection_requirement: None,
            target_ids: vec![],
            host_ids: vec![],
        };
        assert!(matches!(
            validate_scope_create_request(empty_name),
            Err(ApiError::BadRequest(_))
        ));

        let bad_enum = ScopeCreateRequest {
            name: "scope".to_string(),
            comment: None,
            protection_requirement: Some("critical".to_string()),
            target_ids: vec![],
            host_ids: vec![],
        };
        assert!(matches!(
            validate_scope_create_request(bad_enum),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn scope_membership_validation_rejects_invalid_and_duplicate_uuids() {
        let duplicate = ScopeCreateRequest {
            name: "scope".to_string(),
            comment: None,
            protection_requirement: None,
            target_ids: vec![
                "12345678-1234-1234-1234-123456789abc".to_string(),
                "12345678-1234-1234-1234-123456789ABC".to_string(),
            ],
            host_ids: vec![],
        };
        assert!(matches!(
            validate_scope_create_request(duplicate),
            Err(ApiError::Conflict(_))
        ));

        let invalid = ScopePatchRequest {
            name: None,
            comment: None,
            protection_requirement: None,
            target_ids: None,
            host_ids: Some(vec!["not-a-uuid".to_string()]),
        };
        assert!(matches!(
            validate_scope_patch_request(invalid),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn scope_patch_request_distinguishes_preserve_and_replace_membership() {
        let preserve = validate_scope_patch_request(ScopePatchRequest {
            name: None,
            comment: None,
            protection_requirement: None,
            target_ids: None,
            host_ids: None,
        })
        .expect("preserve-only patch");
        assert_eq!(preserve.target_ids, None);
        assert_eq!(preserve.host_ids, None);

        let replace = validate_scope_patch_request(ScopePatchRequest {
            name: Some("renamed".to_string()),
            comment: None,
            protection_requirement: Some("high".to_string()),
            target_ids: Some(vec![]),
            host_ids: Some(vec!["12345678-1234-1234-1234-123456789abc".to_string()]),
        })
        .expect("replace-membership patch");
        assert_eq!(replace.name.as_deref(), Some("renamed"));
        assert_eq!(replace.protection_requirement.as_deref(), Some("high"));
        assert_eq!(replace.target_ids, Some(vec![]));
        assert_eq!(
            replace.host_ids,
            Some(vec!["12345678-1234-1234-1234-123456789abc".to_string()])
        );
    }

    #[test]
    fn scope_mutability_guard_blocks_global_or_predefined_scopes() {
        assert!(ensure_scope_is_mutable(false, false).is_ok());
        for (is_global, predefined) in [(true, false), (false, true), (true, true)] {
            assert!(matches!(
                ensure_scope_is_mutable(is_global, predefined),
                Err(ApiError::Conflict(_))
            ));
        }
    }

    #[test]
    fn scope_write_scaffold_sql_is_read_only_and_targets_expected_tables() {
        for sql in [
            scope_write_operator_owner_sql(),
            scope_write_mutability_sql(),
            scope_write_report_history_sql(),
            scope_write_visible_targets_sql(),
            scope_write_visible_hosts_sql(),
        ] {
            let upper_sql = sql.to_ascii_uppercase();
            assert!(upper_sql.contains("SELECT"));
            for forbidden in ["INSERT", "UPDATE", "DELETE", "TRUNCATE"] {
                assert!(!upper_sql.contains(forbidden), "{forbidden} in {sql}");
            }
        }
        assert!(scope_write_operator_owner_sql().contains("FROM users"));
        assert!(scope_write_mutability_sql().contains("FROM scopes"));
        assert!(scope_write_report_history_sql().contains("FROM scope_reports"));
        assert!(scope_write_visible_targets_sql().contains("FROM targets"));
        assert!(scope_write_visible_hosts_sql().contains("FROM hosts"));
    }

    #[test]
    fn scope_write_scaffold_is_not_registered_as_a_live_route() {
        let main_source = include_str!("main.rs");
        let router_block = main_source
            .split_once("let app = Router::new()")
            .expect("router setup must exist")
            .1
            .split_once(".with_state(state);")
            .expect("router setup must end with app state")
            .0;

        assert!(main_source.contains("mod scope_writes;"));
        for forbidden in [
            "post(scope",
            "put(scope",
            "patch(scope",
            "delete(scope",
            "route(\"/api/v1/scopes\", post",
            "route(\"/api/v1/scopes/:scope_id\", patch",
            "route(\"/api/v1/scopes/:scope_id\", delete",
        ] {
            assert!(
                !router_block.contains(forbidden),
                "live scope write route: {forbidden}"
            );
        }
    }
}
