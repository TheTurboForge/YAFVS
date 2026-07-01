// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    target_write_db::ensure_target_owner_matches_operator,
    target_write_sql::*,
    target_write_validation::{
        MAX_TARGET_TEXT_BYTES, TargetPatchRequest, validate_target_patch_request,
    },
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> TargetPatchRequest {
    TargetPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn target_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_target_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_target_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn target_patch_request_trims_metadata_fields() {
    let validated =
        validate_target_patch_request(patch_request(Some("  scan target  "), Some("  comment  ")))
            .expect("valid target patch");
    assert_eq!(validated.name.as_deref(), Some("scan target"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn target_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_target_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_target_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_target_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn target_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_target_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Target", "hosts": "192.0.2.1"});
    assert!(serde_json::from_value::<TargetPatchRequest>(request).is_err());
}

#[test]
fn target_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_target_patch_request(TargetPatchRequest {
            name: Some("x".repeat(MAX_TARGET_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_sql_is_metadata_only() {
    let sql = target_update_metadata_sql();
    assert!(sql.contains("UPDATE targets"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("RETURNING uuid::text"));
    for forbidden in [
        "targets_login_data",
        "targets_trash",
        "tasks",
        "credentials",
        "port_lists",
        "hosts =",
        "exclude_hosts",
        "port_list",
        "alive_test",
        "allow_simultaneous_ips",
        "reverse_lookup",
        "ssh",
        "smb",
        "snmp",
        "krb5",
        "esxi",
    ] {
        assert!(
            !sql.contains(forbidden),
            "target patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn target_patch_state_and_uniqueness_are_live_metadata_only() {
    let state = target_write_state_sql();
    assert!(state.contains("FROM targets"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(state.contains("owner::integer"));
    assert!(!state.contains("targets_login_data"));
    assert!(!state.contains("targets_trash"));

    let unique = target_unique_name_sql();
    assert!(unique.contains("FROM targets"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(unique.contains("owner = $3"));
    assert!(!unique.contains("targets_login_data"));
    assert!(!unique.contains("targets_trash"));
}
