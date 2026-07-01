// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    alert_write_db::ensure_alert_owner_matches_operator,
    alert_write_sql::*,
    alert_write_validation::{
        AlertPatchRequest, MAX_ALERT_TEXT_BYTES, validate_alert_patch_request,
    },
    errors::ApiError,
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> AlertPatchRequest {
    AlertPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn alert_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_alert_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_alert_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn alert_patch_request_trims_metadata_fields() {
    let validated =
        validate_alert_patch_request(patch_request(Some("  daily alert  "), Some("  comment  ")))
            .expect("valid alert patch");
    assert_eq!(validated.name.as_deref(), Some("daily alert"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn alert_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_alert_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_alert_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_alert_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn alert_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_alert_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_alert_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Alert", "method_data": {"recipient": "operator@example.invalid"}});
    assert!(serde_json::from_value::<AlertPatchRequest>(request).is_err());
}

#[test]
fn alert_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_alert_patch_request(AlertPatchRequest {
            name: Some("x".repeat(MAX_ALERT_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_patch_sql_is_metadata_only() {
    let sql = alert_update_metadata_sql();
    assert!(sql.contains("UPDATE alerts"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("RETURNING uuid::text"));
    for forbidden in [
        "active",
        "filter",
        "event",
        "condition",
        "method",
        "alert_method_data",
        "alert_event_data",
        "alert_condition_data",
        "task_alerts",
        "credential",
        "password",
        "secret",
    ] {
        assert!(
            !sql.contains(forbidden),
            "alert patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn alert_patch_state_and_uniqueness_are_live_metadata_only() {
    let state = alert_write_state_sql();
    assert!(state.contains("FROM alerts"));
    assert!(state.contains("owner::integer"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(!state.contains("alerts_trash"));

    let unique = alert_unique_name_sql();
    assert!(unique.contains("FROM alerts"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(!unique.contains("alerts_trash"));
}
