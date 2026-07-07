// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    task_write_db::ensure_task_owner_matches_operator,
    task_write_sql::*,
    task_write_validation::{MAX_TASK_TEXT_BYTES, TaskPatchRequest, validate_task_patch_request},
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> TaskPatchRequest {
    TaskPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn task_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_task_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_task_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn task_patch_handler_requires_operator_and_owner_before_mutation() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_task")
        .expect("patch task handler must exist")
        .1;

    let owner_check =
        "ensure_task_owner_matches_operator(task_state.owner_id, operator_owner_id)?;";
    assert!(handler.contains("let operator = require_task_write_operator(operator)?;"));
    assert!(handler.contains("resolve_task_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_task_patch_transaction").unwrap(),
        "task patch must verify owner before metadata mutation"
    );
}

#[test]
fn task_patch_request_trims_metadata_fields() {
    let validated =
        validate_task_patch_request(patch_request(Some("  scan task  "), Some("  comment  ")))
            .expect("valid task patch");
    assert_eq!(validated.name.as_deref(), Some("scan task"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn task_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_task_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_task_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_task_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn task_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_task_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_task_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Task", "target_id": "target"});
    assert!(serde_json::from_value::<TaskPatchRequest>(request).is_err());
}

#[test]
fn task_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_task_patch_request(TaskPatchRequest {
            name: Some("x".repeat(MAX_TASK_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_patch_sql_is_metadata_only() {
    let sql = task_update_metadata_sql();
    assert!(sql.contains("UPDATE tasks"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("coalesce(hidden, 0) = 0"));
    assert!(sql.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(sql.contains("RETURNING uuid::text"));
    for forbidden in [
        "target =",
        "config =",
        "schedule =",
        "scanner =",
        "run_status",
        "start_time",
        "end_time",
        "schedule_next_time",
        "schedule_periods",
        "alterable",
        "upload_result_count",
        "task_alerts",
        "task_preferences",
        "reports",
        "results",
        "credentials",
    ] {
        assert!(
            !sql.contains(forbidden),
            "task patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn task_patch_state_and_uniqueness_are_live_scan_metadata_only() {
    let state = task_write_state_sql();
    assert!(state.contains("FROM tasks"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(state.contains("owner::integer"));
    assert!(state.contains("coalesce(hidden, 0) = 0"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(!state.contains("task_alerts"));
    assert!(!state.contains("task_preferences"));

    let unique = task_unique_name_sql();
    assert!(unique.contains("FROM tasks"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(unique.contains("owner = $3"));
    assert!(unique.contains("coalesce(hidden, 0) = 0"));
    assert!(unique.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(!unique.contains("task_alerts"));
    assert!(!unique.contains("task_preferences"));
}
