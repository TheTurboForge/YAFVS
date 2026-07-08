// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    task_write_db::{ensure_task_not_in_use_for_native_trash, ensure_task_owner_matches_operator},
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
fn task_delete_rejects_in_use_run_statuses_before_trash_move() {
    for status in [0, 3, 4, 10, 11, 14, 16, 17, 18, 19] {
        assert!(
            matches!(
                ensure_task_not_in_use_for_native_trash(status),
                Err(ApiError::Conflict(_))
            ),
            "run status {status} must stay on inherited scanner-aware delete path"
        );
    }
    for status in [1, 2, 12, 13, 99] {
        assert!(
            ensure_task_not_in_use_for_native_trash(status).is_ok(),
            "non-active run status {status} should be eligible for native trash move"
        );
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

#[test]
fn task_delete_handler_requires_operator_owner_and_in_use_check_before_trash_move() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn delete_task")
        .expect("delete task handler must exist")
        .1;

    let owner_check =
        "ensure_task_owner_matches_operator(task_state.owner_id, operator_owner_id)?;";
    let in_use_check = "ensure_task_not_in_use_for_native_trash(task_state.run_status)?;";
    assert!(handler.contains("let operator = require_task_write_operator(operator)?;"));
    assert!(handler.contains("resolve_task_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(handler.contains(in_use_check));
    assert!(handler.contains("LOCK TABLE tasks, reports, report_counts, results, results_trash, tag_resources, tag_resources_trash"));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_task_trash_transaction").unwrap(),
        "task delete must verify owner before trash mutation"
    );
    assert!(
        handler.find(in_use_check).unwrap()
            < handler.find("execute_task_trash_transaction").unwrap(),
        "task delete must reject in-use tasks before trash mutation"
    );
    assert!(handler.contains("StatusCode::NO_CONTENT"));
}

#[test]
fn task_delete_sql_matches_inherited_safe_trash_subset() {
    let state = task_write_state_sql();
    assert!(state.contains("coalesce(run_status, 1)::integer"));
    assert!(state.contains("coalesce(hidden, 0) = 0"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));

    for sql in [
        task_trash_task_tag_locations_sql(),
        task_trash_task_trash_tag_locations_sql(),
        task_trash_report_tag_locations_sql(),
        task_trash_report_trash_tag_locations_sql(),
        task_trash_result_tag_locations_sql(),
        task_trash_result_trash_tag_locations_sql(),
    ] {
        assert!(sql.contains("UPDATE tag_resources") || sql.contains("UPDATE tag_resources_trash"));
        assert!(sql.contains("SET resource_location = 1"));
    }

    let insert_results = task_trash_results_insert_sql();
    assert!(insert_results.contains("INSERT INTO results_trash"));
    assert!(insert_results.contains("FROM results"));
    assert!(insert_results.contains("WHERE report IN (SELECT id FROM reports WHERE task = $1)"));

    let delete_results = task_delete_live_results_sql();
    assert!(delete_results.contains("DELETE FROM results"));
    assert!(delete_results.contains("WHERE report IN (SELECT id FROM reports WHERE task = $1)"));

    let delete_counts = task_delete_report_counts_sql();
    assert!(delete_counts.contains("DELETE FROM report_counts"));
    assert!(delete_counts.contains("WHERE report IN (SELECT id FROM reports WHERE task = $1)"));

    let mark_hidden = task_mark_hidden_trash_sql();
    assert!(mark_hidden.contains("UPDATE tasks"));
    assert!(mark_hidden.contains("hidden = 2"));
    assert!(mark_hidden.contains("modification_time = m_now()"));
    assert!(mark_hidden.contains("coalesce(hidden, 0) = 0"));
    assert!(mark_hidden.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(mark_hidden.contains("RETURNING uuid::text"));
}
