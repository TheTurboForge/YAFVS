// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    alert_write_db::ensure_alert_owner_matches_operator,
    alert_write_sql::*,
    alert_write_validation::{
        AlertCloneRequest, AlertPatchRequest, MAX_ALERT_TEXT_BYTES, validate_alert_clone_request,
        validate_alert_patch_request,
    },
    errors::ApiError,
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> AlertPatchRequest {
    AlertPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> AlertCloneRequest {
    AlertCloneRequest {
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
fn alert_clone_handler_requires_operator_owner_and_unique_name_before_mutation() {
    let source = include_str!("alert_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn clone_alert")
        .expect("clone alert handler must exist")
        .1
        .split_once("pub(crate) async fn delete_alert")
        .expect("delete alert handler follows clone handler")
        .0;

    let owner_check = "ensure_alert_owner_matches_operator(source.owner_id, owner_id)?;";
    let unique_check = "ensure_unique_alert_name(&tx, name, -1).await?;";
    assert!(handler.contains("let operator = require_alert_write_operator(operator)?;"));
    assert!(handler.contains("let request = validate_alert_clone_request(request)?;"));
    assert!(handler.contains("resolve_alert_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(handler.contains(unique_check));
    assert!(handler.contains("execute_alert_clone_transaction"));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_alert_clone_transaction").unwrap()
    );
    assert!(
        handler.find(unique_check).unwrap()
            < handler.find("execute_alert_clone_transaction").unwrap()
    );
}

#[test]
fn alert_delete_handler_requires_operator_owner_and_live_task_guard_before_mutation() {
    let source = include_str!("alert_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn delete_alert")
        .expect("delete alert handler must exist")
        .1
        .split_once("pub(crate) async fn patch_alert")
        .expect("patch alert handler follows delete handler")
        .0;

    let owner_check = "ensure_alert_owner_matches_operator(state.owner_id, operator_owner_id)?;";
    let task_guard = "ensure_alert_not_in_use_by_live_tasks(&tx, state.internal_id).await?;";
    assert!(handler.contains("let operator = require_alert_write_operator(operator)?;"));
    assert!(handler.contains("resolve_alert_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(handler.contains(task_guard));
    assert!(handler.contains("execute_alert_trash_transaction"));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_alert_trash_transaction").unwrap()
    );
    assert!(
        handler.find(task_guard).unwrap()
            < handler.find("execute_alert_trash_transaction").unwrap()
    );
}

#[test]
fn alert_patch_handler_requires_operator_and_owner_before_mutation() {
    let source = include_str!("alert_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_alert")
        .expect("patch alert handler must exist")
        .1;

    let owner_check =
        "ensure_alert_owner_matches_operator(alert_state.owner_id, operator_owner_id)?;";
    assert!(handler.contains("let operator = require_alert_write_operator(operator)?;"));
    assert!(handler.contains("resolve_alert_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_alert_patch_transaction").unwrap(),
        "alert patch must verify owner before metadata mutation"
    );
}

#[test]
fn alert_clone_request_trims_optional_metadata_fields() {
    let validated =
        validate_alert_clone_request(clone_request(Some("  copied alert  "), Some("  note  ")))
            .expect("valid alert clone");
    assert_eq!(validated.name.as_deref(), Some("copied alert"));
    assert_eq!(validated.comment.as_deref(), Some("note"));
}

#[test]
fn alert_clone_request_accepts_empty_body_for_inherited_clone_name() {
    let validated = validate_alert_clone_request(clone_request(None, None))
        .expect("empty clone request uses inherited defaults");
    assert_eq!(validated.name, None);
    assert_eq!(validated.comment, None);
}

#[test]
fn alert_clone_request_rejects_blank_name_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_alert_clone_request(clone_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_alert_clone_request(clone_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_alert_clone_request(clone_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Clone", "method_data": {"recipient": "operator@example.invalid"}});
    assert!(serde_json::from_value::<AlertCloneRequest>(request).is_err());
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
    assert!(sql.contains("RETURNING id::integer, uuid::text"));
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
fn alert_clone_sql_copies_metadata_child_rows_and_live_tag_links_only() {
    let metadata = alert_clone_metadata_sql();
    assert!(metadata.contains("INSERT INTO alerts"));
    assert!(metadata.contains("make_uuid()"));
    assert!(metadata.contains("coalesce($3, uniquify('alert', name, $2, ' Clone'))"));
    assert!(metadata.contains("coalesce($4, comment)"));
    assert!(metadata.contains("RETURNING id::integer, uuid::text"));
    assert!(!metadata.contains("alerts_trash"));

    for (sql, table) in [
        (alert_clone_condition_data_sql(), "alert_condition_data"),
        (alert_clone_event_data_sql(), "alert_event_data"),
        (alert_clone_method_data_sql(), "alert_method_data"),
    ] {
        assert!(sql.contains(&format!("INSERT INTO {table}")));
        assert!(sql.contains("SELECT $2, name, data"));
        assert!(sql.contains("WHERE alert = $1"));
        assert!(!sql.contains("_trash"));
    }

    let tags = alert_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'alert'"));
    assert!(tags.contains("resource = $1"));
    assert!(tags.contains("resource_location = 0"));
    assert!(!tags.contains("tag_resources_trash"));
}

#[test]
fn alert_delete_sql_moves_metadata_children_tasks_and_tags_to_trash_before_live_delete() {
    let task_guard = alert_live_task_count_sql();
    assert!(task_guard.contains("JOIN tasks t ON t.id = ta.task"));
    assert!(task_guard.contains("ta.alert_location = 0"));
    assert!(task_guard.contains("coalesce(t.hidden, 0) < 2"));

    let metadata = alert_trash_insert_sql();
    assert!(metadata.contains("INSERT INTO alerts_trash"));
    assert!(metadata.contains("FROM alerts"));
    assert!(metadata.contains("RETURNING id::integer, uuid::text"));

    for (sql, table) in [
        (
            alert_condition_data_trash_insert_sql(),
            "alert_condition_data_trash",
        ),
        (
            alert_event_data_trash_insert_sql(),
            "alert_event_data_trash",
        ),
        (
            alert_method_data_trash_insert_sql(),
            "alert_method_data_trash",
        ),
    ] {
        assert!(sql.contains(&format!("INSERT INTO {table}")));
        assert!(sql.contains("SELECT $1, name, data"));
        assert!(sql.contains("WHERE alert = $2"));
    }

    let task_relink = alert_task_relink_to_trash_sql();
    assert!(task_relink.contains("UPDATE task_alerts"));
    assert!(task_relink.contains("alert_location = 1"));

    let live_tags = alert_tag_locations_to_trash_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_location = 1"));
    assert!(live_tags.contains("resource_type = 'alert'"));

    let trashed_tags = alert_trash_tag_locations_to_trash_sql();
    assert!(trashed_tags.contains("UPDATE tag_resources_trash"));
    assert!(trashed_tags.contains("resource_location = 1"));

    assert_eq!(
        alert_delete_condition_data_sql(),
        "DELETE FROM alert_condition_data WHERE alert = $1;"
    );
    assert_eq!(
        alert_delete_event_data_sql(),
        "DELETE FROM alert_event_data WHERE alert = $1;"
    );
    assert_eq!(
        alert_delete_method_data_sql(),
        "DELETE FROM alert_method_data WHERE alert = $1;"
    );
    assert_eq!(
        alert_delete_metadata_sql(),
        "DELETE FROM alerts WHERE id = $1;"
    );
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
