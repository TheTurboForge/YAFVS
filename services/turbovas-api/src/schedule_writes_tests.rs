// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::errors::ApiError;
use crate::schedule_write_plans::*;
use crate::schedule_write_sql::*;
use crate::schedule_write_validation::*;

fn patch_request(name: Option<&str>, comment: Option<&str>) -> SchedulePatchRequest {
    SchedulePatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> ScheduleCloneRequest {
    ScheduleCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn schedule_write_rejects_operator_owner_mismatch() {
    assert!(ensure_schedule_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_schedule_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn schedule_clone_request_accepts_default_or_metadata_override() {
    let default =
        validate_schedule_clone_request(clone_request(None, None)).expect("default clone metadata");
    assert_eq!(default.name, None);
    assert_eq!(default.comment, None);

    let named = validate_schedule_clone_request(clone_request(
        Some("  copied schedule  "),
        Some("  copied comment  "),
    ))
    .expect("named clone");
    assert_eq!(named.name.as_deref(), Some("copied schedule"));
    assert_eq!(named.comment.as_deref(), Some("copied comment"));

    let clear_comment =
        validate_schedule_clone_request(clone_request(None, Some("   "))).expect("clear comment");
    assert_eq!(clear_comment.comment.as_deref(), Some(""));
}

#[test]
fn schedule_clone_request_rejects_blank_name_control_characters_and_calendar_fields() {
    assert!(matches!(
        validate_schedule_clone_request(clone_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_schedule_clone_request(clone_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    for request in [
        serde_json::json!({"icalendar": "BEGIN:VCALENDAR\nEND:VCALENDAR"}),
        serde_json::json!({"timezone": "UTC"}),
        serde_json::json!({"period": 3600}),
    ] {
        assert!(serde_json::from_value::<ScheduleCloneRequest>(request).is_err());
    }
}

#[test]
fn schedule_clone_sql_copies_calendar_fields_without_recalculation() {
    let metadata = schedule_clone_metadata_sql();
    assert!(metadata.contains("INSERT INTO schedules"));
    assert!(metadata.contains("make_uuid()"));
    assert!(metadata.contains("coalesce($3, uniquify('schedule', name, $2, ' Clone'))"));
    for copied in [
        "first_time",
        "period",
        "period_months",
        "byday",
        "duration",
        "timezone",
        "icalendar",
    ] {
        assert!(
            metadata.contains(copied),
            "schedule clone must copy {copied}"
        );
    }
    for forbidden in [
        "UPDATE tasks",
        "schedule_next_time",
        "icalendar_from_string",
    ] {
        assert!(
            !metadata.contains(forbidden),
            "schedule clone SQL must not perform calendar edit side effect {forbidden}"
        );
    }

    let tags = schedule_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'schedule'"));
    assert!(tags.contains("resource_location = 0"));
}

#[test]
fn schedule_restore_sql_moves_metadata_tasks_and_tags_to_live() {
    let state = schedule_trash_state_sql();
    assert!(state.contains("FROM schedules_trash"));
    assert!(state.contains("uuid = $1"));
    assert!(state.contains("owner::integer"));

    let unique_name = schedule_unique_live_owner_name_sql();
    assert!(unique_name.contains("FROM schedules"));
    assert!(unique_name.contains("name = $1"));
    assert!(unique_name.contains("owner = $2"));

    let uuid_conflict = schedule_live_uuid_conflict_sql();
    assert!(uuid_conflict.contains("FROM schedules"));
    assert!(uuid_conflict.contains("uuid = $1"));

    let restore = schedule_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO schedules"));
    assert!(restore.contains("FROM schedules_trash"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));

    let task_relink = schedule_task_relink_to_live_sql();
    assert!(task_relink.contains("UPDATE tasks"));
    assert!(task_relink.contains("schedule_location = 0"));
    assert!(task_relink.contains("WHERE schedule = $1"));
    assert!(task_relink.contains("schedule_location = 1"));

    for sql in [
        schedule_tag_locations_to_live_sql(),
        schedule_trash_tag_locations_to_live_sql(),
    ] {
        assert!(sql.contains("resource_type = 'schedule'"));
        assert!(sql.contains("resource_location = 0"));
        assert!(sql.contains("resource = $1"));
        assert!(sql.contains("resource = $2"));
    }

    assert_eq!(
        schedule_delete_trash_metadata_sql(),
        "DELETE FROM schedules_trash WHERE id = $1;"
    );
}

#[test]
fn schedule_clone_plan_copies_metadata_and_tags_without_calendar_edit_steps() {
    let named = validate_schedule_clone_request(clone_request(Some("copy"), None))
        .expect("valid named clone");
    assert_eq!(
        schedule_clone_transaction_plan(&named).steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::CloneScheduleMetadata,
            ScheduleWriteStep::CloneScheduleTags,
        ]
    );

    let default =
        validate_schedule_clone_request(clone_request(None, None)).expect("valid default clone");
    assert_eq!(
        schedule_clone_transaction_plan(&default).steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::CloneScheduleMetadata,
            ScheduleWriteStep::CloneScheduleTags,
        ]
    );
}

#[test]
fn schedule_hard_delete_sql_deletes_only_trash_metadata_and_tags() {
    let task_guard = schedule_trash_task_count_sql();
    assert!(task_guard.contains("FROM tasks"));
    assert!(task_guard.contains("WHERE schedule = $1"));
    assert!(task_guard.contains("schedule_location = 1"));
    assert!(!task_guard.contains("hidden = 0"));

    let live_tag_cleanup = schedule_trash_tag_delete_sql();
    assert!(live_tag_cleanup.contains("DELETE FROM tag_resources"));
    assert!(live_tag_cleanup.contains("resource_type = 'schedule'"));
    assert!(live_tag_cleanup.contains("resource_location = 1"));

    let trash_tag_cleanup = schedule_trash_tag_trash_delete_sql();
    assert!(trash_tag_cleanup.contains("DELETE FROM tag_resources_trash"));
    assert!(trash_tag_cleanup.contains("resource_type = 'schedule'"));
    assert!(trash_tag_cleanup.contains("resource_location = 1"));

    let metadata_delete = schedule_delete_trash_metadata_sql();
    assert_eq!(
        metadata_delete,
        "DELETE FROM schedules_trash WHERE id = $1;"
    );
    assert!(!metadata_delete.contains("DELETE FROM schedules WHERE"));
}

#[test]
fn schedule_create_plan_keeps_calendar_validation_before_insert() {
    assert_eq!(
        schedule_create_transaction_plan().steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::InsertSchedule,
        ]
    );
}

#[test]
fn schedule_hard_delete_plan_keeps_trash_safety_and_side_effects_explicit() {
    assert_eq!(
        schedule_hard_delete_transaction_plan().steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTrashTaskDeleteSafety,
            ScheduleWriteStep::RemoveTrashTagLinks,
            ScheduleWriteStep::HardDeleteScheduleFromTrash,
        ]
    );
}

#[test]
fn schedule_restore_plan_keeps_task_and_tag_side_effects_explicit() {
    assert_eq!(
        schedule_restore_transaction_plan().steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::RestoreScheduleFromTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ]
    );
}

#[test]
fn schedule_patch_request_trims_metadata_fields() {
    assert_eq!(
        validate_schedule_patch_request(patch_request(
            Some("  Weekday scan  "),
            Some("  operator-visible note  "),
        ))
        .unwrap(),
        ValidatedSchedulePatch {
            name: Some("Weekday scan".to_string()),
            comment: Some("operator-visible note".to_string()),
        }
    );
}

#[test]
fn schedule_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_schedule_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_schedule_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_request_allows_blank_comment_to_clear_comment() {
    assert_eq!(
        validate_schedule_patch_request(patch_request(None, Some("   "))).unwrap(),
        ValidatedSchedulePatch {
            name: None,
            comment: Some(String::new()),
        }
    );
}

#[test]
fn schedule_patch_request_rejects_control_characters() {
    assert!(matches!(
        validate_schedule_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_schedule_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_request_rejects_unknown_calendar_fields() {
    let request = serde_json::json!({
        "name": "Weekday scan",
        "icalendar": "BEGIN:VCALENDAR\nEND:VCALENDAR",
    });
    assert!(serde_json::from_value::<SchedulePatchRequest>(request).is_err());
}

#[test]
fn schedule_patch_request_rejects_oversized_metadata_fields() {
    let oversized = "a".repeat(MAX_SCHEDULE_TEXT_BYTES + 1);
    assert!(matches!(
        validate_schedule_patch_request(SchedulePatchRequest {
            name: Some(oversized),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_plan_refreshes_tasks_only_for_calendar_changes() {
    assert_eq!(
        schedule_patch_transaction_plan(false).steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::UpdateScheduleMetadata,
        ]
    );
    assert_eq!(
        schedule_patch_transaction_plan(true).steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::UpdateScheduleMetadata,
            ScheduleWriteStep::RefreshTaskNextTimes,
        ]
    );
}

#[test]
fn schedule_patch_sql_is_metadata_only() {
    let state = schedule_write_state_sql();
    assert!(state.contains("owner::integer"));

    let sql = schedule_update_metadata_sql();
    assert!(sql.contains("UPDATE schedules"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    for forbidden in [
        "icalendar",
        "timezone",
        "first_time",
        "period",
        "period_months",
        "byday",
        "duration",
        "tasks",
        "schedule_next_time",
    ] {
        assert!(
            !sql.contains(forbidden),
            "schedule patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn schedule_patch_uniqueness_checks_live_and_trash_names() {
    let sql = schedule_unique_name_sql();
    assert!(sql.contains("FROM schedules WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM schedules_trash WHERE name = $1"));
}

#[test]
fn schedule_delete_sql_moves_metadata_tasks_and_tags_to_trash() {
    assert!(schedule_live_task_count_sql().contains("hidden = 0"));
    assert!(schedule_live_task_count_sql().contains("schedule_location = 0"));

    let trash_insert = schedule_trash_insert_sql();
    assert!(trash_insert.contains("INSERT INTO schedules_trash"));
    assert!(trash_insert.contains("FROM schedules"));
    assert!(trash_insert.contains("RETURNING id::integer, uuid::text"));

    let task_relink = schedule_task_relink_sql();
    assert!(task_relink.contains("UPDATE tasks"));
    assert!(task_relink.contains("schedule_location = 1"));
    assert!(task_relink.contains("WHERE schedule = $2"));
    assert!(task_relink.contains("schedule_location = 0"));

    for sql in [
        schedule_tag_locations_to_trash_sql(),
        schedule_trash_tag_locations_to_trash_sql(),
    ] {
        assert!(sql.contains("resource_type = 'schedule'"));
        assert!(sql.contains("resource_location = 1"));
        assert!(sql.contains("resource = $1"));
        assert!(sql.contains("resource = $2"));
    }

    assert_eq!(
        schedule_delete_metadata_sql(),
        "DELETE FROM schedules WHERE id = $1;"
    );
}

#[test]
fn schedule_delete_plan_keeps_task_and_trash_side_effects_explicit() {
    assert_eq!(
        schedule_delete_transaction_plan().steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTaskDeleteSafety,
            ScheduleWriteStep::MoveScheduleToTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
