// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    process,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::Duration,
};

use super::*;
use crate::errors::ApiError;
use crate::schedule_write_plans::*;
use crate::schedule_write_sql::*;
use crate::schedule_write_validation::*;

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
const OPERATOR_UUID: &str = "11111111-1111-1111-1111-111111111111";
static NEXT_SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

fn mock_socket_path() -> PathBuf {
    let sequence = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "yafvs-schedule-create-{}-{sequence}.sock",
        process::id()
    ))
}

#[test]
fn schedule_create_request_requires_exact_known_fields_and_preserves_calendar_line_breaks() {
    let calendar = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
    let validated = validate_schedule_create_request(create_request(
        "  Nightly  ",
        Some("  operator note  "),
        Some("  Europe/Berlin  "),
        calendar,
    ))
    .expect("valid schedule creation request");
    assert_eq!(
        validated,
        ValidatedScheduleCreate {
            name: "Nightly".to_string(),
            comment: "operator note".to_string(),
            timezone: "Europe/Berlin".to_string(),
            icalendar: calendar.to_string(),
        }
    );

    for request in [
        serde_json::json!({"icalendar": calendar}),
        serde_json::json!({"name": "Nightly"}),
        serde_json::json!({
            "name": "Nightly",
            "icalendar": calendar,
            "unexpected": true,
        }),
    ] {
        assert!(
            serde_json::from_value::<ScheduleCreateRequest>(request).is_err(),
            "missing required fields and unknown fields must be rejected"
        );
    }
}

#[test]
fn schedule_create_request_enforces_bounded_safe_text_without_rejecting_crlf_icalendar() {
    let calendar = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
    for request in [
        create_request("   ", None, None, calendar),
        create_request("bad\nname", None, None, calendar),
        create_request("Nightly", Some("bad\u{0}comment"), None, calendar),
        create_request("Nightly", None, Some("bad\ntimezone"), calendar),
        create_request("Nightly", None, None, ""),
        create_request(
            &"n".repeat(MAX_SCHEDULE_TEXT_BYTES + 1),
            None,
            None,
            calendar,
        ),
        create_request(
            "Nightly",
            Some(&"c".repeat(MAX_SCHEDULE_TEXT_BYTES + 1)),
            None,
            calendar,
        ),
        create_request(
            "Nightly",
            None,
            Some(&"t".repeat(MAX_SCHEDULE_TIMEZONE_BYTES + 1)),
            calendar,
        ),
        create_request(
            "Nightly",
            None,
            None,
            &"i".repeat(MAX_SCHEDULE_ICALENDAR_BYTES + 1),
        ),
    ] {
        assert!(matches!(
            validate_schedule_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
    assert!(
        validate_schedule_create_request(create_request(
            "Nightly",
            None,
            None,
            "BEGIN:VCALENDAR\r\n\tFOLDED:calendar text\r\nEND:VCALENDAR\r\n",
        ))
        .is_ok()
    );

    let maximum = validate_schedule_create_request(create_request(
        &"n".repeat(MAX_SCHEDULE_TEXT_BYTES),
        Some(&"c".repeat(MAX_SCHEDULE_TEXT_BYTES)),
        Some(&"t".repeat(MAX_SCHEDULE_TIMEZONE_BYTES)),
        &"i".repeat(MAX_SCHEDULE_ICALENDAR_BYTES),
    ))
    .expect("all documented maximum field lengths must be accepted");
    assert_eq!(maximum.name.len(), MAX_SCHEDULE_TEXT_BYTES);
    assert_eq!(maximum.comment.len(), MAX_SCHEDULE_TEXT_BYTES);
    assert_eq!(maximum.timezone.len(), MAX_SCHEDULE_TIMEZONE_BYTES);
    assert_eq!(maximum.icalendar.len(), MAX_SCHEDULE_ICALENDAR_BYTES);
}

#[tokio::test]
async fn schedule_create_mock_uds_sends_the_exact_base64_protocol_and_loads_created_uuid() {
    let request = validate_schedule_create_request(create_request(
        "Nightly",
        None,
        Some("Europe/Berlin"),
        "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
    ))
    .expect("valid schedule request");
    let (socket_path, handle) =
        mock_schedule_create_socket(b"0 created 22222222-2222-2222-8222-222222222222\n".to_vec());

    let created_id = request_schedule_create(
        socket_path.to_str().unwrap(),
        CONTROL_SECRET,
        OPERATOR_UUID,
        &request,
    )
    .await
    .expect("created schedule id");
    let command = handle.join().expect("mock UDS thread must finish");
    std::fs::remove_file(socket_path).expect("mock UDS path must be removed");

    assert_eq!(created_id, "22222222-2222-2222-8222-222222222222");
    assert_eq!(
        command,
        format!(
            "schedule-create {CONTROL_SECRET} {OPERATOR_UUID} TmlnaHRseQ==  RXVyb3BlL0Jlcmxpbg== QkVHSU46VkNBTEVOREFSDQpFTkQ6VkNBTEVOREFSDQo=\n"
        )
        .into_bytes()
    );
}

#[test]
fn schedule_create_protocol_maps_only_documented_responses_to_safe_http_errors() {
    let cases = [
        (b"1 exists".as_slice(), 409, "conflict", "already exists"),
        (
            b"3 invalid_ical".as_slice(),
            400,
            "bad_request",
            "iCalendar data is invalid",
        ),
        (
            b"4 invalid_timezone".as_slice(),
            400,
            "bad_request",
            "timezone is invalid",
        ),
        (b"99 forbidden".as_slice(), 403, "forbidden", "operator"),
        (
            b"-1 internal".as_slice(),
            502,
            "control_failure",
            "control service failed",
        ),
        (
            b"0 created malformed".as_slice(),
            502,
            "control_failure",
            "control service failed",
        ),
        (
            b"0 created 22222222-2222-2222-8222-222222222222 extra".as_slice(),
            502,
            "control_failure",
            "control service failed",
        ),
    ];
    for (response, status, code, message) in cases {
        let error = parse_schedule_create_response(response).expect_err("response must fail");
        assert_eq!(error.status_code().as_u16(), status);
        assert_eq!(error.code(), code);
        assert!(error.public_message().contains(message));
        let public_message = error.public_message().to_ascii_lowercase();
        for forbidden in ["secret", "socket", "token", "password", "credential"] {
            assert!(
                !public_message.contains(forbidden),
                "response {response:?} leaked {forbidden}"
            );
        }
    }
    assert_eq!(
        parse_schedule_create_response(b"0 created 22222222-2222-2222-8222-222222222222")
            .expect("valid created response"),
        "22222222-2222-2222-8222-222222222222"
    );
}

#[test]
fn schedule_create_handler_and_browser_proxy_delegate_authorization_calendar_and_transactions_to_gvmd()
 {
    let source = include_str!("schedule_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn create_schedule")
        .expect("schedule create handler must exist")
        .1
        .split_once("pub(crate) async fn clone_schedule")
        .expect("clone handler must follow schedule create")
        .0;
    for required in [
        "require_schedule_write_operator(operator)?",
        "validate_schedule_create_request(request)?",
        "gvmd_control_secret()?",
        "request_schedule_create(",
        "operator.user_uuid()",
        "load_schedule_asset_detail(&client, &schedule_id)",
        "StatusCode::CREATED",
    ] {
        assert!(
            handler.contains(required),
            "schedule create missing {required}"
        );
    }
    for forbidden in [
        "transaction()",
        "resolve_schedule_write_operator_owner",
        "ensure_unique_schedule_name",
        "icalendar_from_string",
        "unsafe",
    ] {
        assert!(
            !handler.contains(forbidden),
            "schedule create must delegate {forbidden} to gvmd"
        );
    }

    let browser_source = include_str!("browser_proxy_schedule.rs");
    let browser_handler = browser_source
        .split_once("pub(crate) async fn browser_proxy_create_schedule")
        .expect("browser schedule create proxy must exist")
        .1
        .split_once("pub(crate) async fn browser_proxy_patch_schedule")
        .expect("browser schedule patch proxy must follow create")
        .0;
    assert!(
        browser_handler
            .contains("browser_proxy_operator_from_headers(&state, &auth, &headers).await?")
    );
    assert!(
        browser_handler.contains(
            "create_schedule(State(state), Some(Extension(operator)), Json(request)).await"
        )
    );
}

#[tokio::test]
async fn schedule_patch_mock_uds_sends_exact_presence_tokens_and_reloads_after_success() {
    let calendar = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
    let request = validate_schedule_patch_request(patch_request_with_calendar(
        Some("  New name  "),
        Some("   "),
        Some("  Europe/Berlin  "),
        Some(calendar),
    ))
    .expect("valid schedule patch request");
    let schedule_id = "22222222-2222-2222-8222-222222222222";
    let (socket_path, handle) = mock_schedule_create_socket(b"0 modified\n".to_vec());

    request_schedule_patch(
        socket_path.to_str().unwrap(),
        CONTROL_SECRET,
        OPERATOR_UUID,
        schedule_id,
        &request,
    )
    .await
    .expect("schedule patch must succeed");
    let command = handle.join().expect("mock UDS thread must finish");
    std::fs::remove_file(socket_path).expect("mock UDS path must be removed");

    assert_eq!(
        command,
        format!(
            "schedule-modify {CONTROL_SECRET} {OPERATOR_UUID} {schedule_id} +TmV3IG5hbWU= + +RXVyb3BlL0Jlcmxpbg== +QkVHSU46VkNBTEVOREFSDQpFTkQ6VkNBTEVOREFSDQo=\n"
        )
        .into_bytes()
    );
}

#[test]
fn schedule_patch_protocol_distinguishes_omitted_and_explicit_empty_fields() {
    let request = validate_schedule_patch_request(patch_request_with_calendar(
        None,
        Some("   "),
        Some(" "),
        None,
    ))
    .expect("explicit empty comment and timezone are valid");
    assert_eq!(request.comment.as_deref(), Some(""));
    assert_eq!(request.timezone.as_deref(), Some(""));
    assert_eq!(
        schedule_patch_command(
            CONTROL_SECRET,
            OPERATOR_UUID,
            "22222222-2222-2222-8222-222222222222",
            &request,
        ),
        format!(
            "schedule-modify {CONTROL_SECRET} {OPERATOR_UUID} 22222222-2222-2222-8222-222222222222 - + + -\n"
        )
    );
}

#[test]
fn schedule_patch_validation_accepts_calendar_fields_and_rejects_invalid_values() {
    let calendar = "BEGIN:VCALENDAR\r\n\tX-FOLDED:value\r\nEND:VCALENDAR\r\n";
    let validated = validate_schedule_patch_request(patch_request_with_calendar(
        None,
        None,
        Some("  Europe/Berlin  "),
        Some(calendar),
    ))
    .expect("calendar patch request must validate");
    assert_eq!(validated.timezone.as_deref(), Some("Europe/Berlin"));
    assert_eq!(validated.icalendar.as_deref(), Some(calendar));

    for request in [
        patch_request_with_calendar(
            None,
            None,
            Some(&"t".repeat(MAX_SCHEDULE_TIMEZONE_BYTES + 1)),
            None,
        ),
        patch_request_with_calendar(None, None, None, Some("")),
        patch_request_with_calendar(None, None, None, Some("BEGIN:VCALENDAR\u{0}")),
        patch_request_with_calendar(
            None,
            None,
            None,
            Some(&"i".repeat(MAX_SCHEDULE_ICALENDAR_BYTES + 1)),
        ),
    ] {
        assert!(matches!(
            validate_schedule_patch_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
}

#[test]
fn schedule_patch_protocol_maps_only_authoritative_responses_to_documented_http_statuses() {
    let cases = [
        (b"1 not_found".as_slice(), 404),
        (b"2 duplicate".as_slice(), 409),
        (b"6 invalid_ical".as_slice(), 422),
        (b"7 invalid_timezone".as_slice(), 422),
        (b"99 forbidden".as_slice(), 403),
        (b"-2 malformed".as_slice(), 400),
        (b"-1 internal".as_slice(), 500),
        (b"unexpected".as_slice(), 500),
    ];
    for (response, status) in cases {
        let error = parse_schedule_patch_response(response).expect_err("response must fail");
        assert_eq!(error.into_response().status().as_u16(), status);
    }
    assert!(parse_schedule_patch_response(b"0 modified").is_ok());
    assert_eq!(
        map_schedule_patch_control_socket_error(ControlSocketError::Unavailable)
            .into_response()
            .status()
            .as_u16(),
        503
    );
}

fn mock_schedule_create_socket(response: Vec<u8>) -> (PathBuf, thread::JoinHandle<Vec<u8>>) {
    let socket_path = mock_socket_path();
    let listener = UnixListener::bind(&socket_path).expect("mock UDS must bind");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("mock UDS must accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock UDS must set read timeout");
        let mut command = Vec::new();
        let mut byte = [0_u8; 1];
        while command.len() < 65536 {
            let count = stream.read(&mut byte).expect("mock UDS must read command");
            if count == 0 {
                break;
            }
            command.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        stream
            .write_all(&response)
            .expect("mock UDS must write response");
        command
    });
    (socket_path, handle)
}

fn create_request(
    name: &str,
    comment: Option<&str>,
    timezone: Option<&str>,
    icalendar: &str,
) -> ScheduleCreateRequest {
    ScheduleCreateRequest {
        name: name.to_string(),
        comment: comment.map(str::to_string),
        timezone: timezone.map(str::to_string),
        icalendar: icalendar.to_string(),
    }
}

fn patch_request(name: Option<&str>, comment: Option<&str>) -> SchedulePatchRequest {
    SchedulePatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        timezone: None,
        icalendar: None,
    }
}

fn patch_request_with_calendar(
    name: Option<&str>,
    comment: Option<&str>,
    timezone: Option<&str>,
    icalendar: Option<&str>,
) -> SchedulePatchRequest {
    SchedulePatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        timezone: timezone.map(str::to_string),
        icalendar: icalendar.map(str::to_string),
    }
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> ScheduleCloneRequest {
    ScheduleCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn schedule_write_accepts_any_human_owner_and_rejects_ownerless_rows() {
    assert_eq!(ensure_schedule_is_human_owned(Some(7)).unwrap(), 7);
    assert!(matches!(
        ensure_schedule_is_human_owned(None),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn schedule_clone_handler_requires_owner_check_before_clone() {
    let source = include_str!("schedule_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn clone_schedule")
        .expect("clone schedule handler must exist")
        .1
        .split_once("pub(crate) async fn delete_schedule")
        .expect("delete schedule handler must follow clone handler")
        .0;

    let owner_check = "ensure_schedule_is_human_owned(source.owner_id)?;";
    assert!(handler.contains("let operator = require_schedule_write_operator(operator)?;"));
    assert!(
        handler.contains(
            "let owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;"
        )
    );
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_schedule_clone_transaction").unwrap(),
        "schedule clone must check source owner before cloning"
    );
}

#[test]
fn schedule_mutating_handlers_enforce_owner_and_task_safety_before_side_effects() {
    let source = include_str!("schedule_writes.rs");
    for (label, start, end, owner_check, safety_guard, side_effect) in [
        (
            "delete",
            "pub(crate) async fn delete_schedule",
            "pub(crate) async fn hard_delete_schedule",
            "ensure_schedule_is_human_owned(state.owner_id)?;",
            "ensure_schedule_not_in_use_by_live_tasks",
            "execute_schedule_trash_transaction",
        ),
        (
            "hard delete",
            "pub(crate) async fn hard_delete_schedule",
            "pub(crate) async fn restore_schedule",
            "ensure_schedule_is_human_owned(trash.owner_id)?;",
            "ensure_schedule_not_in_use_by_trash_tasks",
            "execute_schedule_hard_delete_transaction",
        ),
        (
            "restore",
            "pub(crate) async fn restore_schedule",
            "pub(crate) async fn patch_schedule",
            "ensure_schedule_is_human_owned(trash.owner_id)?;",
            "ensure_schedule_uuid_not_live",
            "execute_schedule_restore_transaction",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} schedule handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} schedule handler end marker must exist"))
            .0;

        assert!(
            handler.contains("require_schedule_write_operator"),
            "{label} handler must require operator"
        );
        assert!(
            handler.contains(owner_check),
            "{label} handler must check owner"
        );
        assert!(
            handler.contains(safety_guard),
            "{label} handler must check safety guard"
        );
        assert!(
            handler.find(owner_check).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check owner before side effects"
        );
        assert!(
            handler.find(safety_guard).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check safety guard before side effects"
        );
    }
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
            timezone: None,
            icalendar: None,
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
            timezone: None,
            icalendar: None,
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
fn schedule_patch_request_accepts_calendar_fields_and_rejects_unknown_fields() {
    let request = serde_json::json!({
        "name": "Weekday scan",
        "timezone": "Europe/Berlin",
        "icalendar": "BEGIN:VCALENDAR\nEND:VCALENDAR",
    });
    assert!(serde_json::from_value::<SchedulePatchRequest>(request).is_ok());
    assert!(
        serde_json::from_value::<SchedulePatchRequest>(serde_json::json!({
            "name": "Weekday scan",
            "period": 3600,
        }))
        .is_err()
    );
}

#[test]
fn schedule_patch_request_rejects_oversized_metadata_fields() {
    let oversized = "a".repeat(MAX_SCHEDULE_TEXT_BYTES + 1);
    assert!(matches!(
        validate_schedule_patch_request(SchedulePatchRequest {
            name: Some(oversized),
            comment: None,
            timezone: None,
            icalendar: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_no_longer_has_a_direct_sql_mutation_path() {
    let handler = include_str!("schedule_writes.rs")
        .split_once("pub(crate) async fn patch_schedule")
        .expect("schedule patch handler must exist")
        .1
        .split_once("pub(crate) async fn request_schedule_patch")
        .expect("schedule patch request helper must follow handler")
        .0;
    for required in [
        "gvmd_control_secret()?",
        "request_schedule_patch(",
        "operator.user_uuid()",
        "load_schedule_asset_detail(&client, &schedule_id)",
    ] {
        assert!(
            handler.contains(required),
            "schedule patch missing {required}"
        );
    }
    for forbidden in [
        "transaction()",
        "resolve_schedule_write_operator_owner",
        "ensure_schedule_is_human_owned",
        "ensure_unique_schedule_name",
        "execute_schedule_patch_transaction",
    ] {
        assert!(
            !handler.contains(forbidden),
            "schedule patch must delegate {forbidden} to gvmd"
        );
    }
    assert!(
        !include_str!("schedule_write_transactions.rs")
            .contains("execute_schedule_patch_transaction")
    );
    assert!(!include_str!("schedule_write_sql.rs").contains("schedule_update_metadata_sql"));
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
