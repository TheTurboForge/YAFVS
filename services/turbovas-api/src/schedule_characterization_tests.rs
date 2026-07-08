// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_SCHEDULES: &str =
    include_str!("../../../components/gvmd/src/manage_sql_schedules.c");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");

fn inherited_function(source: &str, name: &str) -> String {
    let marker = format!("\n{name} (");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} function marker must exist"));
    let tail = &source[start..];
    let end = tail.find("\n/**").unwrap_or(tail.len());
    tail[..end].to_string()
}

fn openapi_path_block(path: &str) -> String {
    let marker = format!("  {path}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{path} path block must exist"));
    let tail = &OPENAPI[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("  /") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn inherited_schedule_schema_has_live_and_trash_state() {
    let schedules_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS schedules")
        .expect("schedules table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS schedules_trash")
        .expect("schedules_trash must follow schedules")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "comment text",
        "first_time integer",
        "period integer",
        "period_months integer",
        "byday integer",
        "duration integer",
        "timezone text",
        "icalendar text",
    ] {
        assert!(
            schedules_table.contains(column),
            "schedules table missing {column}"
        );
    }

    let schedules_trash_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS schedules_trash")
        .expect("schedules_trash table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS scanners_trash")
        .expect("scanners_trash must follow schedules_trash")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "timezone text",
        "icalendar text",
    ] {
        assert!(
            schedules_trash_table.contains(column),
            "schedules_trash table missing {column}"
        );
    }
}

#[test]
fn inherited_create_schedule_validates_acl_timezone_ical_owner_and_name() {
    let create_schedule = inherited_function(MANAGE_SQL_SCHEDULES, "create_schedule");
    for required in [
        "assert (current_credentials.uuid)",
        "assert (ical_string && strcmp (ical_string, \"\"))",
        "acl_user_may (\"create_schedule\")",
        "resource_with_name_exists (name, \"schedule\", 0)",
        "SELECT timezone FROM users",
        "current_credentials.uuid",
        "icalendar_timezone_from_string",
        "icalendar_from_string",
        "icalendar_first_time_from_vcalendar",
        "icalendar_duration_from_vcalendar",
        "icalendar_approximate_rrule_from_vcalendar",
        "INSERT INTO schedules",
        "make_uuid ()",
        "(SELECT id FROM users WHERE users.uuid",
        "m_now (), m_now ()",
    ] {
        assert!(
            create_schedule.contains(required),
            "create_schedule missing {required}"
        );
    }
    assert!(!create_schedule.contains("schedules_trash"));
}

#[test]
fn inherited_modify_schedule_refreshes_ical_timezone_and_task_next_times() {
    let modify_schedule = inherited_function(MANAGE_SQL_SCHEDULES, "modify_schedule");
    for required in [
        "if (schedule_id == NULL)",
        "acl_user_may (\"modify_schedule\")",
        "find_schedule_with_permission (schedule_id, &schedule, \"modify_schedule\")",
        "resource_with_name_exists (name, \"schedule\", schedule)",
        "UPDATE schedules SET",
        "SELECT timezone FROM schedules WHERE id",
        "icalendar_timezone_from_string",
        "icalendar_from_string",
        "icalendar_first_time_from_vcalendar",
        "icalendar_duration_from_vcalendar",
        "period = 0",
        "period_months = 0",
        "byday = 0",
        "icalendar_next_time_from_vcalendar",
        "UPDATE tasks SET schedule_next_time",
        "WHERE schedule = %llu",
    ] {
        assert!(
            modify_schedule.contains(required),
            "modify_schedule missing {required}"
        );
    }
    assert!(!modify_schedule.contains("schedules_trash"));
}

#[test]
fn inherited_delete_schedule_is_task_guarded_trash_permissions_and_tags() {
    let delete_schedule = inherited_function(MANAGE_SQL_SCHEDULES, "delete_schedule");
    for required in [
        "acl_user_may (\"delete_schedule\")",
        "find_schedule_with_permission (schedule_id, &schedule, \"delete_schedule\")",
        "find_trash (\"schedule\", schedule_id, &schedule)",
        "SELECT count(*) FROM tasks",
        "schedule_location = ",
        "INSERT INTO schedules_trash",
        "UPDATE tasks",
        "permissions_set_locations (\"schedule\"",
        "tags_set_locations (\"schedule\"",
        "permissions_set_orphans (\"schedule\"",
        "tags_remove_resource (\"schedule\"",
        "DELETE FROM schedules WHERE id",
        "DELETE FROM schedules_trash WHERE id",
    ] {
        assert!(
            delete_schedule.contains(required),
            "delete_schedule missing {required}"
        );
    }
}

#[test]
fn native_direct_api_allows_only_schedule_metadata_patch_trash_move_and_restore_under_write_control()
 {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/schedules",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc",
        false
    ));
    let export_path = "/api/v1/schedules/12345678-1234-1234-1234-123456789abc/export";
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        export_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        export_path,
        true
    ));
    for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, export_path, true),
            "{method} schedule metadata export must stay closed; calendar create/export remains inherited"
        );
    }
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/schedules", true),
            "{method} /api/v1/schedules must remain closed"
        );
    }
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc/restore",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/schedules/not-a-uuid/restore",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/schedules/12345678-1234-1234-1234-123456789abc/restore",
        false,
    ));

    for method in [Method::POST, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/schedules/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/schedules/{{id}} must remain closed"
        );
    }
}

#[test]
fn openapi_documents_schedule_metadata_patch_and_trash_move_boundary() {
    let list = openapi_path_block("/schedules");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(list.contains("x-turbovas-inherited-still-owns: schedule-create-calendar-edit"));

    let detail = openapi_path_block("/schedules/{schedule_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(detail.contains("x-turbovas-replaces: schedule-metadata-modify"));
    assert!(detail.contains("x-turbovas-replaces: schedule-trash-move"));
    assert!(detail.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(detail.contains("x-turbovas-inherited-still-owns: schedule-create-calendar-edit"));

    let restore = openapi_path_block("/schedules/{schedule_id}/restore");
    assert!(restore.contains("post:"));
    assert!(restore.contains("operationId: postSchedulesByScheduleIdRestore"));
    assert!(restore.contains("x-turbovas-exposure: direct-write"));
    assert!(restore.contains("x-turbovas-replaces: schedule-restore"));
    assert!(restore.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(restore.contains("x-turbovas-inherited-still-owns: schedule-create-calendar-edit"));

    let hard_delete = openapi_path_block("/schedules/{schedule_id}/trash");
    assert!(hard_delete.contains("delete:"));
    assert!(hard_delete.contains("operationId: deleteSchedulesByScheduleIdTrash"));
    assert!(hard_delete.contains("x-turbovas-direct: true"));
    assert!(hard_delete.contains("x-turbovas-exposure: direct-write"));
    assert!(hard_delete.contains("x-turbovas-replaces: schedule-hard-delete"));
    assert!(hard_delete.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(hard_delete.contains("x-turbovas-inherited-still-owns: schedule-create-calendar-edit"));
    let export = openapi_path_block("/schedules/{schedule_id}/export");
    assert!(export.contains("get:"));
    assert!(export.contains("x-turbovas-exposure: direct-read"));
    assert!(export.contains("x-turbovas-replaces: schedule-metadata-export-read"));
    assert!(export.contains("x-turbovas-inherited-still-owns: schedule-create-calendar-edit"));
    assert!(!export.contains("x-turbovas-safety-contract: write-control-v1"));
}
