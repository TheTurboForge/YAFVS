// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const MANAGE_C: &str = include_str!("../../../components/gvmd/src/manage.c");
const MANAGE_OSP_C: &str = include_str!("../../../components/gvmd/src/manage_osp.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVM_LIBS_GMP_C: &str = include_str!("../../../components/gvm-libs/gmp/gmp.c");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");

fn inherited_function(source: &str, name: &str) -> String {
    let marker = format!("\n{name} (");
    let start = source
        .rfind(&marker)
        .unwrap_or_else(|| panic!("{name} function marker must exist"));
    let tail = &source[start..];
    let end = tail.find("\n/**").unwrap_or(tail.len());
    tail[..end].to_string()
}

#[test]
fn inherited_osp_start_checks_target_permission_and_creates_report_before_scanner_work() {
    let run_osp_task = inherited_function(MANAGE_C, "run_osp_task");
    for required in [
        "target = task_target (task)",
        "target_uuid (target)",
        "find_target_with_permission (uuid, &found, \"get_targets\")",
        "if (found == 0)",
        "return 99",
        "get_use_scan_queue ()",
        "queue_scan_task (task, from, report_id)",
        "fork_osp_scan_handler (task, target, from, report_id)",
    ] {
        assert!(
            run_osp_task.contains(required),
            "run_osp_task missing {required}"
        );
    }

    let get_report = inherited_function(MANAGE_OSP_C, "run_osp_scan_get_report");
    for required in [
        "if (from != 0)",
        "return -1",
        "*report_id = NULL",
        "create_current_report (task, report_id, TASK_STATUS_REQUESTED)",
    ] {
        assert!(
            get_report.contains(required),
            "run_osp_scan_get_report missing {required}"
        );
    }

    for helper in ["fork_osp_scan_handler", "queue_scan_task"] {
        let body = inherited_function(MANAGE_C, helper);
        assert!(body.contains("run_osp_scan_get_report (task"));
        assert!(body.contains("TASK_STATUS_REQUESTED"));
    }
}

fn gmp_client_state_block(state: &str) -> String {
    let marker = format!("      case {state}:");
    let start = GMP_C
        .find(&marker)
        .unwrap_or_else(|| panic!("{state} GMP state block must exist"));
    let tail = &GMP_C[start..];
    let end = tail
        .lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("      case CLIENT_") {
                Some(index)
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.lines().count());
    tail.lines().take(end).collect::<Vec<_>>().join("\n")
}

#[test]
fn inherited_openvasd_start_stop_paths_have_scanner_side_effects_and_runtime_gate() {
    let run_openvasd_task = inherited_function(MANAGE_C, "run_openvasd_task");
    for required in [
        "feature_enabled (FEATURE_ID_OPENVASD_SCANNER)",
        "target = task_target (task)",
        "find_target_with_permission (uuid, &found, \"get_targets\")",
        "queue_scan_task (task, from, report_id)",
        "fork_openvasd_scan_handler (task, target, from, report_id)",
    ] {
        assert!(
            run_openvasd_task.contains(required),
            "run_openvasd_task missing {required}"
        );
    }

    let stop_openvasd_task = inherited_function(MANAGE_C, "stop_openvasd_task");
    for required in [
        "feature_enabled (FEATURE_ID_OPENVASD_SCANNER)",
        "task_running_report (task)",
        "http_scanner_connect (scanner, scan_id)",
        "set_task_run_status (task, TASK_STATUS_STOP_REQUESTED)",
        "http_scanner_stop_scan (connector)",
        "delete_http_scanner_scan_with_retry (connector, scan_id)",
        "set_task_end_time_epoch (task, time (NULL))",
        "set_task_run_status (task, TASK_STATUS_STOPPED)",
        "set_report_scan_run_status (scan_report, TASK_STATUS_STOPPED)",
    ] {
        assert!(
            stop_openvasd_task.contains(required),
            "stop_openvasd_task missing {required}"
        );
    }
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
fn inherited_start_task_is_permission_gated_and_delegates_to_run_task() {
    let start_task = inherited_function(MANAGE_C, "start_task");
    for required in [
        "acl_user_may (\"start_task\") == 0",
        "return 99",
        "run_task (task_id, report_id, 0)",
    ] {
        assert!(
            start_task.contains(required),
            "start_task missing {required}"
        );
    }
    assert!(!start_task.contains("stop_task"));
}

#[test]
fn inherited_run_task_checks_process_resume_permission_scanner_and_dispatches() {
    let run_task = inherited_function(MANAGE_C, "run_task");
    for required in [
        "if (current_scanner_task)",
        "return -6",
        "if (from != 0)",
        "return 4",
        "find_task_with_permission (task_id, &task, \"start_task\")",
        "if (task == 0)",
        "return 3",
        "task_scanner (task)",
        "check_available (\"scanner\", scanner, \"get_scanners\")",
        "scanner_type (scanner) == SCANNER_TYPE_CVE",
        "run_cve_task (task)",
        "scanner_type (scanner) == SCANNER_TYPE_OPENVAS",
        "scanner_type (scanner) == SCANNER_TYPE_OSP_SENSOR",
        "run_osp_task (task, from, report_id)",
        "SCANNER_TYPE_OPENVASD",
        "run_openvasd_task (task, from, report_id)",
        "return -1; // Unknown scanner type",
    ] {
        assert!(run_task.contains(required), "run_task missing {required}");
    }
}

#[test]
fn inherited_start_response_maps_report_id_and_legacy_error_cases() {
    let start_block = gmp_client_state_block("CLIENT_START_TASK");
    for required in [
        "start_task (start_task_data->task_id, &report_id)",
        "<start_task_response",
        "STATUS_OK_REQUESTED",
        "<report_id>%s</report_id>",
        "report_id ?: \"0\"",
        "Task is active already",
        "send_find_error_to_client (\"start_task\", \"task\"",
        "Permission denied",
        "Task must have a target",
        "XML_INTERNAL_ERROR (\"start_task\")",
        "SEND_XML_SERVICE_DOWN (\"start_task\")",
        "There is already a task running in",
        "No CA certificate",
        "A task_id attribute is required",
    ] {
        assert!(
            start_block.contains(required),
            "CLIENT_START_TASK missing {required}"
        );
    }
}

#[test]
fn inherited_stop_response_maps_legacy_statuses_and_aborts_on_unexpected_error() {
    let stop_block = gmp_client_state_block("CLIENT_STOP_TASK");
    for required in [
        "stop_task (stop_task_data->task_id)",
        "XML_OK (\"stop_task\")",
        "\"stopped\"",
        "XML_OK_REQUESTED (\"stop_task\")",
        "\"requested to stop\"",
        "send_find_error_to_client (\"stop_task\", \"task\"",
        "Permission denied",
        "A task_id attribute is required",
        "abort ();",
    ] {
        assert!(
            stop_block.contains(required),
            "CLIENT_STOP_TASK missing {required}"
        );
    }
}

#[test]
fn inherited_delete_response_maps_trash_and_scanner_error_cases() {
    let delete_block = gmp_client_state_block("CLIENT_DELETE_TASK");
    for required in [
        "request_delete_task_uuid (delete_task_data->task_id",
        "delete_task_data->ultimate",
        "XML_OK (\"delete_task\")",
        "\"deleted\"",
        "XML_OK_REQUESTED (\"delete_task\")",
        "\"requested for delete\"",
        "Attempt to delete a hidden task",
        "send_find_error_to_client",
        "STATUS_ERROR_BUSY",
        "Reports database is busy. Please try again later.",
        "Permission denied",
        "SEND_XML_SERVICE_DOWN (\"delete_task\")",
        "No CA certificate",
        "A task_id attribute is required",
        "abort ();",
    ] {
        assert!(
            delete_block.contains(required),
            "CLIENT_DELETE_TASK missing {required}"
        );
    }
}

#[test]
fn inherited_stop_task_is_permission_gated_finds_task_and_dispatches_by_scanner_type() {
    let stop_task = inherited_function(MANAGE_C, "stop_task");
    for required in [
        "acl_user_may (\"stop_task\") == 0",
        "return 99",
        "find_task_with_permission (task_id, &task, \"stop_task\")",
        "return 3",
        "scanner_type (task_scanner (task)) == SCANNER_TYPE_OPENVAS",
        "scanner_type (task_scanner (task)) == SCANNER_TYPE_OSP_SENSOR",
        "stop_osp_task (task)",
        "SCANNER_TYPE_OPENVASD",
        "stop_openvasd_task (task)",
        "stop_task_internal (task)",
    ] {
        assert!(stop_task.contains(required), "stop_task missing {required}");
    }
}

#[test]
fn inherited_stop_osp_task_mutates_scanner_task_and_report_state() {
    let stop_osp_task = inherited_function(MANAGE_C, "stop_osp_task");
    for required in [
        "task_running_report (task)",
        "report_uuid (scan_report)",
        "osp_scanner_connect (task_scanner (task))",
        "current_scanner_task = task",
        "global_current_report = task_running_report (task)",
        "set_task_run_status (task, TASK_STATUS_STOP_REQUESTED)",
        "osp_stop_scan (connection, scan_id, NULL)",
        "osp_delete_scan (connection, scan_id)",
        "set_task_end_time_epoch (task, time (NULL))",
        "set_task_run_status (task, TASK_STATUS_STOPPED)",
        "set_scan_end_time_epoch (scan_report, time (NULL))",
        "set_report_scan_run_status (scan_report, TASK_STATUS_STOPPED)",
        "current_scanner_task = previous_task",
        "global_current_report = previous_report",
    ] {
        assert!(
            stop_osp_task.contains(required),
            "stop_osp_task missing {required}"
        );
    }
}

#[test]
fn inherited_stop_internal_only_requests_stop_for_active_task_statuses() {
    let stop_internal = inherited_function(MANAGE_C, "stop_task_internal");
    for required in [
        "run_status = task_run_status (task)",
        "run_status == TASK_STATUS_REQUESTED",
        "run_status == TASK_STATUS_RUNNING",
        "run_status == TASK_STATUS_QUEUED",
        "set_task_run_status (task, TASK_STATUS_STOP_REQUESTED)",
        "return 1",
        "return 0",
    ] {
        assert!(
            stop_internal.contains(required),
            "stop_task_internal missing {required}"
        );
    }
    assert!(!stop_internal.contains("osp_stop_scan"));
    assert!(!stop_internal.contains("osp_delete_scan"));
}

#[test]
fn inherited_gsad_and_gmp_client_layers_proxy_start_stop_verbs() {
    let gsad_delete = inherited_function(GSAD_GMP_C, "delete_task_gmp");
    let gsad_start = inherited_function(GSAD_GMP_C, "start_task_gmp");
    let gsad_stop = inherited_function(GSAD_GMP_C, "stop_task_gmp");
    assert!(gsad_delete.contains("move_resource_to_trash"));
    assert!(gsad_delete.contains("connection, \"task\", credentials, params"));
    assert!(
        gsad_start
            .contains("resource_action (connection, credentials, params, \"task\", \"start\"")
    );
    assert!(
        gsad_stop.contains("resource_action (connection, credentials, params, \"task\", \"stop\"")
    );

    let gmp_start = inherited_function(GVM_LIBS_GMP_C, "gmp_start_task_report_c");
    let gmp_stop = inherited_function(GVM_LIBS_GMP_C, "gmp_stop_task_c");
    assert!(gmp_start.contains("<start_task task_id=\\\"%s\\\"/>"));
    assert!(gmp_start.contains("entity_child (entity, \"report_id\")"));
    assert!(gmp_stop.contains("<stop_task task_id=\\\"%s\\\"/>"));
    assert!(gmp_stop.contains("gmp_check_response_c (connection)"));

    assert!(GSAD_VALIDATOR_C.contains("\"|(delete_task)\""));
    assert!(GSAD_VALIDATOR_C.contains("\"|(start_task)\""));
    assert!(GSAD_VALIDATOR_C.contains("\"|(stop_task)\""));
}

#[test]
fn native_direct_api_keeps_task_lifecycle_methods_closed_until_scanner_contract_lands() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/tasks",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    for method in [Method::POST, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/tasks", true),
            "{method} /api/v1/tasks must remain closed"
        );
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/tasks/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/tasks/{{id}} must remain closed"
        );
    }
    assert!(
        !direct_api_v1_method_is_allowed(&Method::PATCH, "/api/v1/tasks", true),
        "PATCH /api/v1/tasks collection must remain closed"
    );
    for action in ["start", "stop", "resume", "delete"] {
        let path = format!("/api/v1/tasks/12345678-1234-1234-1234-123456789abc/{action}");
        assert!(
            !direct_api_v1_path_is_allowed(&path),
            "{path} must not be direct allowlisted yet"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::POST, &path, true),
            "POST {path} must remain closed until a scanner-control contract lands"
        );
    }
}

#[test]
fn openapi_documents_task_metadata_patch_without_lifecycle_contract() {
    let list = openapi_path_block("/tasks");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(list.contains("x-turbovas-inherited-still-owns: task-scan-control-writes-and-deletes"));
    assert!(list.contains("Native direct API exposes task reads plus metadata-only task updates"));
    assert!(list.contains(
        "Start, stop, delete, clone, export, resume, target/config/schedule/scanner changes"
    ));

    let detail = openapi_path_block("/tasks/{task_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(!detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(detail.contains("x-turbovas-replaces: task-metadata-modify"));
    assert!(detail.contains("$ref: '#/components/schemas/TaskPatchRequest'"));
    assert!(
        detail.contains("x-turbovas-inherited-still-owns: task-scan-control-writes-and-deletes")
    );
    assert!(
        detail.contains("Direct write-control endpoint for updating task name and comment only")
    );
    assert!(
        detail.contains("task/report status transitions remain on inherited compatibility paths")
    );
}
