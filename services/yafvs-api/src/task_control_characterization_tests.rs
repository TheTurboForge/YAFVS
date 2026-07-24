// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const MANAGE_C: &str = include_str!("../../../components/gvmd/src/manage.c");
const MANAGE_H: &str = include_str!("../../../components/gvmd/src/manage.h");
const MANAGE_OSP_C: &str = include_str!("../../../components/gvmd/src/manage_osp.c");
const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_SCHEDULES_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_schedules.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GMPD_C: &str = include_str!("../../../components/gvmd/src/gmpd.c");
const GVMD_C: &str = include_str!("../../../components/gvmd/src/gvmd.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_H: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVM_LIBS_GMP_C: &str = include_str!("../../../components/gvm-libs/gmp/gmp.c");
const GVM_LIBS_GMP_H: &str = include_str!("../../../components/gvm-libs/gmp/gmp.h");
const MANAGE_COMMANDS_C: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const MANAGE_ALERTS_C: &str = include_str!("../../../components/gvmd/src/manage_alerts.c");
const YAFVS_CONTROL_C: &str = include_str!("../../../components/gvmd/src/yafvs_control.c");
const GSA_NATIVE_TASKS: &str = include_str!("../../../components/gsa/src/gmp/native-api/tasks.ts");
const GSA_CAPABILITIES: &str =
    include_str!("../../../components/gsa/src/gmp/capabilities/capabilities.ts");
const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");

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
fn alert_and_scheduler_task_control_use_private_control_after_public_gmp_retirement() {
    let alert_trigger = inherited_function(MANAGE_ALERTS_C, "trigger");
    assert!(!alert_trigger.contains("gmp_start_task_report_c"));
    for required in [
        "manage_fork_alert_child ()",
        "yafvs_control_start_task_client (owner_id, task_id)",
        "alert_secure_gfree (task_id)",
        "alert_secure_free (owner_id)",
        "gvm_close_sentry ()",
    ] {
        assert!(
            alert_trigger.contains(required),
            "alert start missing {required}"
        );
    }
    assert_eq!(
        alert_trigger.matches("manage_fork_alert_child ()").count(),
        1
    );
    assert!(alert_trigger.contains(
        "default:\n                alert_secure_gfree (task_id);\n                alert_secure_free (owner_id);\n                return 0;"
    ));
    for retired in ["gvm_connection_t", "manage_fork_connection", "socketpair"] {
        assert!(
            !alert_trigger.contains(retired),
            "alert start must not retain {retired}"
        );
    }

    let alert_child = inherited_function(GVMD_C, "fork_alert_child");
    assert_eq!(alert_child.matches("pid = fork ()").count(), 1);
    for required in [
        "init_sentry ()",
        "is_parent = 0",
        "cleanup_manage_process (FALSE)",
        "pthread_sigmask (SIG_SETMASK, sigmask_normal, NULL)",
        "return 0",
        "return pid",
    ] {
        assert!(
            alert_child.contains(required),
            "alert child missing {required}"
        );
    }
    let sentry_position = alert_child.find("init_sentry ()").unwrap();
    let child_identity_position = alert_child.find("is_parent = 0").unwrap();
    let cleanup_position = alert_child.find("cleanup_manage_process (FALSE)").unwrap();
    let sigmask_position = alert_child
        .find("pthread_sigmask (SIG_SETMASK, sigmask_normal, NULL)")
        .unwrap();
    assert!(
        sentry_position < child_identity_position
            && child_identity_position < cleanup_position
            && cleanup_position < sigmask_position,
        "alert child must establish child identity and clean inherited manager state before private control"
    );
    for retired in [
        "socketpair",
        "serve_client",
        "init_gmpd_process",
        "fork_with_handlers",
        "gvm_server_new",
        "gvm_server_attach",
        "gvm_sleep (5)",
        "sigaction",
        "setup_signal_handler",
    ] {
        assert!(
            !alert_child.contains(retired),
            "alert child must not retain {retired}"
        );
    }
    for source in [MANAGE_C, MANAGE_H, MANAGE_SQL_C, GVMD_C] {
        for retired in [
            "authenticate_allow_all",
            "manage_auth_allow_all",
            "schedule_user_uuid",
            "get_scheduled_user_uuid",
            "set_scheduled_user_uuid",
        ] {
            assert!(
                !source.contains(retired),
                "retired bypass remains: {retired}"
            );
        }
    }

    let private_start = inherited_function(YAFVS_CONTROL_C, "yafvs_control_start_task");
    for required in [
        "yafvs_control_start_operator_session (operator_uuid)",
        "start_task_with_mode (task_uuid, &report_id, mode)",
        "yafvs_control_finish_operator_session ()",
    ] {
        assert!(
            private_start.contains(required),
            "private start missing {required}"
        );
    }
    assert!(YAFVS_CONTROL_C.contains("YAFVS_CONTROL_START_TASK_COMMAND \"start \""));
    assert!(
        YAFVS_CONTROL_C.contains("YAFVS_CONTROL_START_SCHEDULED_TASK_COMMAND \"start-scheduled \"")
    );

    for retired in [
        "CLIENT_START_TASK",
        "CLIENT_STOP_TASK",
        "strcasecmp (\"START_TASK\", element_name)",
        "strcasecmp (\"STOP_TASK\", element_name)",
    ] {
        assert!(
            !GMP_C.contains(retired),
            "public GMP transport remains: {retired}"
        );
    }
    for retired in [
        "gmp_start_task_report",
        "gmp_start_task_report_c",
        "gmp_start_task_ext_c",
        "gmp_stop_task",
        "gmp_stop_task_c",
        "gmp_start_task_opts_t",
    ] {
        assert!(
            !GVM_LIBS_GMP_C.contains(retired),
            "public GMP client remains: {retired}"
        );
    }
    assert!(GVMD_C.contains("init_gmpd ("));
    assert!(GVMD_C.contains("accept_and_maybe_fork"));
    assert!(GMPD_C.contains("serve_gmp ("));
    let scheduler_start = inherited_function(MANAGE_C, "scheduled_task_start");
    for required in [
        "pid = fork ();",
        "cleanup_manage_process (FALSE)",
        "pthread_sigmask (SIG_SETMASK, sigmask_current, NULL)",
        "setup_signal_handler (SIGTERM, SIG_DFL, 0)",
        "setup_signal_handler (SIGINT, SIG_DFL, 0)",
        "setup_signal_handler (SIGQUIT, SIG_DFL, 0)",
        "yafvs_control_start_scheduled_task_client (",
        "scheduled_task->task_uuid)",
        "case YAFVS_CONTROL_START_TASK_OK:",
        "case YAFVS_CONTROL_START_TASK_FORBIDDEN:",
        "while (waitpid (pid, &status, 0) < 0)",
        "if (errno == EINTR)",
        "set_task_schedule_uuid (task_uuid, 0, -1)",
        "set_task_schedule_periods (task_uuid,",
        "set_task_schedule_next_time_uuid (task_uuid, 0)",
        "reschedule_task (scheduled_task->task_uuid)",
    ] {
        assert!(
            scheduler_start.contains(required),
            "scheduler start missing {required}"
        );
    }
    for forbidden in [
        "gmp_authenticate_info_ext_c",
        "gmp_start_task_ext_c",
        "fork_connection (",
        "yafvs_control_start_task_client (scheduled_task->owner_uuid,",
    ] {
        assert!(
            !scheduler_start.contains(forbidden),
            "scheduler start must not retain {forbidden}"
        );
    }
    for success in [
        "case YAFVS_CONTROL_START_TASK_OK:\n              scheduled_task_free (scheduled_task);\n              gvm_close_sentry ();\n              exit (EXIT_SUCCESS);",
        "case YAFVS_CONTROL_START_TASK_FORBIDDEN:\n              g_warning (\"%s: user denied permission to start task\", __func__);\n              scheduled_task_free (scheduled_task);\n              gvm_close_sentry ();\n              /* Consume this schedule rather than retrying permission denial. */\n              exit (EXIT_SUCCESS);",
    ] {
        assert!(
            scheduler_start.contains(success),
            "scheduler success policy changed: {success}"
        );
    }
    assert!(
        scheduler_start.contains(
            "default:\n              g_warning (\"%s: private task start failed\", __func__);\n              scheduled_task_free (scheduled_task);\n              gvm_close_sentry ();\n              exit (EXIT_FAILURE);"
        ),
        "scheduler must reschedule every non-success/non-forbidden result"
    );
    let scheduler_stop = inherited_function(MANAGE_C, "scheduled_task_stop");
    for required in [
        "pid = fork ();",
        "cleanup_manage_process (FALSE)",
        "pthread_sigmask (SIG_SETMASK, sigmask_current, NULL)",
        "setup_signal_handler (SIGTERM, SIG_DFL, 0)",
        "setup_signal_handler (SIGINT, SIG_DFL, 0)",
        "setup_signal_handler (SIGQUIT, SIG_DFL, 0)",
        "yafvs_control_stop_task_client (scheduled_task->owner_uuid,",
        "scheduled_task->task_uuid)",
        "case YAFVS_CONTROL_STOP_TASK_STOPPED:",
        "case YAFVS_CONTROL_STOP_TASK_REQUESTED:",
        "case YAFVS_CONTROL_STOP_TASK_INACTIVE:",
    ] {
        assert!(
            scheduler_stop.contains(required),
            "scheduler stop missing {required}"
        );
    }
    for forbidden in [
        "gmp_authenticate_info_ext_c",
        "gmp_stop_task_c",
        "fork_connection (",
        "waitpid (",
        "log_event (",
    ] {
        assert!(
            !scheduler_stop.contains(forbidden),
            "scheduler stop must not retain {forbidden}"
        );
    }

    let private_stop = inherited_function(YAFVS_CONTROL_C, "yafvs_control_stop_task");
    for required in [
        "yafvs_control_start_operator_session (operator_uuid)",
        "result = stop_task (task_uuid)",
        "case 0:",
        "log_event (\"task\", \"Task\", task_uuid, \"stopped\")",
        "case 1:",
        "\"requested to stop\"",
        "case 99:",
        "log_event_fail (\"task\", \"Task\", task_uuid, \"stopped\")",
        "yafvs_control_finish_operator_session ()",
    ] {
        assert!(
            private_stop.contains(required),
            "private stop missing {required}"
        );
    }
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
        "queue_scan_task (task, from, report_id, scheduled)",
        "fork_osp_scan_handler (task, target, from, report_id, scheduled)",
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
        "create_current_report (task, report_id, TASK_STATUS_REQUESTED,",
        "scheduled)",
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
        "queue_scan_task (task, from, report_id, scheduled)",
        "fork_openvasd_scan_handler (task, target, from, report_id,",
        "scheduled)",
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
    assert!(start_task.contains("start_task_with_mode (task_id, report_id, TASK_START_MANUAL)"));
    assert!(!start_task.contains("stop_task"));

    let start_task_with_mode = inherited_function(MANAGE_C, "start_task_with_mode");
    for required in [
        "acl_user_may (\"start_task\") == 0",
        "return 99",
        "run_task (task_id, report_id, 0, mode)",
    ] {
        assert!(
            start_task_with_mode.contains(required),
            "start_task_with_mode missing {required}"
        );
    }
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
        "run_cve_task (task, mode == TASK_START_SCHEDULED)",
        "scanner_type (scanner) == SCANNER_TYPE_OPENVAS",
        "scanner_type (scanner) == SCANNER_TYPE_OSP_SENSOR",
        "run_osp_task (task, from, report_id, mode == TASK_START_SCHEDULED)",
        "SCANNER_TYPE_OPENVASD",
        "run_openvasd_task (task, from, report_id,",
        "mode == TASK_START_SCHEDULED)",
        "return -1; // Unknown scanner type",
    ] {
        assert!(run_task.contains(required), "run_task missing {required}");
    }
}

#[test]
fn scheduled_report_marker_is_explicit_and_reaches_every_report_creation_branch() {
    assert!(MANAGE_H.contains("TASK_START_MANUAL"));
    assert!(MANAGE_H.contains("TASK_START_SCHEDULED"));
    assert!(MANAGE_H.contains("start_task_with_mode"));

    let private_start = inherited_function(YAFVS_CONTROL_C, "yafvs_control_start_task");
    assert!(private_start.contains("start_task_with_mode (task_uuid, &report_id, mode)"));
    assert!(YAFVS_CONTROL_C.contains("TASK_START_MANUAL, created_uuid"));
    assert!(YAFVS_CONTROL_C.contains("TASK_START_SCHEDULED, created_uuid"));
    assert!(YAFVS_CONTROL_C.contains("yafvs_control_start_task_client_with_command"));
    assert!(YAFVS_CONTROL_C.contains("yafvs_control_start_scheduled_task_client"));

    let run_task = inherited_function(MANAGE_C, "run_task");
    for required in [
        "run_cve_task (task, mode == TASK_START_SCHEDULED)",
        "run_osp_task (task, from, report_id, mode == TASK_START_SCHEDULED)",
        "run_openvasd_task (task, from, report_id,",
        "mode == TASK_START_SCHEDULED)",
    ] {
        assert!(run_task.contains(required), "run_task missing {required}");
    }
    for helper in [
        "fork_cve_scan_handler",
        "fork_osp_scan_handler",
        "queue_scan_task",
        "fork_openvasd_scan_handler",
    ] {
        let body = inherited_function(MANAGE_C, helper);
        assert!(
            body.contains("scheduled"),
            "{helper} must retain the explicit mode"
        );
    }
    let osp_report = inherited_function(MANAGE_OSP_C, "run_osp_scan_get_report");
    assert!(osp_report.contains("create_current_report (task, report_id, TASK_STATUS_REQUESTED,"));
    assert!(osp_report.contains("scheduled"));

    let report_marker = inherited_function(MANAGE_SQL_C, "set_report_scheduled");
    assert!(report_marker.contains("if (scheduled)"));
    assert!(report_marker.contains("UPDATE reports SET flags = 1"));
    assert!(report_marker.contains("UPDATE reports SET flags = 0"));
    assert!(!report_marker.contains("authenticate_allow_all"));
    let current_report = inherited_function(MANAGE_SQL_C, "create_current_report");
    assert!(current_report.contains("make_report (task, *report_id, status)"));
    assert!(current_report.contains("set_report_scheduled (global_current_report, scheduled)"));

    let duration_stop =
        inherited_function(MANAGE_SQL_SCHEDULES_C, "task_schedule_iterator_stop_due");
    assert!(duration_stop.contains("report_scheduled (report) == 0"));
    assert!(crate::task_control_sql::task_start_insert_report_sql().contains("0, 0)"));
}

#[test]
fn public_start_stop_gmp_parser_and_clients_are_absent() {
    for retired in [
        "start_task_data_t",
        "stop_task_data_t",
        "start_task_data_reset",
        "stop_task_data_reset",
        "CLIENT_START_TASK",
        "CLIENT_STOP_TASK",
        "<start_task_response",
        "<stop_task_response",
        "strcasecmp (\"START_TASK\", element_name)",
        "strcasecmp (\"STOP_TASK\", element_name)",
    ] {
        assert!(
            !GMP_C.contains(retired),
            "public GMP parser residue remains: {retired}"
        );
    }
    for retired in [
        "gmp_start_task_report",
        "gmp_start_task_report_c",
        "gmp_start_task_ext_c",
        "gmp_stop_task",
        "gmp_stop_task_c",
        "gmp_start_task_opts_t",
        "<start_task task_id=\\\"%s\\\"/>",
        "<stop_task task_id=\\\"%s\\\"/>",
    ] {
        assert!(
            !GVM_LIBS_GMP_C.contains(retired),
            "public GMP client residue remains: {retired}"
        );
        assert!(
            !GVM_LIBS_GMP_H.contains(retired),
            "public GMP client declaration remains: {retired}"
        );
    }
    for retired in ["start_task", "stop_task"] {
        assert!(
            !GMP_SCHEMA.contains(&format!("<name>{retired}</name>")),
            "live GMP schema command remains: {retired}"
        );
    }
    for retired in ["START_TASK", "STOP_TASK"] {
        assert!(
            !MANAGE_COMMANDS_C.contains(&format!("{{\"{retired}\",")),
            "public GMP HELP row remains: {retired}"
        );
        assert!(
            MANAGE_COMMANDS_C.contains(&format!("\"{retired}\",")),
            "retained native ACL operation lost: {retired}"
        );
    }
    assert!(GMP_SCHEMA.contains("<command>RESUME_OR_START_TASK</command>"));
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
        "task_unfinished_report (task, &scan_report)",
        "report_uuid (scan_report)",
        "report_scan_run_status (scan_report, &report_status)",
        "current_scanner_task = task",
        "global_current_report = scan_report",
        "ensure_osp_scan_absent (task, scan_id)",
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
fn osp_start_stop_is_serialized_and_only_verified_absence_is_success() {
    let stop = inherited_function(MANAGE_C, "stop_osp_task");
    for required in [
        "yafvs_task_control_lock (task, &control_lock)",
        "set_report_scan_run_status (scan_report, TASK_STATUS_STOP_REQUESTED)",
        "report_scan_run_status (scan_report, &report_status)",
        "scan_queue_remove (scan_report)",
        "ensure_osp_scan_absent (task, scan_id)",
        "set_task_run_status (task, TASK_STATUS_STOPPED)",
        "set_report_scan_run_status (scan_report, TASK_STATUS_STOPPED)",
        "yafvs_task_control_unlock (&control_lock)",
    ] {
        assert!(stop.contains(required), "stop_osp_task missing {required}");
    }
    assert!(stop.contains("task_unfinished_report (task, &scan_report)"));
    assert!(!stop.contains("task_last_report_any_status"));
    assert!(!stop.contains("task_running_report (task)"));
    assert!(
        stop.find("ensure_osp_scan_absent (task, scan_id)")
            < stop.find("scan_queue_remove (scan_report)")
    );

    let ensure_absent = inherited_function(MANAGE_C, "ensure_osp_scan_absent");
    for required in [
        "osp_scan_status_for_stop (task, scan_id, &status, &absent)",
        "osp_stop_scan (connection, scan_id, &error)",
        "osp_delete_scan (connection, scan_id)",
        "if (absent)",
        "return -5",
    ] {
        assert!(
            ensure_absent.contains(required),
            "ensure_osp_scan_absent missing {required}"
        );
    }

    let start = inherited_function(MANAGE_OSP_C, "handle_osp_scan_start");
    let lock_offset = start.find("yafvs_task_control_lock").unwrap();
    let launch_offset = start.find("launch_osp_openvas_task").unwrap();
    let unlock_offset = launch_offset
        + start[launch_offset..]
            .find("yafvs_task_control_unlock")
            .unwrap();
    assert!(lock_offset < launch_offset);
    assert!(launch_offset < unlock_offset);
    assert!(start.contains("task_run_status (task) != TASK_STATUS_REQUESTED"));

    let status_update = inherited_function(MANAGE_OSP_C, "set_osp_active_status");
    assert!(status_update.contains("yafvs_task_control_lock"));
    assert!(status_update.contains("current != TASK_STATUS_REQUESTED"));
    assert!(status_update.contains("current != TASK_STATUS_QUEUED"));
    assert!(status_update.contains("current != TASK_STATUS_RUNNING"));

    let running_report = inherited_function(MANAGE_SQL_C, "task_running_report");
    assert!(running_report.contains("run_status == TASK_STATUS_STOP_REQUESTED"));
    assert!(running_report.contains("TASK_STATUS_STOP_REQUESTED"));
    assert!(running_report.contains("end_time IS NULL"));

    let unfinished_report = inherited_function(MANAGE_SQL_C, "task_unfinished_report");
    assert!(unfinished_report.contains("end_time IS NULL"));
    assert!(unfinished_report.contains("TASK_STATUS_INTERRUPTED"));
    assert!(!unfinished_report.contains("ORDER BY creation_time"));
}

#[test]
fn osp_handlers_reject_stale_reports_and_serialize_finalization_with_stop() {
    let start = inherited_function(MANAGE_OSP_C, "handle_osp_scan_start");
    for required in [
        "yafvs_task_control_lock (task, &control_lock)",
        "report_scan_run_status (global_current_report, &report_status)",
        "task_run_status (task) != TASK_STATUS_REQUESTED",
        "report_status != TASK_STATUS_REQUESTED",
        "launch_osp_openvas_task",
        "yafvs_task_control_unlock (&control_lock)",
    ] {
        assert!(
            start.contains(required),
            "handle_osp_scan_start missing {required}"
        );
    }
    assert!(
        start.find("report_status != TASK_STATUS_REQUESTED")
            < start.find("launch_osp_openvas_task")
    );

    let active = inherited_function(MANAGE_OSP_C, "set_osp_active_status");
    for required in [
        "report_scan_run_status (report, &report_status)",
        "report_status != TASK_STATUS_REQUESTED",
        "report_status != TASK_STATUS_QUEUED",
        "report_status != TASK_STATUS_RUNNING",
    ] {
        assert!(
            active.contains(required),
            "set_osp_active_status missing {required}"
        );
    }

    let end = inherited_function(MANAGE_OSP_C, "handle_osp_scan_end");
    for required in [
        "yafvs_task_control_lock (task, &control_lock)",
        "report_scan_run_status (global_current_report, &report_status)",
        "already_finalized",
        "yafvs_task_control_unlock (&control_lock)",
    ] {
        assert!(
            end.contains(required),
            "handle_osp_scan_end missing {required}"
        );
    }
}

#[test]
fn native_browser_task_transports_retire_only_the_gsad_gmp_bridges() {
    for retired in [
        "create_task_gmp",
        "save_task_gmp",
        "get_task_gmp",
        "get_tasks_gmp",
        "export_task_gmp",
        "export_tasks_gmp",
        "delete_task_gmp",
        "start_task_gmp",
        "stop_task_gmp",
        "ELSE (create_task)",
        "ELSE (save_task)",
        "ELSE (get_task)",
        "ELSE (get_tasks)",
        "ELSE (export_task)",
        "ELSE (export_tasks)",
        "ELSE (delete_task)",
        "ELSE (start_task)",
        "ELSE (stop_task)",
    ] {
        assert!(
            !GSAD_GMP_C.contains(retired),
            "retired gsad task-control bridge remains: {retired}"
        );
    }
    for retired in [
        "create_task_gmp",
        "save_task_gmp",
        "get_task_gmp",
        "get_tasks_gmp",
        "export_task_gmp",
        "export_tasks_gmp",
        "delete_task_gmp",
        "start_task_gmp",
        "stop_task_gmp",
    ] {
        assert!(
            !GSAD_GMP_H.contains(retired),
            "retired gsad task-control declaration remains: {retired}"
        );
    }
    assert!(GSAD_GMP_C.contains("exec_gmp_post"));
    assert!(
        GSA_NATIVE_TASKS.contains("deleteNative(gmp, `api/v1/tasks/${encodeURIComponent(id)}`)"),
        "GSA browser task delete must use the same-origin native route"
    );
    assert!(
        GSA_NATIVE_TASKS.contains("`api/v1/tasks/${encodeURIComponent(id)}/start`"),
        "GSA browser task start must use the same-origin native route"
    );
    assert!(
        GSA_NATIVE_TASKS.contains("`api/v1/tasks/${encodeURIComponent(id)}/stop`"),
        "GSA browser task stop must use the same-origin native route"
    );
    assert!(
        GSA_CAPABILITIES.contains("'start_task'"),
        "GSA task-start availability capability must remain lowercase"
    );
    assert!(
        GSA_CAPABILITIES.contains("'stop_task'"),
        "GSA task-stop availability capability must remain lowercase"
    );

    let gmp_delete = inherited_function(GVM_LIBS_GMP_C, "gmp_delete_task");
    let gmp_delete_ext = inherited_function(GVM_LIBS_GMP_C, "gmp_delete_task_ext");
    assert!(gmp_delete.contains("<delete_task task_id=\\\"%s\\\"/>"));
    assert!(gmp_delete_ext.contains("<delete_task task_id=\\\"%s\\\" ultimate=\\\"%d\\\"/>"));
    assert!(gmp_delete_ext.contains("opts.ultimate"));

    for retired in [
        "create_task",
        "save_task",
        "get_task",
        "get_tasks",
        "export_task",
        "export_tasks",
        "delete_task",
        "start_task",
        "stop_task",
    ] {
        assert!(
            !GSAD_VALIDATOR_C.contains(&format!("\"|({retired})\"")),
            "retired gsad task command remains valid: {retired}"
        );
    }
    assert!(GMP_C.contains("strcasecmp (\"DELETE_TASK\", element_name)"));
    assert!(GMP_C.contains("set_client_state (CLIENT_DELETE_TASK)"));
    assert!(GMP_C.contains("case CLIENT_DELETE_TASK:"));
    assert!(!GMP_C.contains("strcasecmp (\"START_TASK\", element_name)"));
    assert!(!GMP_C.contains("strcasecmp (\"STOP_TASK\", element_name)"));
    assert!(!GMP_C.contains("CLIENT_START_TASK"));
    assert!(!GMP_C.contains("CLIENT_STOP_TASK"));
}

#[test]
fn native_direct_api_allows_guarded_task_controls_and_keeps_unmigrated_lifecycle_methods_closed() {
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
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/export",
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
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/trash",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/trash",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tasks",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tasks",
        true,
    ));
    for method in [Method::PUT] {
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
        !direct_api_v1_method_is_allowed(&Method::DELETE, "/api/v1/tasks", true),
        "DELETE /api/v1/tasks collection must remain closed"
    );
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/export",
                true,
            ),
            "{method} /api/v1/tasks/{{id}}/export must remain closed"
        );
    }
    assert!(
        !direct_api_v1_method_is_allowed(&Method::PATCH, "/api/v1/tasks", true),
        "PATCH /api/v1/tasks collection must remain closed"
    );
    let start_path = "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/start";
    assert!(!direct_api_v1_path_is_allowed(start_path));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        start_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        start_path,
        true
    ));
    let stop_path = "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/stop";
    assert!(!direct_api_v1_path_is_allowed(stop_path));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        stop_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        stop_path,
        true
    ));
    let replace_target_path = "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/replace-target";
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        replace_target_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        replace_target_path,
        true
    ));
    let replace_configuration_path =
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/replace-configuration";
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        replace_configuration_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        replace_configuration_path,
        true
    ));
    for action in ["resume", "delete"] {
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
    for path in [
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/export/extra",
        "/api/v1/tasks/../export",
        "/api/v1/tasks/./export",
        "/api/v1/tasks//export",
        "/api/v1/tasks/12345678-1234-1234-1234-123456789abc/../export",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "task metadata export classifier must reject malformed path: {path}"
        );
    }
}

#[test]
fn openapi_documents_task_metadata_and_guarded_control_contracts() {
    let list = openapi_path_block("/tasks");
    assert!(list.contains("get:"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-yafvs-exposure: direct-read"));
    assert!(list.contains("x-yafvs-exposure: direct-write"));
    assert!(list.contains("x-yafvs-replaces: task-create-with-retained-editor-configuration"));
    assert!(list.contains("$ref: '#/components/schemas/TaskCreateRequest'"));
    assert!(
        list.contains("x-yafvs-inherited-still-owns: task-resume-file-and-other-scanner-control")
    );
    assert!(list.contains("name: schedules_only"));
    assert!(list.contains("Return only scan tasks with an attached schedule."));
    assert!(list.contains("type: boolean"));
    assert!(list.contains("task creation and complete retained editor configuration"));
    assert!(list.contains(
        "Direct write-control endpoint for creating a new scan task owned by the authenticated operator"
    ));
    assert!(list.contains("Resume, inherited file export"));

    let detail = openapi_path_block("/tasks/{task_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("x-yafvs-exposure: direct-read"));
    assert!(detail.contains("x-yafvs-exposure: direct-write"));
    assert!(detail.contains("x-yafvs-replaces: task-metadata-modify"));
    assert!(detail.contains("$ref: '#/components/schemas/TaskPatchRequest'"));
    assert!(!detail.contains("x-yafvs-inherited-still-owns:"));
    assert!(detail.contains(
        "Direct write-control endpoint for updating a human-owned task's name and comment only"
    ));
    assert!(detail.contains("Task clone, start, and stop have separate guarded control routes"));
    assert!(detail.contains("operationId: deleteTasksByTaskId"));
    assert!(detail.contains("x-yafvs-replaces: task-trash-move"));
    assert!(detail.contains("safe non-running live-task trash moves"));
    assert!(detail.contains("Running, queued, requested, stop/delete-waiting, processing"));

    let replace_configuration = openapi_path_block("/tasks/{task_id}/replace-configuration");
    for required in [
        "post:",
        "operationId: postTasksByTaskIdReplaceConfiguration",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: task-retained-editor-configuration-modify",
        "x-yafvs-side-effect: scanner-control",
        "$ref: '#/components/schemas/TaskReplaceRequest'",
        "atomically replaces",
        "fixed YAFVS report-retention defaults remain unchanged",
        "never starts a scan",
    ] {
        assert!(
            replace_configuration.contains(required),
            "task replacement OpenAPI block missing {required}"
        );
    }

    let clone = openapi_path_block("/tasks/{task_id}/clone");
    for required in [
        "post:",
        "operationId: postTasksByTaskIdClone",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-maturity: live-write",
        "x-yafvs-replaces: task-clone",
        "x-yafvs-side-effect: scanner-control",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-owner-semantics: request-operator-owner",
        "$ref: '#/components/schemas/Task'",
        "Location:",
        "committed_response_unavailable",
        "$ref: '#/components/responses/BadGateway'",
        "$ref: '#/components/responses/ServiceUnavailable'",
        "authenticated same-origin browser proxy",
        "does not directly start a scan",
        "a due copied schedule can start the clone later",
    ] {
        assert!(
            clone.contains(required),
            "task clone OpenAPI block missing {required}"
        );
    }
    assert!(
        !clone.contains("requestBody:"),
        "task clone must not accept a request body"
    );

    let copy_task = inherited_function(MANAGE_SQL_C, "copy_task");
    for required in [
        "copy_resource_lock (\"task\"",
        "schedule_next_time",
        "set_task_run_status (new, TASK_STATUS_NEW)",
        "INSERT INTO task_preferences",
        "enforce_task_defaults (new)",
        "INSERT INTO task_alerts",
        "sql_commit ()",
    ] {
        assert!(copy_task.contains(required), "copy_task missing {required}");
    }
    for retired_rbac_reference in [
        "INSERT INTO permissions",
        "permissions_trash",
        "cache_permissions_for_resource",
    ] {
        assert!(
            !copy_task.contains(retired_rbac_reference),
            "operator-only task clone still references {retired_rbac_reference}"
        );
    }

    let start = openapi_path_block("/tasks/{task_id}/start");
    for required in [
        "post:",
        "operationId: postTasksByTaskIdStart",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-maturity: live-control",
        "x-yafvs-replaces: task-start",
        "x-yafvs-side-effect: scanner-control",
        "$ref: '#/components/schemas/TaskStartResult'",
        "gvmd remains responsible for scanner protocol execution",
    ] {
        assert!(
            start.contains(required),
            "task start OpenAPI block missing {required}"
        );
    }

    let replace_target = openapi_path_block("/tasks/{task_id}/replace-target");
    for required in [
        "post:",
        "operationId: postTasksByTaskIdReplaceTarget",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-maturity: live-write",
        "x-yafvs-replaces: task-target-clone-rebind-delete",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: scanner-control",
        "$ref: '#/components/schemas/TaskTargetReplaceRequest'",
        "$ref: '#/components/schemas/TaskTargetReplaceResult'",
        "atomically cloning the complete retained configuration",
        "never starts a scan",
    ] {
        assert!(
            replace_target.contains(required),
            "task target replacement OpenAPI block missing {required}"
        );
    }

    let stop = openapi_path_block("/tasks/{task_id}/stop");
    for required in [
        "post:",
        "operationId: postTasksByTaskIdStop",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-maturity: live-control",
        "x-yafvs-replaces: task-stop",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-owner-semantics: gvmd-acl-user-and-task-permission",
        "x-yafvs-side-effect: scanner-control",
        "$ref: '#/components/schemas/TaskStopResult'",
        "YAFVS_API_GVMD_CONTROL_SOCKET",
        "shared-secret-authenticated",
        "$ref: '#/components/responses/Conflict'",
        "$ref: '#/components/responses/BadGateway'",
        "$ref: '#/components/responses/ServiceUnavailable'",
    ] {
        assert!(
            stop.contains(required),
            "task stop OpenAPI block missing {required}"
        );
    }

    let export = openapi_path_block("/tasks/{task_id}/export");
    for required in [
        "get:",
        "operationId: getTasksByTaskIdExport",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-maturity: live-read",
        "x-yafvs-replaces: task-metadata-export-read",
        "$ref: '#/components/schemas/Task'",
        "Task start is available through a separate guarded scan-queue route",
        "inherited file-export formats remain outside this endpoint",
    ] {
        assert!(
            export.contains(required),
            "task metadata export OpenAPI block missing {required}"
        );
    }
    for forbidden in [
        "x-yafvs-inherited-still-owns:",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-safety-contract: write-control-v1",
        "\n    post:",
        "\n    patch:",
        "\n    put:",
    ] {
        assert!(
            !export.contains(forbidden),
            "task metadata export must not expose scanner-control/write/file-export behavior: {forbidden}"
        );
    }
}
