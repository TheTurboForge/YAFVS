// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;
use std::path::Path;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const GSA_ALERT_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/alert.ts");
const GSA_ALLOWED_SNAKE_CASE: &str =
    include_str!("../../../components/gsa/eslint-script/allowedSnakeCase.js");
const GSA_ALERT_MODEL: &str = include_str!("../../../components/gsa/src/gmp/models/alert.ts");
const GSA_ALERT_COMPONENT: &str =
    include_str!("../../../components/gsa/src/web/pages/alerts/AlertComponent.jsx");
const GSA_ALERT_DIALOG: &str =
    include_str!("../../../components/gsa/src/web/pages/alerts/Dialog.jsx");
const GSA_ALERT_METHOD: &str =
    include_str!("../../../components/gsa/src/web/pages/alerts/Method.jsx");
const GSA_DE_LOCALE: &str = include_str!("../../../components/gsa/public/locales/gsa-de.json");
const GSA_EN_LOCALE: &str = include_str!("../../../components/gsa/public/locales/gsa-en.json");
const GSA_ZH_CN_LOCALE: &str =
    include_str!("../../../components/gsa/public/locales/gsa-zh_CN.json");
const GSA_ZH_TW_LOCALE: &str =
    include_str!("../../../components/gsa/public/locales/gsa-zh_TW.json");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GVMD_CMAKE: &str = include_str!("../../../components/gvmd/CMakeLists.txt");
const GVMD_GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GVMD_INSTALL: &str = include_str!("../../../components/gvmd/INSTALL.md");
const MANAGE_ALERTS_C: &str = include_str!("../../../components/gvmd/src/manage_alerts.c");
const MANAGE_ALERTS_H: &str = include_str!("../../../components/gvmd/src/manage_alerts.h");
const MANAGE_EVENTS_C: &str = include_str!("../../../components/gvmd/src/manage_events.c");
const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_ALERTS_C: &str = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
const MANAGE_SQL_REPORT_FORMATS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_report_formats.c");
const ALERT_QUERY_SQL: &str = include_str!("alert_query_sql.rs");
const ALERT_WRITES: &str = include_str!("alert_writes.rs");
const TURBOVAS_CONTROL_C: &str = include_str!("../../../components/gvmd/src/turbovas_control.c");
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

#[test]
fn retired_alert_method_holes_are_removed_full_stack_without_renumbering() {
    let retired_connector_names = [
        ["source", "fire"].concat(),
        ["verinice", " connector"].concat(),
    ];
    let retired_method_name = ["tip", "ping", "point sms"].concat();
    let retired_method_fields = [
        ["tp", "_sms_credential"].concat(),
        ["tp", "_sms_hostname"].concat(),
        ["tp", "_sms_tls_certificate"].concat(),
        ["tp", "_sms_tls_workaround"].concat(),
    ];
    for (path, source) in [
        ("GSA snake-case allowlist", GSA_ALLOWED_SNAKE_CASE),
        ("GSA alert command", GSA_ALERT_COMMAND),
        ("GSA alert model", GSA_ALERT_MODEL),
        ("GSA alert component", GSA_ALERT_COMPONENT),
        ("GSA alert dialog", GSA_ALERT_DIALOG),
        ("GSA alert method view", GSA_ALERT_METHOD),
        ("GSA German locale", GSA_DE_LOCALE),
        ("GSA English locale", GSA_EN_LOCALE),
        ("GSA Simplified Chinese locale", GSA_ZH_CN_LOCALE),
        ("GSA Traditional Chinese locale", GSA_ZH_TW_LOCALE),
        ("gsad GMP bridge", GSAD_GMP_C),
        ("gvmd CMake", GVMD_CMAKE),
        ("gvmd GMP", GVMD_GMP_C),
        ("gvmd install guide", GVMD_INSTALL),
        ("gvmd alert execution", MANAGE_ALERTS_C),
        ("gvmd alert declarations", MANAGE_ALERTS_H),
        ("gvmd alert SQL", MANAGE_SQL_ALERTS_C),
        ("gvmd report-format SQL", MANAGE_SQL_REPORT_FORMATS_C),
        ("gvmd database cleanup", MANAGE_SQL_C),
        ("native alert query SQL", ALERT_QUERY_SQL),
        ("native alert writes", ALERT_WRITES),
    ] {
        for key in ["send_host", "send_port", "send_report_format"] {
            assert!(
                !source.contains(key),
                "{path} still contains retired alert field {key}"
            );
        }
        for retired_connector_name in &retired_connector_names {
            assert!(
                !source.to_ascii_lowercase().contains(retired_connector_name),
                "{path} still contains the retired connector"
            );
        }
        assert!(
            !source.to_ascii_lowercase().contains(&retired_method_name),
            "{path} still contains the retired alert method"
        );
        for retired_method_field in &retired_method_fields {
            assert!(
                !source.contains(retired_method_field),
                "{path} still contains retired alert field {retired_method_field}"
            );
        }
    }

    for (path, source) in [
        ("GSA snake-case allowlist", GSA_ALLOWED_SNAKE_CASE),
        ("GSA alert command", GSA_ALERT_COMMAND),
        ("GSA alert model", GSA_ALERT_MODEL),
        ("GSA alert component", GSA_ALERT_COMPONENT),
        ("GSA alert dialog", GSA_ALERT_DIALOG),
        ("GSA alert method view", GSA_ALERT_METHOD),
        ("gsad GMP bridge", GSAD_GMP_C),
        ("gvmd GMP", GVMD_GMP_C),
        ("gvmd alert execution", MANAGE_ALERTS_C),
        ("gvmd alert declarations", MANAGE_ALERTS_H),
        ("gvmd alert SQL", MANAGE_SQL_ALERTS_C),
        ("gvmd report-format SQL", MANAGE_SQL_REPORT_FORMATS_C),
        ("gvmd database cleanup", MANAGE_SQL_C),
        ("native alert query SQL", ALERT_QUERY_SQL),
        ("native alert writes", ALERT_WRITES),
    ] {
        for key in [
            "verinice_server_credential",
            "verinice_server_url",
            "verinice_server_report_format",
        ] {
            assert!(
                !source.contains(key),
                "{path} still contains retired alert field {key}"
            );
        }
    }

    for required in [
        "Value 2 is retired; alert method IDs are persisted and must not shift.",
        "ALERT_METHOD_START_TASK = 4",
        "ALERT_METHOD_SYSLOG = 5",
        "Value 6 is retired; alert method IDs are persisted and must not shift.",
        "Value 7 is retired; alert method IDs are persisted and must not shift.",
        "ALERT_METHOD_SCP = 8",
        "ALERT_METHOD_SNMP = 9",
        "ALERT_METHOD_SMB = 10",
        "Value 11 is retired; alert method IDs are persisted and must not shift.",
        "Value 12 is retired; alert method IDs are persisted and must not shift.",
    ] {
        assert!(
            MANAGE_ALERTS_H.contains(required),
            "persisted alert method mapping missing {required}"
        );
    }
    assert!(
        !MANAGE_ALERTS_H.contains("ALERT_METHOD_SEND"),
        "retired alert method must not remain in the enum"
    );
    let retired_http_method = ["ALERT_METHOD_", "HTTP", "_GET"].concat();
    assert!(
        !MANAGE_ALERTS_H.contains(&retired_http_method),
        "retired alert method must not remain in the enum"
    );
    assert!(
        !MANAGE_ALERTS_H.contains("ALERT_METHOD_VERINICE"),
        "retired alert method must not remain in the enum"
    );
    let retired_method_name = format!("ALERT_METHOD_{}{}", "VF", "IRE");
    assert!(
        !MANAGE_ALERTS_H.contains(&retired_method_name),
        "retired alert method must not remain in the enum"
    );
    assert!(
        !MANAGE_ALERTS_H.contains(&["ALERT_METHOD_", "TIPP", "INGPOINT"].concat()),
        "retired alert method must not remain in the enum"
    );
    assert!(
        !MANAGE_ALERTS_C.contains("case ALERT_METHOD_SEND"),
        "retired alert method must not remain executable"
    );
    assert!(
        !MANAGE_ALERTS_C.contains(&format!("case {retired_http_method}")),
        "retired alert method must not remain executable"
    );
    assert!(
        !MANAGE_ALERTS_C.contains(&["(name, \"HTTP", " Get\")"].concat()),
        "retired alert method must not remain parseable"
    );
    assert!(
        !GVMD_GMP_C.contains(&["Method does not match", " event type"].concat()),
        "retired alert method validation error must not remain exposed"
    );
    assert!(
        !MANAGE_ALERTS_C.contains("case ALERT_METHOD_VERINICE"),
        "retired alert method must not remain executable"
    );
    assert!(
        !MANAGE_ALERTS_C.contains(&["case ALERT_METHOD_", "TIPP", "INGPOINT"].concat()),
        "retired alert method must not remain executable"
    );
    assert!(
        !MANAGE_ALERTS_C.contains("(name, \"Send\")"),
        "retired alert method must not remain parseable"
    );
    assert!(
        !ALERT_QUERY_SQL.contains("WHEN 7 THEN 'Send'"),
        "native SQL must not label the retired alert method"
    );
    assert!(
        !ALERT_QUERY_SQL.contains(&["WHEN 2 THEN 'HTTP", " Get'"].concat()),
        "native SQL must not label the retired alert method"
    );
    assert!(
        !ALERT_QUERY_SQL.contains("WHEN 6 THEN 'verinice Connector'"),
        "native SQL must not label the retired alert method"
    );
    assert!(
        !ALERT_QUERY_SQL.contains(&format!("WHEN 11 THEN '{}'", retired_method_name)),
        "native SQL must not label the retired alert method"
    );
    assert!(
        GVMD_INSTALL.contains("Prerequisites for generating verinice reports:"),
        "verinice report-generation prerequisites must remain supported"
    );
    for status in [
        "invalid_send_host",
        "invalid_send_port",
        "send_format_not_found",
        "invalid_tp_credential",
        "invalid_tp_host",
        "invalid_tp_certificate",
        "invalid_tp_tls",
    ] {
        assert!(
            !TURBOVAS_CONTROL_C.contains(status),
            "control-plane status mapping still contains {status}"
        );
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let retired_connector_directory = ["Source", "fire"].concat();
    let retired_method_directory = ["Tip", "ping", "Point"].concat();
    assert!(
        !root
            .join("components/gvmd/src/alert_methods")
            .join(retired_connector_directory)
            .join("alert")
            .exists()
    );
    assert!(
        !root
            .join("components/gsa/src/web/pages/alerts/dialog")
            .join(["Source", "FireMethodPart.tsx"].concat())
            .exists()
    );
    assert!(
        !root
            .join("components/gvmd/src/alert_methods")
            .join("Send")
            .join("alert")
            .exists()
    );
    assert!(
        !root
            .join("components/gsa/src/web/pages/alerts/dialog")
            .join("SendMethodPart.tsx")
            .exists()
    );
    assert!(
        !root
            .join("components/gsa/src/web/pages/alerts/dialog")
            .join(["Http", "MethodPart.tsx"].concat())
            .exists()
    );
    assert!(
        !root
            .join("components/gvmd/src/alert_methods")
            .join("verinice")
            .join("alert")
            .exists()
    );
    assert!(
        !root
            .join("components/gsa/src/web/pages/alerts/dialog")
            .join("VeriniceMethodPart.tsx")
            .exists()
    );
    assert!(
        !root
            .join("components/gvmd/src/alert_methods")
            .join(&retired_method_directory)
            .join("alert")
            .exists()
    );
    assert!(
        !root
            .join("components/gsa/src/web/pages/alerts/dialog")
            .join(["Tip", "ping", "PointMethodPart.tsx"].concat())
            .exists()
    );
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

fn openapi_operation_block(path_block: &str, method: &str) -> String {
    let marker = format!("    {method}:");
    let start = path_block
        .find(&marker)
        .unwrap_or_else(|| panic!("{method} operation block must exist"));
    let tail = &path_block[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            let trimmed = line.trim_end();
            if line.starts_with("    ")
                && !line.starts_with("      ")
                && matches!(
                    trimmed,
                    "    get:" | "    post:" | "    patch:" | "    put:" | "    delete:"
                )
            {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn generic_gvmd_alert_create_and_modify_entry_points_are_removed() {
    for retired in ["\ncreate_alert (", "\nmodify_alert ("] {
        assert!(
            !MANAGE_SQL_ALERTS_C.contains(retired),
            "generic gvmd Alert mutation entry point remains: {retired}"
        );
    }

    for retained_native_control_helper in [
        "create_alert_task_status_changed (",
        "create_alert_email_with_report_refs",
        "create_alert_smb_with_report_refs",
        "create_alert_scp_with_report_refs",
        "create_alert_start_task_with_task_ref",
    ] {
        assert!(
            MANAGE_SQL_ALERTS_C.contains(retained_native_control_helper),
            "native-control Alert helper missing {retained_native_control_helper}"
        );
    }
}

#[test]
fn inherited_alert_copy_delete_restore_and_test_keep_child_tables_and_task_links_explicit() {
    let copy = inherited_function(MANAGE_SQL_ALERTS_C, "copy_alert");
    for required in [
        "copy_resource_lock (\"alert\", name, comment, alert_id",
        "INSERT INTO alert_condition_data (alert, name, data)",
        "INSERT INTO alert_event_data (alert, name, data)",
        "INSERT INTO alert_method_data (alert, name, data)",
        "sql_commit ();",
    ] {
        assert!(copy.contains(required), "copy_alert missing {required}");
    }

    let delete = inherited_function(MANAGE_SQL_ALERTS_C, "delete_alert");
    for required in [
        "acl_user_may (\"delete_alert\") == 0",
        "find_alert_with_permission (alert_id, &alert, \"delete_alert\")",
        "find_trash (\"alert\", alert_id, &alert)",
        "SELECT count(*) FROM task_alerts",
        "INSERT INTO alerts_trash",
        "INSERT INTO alert_condition_data_trash",
        "INSERT INTO alert_event_data_trash",
        "INSERT INTO alert_method_data_trash",
        "UPDATE task_alerts",
        "permissions_set_locations (\"alert\"",
        "tags_set_locations (\"alert\"",
        "DELETE FROM alert_condition_data WHERE alert = %llu;",
        "DELETE FROM alert_event_data WHERE alert = %llu;",
        "DELETE FROM alert_method_data WHERE alert = %llu;",
        "DELETE FROM alerts WHERE id = %llu;",
    ] {
        assert!(delete.contains(required), "delete_alert missing {required}");
    }

    for required in [
        "INSERT INTO alert_condition_data",
        "FROM alert_condition_data_trash WHERE alert = %llu;",
        "INSERT INTO alert_event_data",
        "FROM alert_event_data_trash WHERE alert = %llu;",
        "INSERT INTO alert_method_data",
        "FROM alert_method_data_trash WHERE alert = %llu;",
        "UPDATE task_alerts",
        "DELETE FROM alert_condition_data_trash WHERE alert = %llu;",
        "DELETE FROM alert_event_data_trash WHERE alert = %llu;",
        "DELETE FROM alert_method_data_trash WHERE alert = %llu;",
    ] {
        assert!(
            MANAGE_SQL_C.contains(required),
            "alert restore path missing {required}"
        );
    }

    let test_alert = inherited_function(MANAGE_ALERTS_C, "manage_test_alert");
    for required in [
        "acl_user_may (\"test_alert\") == 0",
        "find_alert_with_permission (alert_id, &alert, \"test_alert\")",
        "alert_event (alert) == EVENT_NEW_SECINFO",
        "manage_alert (alert_id, \"0\", EVENT_NEW_SECINFO",
        "make_task (g_strdup (\"Temporary Task for Alert\")",
        "ret = manage_alert (alert_id,",
        "EVENT_TASK_RUN_STATUS_CHANGED",
        "(void*) TASK_STATUS_DONE",
    ] {
        assert!(
            test_alert.contains(required),
            "manage_test_alert missing {required}"
        );
    }

    let trigger = inherited_function(MANAGE_EVENTS_C, "trigger_with_presets");
    for required in [
        "get.details = 1",
        "setting_filter (\"Results\")",
        "overrides=1 sort-reverse=severity",
        "method == ALERT_METHOD_EMAIL ? 1000 : -1",
        "trigger (alert, task, report, event, event_data, method, condition,",
    ] {
        assert!(
            trigger.contains(required),
            "trigger_with_presets missing {required}"
        );
    }
}

#[test]
fn gsad_and_gsa_alert_definition_paths_are_native_only() {
    for retired in [
        "append_alert_method_data",
        "create_alert_gmp",
        "save_alert_gmp",
        "<create_alert>",
        "<modify_alert",
        "ELSE (create_alert)",
        "ELSE (save_alert)",
    ] {
        assert!(
            !GSAD_GMP_C.contains(retired),
            "gsad still contains retired Alert GMP surface {retired}"
        );
    }

    for required in [
        "fetchNativeAlertDefinition",
        "replaceNativeAlertDefinition",
        "createNativeAlert",
        "cloneNativeAlert",
        "deleteNativeAlert",
        "testNativeAlert",
    ] {
        assert!(
            GSA_ALERT_COMMAND.contains(required),
            "GSA native Alert command missing {required}"
        );
    }

    for retired in [
        "cmd: 'create_alert'",
        "cmd: 'save_alert'",
        "cmd: 'new_alert'",
        "cmd: 'edit_alert'",
        "cmd: 'test_alert'",
        "convertData('method_data'",
        "convertData('condition_data'",
        "convertData('event_data'",
    ] {
        assert!(
            !GSA_ALERT_COMMAND.contains(retired),
            "GSA Alert command still contains retired GMP surface {retired}"
        );
    }
}

#[test]
fn native_retained_alert_create_methods_are_guarded_and_broad_mutation_routes_remain_closed() {
    for path in [
        "/api/v1/alerts",
        "/api/v1/alerts/12345678-1234-1234-1234-123456789abc",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "alert read path must remain direct allowlisted: {path}"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "alert read path must allow GET without write control: {path}"
        );
        for method in [Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "alert native mutation must remain closed for {method} {path}"
            );
        }
    }
    assert!(
        !direct_api_v1_method_is_allowed(&Method::POST, "/api/v1/alerts", false),
        "retained alert create methods must require direct write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::POST, "/api/v1/alerts", true),
        "retained alert create methods must be enabled by direct write-control"
    );
    assert!(
        !direct_api_v1_method_is_allowed(
            &Method::POST,
            "/api/v1/alerts/12345678-1234-1234-1234-123456789abc",
            true
        ),
        "alert detail POST must remain closed"
    );
    assert!(
        !direct_api_v1_method_is_allowed(&Method::DELETE, "/api/v1/alerts", true),
        "alert collection DELETE must remain closed"
    );
    assert!(
        !direct_api_v1_method_is_allowed(
            &Method::DELETE,
            "/api/v1/alerts/12345678-1234-1234-1234-123456789abc",
            false
        ),
        "alert metadata DELETE must require direct write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(
            &Method::DELETE,
            "/api/v1/alerts/12345678-1234-1234-1234-123456789abc",
            true
        ),
        "alert metadata DELETE must be allowed when direct write-control is enabled"
    );
    assert!(
        !direct_api_v1_method_is_allowed(&Method::PATCH, "/api/v1/alerts", true),
        "alert collection PATCH must remain closed"
    );
    assert!(
        !direct_api_v1_method_is_allowed(
            &Method::PATCH,
            "/api/v1/alerts/12345678-1234-1234-1234-123456789abc",
            false
        ),
        "alert metadata PATCH must require direct write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(
            &Method::PATCH,
            "/api/v1/alerts/12345678-1234-1234-1234-123456789abc",
            true
        ),
        "alert metadata PATCH must be allowed when direct write-control is enabled"
    );

    let clone_path = "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/clone";
    assert!(
        direct_api_v1_path_is_allowed(clone_path),
        "alert clone path is now direct allowlisted"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::POST, clone_path, true),
        "alert clone must require direct write-control"
    );
    assert!(
        !direct_api_v1_method_is_allowed(&Method::POST, clone_path, false),
        "alert clone must stay closed without direct write-control"
    );

    for path in [
        "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/test",
        "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/restore",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "alert delivery/control path must not be direct allowlisted: {path}"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::GET, path, true),
            "alert delivery/control path must not be reachable: {path}"
        );
    }

    assert!(
        direct_api_v1_path_is_allowed("/api/v1/alerts/12345678-1234-1234-1234-123456789abc/export"),
        "redacted alert metadata export is scriptable native JSON"
    );
    let export_path = "/api/v1/alerts/12345678-1234-1234-1234-123456789abc/export";
    assert!(
        direct_api_v1_method_is_allowed(&Method::GET, export_path, false),
        "alert metadata export must allow GET without write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::GET, export_path, true),
        "alert metadata export must remain GET-able with write-control enabled"
    );
    for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, export_path, true),
            "{method} alert metadata export must stay closed; inherited XML export and unrelated control semantics remain separate"
        );
    }

    for (path, replaces, forbidden_methods) in [
        (
            "/alerts",
            "alert-metadata-list-read",
            ["    put:", "    patch:", "    delete:"].as_slice(),
        ),
        (
            "/alerts/{alert_id}",
            "alert-metadata-detail-read",
            ["    post:", "    put:"].as_slice(),
        ),
    ] {
        let block = openapi_path_block(path);
        for required in [
            "x-turbovas-exposure: direct-read",
            replaces,
            "condition data, event data, method delivery payloads, credentials, destinations, message bodies, certificates",
            "inherited XML export, restore, hard-delete, and delivery-payload mutations",
        ] {
            assert!(block.contains(required), "{path} missing {required}");
        }
        for forbidden in forbidden_methods {
            assert!(
                !block.contains(forbidden),
                "{path} must not declare alert mutation method {forbidden}"
            );
        }
    }
    let detail = openapi_path_block("/alerts/{alert_id}");
    let patch = openapi_operation_block(&detail, "patch");
    for required in [
        "    patch:",
        "operationId: patchAlertsByAlertId",
        "x-turbovas-exposure: direct-write",
        "x-turbovas-replaces: alert-metadata-modify",
        "x-turbovas-safety-contract: write-control-v1",
        "AlertPatchRequest",
        "event/condition/method data, delivery payloads, credentials, destinations, task links, inherited XML export, restore, hard-delete, and delivery-payload mutation remain on inherited compatibility paths",
    ] {
        assert!(
            patch.contains(required),
            "/alerts/{{alert_id}} missing {required}"
        );
    }
    assert!(!patch.contains("x-turbovas-inherited-still-owns: alert-detail-delivery-control"));
    let delete = openapi_operation_block(&detail, "delete");
    for required in [
        "    delete:",
        "operationId: deleteAlertsByAlertId",
        "x-turbovas-replaces: alert-trash-move",
        "x-turbovas-side-effect: metadata-delete",
    ] {
        assert!(
            delete.contains(required),
            "/alerts/{{alert_id}} delete missing {required}"
        );
    }

    let clone = openapi_path_block("/alerts/{alert_id}/clone");
    for required in [
        "    post:",
        "operationId: postAlertsByAlertIdClone",
        "x-turbovas-exposure: direct-write",
        "x-turbovas-replaces: alert-clone",
        "x-turbovas-safety-contract: write-control-v1",
        "AlertCloneRequest",
    ] {
        assert!(
            clone.contains(required),
            "/alerts/{{alert_id}}/clone missing {required}"
        );
    }
    assert!(!delete.contains("x-turbovas-inherited-still-owns: alert-detail-delivery-control"));
    assert!(!clone.contains("x-turbovas-inherited-still-owns: alert-detail-delivery-control"));
}

#[test]
fn native_scp_alert_create_contract_is_explicitly_parsed_scrubbed_and_direct_write_documented() {
    let parser = inherited_function(
        TURBOVAS_CONTROL_C,
        "turbovas_control_parse_alert_scp_create_request",
    );
    for required in [
        "TURBOVAS_CONTROL_ALERT_SCP_CREATE_COMMAND",
        "turbovas_control_parse_authenticated_prefix",
        "TURBOVAS_CONTROL_ALERT_UUID_MAX_BYTES",
        "TURBOVAS_CONTROL_ALERT_SCP_PORT_MAX_BYTES",
        "turbovas_control_uuid_is_valid (alert->credential_uuid)",
        "turbovas_control_uuid_is_valid (alert->report_format_uuid)",
        "turbovas_control_alert_scp_port_is_valid (alert->port)",
        "alert->known_hosts, strlen (alert->known_hosts), TRUE",
        "alert->path, strlen (alert->path), FALSE",
        "turbovas_control_alert_scp_create_request_clear (alert)",
    ] {
        assert!(
            parser.contains(required),
            "SCP control parser missing {required}"
        );
    }

    let create = inherited_function(TURBOVAS_CONTROL_C, "turbovas_control_create_alert_scp");
    for required in [
        "turbovas_control_start_operator_session (operator_uuid)",
        "scp_credential",
        "scp_host",
        "scp_port",
        "scp_known_hosts",
        "scp_path",
        "scp_report_format",
        "create_alert_scp_with_report_refs",
        "turbovas_control_secure_array_free (method_data)",
        "turbovas_control_finish_operator_session ()",
    ] {
        assert!(
            create.contains(required),
            "SCP control create missing {required}"
        );
    }
    assert!(
        TURBOVAS_CONTROL_C
            .contains("turbovas_control_alert_scp_create_request_clear (&scp_alert_request)")
    );
    assert!(TURBOVAS_CONTROL_C.contains("turbovas_control_secure_clear (request, request_len)"));

    let create_path = openapi_path_block("/alerts");
    let create = openapi_operation_block(&create_path, "post");
    for required in [
        "x-turbovas-replaces: alert-email-smb-syslog-snmp-scp-start-task-create",
        "summary: Create a task-status EMAIL, SMB, Syslog, SNMP, SCP, or Start Task alert",
        "Creates one operator-owned EMAIL, SMB, Syslog, SNMP, SCP, or Start Task alert",
    ] {
        assert!(
            create.contains(required),
            "SCP create metadata missing {required}"
        );
    }
    assert!(create.contains("delivery-payload-mutations"));
    assert!(!create.contains("alert-test-actions-and-delivery-payload-mutations"));
    assert!(!create.contains("alert-start-task-create-test-actions"));

    let schema = OPENAPI
        .split_once("    AlertScpCreateRequest:\n")
        .expect("SCP create schema must exist")
        .1
        .split_once("    AlertSmbCreateRequest:\n")
        .expect("SCP create schema must be bounded")
        .0;
    for required in [
        "additionalProperties: false",
        "required: [method, name, active, status, scp_credential_id, scp_host, scp_port, scp_known_hosts, scp_path, report_format_id]",
        "const: SCP",
        "minimum: 1",
        "maximum: 65535",
        "Required OpenSSH known-hosts content used as the exclusive host-key trust source",
    ] {
        assert!(schema.contains(required), "SCP schema missing {required}");
    }
}
