// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const GSA_ALERT_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/alert.ts");
const GSA_ENTITY_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/entity.ts");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const MANAGE_ALERTS_C: &str = include_str!("../../../components/gvmd/src/manage_alerts.c");
const MANAGE_EVENTS_C: &str = include_str!("../../../components/gvmd/src/manage_events.c");
const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_ALERTS_C: &str = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
const PYTHON_GVM_ALERTS: &str =
    include_str!("../../../components/python-gvm/gvm/protocols/gmp/requests/v224/_alerts.py");
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
fn inherited_alert_create_and_modify_are_acl_filter_and_payload_guarded() {
    let create = inherited_function(MANAGE_SQL_ALERTS_C, "create_alert");
    for required in [
        "acl_user_may (\"create_alert\") == 0",
        "check_alert_params (event, condition, method)",
        "find_filter_with_permission (filter_id, &filter, \"get_filters\")",
        "SELECT type FROM filters WHERE id = %llu;",
        "resource_with_name_exists (name, \"alert\", 0)",
        "INSERT INTO alerts (uuid, owner, name, comment, event, condition,",
        "validate_alert_condition_data (data_name,",
        "INSERT INTO alert_condition_data (alert, name, data)",
        "validate_alert_event_data (data_name, data, event)",
        "INSERT INTO alert_event_data (alert, name, data)",
        "validate_email_data (method, data_name, &data, 0)",
        "validate_scp_data (method, data_name, &data)",
        "validate_send_data (method, data_name, &data)",
        "validate_smb_data (method, data_name, &data)",
        "validate_sourcefire_data (method, data_name, &data)",
        "validate_tippingpoint_data (method, data_name, &data)",
        "validate_vfire_data (method, data_name, &data)",
        "INSERT INTO alert_method_data (alert, name, data)",
        "sql_commit ();",
    ] {
        assert!(create.contains(required), "create_alert missing {required}");
    }

    let modify = inherited_function(MANAGE_SQL_ALERTS_C, "modify_alert");
    for required in [
        "acl_user_may (\"modify_alert\") == 0",
        "check_alert_params (event, condition, method)",
        "find_alert_with_permission (alert_id, &alert, \"modify_alert\")",
        "resource_with_name_exists (name, \"alert\", alert)",
        "find_filter_with_permission (filter_id, &filter, \"get_filters\")",
        "UPDATE alerts SET",
        "DELETE FROM alert_event_data WHERE alert = %llu",
        "INSERT INTO alert_event_data (alert, name, data)",
        "DELETE FROM alert_condition_data WHERE alert = %llu",
        "INSERT INTO alert_condition_data (alert, name, data)",
        "DELETE FROM alert_method_data WHERE alert = %llu",
        "validate_email_data (method, data_name, &data, 1)",
        "INSERT INTO alert_method_data (alert, name, data)",
        "sql_commit ();",
    ] {
        assert!(modify.contains(required), "modify_alert missing {required}");
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
fn gsad_and_gsa_alert_commands_proxy_delivery_payloads_and_control_verbs() {
    let append_method = inherited_function(GSAD_GMP_C, "append_alert_method_data");
    for required in [
        "scp_credential",
        "smb_credential",
        "tp_sms_credential",
        "verinice_server_credential",
        "vfire_credential",
        "recipient_credential",
        "send_report_config",
        "send_report_format",
        "notice_report_config",
        "notice_report_format",
        "pkcs12_credential",
        "g_base64_encode ((guchar *) param->value, param->value_size)",
        "composer_include_overrides",
        "composer_ignore_pagination",
    ] {
        assert!(
            append_method.contains(required),
            "append_alert_method_data missing {required}"
        );
    }

    for (name, required) in [
        (
            "create_alert_gmp",
            &[
                "CHECK_VARIABLE_INVALID (name, \"Create Alert\")",
                "params_values (params, \"method_data:\")",
                "params_values (params, \"event_data:\")",
                "params_values (params, \"condition_data:\")",
                "params_values (params, \"report_format_ids:\")",
                "<create_alert>",
                "append_alert_event_data (xml, event_data, event)",
                "append_alert_method_data (xml, method_data, method, report_formats)",
                "append_alert_condition_data (xml, condition_data, condition)",
            ][..],
        ),
        (
            "save_alert_gmp",
            &[
                "CHECK_VARIABLE_INVALID (alert_id, \"Save Alert\")",
                "params_values (params, \"method_data:\")",
                "<modify_alert alert_id=\\\"%s\\\">",
                "append_alert_event_data (xml, event_data, event)",
                "append_alert_method_data (xml, method_data, method, report_formats)",
                "append_alert_condition_data (xml, condition_data, condition)",
            ][..],
        ),
    ] {
        let function = inherited_function(GSAD_GMP_C, name);
        for needle in required {
            assert!(function.contains(needle), "{name} missing {needle}");
        }
    }

    for required in [
        "return move_resource_to_trash (connection, \"alert\"",
        "gvm_connection_sendf (connection, \"<test_alert alert_id=\\\"%s\\\"/>",
        "return export_resource (connection, \"alert\"",
        "return export_many (connection, \"alert\"",
        "ELSE (create_alert)",
        "ELSE (delete_alert)",
        "ELSE (save_alert)",
        "ELSE (test_alert)",
    ] {
        assert!(
            GSAD_GMP_C.contains(required),
            "gsad alert surface missing {required}"
        );
    }

    for required in [
        "cmd: 'create_alert'",
        "cmd: 'save_alert'",
        "cmd: 'new_alert'",
        "cmd: 'edit_alert'",
        "cmd: 'test_alert'",
        "convertData('method_data'",
        "convertData('condition_data'",
        "convertData('event_data'",
        "'report_format_ids:'",
        "'report_config_ids:'",
        "credentials: map(",
        "filters: map(",
        "tasks: map(",
    ] {
        assert!(
            GSA_ALERT_COMMAND.contains(required),
            "GSA alert command missing {required}"
        );
    }

    for required in [
        "cmd: 'clone'",
        "cmd: 'delete_' + this.name",
        "cmd: 'bulk_export'",
    ] {
        assert!(
            GSA_ENTITY_COMMAND.contains(required),
            "generic GSA entity command missing alert {required} surface"
        );
    }
}

#[test]
fn python_gvm_still_exposes_alert_mutation_and_test_requests() {
    for required in [
        "def create_alert(",
        "def modify_alert(",
        "def clone_alert(cls, alert_id: EntityID)",
        "def delete_alert(",
        "def test_alert(cls, alert_id: EntityID)",
        "XmlCommand(\"create_alert\")",
        "XmlCommand(\"modify_alert\")",
        "XmlCommand(\"delete_alert\")",
        "XmlCommand(\"test_alert\")",
        "cmd.add_element(\"copy\", str(alert_id))",
        "cmd.set_attribute(\"ultimate\", to_bool(ultimate))",
    ] {
        assert!(
            PYTHON_GVM_ALERTS.contains(required),
            "python-gvm alert request surface missing {required}"
        );
    }
}

#[test]
fn native_alert_delivery_and_broad_mutation_routes_remain_closed() {
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
        for method in [Method::POST, Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "alert native mutation must remain closed for {method} {path}"
            );
        }
    }
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
            "{method} alert metadata export must stay closed; inherited XML/export/test/control semantics remain inherited"
        );
    }

    for (path, replaces, forbidden_methods) in [
        (
            "/alerts",
            "alert-metadata-list-read",
            ["    post:", "    put:", "    patch:", "    delete:"].as_slice(),
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
            "inherited XML export/test actions",
            "create, restore, hard-delete, and delivery-payload mutations",
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
    for required in [
        "    patch:",
        "operationId: patchAlertsByAlertId",
        "x-turbovas-exposure: direct-write",
        "x-turbovas-replaces: alert-metadata-modify",
        "x-turbovas-safety-contract: write-control-v1",
        "AlertPatchRequest",
        "event/condition/method data, delivery payloads, credentials, destinations, task links, inherited XML export, test, create, restore, hard-delete, and delivery-payload mutation remain on inherited compatibility paths",
    ] {
        assert!(
            detail.contains(required),
            "/alerts/{{alert_id}} missing {required}"
        );
    }
    for required in [
        "    delete:",
        "operationId: deleteAlertsByAlertId",
        "x-turbovas-replaces: alert-trash-move",
        "x-turbovas-side-effect: metadata-delete",
    ] {
        assert!(
            detail.contains(required),
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
}
