// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::{
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
    user_account_query_sql::{user_account_detail_sql, user_accounts_sql},
};

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const GSA_USER_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/user.ts");
const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_HEADER: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_NATIVE_API: &str = include_str!("../../../components/gsad/src/gsad_native_api.c");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVMD: &str = include_str!("../../../components/gvmd/src/gvmd.c");
const GVMD_GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GVMD_GMP_SCHEMA: &str =
    include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const GVMD_MANAGE_COMMANDS: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const GVMD_MANAGE_USERS: &str = include_str!("../../../components/gvmd/src/manage_users.h");
const GVMD_SQL_USERS: &str = include_str!("../../../components/gvmd/src/manage_sql_users.c");
const GVMD_YAFVS_CONTROL: &str = include_str!("../../../components/gvmd/src/yafvs_control.c");
const GVMD_INSTALL: &str = include_str!("../../../components/gvmd/INSTALL.md");
const GVMD_MANPAGE: &str = include_str!("../../../components/gvmd/docs/gvmd.8");
const GVMD_MANPAGE_HTML: &str = include_str!("../../../components/gvmd/docs/gvmd.html");
const GVMD_MANPAGE_XML: &str = include_str!("../../../components/gvmd/docs/gvmd.8.xml");

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
fn legacy_user_lifecycle_is_native_only_not_public_gmp_transport() {
    for command in ["CREATE_USER", "MODIFY_USER", "DELETE_USER"] {
        assert!(
            !GVMD_MANAGE_COMMANDS.contains(&format!("{{\"{command}\"")),
            "public GMP HELP must not advertise {command}"
        );
        assert!(
            GVMD_MANAGE_COMMANDS.contains(&format!("\"{command}\",")),
            "native ACL inventory must retain {command}"
        );
    }

    for retired in ["create_user", "modify_user", "delete_user"] {
        assert!(
            !GSAD_GMP.contains(&format!("{retired}_gmp")),
            "gsad must not bridge {retired}"
        );
        assert!(
            !GSAD_GMP_HEADER.contains(&format!("{retired}_gmp")),
            "gsad must not declare {retired} bridge"
        );
        assert!(
            !GSAD_GMP.contains(&format!("ELSE ({retired})")),
            "gsad must not dispatch {retired}"
        );
        assert!(
            !GSAD_VALIDATOR.contains(&format!("|({retired})")),
            "gsad validator must not accept {retired}"
        );
        assert!(
            !GVMD_GMP_SCHEMA.contains(&format!("<name>{retired}</name>")),
            "GMP XML schema must not define {retired}"
        );
    }
    for command in ["CREATE_USER", "MODIFY_USER", "DELETE_USER"] {
        assert!(
            !GVMD_GMP.contains(command),
            "authenticated GMP parser must not accept {command}"
        );
    }
    for historical_record in [
        "<command>CREATE_TASK, CREATE_USER, GET_TASKS, GET_USERS, MODIFY_TASK, MODIFY_USER</command>",
        "<command>CREATE_USER, MODIFY_USER</command>",
    ] {
        assert!(
            GVMD_GMP_SCHEMA.contains(historical_record),
            "retiring live commands must not rewrite protocol history: {historical_record}"
        );
    }

    for native_call in [
        "createNativeUser(",
        "cloneNativeUser(",
        "patchNativeUser(",
        "deleteNativeUser(",
    ] {
        assert!(GSA_USER_COMMAND.contains(native_call));
    }
    assert!(GSAD_NATIVE_API.contains("USER_MANAGEMENT_USERS_PATH"));
    assert!(GSAD_NATIVE_API.contains("USER_MANAGEMENT_USER_PREFIX"));
    for control_command in ["user-create", "user-clone", "user-modify", "user-delete"] {
        assert!(GVMD_YAFVS_CONTROL.contains(control_command));
    }
    for manager_function in [
        "create_user (",
        "copy_user (",
        "modify_user (",
        "delete_user (",
    ] {
        assert!(GVMD_SQL_USERS.contains(manager_function));
    }
    assert!(GVMD.contains("\"create-user\""));
    assert!(GVMD.contains("\"delete-user\""));
}

#[test]
fn user_inventory_is_native_and_legacy_user_inventory_transports_are_absent() {
    assert!(GSA_USER_COMMAND.contains("gmp/native-api/users"));
    for source in [GSAD_GMP, GSAD_GMP_HEADER, GSAD_VALIDATOR, GVMD, GVMD_GMP] {
        assert!(!source.contains("get_users_gmp"));
        assert!(!source.contains("GET_USERS"));
        assert!(!source.contains("--get-users"));
    }
    assert!(!GVMD_MANAGE_USERS.contains("manage_get_users"));
    for source in [
        GVMD_INSTALL,
        GVMD_MANPAGE,
        GVMD_MANPAGE_HTML,
        GVMD_MANPAGE_XML,
    ] {
        assert!(!source.contains("--get-users"));
    }
    assert!(GVMD_SQL_USERS.contains("\"get_users\""));
}

#[test]
fn operator_capabilities_and_session_ping_have_no_public_gmp_route() {
    let capabilities = GSA_USER_COMMAND
        .split_once("async currentCapabilities()")
        .expect("current capabilities method")
        .1
        .split_once("async currentFeatures()")
        .expect("current capabilities method boundary")
        .0;
    assert!(capabilities.contains("new Capabilities(['everything'])"));
    assert!(!capabilities.contains("this.http"));

    let ping = GSA_USER_COMMAND
        .split_once("async ping()")
        .expect("session ping method")
        .1;
    assert!(ping.contains("api/v1/session/ping"));
    assert!(ping.contains("method: 'GET'"));

    for retired in ["get_capabilities", "ping"] {
        let handler = format!("{retired}_gmp");
        let dispatch = format!("ELSE ({retired})");
        let validator = format!("|({retired})");
        assert!(!GSAD_GMP.contains(&handler), "gsad still defines {handler}");
        assert!(
            !GSAD_GMP_HEADER.contains(&handler),
            "gsad still declares {handler}"
        );
        assert!(
            !GSAD_GMP.contains(&dispatch),
            "gsad still dispatches {dispatch}"
        );
        assert!(
            !GSAD_VALIDATOR.contains(&validator),
            "gsad still accepts {validator}"
        );
    }

    assert!(GSAD_NATIVE_API.contains("g_strcmp0 (path, SESSION_PING_PATH) == 0"));
    assert!(GSAD_NATIVE_API.contains(r#"{\"status\":\"ok\"}"#));

    let login_auth = GSAD_GMP
        .split_once("authenticate_gmp_with_user_uuid (")
        .expect("manager-backed login helper")
        .1
        .split_once("\nint\nauthenticate_gmp (")
        .expect("manager-backed login helper boundary")
        .0;
    assert!(login_auth.contains(r#"<help format=\"XML\" type=\"brief\"/>"#));
}

#[test]
fn user_account_native_reads_are_redacted() {
    for sql in [
        user_accounts_sql("name ASC"),
        user_account_detail_sql().to_string(),
    ] {
        let lowered = sql.to_ascii_lowercase();
        for forbidden in [
            "password",
            "auth_cache",
            "hash",
            "method",
            "timezone",
            "credential",
            "token",
            "session",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "user native read SQL must not expose account/auth internals: {forbidden} in {sql}"
            );
        }
    }
}

#[test]
fn user_account_routes_are_direct_read_only_allowlisted() {
    for path in [
        "/api/v1/users",
        "/api/v1/users/12345678-1234-1234-1234-123456789abc",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "GET {path} must be direct-read allowlisted"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "GET {path} must be method-allowlisted without write control"
        );
        for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "{method} {path} must remain closed for account/auth safety"
            );
        }
    }
}

#[test]
fn user_account_openapi_declares_redacted_read_boundary() {
    for (path, replaces) in [
        ("/users", "user-redacted-list-read"),
        ("/users/{user_id}", "user-redacted-detail-read"),
    ] {
        let block = openapi_path_block(path);
        for required in [
            "x-yafvs-direct: true",
            "x-yafvs-exposure: direct-read",
            "x-yafvs-maturity: live-read",
            replaces,
        ] {
            assert!(block.contains(required), "{path} missing {required}");
        }
        assert!(!block.contains("x-yafvs-inherited-still-owns:"));
    }

    let tail = OPENAPI
        .split_once("    UserAccount:")
        .expect("UserAccount schema exists")
        .1;
    let schema = tail
        .lines()
        .take_while(|line| {
            !(line.starts_with("    ") && !line.starts_with("      ") && line.ends_with(':'))
        })
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["password", "hash", "method", "timezone", "auth"] {
        assert!(
            !schema.to_ascii_lowercase().contains(forbidden),
            "UserAccount schema must stay redacted: {forbidden}"
        );
    }
}
