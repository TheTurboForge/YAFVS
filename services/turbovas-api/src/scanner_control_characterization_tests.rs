// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
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
fn inherited_create_scanner_couples_metadata_host_relay_ca_and_credentials() {
    let create = inherited_function(MANAGE_SQL_C, "create_scanner");
    for required in [
        "acl_user_may (\"create_scanner\") == 0",
        "resource_with_name_exists (name, \"scanner\", 0)",
        "scanner_type_valid (itype) == 0",
        "check_scanner_feature (",
        "SCANNER_FEATURE_OPENVASD_DISABLED",
        "scanner_type_supports_unix_sockets (itype)",
        "gvm_get_host_type (host) == -1",
        "get_single_relay_from_file (itype",
        "CREATE_SCANNER_INVALID_RELAY_PORT",
        "find_credential_with_permission",
        "SELECT type != 'cc' FROM credentials",
        "UPDATE scanners SET credential = %llu WHERE id = %llu;",
        "sql_commit ();",
    ] {
        assert!(
            create.contains(required),
            "create_scanner missing {required}"
        );
    }
}

#[test]
fn inherited_modify_scanner_revalidates_connectivity_fields_and_secret_links() {
    let modify = inherited_function(MANAGE_SQL_C, "modify_scanner");
    for required in [
        "acl_user_may (\"modify_scanner\") == 0",
        "find_scanner_with_permission (scanner_id, &scanner, \"modify_scanner\")",
        "scanner_type_valid (itype) == 0",
        "check_scanner_feature (",
        "scanner_type_supports_unix_sockets (itype)",
        "gvm_get_host_type (used_host) == -1",
        "MODIFY_SCANNER_INVALID_RELAY_HOST",
        "find_credential_with_permission (credential_id, &credential",
        "SELECT type != 'cc' FROM credentials WHERE id = %llu;",
        "resource_with_name_exists (name, \"scanner\", scanner)",
        "UPDATE scanners SET name = %s, comment = %s, type = %d,",
        "UPDATE scanners SET ca_pub = '%s' WHERE id = %llu;",
        "UPDATE scanners SET credential = %llu WHERE id = %llu;",
        "UPDATE scanners SET credential = NULL WHERE id = %llu;",
    ] {
        assert!(
            modify.contains(required),
            "modify_scanner missing {required}"
        );
    }
}

#[test]
fn inherited_delete_scanner_has_predefined_in_use_trash_and_tag_permission_semantics() {
    let delete = inherited_function(MANAGE_SQL_C, "delete_scanner");
    for required in [
        "acl_user_may (\"delete_scanner\") == 0",
        "strcmp (scanner_id, SCANNER_UUID_CVE) == 0",
        "strcmp (scanner_id, SCANNER_UUID_DEFAULT) == 0",
        "find_scanner_with_permission (scanner_id, &scanner, \"delete_scanner\")",
        "find_trash (\"scanner\", scanner_id, &scanner)",
        "WHERE scanner = %llu",
        "LOCATION_TABLE",
        "INSERT INTO scanners_trash",
        "UPDATE tasks",
        "permissions_set_locations (\"scanner\"",
        "tags_set_locations (\"scanner\"",
        "permissions_set_orphans (\"scanner\"",
        "tags_remove_resource (\"scanner\"",
        "DELETE FROM scanners WHERE id = %llu;",
    ] {
        assert!(
            delete.contains(required),
            "delete_scanner missing {required}"
        );
    }
}

#[test]
fn inherited_verify_scanner_can_contact_osp_scanners_and_maps_other_types() {
    let verify = inherited_function(MANAGE_SQL_C, "verify_scanner");
    for required in [
        "acl_user_may (\"verify_scanner\") == 0",
        "init_scanner_iterator (&scanner, &get)",
        "scanner_iterator_type (&scanner) == SCANNER_TYPE_OPENVAS",
        "scanner_iterator_type (&scanner) == SCANNER_TYPE_OSP_SENSOR",
        "osp_get_version_from_iterator",
        "SCANNER_TYPE_OPENVASD",
        "SCANNER_TYPE_OPENVASD_SENSOR",
        "SCANNER_TYPE_CVE",
        "g_strdup (\"GVM/\" GVMD_VERSION)",
    ] {
        assert!(
            verify.contains(required),
            "verify_scanner missing {required}"
        );
    }
}

#[test]
fn inherited_gsad_and_gmp_layers_proxy_scanner_control_and_secret_fields() {
    let create = inherited_function(GSAD_GMP_C, "create_scanner_gmp");
    for required in [
        "params_value (params, \"scanner_host\")",
        "params_value (params, \"scanner_type\")",
        "params_value (params, \"ca_pub\")",
        "params_value (params, \"credential_id\")",
        "<create_scanner>",
        "<ca_pub>%s</ca_pub>",
        r#"<credential id=\"%s\"/>"#,
    ] {
        assert!(
            create.contains(required),
            "create_scanner_gmp missing {required}"
        );
    }

    let modify = inherited_function(GSAD_GMP_C, "save_scanner_gmp");
    for required in [
        r#"<modify_scanner scanner_id=\"%s\">"#,
        "<host>%s</host>",
        "<port>%s</port>",
        "<type>%s</type>",
        "<ca_pub>%s</ca_pub>",
        r#"<credential id=\"%s\"/>"#,
    ] {
        assert!(
            modify.contains(required),
            "save_scanner_gmp missing {required}"
        );
    }

    let delete = inherited_function(GSAD_GMP_C, "delete_scanner_gmp");
    assert!(delete.contains("move_resource_to_trash (connection, \"scanner\""));
    let verify = inherited_function(GSAD_GMP_C, "verify_scanner_gmp");
    assert!(verify.contains(r#"<verify_scanner scanner_id=\"%s\"/>"#));

    for command in [
        "|(create_scanner)",
        "|(delete_scanner)",
        "|(get_scanner)",
        "|(get_scanners)",
        "|(verify_scanner)",
    ] {
        assert!(
            GSAD_VALIDATOR_C.contains(command),
            "validator missing {command}"
        );
    }

    for state in [
        "CLIENT_CREATE_SCANNER",
        "CLIENT_MODIFY_SCANNER",
        "CLIENT_DELETE_SCANNER",
        "CLIENT_VERIFY_SCANNER",
    ] {
        assert!(GMP_C.contains(state), "GMP parser missing {state}");
    }
}

#[test]
fn native_direct_api_keeps_scanner_control_methods_closed_until_contract_lands() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/scanners",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/export",
        false,
    ));
    for method in [Method::POST, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/scanners", true),
            "{method} /api/v1/scanners must remain closed"
        );
    }
    for method in [Method::POST, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/scanners/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/scanners/{{id}} must remain closed"
        );
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/export",
                true,
            ),
            "{method} /api/v1/scanners/{{id}}/export must remain closed"
        );
    }
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    for action in ["verify", "download", "trash"] {
        let path = format!("/api/v1/scanners/12345678-1234-1234-1234-123456789abc/{action}");
        assert!(
            !direct_api_v1_path_is_allowed(&path),
            "{path} must not be direct allowlisted yet"
        );
    }
}

#[test]
fn openapi_documents_scanners_as_read_only_until_control_contract_lands() {
    let list = openapi_path_block("/scanners");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(!list.contains("x-turbovas-inherited-still-owns:"));
    assert!(list.contains(
        "Credential secrets, scanner CA material, and control operations are intentionally excluded"
    ));

    let detail = openapi_path_block("/scanners/{scanner_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(!detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(!detail.contains("x-turbovas-inherited-still-owns: remote-scanner-certificate-context-control-credentials-writes-downloads-and-deletes"));
    assert!(
        detail.contains("Native direct write-control can patch scanner name/comment metadata only")
    );
    for residual in [
        "Credential secrets, credential certificate metadata",
        "live scanner status, verify/control operations",
        "host/port/type/relay mutation",
        "export/download behavior, create, clone, restore, and delete remain inherited",
    ] {
        assert!(detail.contains(residual), "detail docs missing {residual}");
    }

    let export = openapi_path_block("/scanners/{scanner_id}/export");
    for required in [
        "get:",
        "operationId: getScannersByScannerIdExport",
        "x-turbovas-direct: true",
        "x-turbovas-exposure: direct-read",
        "x-turbovas-maturity: live-read",
        "x-turbovas-replaces: scanner-metadata-export-read",
        "$ref: '#/components/schemas/ScannerAssetDetail'",
        "including scanner CA public certificate text when present",
        "Credential secrets, credential certificate metadata",
        "verify/control operations",
    ] {
        assert!(
            export.contains(required),
            "scanner metadata export OpenAPI block missing {required}"
        );
    }
    assert!(!export.contains("x-turbovas-inherited-still-owns: remote-scanner-certificate-context-control-credentials-writes-downloads-and-deletes"));
    for forbidden in [
        "x-turbovas-exposure: direct-write",
        "x-turbovas-safety-contract: write-control-v1",
        "\n    post:",
        "\n    patch:",
        "\n    delete:",
    ] {
        assert!(
            !export.contains(forbidden),
            "scanner metadata export must not expose inherited control/download/write behavior: {forbidden}"
        );
    }
}
