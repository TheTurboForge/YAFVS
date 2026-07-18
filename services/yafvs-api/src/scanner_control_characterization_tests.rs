// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
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
fn native_direct_api_gates_scanner_configuration_metadata_and_verify_controls() {
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
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scanners",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scanners",
        false
    ));
    for method in [Method::DELETE, Method::PUT] {
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
    let replace_configuration =
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/replace-configuration";
    assert!(!direct_api_v1_path_is_allowed(replace_configuration));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        replace_configuration,
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        replace_configuration,
        false,
    ));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/verify"
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/verify",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc/verify",
        false,
    ));
    for action in ["download", "trash"] {
        let path = format!("/api/v1/scanners/12345678-1234-1234-1234-123456789abc/{action}");
        assert!(
            !direct_api_v1_path_is_allowed(&path),
            "{path} must not be direct allowlisted yet"
        );
    }
}

#[test]
fn openapi_documents_scanner_configuration_metadata_and_verify_control_boundary() {
    let list = openapi_path_block("/scanners");
    assert!(list.contains("get:"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-yafvs-exposure: direct-read"));
    assert!(list.contains("x-yafvs-exposure: direct-write"));
    assert!(!list.contains("x-yafvs-inherited-still-owns:"));
    for required in [
        "operationId: postScanners",
        "x-yafvs-replaces: scanner-create",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-owner-semantics: request-operator-owner",
        "x-yafvs-safety-contract: write-control-v1",
        "$ref: '#/components/schemas/ScannerConfigurationRequest'",
        "'201':",
        "Location:",
        "without contacting or verifying the scanner",
        "Relay configuration is initialized empty",
    ] {
        assert!(
            list.contains(required),
            "scanner create docs missing {required}"
        );
    }

    let detail = openapi_path_block("/scanners/{scanner_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(!detail.contains("delete:"));
    assert!(detail.contains("x-yafvs-exposure: direct-read"));
    assert!(detail.contains("x-yafvs-exposure: direct-write"));
    assert!(!detail.contains("x-yafvs-inherited-still-owns: remote-scanner-certificate-context-control-credentials-writes-downloads-and-deletes"));
    assert!(
        detail.contains("Native direct write-control can create scanners, replace complete retained editor configuration, patch name/comment metadata, and verify bounded local scanner availability")
    );
    for residual in [
        "Credential secrets, credential certificate metadata",
        "remote/TLS/relay verification",
        "relay mutation",
        "inherited export/download formats, clone, restore, and delete remain inherited",
    ] {
        assert!(detail.contains(residual), "detail docs missing {residual}");
    }

    let replace = openapi_path_block("/scanners/{scanner_id}/replace-configuration");
    for required in [
        "post:",
        "operationId: postScannersByScannerIdReplaceConfiguration",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: scanner-complete-retained-editor-configuration-modify",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-owner-semantics: preserve-existing-owner",
        "x-yafvs-safety-contract: write-control-v1",
        "$ref: '#/components/schemas/ScannerConfigurationRequest'",
        "$ref: '#/components/schemas/ScannerAssetDetail'",
        "without contacting or verifying it",
        "not referenced by a live non-hidden task",
        "In-use scanners return conflict",
        "Existing relay host and relay port are preserved",
    ] {
        assert!(
            replace.contains(required),
            "scanner replace docs missing {required}"
        );
    }
    for forbidden in ["\n    get:", "\n    patch:", "\n    delete:"] {
        assert!(
            !replace.contains(forbidden),
            "scanner replace must not expose extra methods: {forbidden}"
        );
    }

    let verify = openapi_path_block("/scanners/{scanner_id}/verify");
    for required in [
        "post:",
        "operationId: postScannersByScannerIdVerify",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-inherited-still-owns: remote-scanner-tls-relay-verification",
        "x-yafvs-maturity: live-control",
        "x-yafvs-replaces: scanner-verify",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-owner-semantics: no-owner-state",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: scanner-control",
        "$ref: '#/components/schemas/ScannerVerifyResult'",
        "local Unix-socket OSP scanners",
        "Remote, TLS, TCP, relay",
    ] {
        assert!(
            verify.contains(required),
            "scanner verify OpenAPI block missing {required}"
        );
    }
    for forbidden in ["\n    get:", "\n    patch:", "\n    delete:"] {
        assert!(
            !verify.contains(forbidden),
            "scanner verify must not expose extra methods: {forbidden}"
        );
    }

    let export = openapi_path_block("/scanners/{scanner_id}/export");
    for required in [
        "get:",
        "operationId: getScannersByScannerIdExport",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-maturity: live-read",
        "x-yafvs-replaces: scanner-metadata-export-read",
        "$ref: '#/components/schemas/ScannerAssetDetail'",
        "including scanner CA public certificate text when present",
        "Credential secrets, credential certificate metadata",
        "remote/TLS/relay verification",
    ] {
        assert!(
            export.contains(required),
            "scanner metadata export OpenAPI block missing {required}"
        );
    }
    assert!(!export.contains("x-yafvs-inherited-still-owns: remote-scanner-certificate-context-control-credentials-writes-downloads-and-deletes"));
    for forbidden in [
        "x-yafvs-exposure: direct-write",
        "x-yafvs-safety-contract: write-control-v1",
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
