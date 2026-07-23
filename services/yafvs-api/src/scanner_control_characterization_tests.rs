// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;
use std::path::{Path, PathBuf};

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const MANAGE_C: &str = include_str!("../../../components/gvmd/src/manage.c");
const MANAGE_COMMANDS_C: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_CONFIGS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_configs.c");
const MANAGE_H: &str = include_str!("../../../components/gvmd/src/manage.h");
const MANAGE_OSP_C: &str = include_str!("../../../components/gvmd/src/manage_osp.c");
const MANAGE_OSP_H: &str = include_str!("../../../components/gvmd/src/manage_osp.h");
const GVMD_C: &str = include_str!("../../../components/gvmd/src/gvmd.c");
const GVMD_CMAKE: &str = include_str!("../../../components/gvmd/src/CMakeLists.txt");
const GVMD_MANPAGE_XML: &str = include_str!("../../../components/gvmd/docs/gvmd.8.xml");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GSA_SCANNER_TS: &str = include_str!("../../../components/gsa/src/gmp/commands/scanner.ts");
const GSA_CAPABILITIES_TS: &str =
    include_str!("../../../components/gsa/src/gmp/capabilities/capabilities.ts");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const SCANNER_WRITE_SQL: &str = include_str!("scanner_write_sql.rs");
const SCANNER_WRITE_VALIDATION: &str = include_str!("scanner_write_validation.rs");

fn repository_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

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
fn automatic_scanner_relay_options_modules_and_subprocess_path_stay_deleted() {
    for retired in [
        "\"relay-mapper\"",
        "\"relays-path\"",
        "relay_mapper",
        "relays_path",
        "set_relays_path",
    ] {
        assert!(!GVMD_C.contains(retired), "gvmd still contains {retired}");
    }

    for retired in [
        "relay_mapper_path",
        "get_relay_mapper_path",
        "set_relay_mapper_path",
        "get_relay_info_entity",
        "slave_get_relay",
        "slave_relay_connection",
        "sync_scanner_relays",
        "scanner_relays_update_time",
        "update_all_scanner_relays",
    ] {
        assert!(
            !MANAGE_C.contains(retired)
                && !MANAGE_H.contains(retired)
                && !MANAGE_SQL_C.contains(retired),
            "manager sources still contain {retired}"
        );
    }

    for retired in [
        "use_relay_mapper",
        "osp_scanner_mapped_relay_connect",
        "slave_get_relay",
    ] {
        assert!(
            !MANAGE_OSP_C.contains(retired) && !MANAGE_OSP_H.contains(retired),
            "OSP connection path still contains {retired}"
        );
    }

    for module in [
        "manage_scanner_relays",
        "manage_sql_scanner_relays",
        "manage-scanner-relays",
    ] {
        assert!(
            !GVMD_CMAKE.contains(module),
            "gvmd build still includes {module}"
        );
    }
    for relative in [
        "components/gvmd/src/manage_scanner_relays.c",
        "components/gvmd/src/manage_scanner_relays.h",
        "components/gvmd/src/manage_scanner_relays_tests.c",
        "components/gvmd/src/manage_sql_scanner_relays.c",
        "components/gvmd/src/manage_sql_scanner_relays.h",
    ] {
        assert!(
            !repository_path(relative).exists(),
            "deleted automatic-relay module returned: {relative}"
        );
    }
    for retired in ["--relay-mapper", "--relays-path"] {
        assert!(
            !GVMD_MANPAGE_XML.contains(retired),
            "gvmd manpage still advertises {retired}"
        );
    }
    assert!(
        !OPENAPI.contains("external relay-file synchronization"),
        "OpenAPI still claims deleted relay-file synchronization is inherited"
    );
    assert!(
        OPENAPI.contains("Remote TLS/relay verification remains inherited."),
        "OpenAPI lost the retained remote verification boundary"
    );
}

#[test]
fn explicit_native_relay_fields_and_direct_osp_connections_remain() {
    for required in [
        "relay_host, relay_port",
        "relay_host = $9",
        "relay_port = $10",
    ] {
        assert!(
            SCANNER_WRITE_SQL.contains(required),
            "native scanner SQL missing {required}"
        );
    }
    for required in [
        "normalize_scanner_text_value(relay_host, \"relay_host\")",
        "relay_port must be 0 when relay_host is empty",
        "relay_port must be 0 for a Unix socket relay",
        "relay_port must be between 1 and 65535 for a network relay",
    ] {
        assert!(
            SCANNER_WRITE_VALIDATION.contains(required),
            "native scanner relay validation missing {required}"
        );
    }

    let has_relay = inherited_function(MANAGE_SQL_C, "scanner_has_relay");
    assert!(has_relay.contains("coalesce (relay_host, '') != ''"));
    let from_scanner = inherited_function(MANAGE_OSP_C, "osp_connect_data_from_scanner");
    for required in [
        "has_relay = scanner_has_relay (scanner)",
        "scanner_host (scanner, has_relay)",
        "scanner_port (scanner, has_relay)",
        "conn_data->port = 0",
        "conn_data->ca_pub = NULL",
    ] {
        assert!(
            from_scanner.contains(required),
            "scanner OSP connection data missing {required}"
        );
    }

    let from_iterator = inherited_function(MANAGE_OSP_C, "osp_connect_data_from_scanner_iterator");
    for required in [
        "scanner_iterator_relay_host (iterator)",
        "scanner_iterator_relay_port (iterator)",
        "scanner_iterator_host (iterator)",
        "scanner_iterator_port (iterator)",
    ] {
        assert!(
            from_iterator.contains(required),
            "scanner iterator connection data missing {required}"
        );
    }

    let connect = inherited_function(MANAGE_OSP_C, "osp_connect_with_data");
    let normalized_connect = connect.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_connect.contains(
        "osp_connection_new (conn_data->host, conn_data->port, conn_data->ca_pub, conn_data->key_pub, conn_data->key_priv)"
    ));
    assert!(connect.contains("Could not connect to Scanner at %s"));
    assert!(connect.contains("Could not connect to Scanner at %s:%d"));
}

#[test]
fn retired_cli_and_protocol_scanner_commands_stay_absent_while_verify_remains() {
    for retired in [
        "--create-scanner",
        "--modify-scanner",
        "--delete-scanner",
        "--get-scanners",
        "--scanner-ca-pub",
        "--scanner-credential",
        "--scanner-host",
        "--scanner-key-priv",
        "--scanner-key-pub",
        "--scanner-name",
        "--scanner-port",
        "--scanner-relay-host",
        "--scanner-relay-port",
        "--scanner-type",
        "--no-default-certs",
        "manage_create_scanner",
        "manage_modify_scanner",
        "manage_delete_scanner",
        "manage_get_scanners",
    ] {
        assert!(
            !GVMD_C.contains(retired),
            "gvmd CLI still exposes {retired}"
        );
    }
    for retired in [
        "manage_create_scanner (",
        "manage_modify_scanner (",
        "manage_delete_scanner (",
        "manage_get_scanners (",
        "create_scanner (",
        "modify_scanner (",
        "delete_scanner (",
        "insert_scanner (",
    ] {
        assert!(
            !MANAGE_H.contains(retired),
            "manage.h still declares {retired}"
        );
        assert!(
            !MANAGE_SQL_C.contains(retired),
            "manage_sql.c still defines or calls {retired}"
        );
    }
    assert!(GVMD_C.contains("\"verify-scanner\""));
    assert!(GVMD_C.contains("manage_verify_scanner ("));
    assert!(MANAGE_H.contains("manage_verify_scanner ("));
    assert!(MANAGE_H.contains("verify_scanner ("));
    assert!(MANAGE_SQL_C.contains("manage_verify_scanner ("));
    assert!(MANAGE_SQL_C.contains("verify_scanner ("));
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
fn scanner_read_permission_vocabulary_remains_for_internal_authorization() {
    assert!(MANAGE_C.contains("check_available (\"scanner\", scanner, \"get_scanners\")"));
    assert!(MANAGE_SQL_C.contains("array_add (permissions, g_strdup (\"get_scanners\"))"));
    assert!(
        MANAGE_SQL_CONFIGS_C
            .contains("find_scanner_with_permission (scanner_id, &scanner, \"get_scanners\")")
    );
    assert!(GSA_CAPABILITIES_TS.contains("'get_scanners'"));
}

#[test]
fn retired_browser_gmp_scanner_commands_stay_absent_while_verify_remains() {
    for retired in [
        "create_scanner_gmp",
        "save_scanner_gmp",
        "delete_scanner_gmp",
        "verify_scanner_gmp",
        "get_scanner_gmp",
        "get_scanners_gmp",
        "export_scanner_gmp",
        "export_scanners_gmp",
        "ELSE (create_scanner)",
        "ELSE (save_scanner)",
        "ELSE (delete_scanner)",
        "ELSE (get_scanner)",
        "ELSE (get_scanners)",
        "ELSE (export_scanner)",
        "ELSE (export_scanners)",
        "CLIENT_CREATE_SCANNER",
        "CLIENT_MODIFY_SCANNER",
        "CLIENT_DELETE_SCANNER",
        "CLIENT_VERIFY_SCANNER",
        "CLIENT_GET_SCANNERS",
        "<name>create_scanner</name>",
        "<name>modify_scanner</name>",
        "<name>delete_scanner</name>",
        "<name>verify_scanner</name>",
        "<name>get_scanners</name>",
    ] {
        assert!(
            !GSAD_GMP_C.contains(retired),
            "gsad still exposes {retired}"
        );
        assert!(
            !GMP_C.contains(retired),
            "GMP parser still exposes {retired}"
        );
        assert!(
            !GMP_SCHEMA.contains(retired),
            "GMP schema still exposes {retired}"
        );
    }
    for retired in [
        "{\"CREATE_SCANNER\"",
        "{\"DELETE_SCANNER\"",
        "{\"GET_SCANNERS\"",
        "{\"MODIFY_SCANNER\"",
        "{\"VERIFY_SCANNER\"",
    ] {
        assert!(
            !MANAGE_COMMANDS_C.contains(retired),
            "GMP help still advertises {retired}"
        );
    }
    for retired in [
        "|(create_scanner)",
        "|(save_scanner)",
        "|(delete_scanner)",
        "|(verify_scanner)",
        "|(get_scanner)",
        "|(get_scanners)",
        "|(export_scanner)",
        "|(export_scanners)",
    ] {
        assert!(
            !GSAD_VALIDATOR_C.contains(retired),
            "validator still accepts {retired}"
        );
    }
    for retired in [
        "super.clone({id})",
        "super.delete({id})",
        "cmd: 'verify_scanner'",
        "httpGetWithTransform",
        "getElementFromRoot",
    ] {
        assert!(
            !GSA_SCANNER_TS.contains(retired),
            "GSA scanner command still has inherited fallback {retired}"
        );
    }

    assert!(!GSAD_GMP_C.contains("get_trash_scanners_gmp"));
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
    for method in [Method::POST, Method::PUT] {
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
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/scanners/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    for (method, action) in [
        (Method::POST, "clone"),
        (Method::POST, "restore"),
        (Method::DELETE, "trash"),
    ] {
        let path = format!("/api/v1/scanners/12345678-1234-1234-1234-123456789abc/{action}");
        assert!(!direct_api_v1_path_is_allowed(&path));
        assert!(direct_api_v1_method_is_allowed(&method, &path, true));
        assert!(!direct_api_v1_method_is_allowed(&method, &path, false));
    }
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
    for action in ["download"] {
        let path = format!("/api/v1/scanners/12345678-1234-1234-1234-123456789abc/{action}");
        assert!(
            !direct_api_v1_path_is_allowed(&path),
            "{path} must not be direct allowlisted yet"
        );
    }
}

#[test]
fn openapi_documents_complete_native_scanner_lifecycle_and_verify_boundary() {
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
        "Relay configuration is validated and stored",
    ] {
        assert!(
            list.contains(required),
            "scanner create docs missing {required}"
        );
    }

    let detail = openapi_path_block("/scanners/{scanner_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("x-yafvs-exposure: direct-read"));
    assert!(detail.contains("x-yafvs-exposure: direct-write"));
    assert!(!detail.contains("x-yafvs-inherited-still-owns: remote-scanner-certificate-context-control-credentials-writes-downloads-and-deletes"));
    assert!(detail.contains("Native direct write-control owns create, clone"));
    for residual in [
        "Credential secrets, credential certificate metadata",
        "remote/TLS/relay verification",
        "inherited file export/download formats remain inherited",
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
    ] {
        assert!(
            replace.contains(required),
            "scanner replace docs missing {required}"
        );
    }
    let normalized_replace = replace.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "without contacting or verifying it",
        "not referenced by a live non-hidden task",
        "In-use scanners return conflict",
        "Relay configuration is fully replaced",
    ] {
        assert!(
            normalized_replace.contains(required),
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

    for (path, operation) in [
        (
            "/scanners/{scanner_id}/clone",
            "operationId: postScannersByScannerIdClone",
        ),
        (
            "/scanners/{scanner_id}/restore",
            "operationId: postScannersByScannerIdRestore",
        ),
        (
            "/scanners/{scanner_id}/trash",
            "operationId: deleteScannersByScannerIdTrash",
        ),
    ] {
        let block = openapi_path_block(path);
        assert!(block.contains(operation), "{path} missing {operation}");
        assert!(block.contains("x-yafvs-exposure: direct-write"));
        assert!(block.contains("x-yafvs-safety-contract: write-control-v1"));
    }
}
