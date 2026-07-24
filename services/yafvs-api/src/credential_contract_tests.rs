// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::{
    credential_query_sql::{
        credential_asset_detail_sql, credential_assets_sql, credential_certificate_sql,
        credential_scanner_references_sql, credential_target_references_sql,
    },
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
};

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const GSA_CREDENTIAL_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/credential.ts");
const GSA_CREDENTIALS_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/credentials.ts");
const GSA_NATIVE_CREDENTIALS: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/credentials.ts");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_NATIVE_API_C: &str = include_str!("../../../components/gsad/src/gsad_native_api.c");
const GSAD_GMP_HEADER: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVMD_GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GVMD_MANAGE_HEADER: &str = include_str!("../../../components/gvmd/src/manage.h");
const GVMD_MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");

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
fn credential_create_gsa_routes_only_manual_up_and_usk_to_native_api() {
    for required in [
        "createNativeCredential(this.http, {",
        "args.autogenerate !== true",
        "args.credentialType === USERNAME_PASSWORD_CREDENTIAL_TYPE",
        "args.credentialType === USERNAME_SSH_KEY_CREDENTIAL_TYPE",
        "type: USERNAME_PASSWORD_CREDENTIAL_TYPE",
        "type: USERNAME_SSH_KEY_CREDENTIAL_TYPE",
        "privateKey: args.privateKey ? await args.privateKey.text() : ''",
    ] {
        assert!(
            GSA_CREDENTIAL_COMMAND.contains(required),
            "manual UP/USK native creation marker is missing: {required}"
        );
    }
    let native_create = GSA_NATIVE_CREDENTIALS
        .split_once("export const createNativeCredential")
        .expect("native credential-create adapter")
        .1
        .split_once("export const cloneNativeCredential")
        .expect("native credential-create adapter boundary")
        .0;
    assert!(
        !native_create.contains("allow_insecure"),
        "manual browser creation must keep the native secure-use default"
    );
    for required in [
        "export const createNativeCredential",
        "'api/v1/credentials'",
        "action: 'create_credential'",
        "private_key: args.privateKey",
    ] {
        assert!(
            GSA_NATIVE_CREDENTIALS.contains(required),
            "native credential-create adapter marker is missing: {required}"
        );
    }

    let (create, _) = GSA_CREDENTIAL_COMMAND
        .split_once("async create(args: CredentialCommandCreateArgs)")
        .expect("credential create command")
        .1
        .split_once("  createKrb5(")
        .expect("credential create command boundary");
    assert!(
        create
            .contains("const baseData = this.createBase(args);\n    return this.action(baseData);"),
        "autogenerate and other credential types must retain inherited create_credential"
    );
    assert!(
        GSA_CREDENTIAL_COMMAND.contains("cmd: 'create_credential'"),
        "raw inherited CREATE_CREDENTIAL must remain for compatibility paths"
    );
}

#[test]
fn credential_live_delete_is_native_only() {
    assert!(GSA_CREDENTIAL_COMMAND.contains("deleteNativeCredential(this.http, id)"));
    assert!(!GSA_CREDENTIAL_COMMAND.contains("cmd: 'delete_credential'"));

    for retained in [
        "export class NativeCredentialBulkDeleteError",
        "async deleteByIds(ids: string[])",
        "await deleteNativeCredential(this.http, id)",
        "ids.slice(index)",
    ] {
        assert!(
            GSA_CREDENTIALS_COMMAND.contains(retained),
            "native credential bulk-delete contract is missing: {retained}"
        );
    }
    assert!(
        !GSA_CREDENTIALS_COMMAND.contains("cmd: 'bulk_delete'"),
        "credential bulk deletion must not fall back to raw GMP/XML"
    );

    for retired in ["delete_credential_gmp", "ELSE (delete_credential)"] {
        assert!(
            !GSAD_GMP_C.contains(retired),
            "retired gsad credential-delete transport remains: {retired}"
        );
        assert!(
            !GSAD_GMP_HEADER.contains(retired),
            "retired gsad credential-delete declaration remains: {retired}"
        );
    }
    assert!(
        !GSAD_VALIDATOR_C.contains("|(delete_credential)"),
        "retired credential-delete action remains accepted by gsad"
    );
    let bulk_delete = GSAD_GMP_C
        .split_once("bulk_delete_gmp (")
        .expect("bulk-delete handler must remain for other resource types")
        .1
        .split_once("/* Extra attributes */")
        .expect("bulk-delete credential guard boundary")
        .0;
    assert!(bulk_delete.contains("g_ascii_strcasecmp (type, \"credential\") == 0"));
    assert!(bulk_delete.contains("Credential deletion must use the native API"));
    let browser_delete_allowlist = GSAD_NATIVE_API_C
        .split_once("native_api_delete_path_is_allowed (")
        .expect("browser DELETE allowlist must exist")
        .1
        .split_once("native_api_post_path_is_allowed (")
        .expect("browser DELETE allowlist boundary must exist")
        .0;
    let credential_delete = browser_delete_allowlist
        .split_once("g_str_has_prefix (path, credential_prefix)")
        .expect("browser credential DELETE branch must exist")
        .1
        .split_once("g_str_has_prefix (path, scanner_prefix)")
        .expect("browser credential DELETE branch boundary must exist")
        .0;
    assert!(
        credential_delete.contains("is_uuid_segment (id, strlen (id))"),
        "browser proxy must allow canonical live credential DELETE"
    );
    assert!(
        credential_delete.contains("is_uuid_segment_with_suffix (id, trash_suffix)"),
        "browser proxy must retain canonical trash credential DELETE"
    );

    for retired in [
        "CLIENT_DELETE_CREDENTIAL",
        "delete_credential_data",
        "CASE_DELETE (CREDENTIAL",
    ] {
        assert!(
            !GVMD_GMP_C.contains(retired),
            "retired gvmd GMP credential-delete parser state remains: {retired}"
        );
    }
    for retired in ["\ndelete_credential ("] {
        assert!(
            !GVMD_MANAGE_SQL.contains(retired),
            "retired gvmd credential-delete writer/helper remains: {retired}"
        );
        assert!(
            !GVMD_MANAGE_HEADER.contains(retired),
            "retired gvmd credential-delete declaration remains: {retired}"
        );
    }
    for retained in ["\ncredential_in_use (", "\ntrash_credential_in_use ("] {
        assert!(
            GVMD_MANAGE_SQL.contains(retained),
            "credential GET in-use helper must remain: {retained}"
        );
        assert!(
            GVMD_MANAGE_HEADER.contains(retained.trim()),
            "credential GET in-use declaration must remain: {retained}"
        );
    }
    assert!(GVMD_GMP_C.contains("SEND_GET_COMMON (credential"));
    assert!(
        !GMP_SCHEMA.contains("<name>delete_credential</name>"),
        "retired raw GMP credential-delete command remains in the live schema"
    );

    assert!(GVMD_GMP_C.contains("CLIENT_GET_CREDENTIALS"));
    assert!(GMP_SCHEMA.contains("<name>get_credentials</name>"));
}

#[test]
fn credential_metadata_reads_and_browser_downloads_are_native_only() {
    for native_marker in [
        "fetchNativeCredential(this.http, id)",
        "exportNativeCredentialMetadata(this.http, id)",
        "fetchNativeCredentialCertificate(this.http, id)",
    ] {
        assert!(
            GSA_CREDENTIAL_COMMAND.contains(native_marker),
            "GSA credential command must retain native ownership: {native_marker}"
        );
    }

    for retired in [
        "get_credential_gmp",
        "get_credentials_gmp",
        "export_credential_gmp",
        "export_credentials_gmp",
    ] {
        assert!(
            !GSAD_GMP_C.contains(retired),
            "retired credential metadata alias remains in gsad C: {retired}"
        );
        assert!(
            !GSAD_GMP_HEADER.contains(retired),
            "retired credential metadata declaration remains: {retired}"
        );
    }
    for retired_dispatch in [
        "ELSE (get_credential)",
        "ELSE (get_credentials)",
        "ELSE (export_credential)",
        "ELSE (export_credentials)",
    ] {
        assert!(
            !GSAD_GMP_C.contains(retired_dispatch),
            "retired credential metadata dispatch remains: {retired_dispatch}"
        );
    }
    for retired_token in [
        "|(get_credential)",
        "|(get_credentials)",
        "|(export_credential)",
        "|(export_credentials)",
    ] {
        assert!(
            !GSAD_VALIDATOR_C.contains(retired_token),
            "retired credential metadata validator token remains: {retired_token}"
        );
    }

    for retired in ["download_credential_gmp", "ELSE (download_credential)"] {
        assert!(
            !GSAD_GMP_C.contains(retired),
            "retired credential-download transport remains in gsad C: {retired}"
        );
    }
    assert!(!GSAD_GMP_C.contains("content_type_from_format_string"));
    assert!(!GSAD_GMP_HEADER.contains("download_credential_gmp"));
    assert!(!GSAD_VALIDATOR_C.contains("|(download_credential)"));
    assert!(!GSAD_VALIDATOR_C.contains("\"package_format\""));
    assert!(GVMD_GMP_C.contains("CLIENT_GET_CREDENTIALS"));
    assert!(GMP_SCHEMA.contains("<name>get_credentials</name>"));

    assert!(
        GSA_CREDENTIAL_COMMAND.contains("if (format === 'key')"),
        "GSA must route SSH public-key download through the native API unconditionally"
    );
    assert!(
        !GSA_CREDENTIAL_COMMAND.contains("format === 'key' && canUseNativeApi"),
        "GSA must not fall back to inherited KEY transport"
    );
    let inherited_get = GVMD_GMP_C
        .split_once("handle_get_credentials (")
        .expect("retained credential metadata handler")
        .1
        .split_once("handle_get_nvts (")
        .expect("credential metadata handler boundary")
        .0;
    for retired in [
        "get_credentials_data->format",
        "credential_iterator_formats_xml",
        "CREDENTIAL_FORMAT_KEY",
        "CREDENTIAL_FORMAT_PEM",
        "\"<certificate>%s</certificate>\"",
        "\"<public_key>%s</public_key>\"",
    ] {
        assert!(
            !inherited_get.contains(retired),
            "retired inherited credential download response remains: {retired}"
        );
    }
    for retired in [
        "credential_format_t",
        "credential_iterator_format_available",
        "credential_iterator_formats_xml",
    ] {
        assert!(
            !GVMD_MANAGE_HEADER.contains(retired),
            "retired credential format declaration remains: {retired}"
        );
        assert!(
            !GVMD_MANAGE_SQL.contains(retired),
            "retired credential format helper remains: {retired}"
        );
    }
    let get_credentials_schema = GMP_SCHEMA
        .split_once("<name>get_credentials</name>")
        .expect("retained get_credentials schema")
        .1
        .split_once("</command>")
        .expect("get_credentials schema boundary")
        .0;
    for retired in [
        "<name>format</name>",
        "<name>formats</name>",
        "<name>public_key</name>",
        "<name>package</name>",
        "<name>certificate</name>",
        "<formats>",
    ] {
        assert!(
            !get_credentials_schema.contains(retired),
            "retired credential download schema remains: {retired}"
        );
    }
    assert!(
        !GSA_CREDENTIAL_COMMAND.contains("cmd: 'download_credential'"),
        "GSA client-certificate download must fail closed without a GMP fallback"
    );
}

#[test]
fn credential_clone_uses_native_secret_opaque_contract() {
    assert!(GSA_CREDENTIAL_COMMAND.contains("async clone({id}: EntityCommandParams)"));
    assert!(GSA_CREDENTIAL_COMMAND.contains("return cloneNativeCredential(this.http, id)"));
    assert!(!GSA_CREDENTIAL_COMMAND.contains("cmd: 'clone'"));
    assert!(GSA_NATIVE_CREDENTIALS.contains("api/v1/credentials/"));
    assert!(GSA_NATIVE_CREDENTIALS.contains("/clone"));
    assert!(!GSAD_GMP_C.contains("\nclone_gmp ("));
    assert!(!GSAD_GMP_C.contains("ELSE (clone)"));
    assert!(!GSAD_GMP_C.contains("<create_credential><copy>"));
    assert!(!GSAD_VALIDATOR_C.contains("|(clone)"));
    assert!(!GVMD_MANAGE_SQL.contains("copy_credential ("));
    assert!(!GVMD_GMP_C.contains("CLIENT_CREATE_CREDENTIAL_COPY"));
    assert!(GVMD_GMP_C.contains("copy_requested"));
    assert!(GVMD_GMP_C.contains(
        "create_credential_data->copy_requested = 1;\n            set_read_over (gmp_parser);"
    ));
    assert!(GVMD_GMP_C.contains("Credential copy is no longer supported"));
    let credential_end = GVMD_GMP_C
        .split_once(
            "case CLIENT_CREATE_CREDENTIAL:\n        {\n          credential_t new_credential;",
        )
        .expect("credential end handler")
        .1
        .split_once("create_credential_data_reset (create_credential_data);")
        .expect("credential end handler boundary")
        .0;
    assert!(
        credential_end
            .find("copy_requested")
            .expect("copy tombstone")
            < credential_end
                .find("strlen (create_credential_data->name)")
                .expect("normal create validation"),
        "retired copy requests must be rejected before normal credential creation"
    );
    let create_credential_schema = GMP_SCHEMA
        .split_once("<name>create_credential</name>")
        .expect("create_credential schema")
        .1
        .split_once("</command>")
        .expect("create_credential schema boundary")
        .0;
    assert!(!create_credential_schema.contains("<e>copy</e>"));
    assert!(!create_credential_schema.contains("<name>copy</name>"));

    let path = "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/clone";
    assert!(!direct_api_v1_method_is_allowed(&Method::POST, path, false));
    assert!(direct_api_v1_method_is_allowed(&Method::POST, path, true));
    let block = openapi_path_block("/credentials/{credential_id}/clone");
    for required in [
        "operationId: postCredentialsByCredentialIdClone",
        "x-yafvs-replaces: credential-clone",
        "x-yafvs-owner-semantics: request-operator-owner",
        "x-yafvs-side-effect: secret-opaque-clone",
        "encrypted credential data rows",
        "response contains redacted metadata only",
    ] {
        assert!(
            block.contains(required),
            "credential clone block missing {required}"
        );
    }
}

#[test]
fn browser_credential_handlers_omit_allow_insecure_while_raw_gmp_support_remains() {
    let create = GSAD_GMP_C
        .split_once("create_credential_gmp (")
        .expect("browser credential-create handler")
        .1
        .split_once("save_credential_gmp (")
        .expect("browser credential-create handler boundary")
        .0;
    let save = GSAD_GMP_C
        .split_once("save_credential_gmp (")
        .expect("browser credential-save handler")
        .1
        .split_once("\n/**")
        .expect("browser credential-save handler boundary")
        .0;
    for (handler, source) in [("create", create), ("save", save)] {
        assert!(
            !source.contains("<allow_insecure>"),
            "browser credential {handler} handler must not silently emit allow_insecure"
        );
    }

    for command in ["create_credential", "modify_credential"] {
        let schema = GMP_SCHEMA
            .split_once(&format!("<name>{command}</name>"))
            .expect("retained raw GMP credential command")
            .1
            .split_once("</command>")
            .expect("raw GMP credential command boundary")
            .0;
        assert!(
            schema.contains("<o><e>allow_insecure</e></o>"),
            "raw GMP {command} compatibility schema must retain explicit allow_insecure"
        );
    }
    for parser_marker in [
        "APPEND (CLIENT_CREATE_CREDENTIAL_ALLOW_INSECURE,",
        "APPEND (CLIENT_MODIFY_CREDENTIAL_ALLOW_INSECURE,",
    ] {
        assert!(
            GVMD_GMP_C.contains(parser_marker),
            "raw gvmd/GMP parser must retain explicit compatibility marker: {parser_marker}"
        );
    }
    for sql_marker in [
        "const char* given_type, const char* allow_insecure,",
        "const char* allow_insecure)",
        "UPDATE credentials SET allow_insecure = 1",
        "UPDATE credentials SET allow_insecure = 0",
    ] {
        assert!(
            GVMD_MANAGE_SQL.contains(sql_marker),
            "manage_sql must retain explicit raw compatibility support: {sql_marker}"
        );
    }
}

#[test]
fn credential_list_supports_exact_type_filter_and_redacted_smb_proof() {
    let sql = credential_assets_sql("name ASC");
    assert!(sql.contains("credential_type = $4"));
    assert!(sql.contains("AND ($4 = '' OR credential_rows.credential_type = $4)"));
    assert!(sql.contains("u.uuid AS owner_id"));
    assert!(sql.contains("AS smb_compatible"));
    assert!(sql.contains("SELECT count(*)"));
    assert!(sql.contains("cd.type = 'username') = 1"));
    assert!(sql.contains("cd.type = 'username'"));
    assert!(sql.contains("cd.value <> ''"));
    assert!(sql.contains("strpos(cd.value, '@') = 0"));
    assert!(sql.contains("strpos(cd.value, ':') = 0"));
}

#[test]
fn credential_openapi_documents_redacted_smb_preflight_proof() {
    let schema = OPENAPI
        .split_once("    CredentialAsset:")
        .expect("credential asset schema")
        .1
        .split_once("    UserAccountCollection:")
        .expect("next schema")
        .0;
    for required in [
        "required: [id, name, owner_id, owner, credential_type, smb_compatible",
        "owner_id:",
        "format: uuid",
        "type: [string, 'null']",
        "smb_compatible:",
        "The login and all other secret material remain write-only.",
    ] {
        assert!(
            schema.contains(required),
            "credential schema missing {required}"
        );
    }
    for forbidden in ["username:", "password:", "private_key:"] {
        assert!(
            !schema.contains(forbidden),
            "credential read schema must not expose {forbidden}"
        );
    }
}

#[test]
fn credential_native_reads_do_not_return_secret_data_or_values() {
    let list_sql = credential_assets_sql("name ASC");
    for sql in [list_sql.as_str(), credential_asset_detail_sql()] {
        let lowered = sql.to_ascii_lowercase();
        assert!(lowered.contains("from credentials_data cd"));
        assert!(lowered.contains("as smb_compatible"));
        for forbidden in [
            "cd.value as",
            "select cd.value",
            "password",
            "private_key",
            "community",
            "secret",
            "vault_id",
            "host_identifier",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "credential native read SQL must derive compatibility without returning secret-bearing data: {forbidden} in {sql}"
            );
        }
    }

    for sql in [
        credential_target_references_sql(),
        credential_scanner_references_sql(),
    ] {
        let lowered = sql.to_ascii_lowercase();
        for forbidden in [
            "credentials_data",
            "credentials_trash_data",
            " value",
            ".value",
            "password",
            "private_key",
            "community",
            "secret",
            "vault_id",
            "host_identifier",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "credential native read SQL must not expose or select secret-bearing data: {forbidden} in {sql}"
            );
        }
    }
}

#[test]
fn credential_payload_exposes_only_redacted_smb_preflight_fields() {
    let payloads = include_str!("credential_payloads.rs");
    for required in ["owner_id: Option<String>", "smb_compatible: bool"] {
        assert!(payloads.contains(required), "missing {required}");
    }
    for forbidden in ["username:", "password:", "secret:"] {
        assert!(
            !payloads.contains(forbidden),
            "credential payload must not expose {forbidden}"
        );
    }
}

#[test]
fn credential_openapi_documents_exact_type_filter() {
    let block = openapi_path_block("/credentials");
    assert!(block.contains("name: credential_type"));
    assert!(block.contains("Optional exact credential type filter"));
}

#[test]
fn credential_routes_are_direct_read_and_bounded_create_allowlisted() {
    let list_path = "/api/v1/credentials";
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        list_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        list_path,
        true
    ));
    for path in [
        "/api/v1/credentials",
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc",
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/export",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "GET {path} must be direct-read allowlisted"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "GET {path} must be method-allowlisted without write control"
        );
        let patch_allowed = direct_api_v1_method_is_allowed(&Method::PATCH, path, true);
        if path == "/api/v1/credentials/12345678-1234-1234-1234-123456789abc" {
            assert!(
                patch_allowed,
                "credential detail PATCH must be direct write-control allowlisted"
            );
        } else {
            assert!(
                !patch_allowed,
                "credential non-detail PATCH must remain closed"
            );
        }
    }
}

#[test]
fn credential_openapi_declares_redacted_read_boundary() {
    for (path, replaces) in [
        ("/credentials", "credential-redacted-metadata-list-read"),
        (
            "/credentials/{credential_id}",
            "credential-redacted-metadata-detail-read",
        ),
        (
            "/credentials/{credential_id}/export",
            "credential-redacted-metadata-export-read",
        ),
    ] {
        let block = openapi_path_block(path);
        for required in [
            "x-yafvs-direct: true",
            "x-yafvs-exposure: direct-read",
            "x-yafvs-maturity: live-read",
            replaces,
            "credential-secret-updates-non-up-usk-types-allow-insecure-and-link-mutations",
            "secret",
        ] {
            assert!(
                block.contains(required),
                "{path} OpenAPI block missing {required}"
            );
        }
    }
}

#[test]
fn credential_create_openapi_is_write_only_secret_bearing_and_redacted_on_response() {
    let block = openapi_path_block("/credentials");
    for required in [
        "    post:",
        "operationId: postCredentials",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: credential-up-usk-create",
        "x-yafvs-owner-semantics: request-operator-owner",
        "x-yafvs-side-effect: credential-secret-control",
        "CredentialCreateRequest",
        "response contains redacted metadata only",
    ] {
        assert!(
            block.contains(required),
            "credential create missing {required}"
        );
    }
    let schema = OPENAPI
        .split_once("    CredentialCreateRequest:")
        .expect("credential create schema")
        .1
        .split_once("    ScannerPatchRequest:")
        .expect("next schema")
        .0;
    for secret in ["password:", "passphrase:", "private_key:"] {
        let property = schema.split_once(secret).expect("secret property").1;
        assert!(property.contains("writeOnly: true"));
    }
}

#[test]
fn credential_patch_route_is_direct_write_control_metadata_only() {
    let path = "/api/v1/credentials/12345678-1234-1234-1234-123456789abc";
    assert!(
        !direct_api_v1_method_is_allowed(&Method::PATCH, path, false),
        "credential PATCH must be denied without direct write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::PATCH, path, true),
        "credential PATCH must be direct write-control allowlisted"
    );

    let block = openapi_path_block("/credentials/{credential_id}");
    for required in [
        "    patch:",
        "operationId: patchCredentialsByCredentialId",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: credential-metadata-modify",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-owner-semantics: preserve-existing-owner",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: metadata-write",
        "CredentialPatchRequest",
        "SSH public-key and stored client-certificate retrieval are native. Secret updates, allow_insecure mutation, credential type changes, and target/scanner link mutation remain on inherited compatibility paths; clone, live trash move, restore, and permanent trash deletion are separately native.",
    ] {
        assert!(
            block.contains(required),
            "credential patch block missing {required}"
        );
    }
}

#[test]
fn credential_delete_route_and_openapi_define_native_secret_opaque_trash_move() {
    let path = "/api/v1/credentials/12345678-1234-1234-1234-123456789abc";
    assert!(
        !direct_api_v1_method_is_allowed(&Method::DELETE, path, false),
        "credential DELETE must be denied without direct write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::DELETE, path, true),
        "credential DELETE must be direct write-control allowlisted"
    );

    let block = openapi_path_block("/credentials/{credential_id}");
    for required in [
        "    delete:",
        "operationId: deleteCredentialsByCredentialId",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: credential-live-move-to-trash",
        "x-yafvs-inherited-still-owns: credential-secret-updates-non-up-usk-types-allow-insecure-and-link-mutations",
        "x-yafvs-owner-semantics: preserve-existing-owner",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: secret-opaque-trash-move",
        "allow-insecure state",
        "opaque encrypted secret-data rows",
        "'204':",
    ] {
        assert!(
            block.contains(required),
            "credential delete block missing {required}"
        );
    }
}

#[test]
fn credential_public_key_openapi_declares_bounded_native_binary_read() {
    let block = openapi_path_block("/credentials/{credential_id}/public-key");
    for required in [
        "operationId: getCredentialsByCredentialIdPublicKey",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-replaces: credential-ssh-public-key-download-read",
        "x-yafvs-inherited-still-owns: credential-secret-updates-non-up-usk-types-allow-insecure-and-link-mutations",
        "application/key:",
        "format: binary",
        "Content-Disposition:",
        "Content-Length:",
        "Cache-Control:",
        "X-Content-Type-Options:",
        "'502':",
    ] {
        assert!(
            block.contains(required),
            "credential public-key OpenAPI block missing {required}"
        );
    }
}

#[test]
fn credential_certificate_query_and_openapi_are_bounded_native_binary_read() {
    let sql = credential_certificate_sql();
    for required in [
        "WITH matching AS",
        "SELECT cd.value",
        "JOIN credentials_data cd ON cd.credential = c.id",
        "WHERE c.uuid = $1",
        "c.type = 'cc'",
        "cd.type = 'certificate'",
        "SELECT value AS certificate",
        "octet_length(value) BETWEEN 1 AND $2",
        "(SELECT count(*) FROM matching) = 1",
    ] {
        assert!(
            sql.contains(required),
            "credential certificate SQL missing {required}"
        );
    }
    for forbidden in ["private_key", "password", "passphrase", "secret", "LIMIT 1"] {
        assert!(
            !sql.contains(forbidden),
            "credential certificate SQL must reject duplicate rows and avoid secret fields: {forbidden}"
        );
    }

    let block = openapi_path_block("/credentials/{credential_id}/certificate");
    for required in [
        "operationId: getCredentialsByCredentialIdCertificate",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-replaces: credential-client-certificate-download-read",
        "application/octet-stream:",
        "format: binary",
        "Content-Disposition:",
        "Content-Length:",
        "Cache-Control:",
        "X-Content-Type-Options:",
        "private-key-bearing",
        "'502':",
    ] {
        assert!(
            block.contains(required),
            "credential certificate OpenAPI block missing {required}"
        );
    }
}
