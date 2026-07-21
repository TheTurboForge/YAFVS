// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::{
    credential_query_sql::{
        credential_asset_detail_sql, credential_assets_sql, credential_scanner_references_sql,
        credential_target_references_sql,
    },
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
};

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");

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
fn credential_list_supports_exact_type_filter_and_redacted_smb_proof() {
    let sql = credential_assets_sql("name ASC");
    assert!(sql.contains("credential_type = $4"));
    assert!(sql.contains("AND ($4 = '' OR credential_type = $4)"));
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
            "credential-secret-updates-non-up-usk-types-and-deletes",
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
        "Secret updates, allow_insecure, credential type changes, target/scanner links, export, download, clone, restore, and delete remain on inherited compatibility paths.",
    ] {
        assert!(
            block.contains(required),
            "credential patch block missing {required}"
        );
    }
}
