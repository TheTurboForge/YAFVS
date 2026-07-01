// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::{
    credentials::{
        credential_asset_detail_sql, credential_assets_sql, credential_scanner_references_sql,
        credential_target_references_sql,
    },
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
};

const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");

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
fn credential_native_reads_do_not_select_secret_data_tables_or_values() {
    let list_sql = credential_assets_sql("name ASC");
    for sql in [
        list_sql.as_str(),
        credential_asset_detail_sql(),
        credential_target_references_sql(),
        credential_scanner_references_sql(),
    ] {
        let lowered = sql.to_ascii_lowercase();
        for forbidden in [
            "credentials_data",
            "credentials_trash_data",
            "credential_store_preferences",
            "credential_store_selectors",
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
fn credential_routes_are_direct_read_only_allowlisted() {
    for path in [
        "/api/v1/credentials",
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "GET {path} must be direct-read allowlisted"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "GET {path} must be method-allowlisted without write control"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::PATCH, path, true),
            "credential native reads must not accidentally allow write methods"
        );
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
    ] {
        let block = openapi_path_block(path);
        for required in [
            "x-turbovas-direct: true",
            "x-turbovas-exposure: direct-read",
            "x-turbovas-maturity: live-read",
            replaces,
            "credential-secrets-writes-and-deletes",
            "Credential secrets, credential-store secret selectors, export/download behavior, and all credential writes are intentionally excluded",
        ] {
            assert!(
                block.contains(required),
                "{path} OpenAPI block missing {required}"
            );
        }
    }
}
