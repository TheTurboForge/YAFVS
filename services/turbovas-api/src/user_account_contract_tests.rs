// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::{
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
    user_account_query_sql::{user_account_detail_sql, user_accounts_sql},
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
            "x-turbovas-direct: true",
            "x-turbovas-exposure: direct-read",
            "x-turbovas-maturity: live-read",
            replaces,
            "account-auth-management",
        ] {
            assert!(block.contains(required), "{path} missing {required}");
        }
    }

    let tail = OPENAPI
        .split_once("    UserAccount:")
        .expect("UserAccount schema exists")
        .1;
    let schema = tail
        .lines()
        .take_while(|line| !line.starts_with("    ScanConfigAssetCollection:"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["password", "hash", "method", "timezone", "auth"] {
        assert!(
            !schema.to_ascii_lowercase().contains(forbidden),
            "UserAccount schema must stay redacted: {forbidden}"
        );
    }
}
