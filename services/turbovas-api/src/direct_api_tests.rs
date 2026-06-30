// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
fn token_file(name: &str, value: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = env::temp_dir().join(format!("turbovas-direct-token-{name}-{nonce}"));
    fs::write(&path, value).expect("write direct token fixture");
    path.to_string_lossy().into_owned()
}
#[test]
fn direct_api_audit_path_omits_query_string() {
    let uri: Uri = "/api/v1/reports?page_size=1&token=secret-like"
        .parse()
        .unwrap();
    assert_eq!(direct_api_audit_path(&uri), "/api/v1/reports");
}
#[test]
fn direct_api_audit_logs_do_not_include_auth_material() {
    let source = include_str!("direct_api.rs");
    let audit_block = source
        .split_once("pub(crate) async fn require_direct_api_auth")
        .expect("direct API auth middleware must exist")
        .1
        .split_once("fn direct_api_audit_path")
        .expect("audit path helper must follow auth middleware")
        .0;
    let tracing_lines = audit_block
        .lines()
        .filter(|line| line.contains("tracing::"))
        .collect::<Vec<_>>();
    assert!(tracing_lines.len() >= 3, "expected direct API audit logs");
    for line in tracing_lines {
        let fields = line
            .split_once('"')
            .map(|(fields, _message)| fields)
            .unwrap_or(line);
        let lower = fields.to_ascii_lowercase();
        assert!(
            !lower.contains("authorization")
                && !lower.contains("bearer")
                && !lower.contains("token")
                && !lower.contains("header"),
            "direct API audit log fields must not include auth material: {line}"
        );
    }
}
#[test]
fn direct_api_audit_logs_include_structured_reason_field() {
    let source = include_str!("direct_api.rs");
    let audit_block = source
        .split_once("pub(crate) async fn require_direct_api_auth")
        .expect("direct API auth middleware must exist")
        .1
        .split_once("fn direct_api_audit_path")
        .expect("audit path helper must follow auth middleware")
        .0;
    let tracing_lines = audit_block
        .lines()
        .filter(|line| line.contains("tracing::"))
        .collect::<Vec<_>>();
    assert!(tracing_lines.len() >= 4, "expected direct API audit logs");
    for line in tracing_lines {
        assert!(
            line.contains("reason ="),
            "direct API audit logs should include a structured reason field: {line}"
        );
    }
    for reason in [
        "route_not_allowlisted",
        "method_not_allowed",
        "request_shape_denied",
        "rate_limited",
        "handler_client_error",
        "server_error",
        "unauthorized",
        "ok",
    ] {
        assert!(
            audit_block.contains(reason),
            "direct API audit reason {reason} should be present"
        );
    }
}
#[test]
fn direct_api_security_headers_are_attached() {
    let mut response = ApiError::Unauthorized.into_response();
    attach_direct_api_security_headers(&mut response);
    let headers = response.headers();
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
}
#[test]
fn direct_api_auth_slots_enforce_in_flight_cap_and_release_on_drop() {
    let auth = DirectApiAuth::with_max_in_flight_requests(
        "token-0123456789abcdef0123456789abcdef".to_string(),
        1,
    );
    let first = auth
        .try_acquire_request_slot()
        .expect("first direct request slot should be available");
    assert!(auth.try_acquire_request_slot().is_none());
    drop(first);
    assert!(auth.try_acquire_request_slot().is_some());
}
#[test]
fn direct_api_operator_extension_is_attached_only_when_configured() {
    let operator = DirectApiOperator::new(
        "12345678-1234-1234-1234-123456789abc",
        Some("admin".to_string()),
    )
    .expect("valid operator identity");
    let auth = DirectApiAuth::new("token-0123456789abcdef0123456789abcdef".to_string())
        .with_operator(Some(operator.clone()));
    let mut request = Request::builder()
        .uri("/api/v1/reports")
        .body(axum::body::Body::empty())
        .expect("request fixture");
    attach_direct_api_operator_extension(&mut request, &auth);
    assert_eq!(
        request.extensions().get::<DirectApiOperator>(),
        Some(&operator)
    );
    let unbound_auth = DirectApiAuth::new("token-0123456789abcdef0123456789abcdef".to_string());
    let mut unbound_request = Request::builder()
        .uri("/api/v1/reports")
        .body(axum::body::Body::empty())
        .expect("request fixture");
    attach_direct_api_operator_extension(&mut unbound_request, &unbound_auth);
    assert!(
        unbound_request
            .extensions()
            .get::<DirectApiOperator>()
            .is_none()
    );
}
#[test]
fn direct_api_bearer_token_prefers_file_source() {
    let path = token_file("preferred", "file-token-0123456789abcdef0123456789abcdef\n");
    let token = direct_api_bearer_token_from_sources(
        Some(path.clone()),
        Some("env-token-0123456789abcdef0123456789abcdef".to_string()),
    )
    .expect("file token should load");
    fs::remove_file(path).ok();
    assert_eq!(token, "file-token-0123456789abcdef0123456789abcdef");
}
#[test]
fn direct_api_bearer_token_keeps_environment_fallback() {
    let token = direct_api_bearer_token_from_sources(
        None,
        Some("env-token-0123456789abcdef0123456789abcdef".to_string()),
    )
    .expect("environment token should load");
    assert_eq!(token, "env-token-0123456789abcdef0123456789abcdef");
}
#[test]
fn direct_api_operator_requires_uuid_before_name() {
    let operator = direct_api_operator_from_sources(
        Some("12345678-1234-1234-1234-123456789abc".to_string()),
        Some("admin".to_string()),
    )
    .expect("operator should parse")
    .expect("operator should be present");
    assert_eq!(operator.user_uuid(), "12345678-1234-1234-1234-123456789abc");
    assert_eq!(operator.user_name(), Some("admin"));
    assert!(
        direct_api_operator_from_sources(None, None)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        direct_api_operator_from_sources(None, Some("admin".to_string())),
        Err(ApiError::Config)
    ));
    assert!(matches!(
        direct_api_operator_from_sources(Some("not-a-uuid".to_string()), None),
        Err(ApiError::Config)
    ));
}
#[test]
fn direct_api_write_control_requires_configured_operator() {
    let operator = direct_api_operator_from_sources(
        Some("12345678-1234-1234-1234-123456789abc".to_string()),
        Some("admin".to_string()),
    )
    .expect("operator should parse");
    assert!(require_direct_api_write_control_operator(false, None).is_ok());
    assert!(require_direct_api_write_control_operator(true, operator.as_ref()).is_ok());
    assert!(matches!(
        require_direct_api_write_control_operator(true, None),
        Err(ApiError::Config)
    ));
}
#[test]
fn direct_api_write_control_flag_is_strict_boolean() {
    assert!(!direct_api_write_control_enabled_from_source(None).expect("default false"));
    for value in ["1", "true", "TRUE", "yes", "on"] {
        assert!(
            direct_api_write_control_enabled_from_source(Some(value.to_string()))
                .expect("truthy value")
        );
    }
    for value in ["0", "false", "FALSE", "no", "off"] {
        assert!(
            !direct_api_write_control_enabled_from_source(Some(value.to_string()))
                .expect("false value")
        );
    }
    assert!(matches!(
        direct_api_write_control_enabled_from_source(Some("maybe".to_string())),
        Err(ApiError::Config)
    ));
}
#[test]
fn direct_api_path_classifier_uses_positive_scriptable_allowlist() {
    assert!(direct_api_v1_path_is_allowed("/api/v1/reports"));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/reports/report-id/results"
    ));
    assert!(direct_api_v1_path_is_allowed("/api/v1/feeds"));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/tags/resource-names/alert"
    ));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/cpes/cpe:/a:example:thing/1.0"
    ));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes///"));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes/."));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes/.."));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes/foo/../bar"));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/reports/."));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/reports/.."));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/tags/tag-id/.."));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/cert-bund-advisories/.."
    ));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/scopes/scope-id/reports/report-id/metrics"
    ));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/scopes/./reports/report-id/metrics"
    ));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/scopes/scope-id/reports/../metrics"
    ));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/scope-reports/scope-report-id"
    ));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/scopes/scope-id/reports/report-id/retention-plan"
    ));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/scopes//reports/report-id/results"
    ));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/reports//results"));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/scopes/scope-id/reports/scope-report-id"
    ));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/internal-preview"));
    assert!(!direct_api_v1_path_is_allowed("/api/v1/reports/id/raw-xml"));
}
#[test]
fn direct_api_method_classifier_gates_scope_writes_on_write_control_flag() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/scopes",
        false
    ));
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/scopes", false),
            "{method} should stay closed while direct write-control is disabled"
        );
    }
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scopes",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scopes/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/scopes/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PUT,
        "/api/v1/scopes/scope-id",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/internal-preview",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scopes",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scopes/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/scopes/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PUT,
        "/api/v1/scopes/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scopes/../",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scopes/not-a-uuid",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tags/not-a-uuid",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc/resources",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags/not-a-uuid/resources",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/report-configs",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/report-configs",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/report-configs/not-a-uuid",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/report-configs/not-a-uuid",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/port-lists/not-a-uuid",
        true
    ));
}
#[test]
fn direct_api_bearer_token_rejects_empty_file_source() {
    let path = token_file("empty", "\n");
    let result = direct_api_bearer_token_from_sources(
        Some(path.clone()),
        Some("env-token-0123456789abcdef0123456789abcdef".to_string()),
    );
    fs::remove_file(path).ok();
    assert!(matches!(result, Err(ApiError::Config)));
}
#[test]
fn direct_api_bearer_token_rejects_oversized_file_source() {
    let path = token_file(
        "oversized",
        &"A".repeat(MAX_DIRECT_API_BEARER_TOKEN_LENGTH + 2),
    );
    let result = direct_api_bearer_token_from_sources(
        Some(path.clone()),
        Some("env-token-0123456789abcdef0123456789abcdef".to_string()),
    );
    fs::remove_file(path).ok();
    assert!(matches!(result, Err(ApiError::Config)));
}
#[test]
fn direct_api_bearer_token_accepts_maximum_file_source_with_newline() {
    let value = "A".repeat(MAX_DIRECT_API_BEARER_TOKEN_LENGTH);
    let path = token_file("maximum", &format!("{value}\n"));
    let token = direct_api_bearer_token_from_sources(Some(path.clone()), None)
        .expect("maximum token with trailing newline should load");
    fs::remove_file(path).ok();
    assert_eq!(token, value);
}
