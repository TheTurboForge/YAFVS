// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, fs::File, io::Read};

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    auth::{
        DirectApiAuth, DirectApiOperator, MAX_DIRECT_API_BEARER_TOKEN_LENGTH, bearer_token_matches,
        direct_api_bearer_token_is_acceptable,
    },
    errors::ApiError,
    request_ids::{attach_request_id_header, request_id_from_headers},
    request_shapes::direct_api_request_shape_is_allowed,
};

const DIRECT_API_BIND_ENV: &str = "TURBOVAS_API_DIRECT_BIND";
const DIRECT_API_BEARER_TOKEN_ENV: &str = "TURBOVAS_API_BEARER_TOKEN";
const DIRECT_API_BEARER_TOKEN_FILE_ENV: &str = "TURBOVAS_API_BEARER_TOKEN_FILE";
const DIRECT_API_OPERATOR_UUID_ENV: &str = "TURBOVAS_API_OPERATOR_UUID";
const DIRECT_API_OPERATOR_NAME_ENV: &str = "TURBOVAS_API_OPERATOR_NAME";

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn direct_api_config() -> Result<Option<(String, DirectApiAuth)>, ApiError> {
    let Some(bind) = env_string(DIRECT_API_BIND_ENV) else {
        return Ok(None);
    };
    let token = direct_api_bearer_token()?;
    if !direct_api_bearer_token_is_acceptable(&token) {
        return Err(ApiError::Config);
    }
    let operator = direct_api_operator_from_sources(
        env_string(DIRECT_API_OPERATOR_UUID_ENV),
        env_string(DIRECT_API_OPERATOR_NAME_ENV),
    )?;
    Ok(Some((
        bind,
        DirectApiAuth::new(token).with_operator(operator),
    )))
}

fn direct_api_bearer_token() -> Result<String, ApiError> {
    direct_api_bearer_token_from_sources(
        env_string(DIRECT_API_BEARER_TOKEN_FILE_ENV),
        env_string(DIRECT_API_BEARER_TOKEN_ENV),
    )
}

fn direct_api_bearer_token_from_sources(
    token_file: Option<String>,
    token_env: Option<String>,
) -> Result<String, ApiError> {
    if let Some(path) = token_file {
        return read_direct_api_bearer_token_file(&path);
    }
    token_env.ok_or(ApiError::Config)
}

fn read_direct_api_bearer_token_file(path: &str) -> Result<String, ApiError> {
    let mut value = String::new();
    File::open(path)
        .map_err(|_| ApiError::Config)?
        .take((MAX_DIRECT_API_BEARER_TOKEN_LENGTH + 2) as u64)
        .read_to_string(&mut value)
        .map_err(|_| ApiError::Config)?;
    if value.len() > MAX_DIRECT_API_BEARER_TOKEN_LENGTH + 1 {
        return Err(ApiError::Config);
    }
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > MAX_DIRECT_API_BEARER_TOKEN_LENGTH {
        Err(ApiError::Config)
    } else {
        Ok(value)
    }
}

fn direct_api_operator_from_sources(
    operator_uuid: Option<String>,
    operator_name: Option<String>,
) -> Result<Option<DirectApiOperator>, ApiError> {
    match (operator_uuid, operator_name) {
        (Some(user_uuid), user_name) => DirectApiOperator::new(&user_uuid, user_name).map(Some),
        (None, Some(_)) => Err(ApiError::Config),
        (None, None) => Ok(None),
    }
}

pub(crate) async fn require_direct_api_auth(
    State(auth): State<DirectApiAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request_id_from_headers(request.headers());
    let method = request.method().clone();
    let path = direct_api_audit_path(request.uri()).to_string();
    let operator_uuid = auth.operator_uuid().unwrap_or("unbound");
    let api_path = path.starts_with("/api/v1/") || path == "/api/v1";
    let authenticated_api_path = api_path && bearer_token_matches(request.headers(), &auth.token);
    let mut audit_reason: Option<&'static str> = None;

    let mut response = if !api_path {
        next.run(request).await
    } else if authenticated_api_path {
        if !direct_api_v1_path_is_allowed(&path) {
            audit_reason = Some("route_not_allowlisted");
            ApiError::NotFound.into_response()
        } else if request.method() == Method::GET {
            if direct_api_request_shape_is_allowed(&request) {
                if let Some(_slot) = auth.try_acquire_request_slot() {
                    attach_direct_api_operator_extension(&mut request, &auth);
                    next.run(request).await
                } else {
                    audit_reason = Some("rate_limited");
                    ApiError::TooManyRequests.into_response()
                }
            } else {
                audit_reason = Some("request_shape_denied");
                ApiError::RequestTooLarge.into_response()
            }
        } else {
            audit_reason = Some("method_not_allowed");
            ApiError::MethodNotAllowed.into_response()
        }
    } else {
        tracing::warn!(request_id = %request_id, %method, path = %path, reason = "unauthorized", "direct native API bearer authentication failed");
        ApiError::Unauthorized.into_response()
    };

    let status = response.status();
    let audit_reason = audit_reason.unwrap_or_else(|| {
        if status.is_server_error() {
            "server_error"
        } else if status.is_client_error() {
            "handler_client_error"
        } else {
            "ok"
        }
    });
    if authenticated_api_path && status == StatusCode::TOO_MANY_REQUESTS {
        tracing::warn!(request_id = %request_id, %method, path = %path, status = status.as_u16(), reason = %audit_reason, operator_uuid = %operator_uuid, "direct native API request rejected by in-flight limit");
    } else if authenticated_api_path && status.is_server_error() {
        tracing::warn!(request_id = %request_id, %method, path = %path, status = status.as_u16(), reason = %audit_reason, operator_uuid = %operator_uuid, "direct native API request completed with server error");
    } else if authenticated_api_path {
        tracing::info!(request_id = %request_id, %method, path = %path, status = status.as_u16(), reason = %audit_reason, operator_uuid = %operator_uuid, "direct native API request completed");
    }
    attach_direct_api_security_headers(&mut response);
    attach_request_id_header(&mut response, &request_id);
    response
}

fn attach_direct_api_operator_extension(request: &mut Request, auth: &DirectApiAuth) {
    if let Some(operator) = auth.operator() {
        request.extensions_mut().insert(operator.clone());
    }
}

fn attach_direct_api_security_headers(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
}

fn direct_api_audit_path(uri: &Uri) -> &str {
    uri.path()
}

pub(crate) fn direct_api_v1_path_is_allowed(path: &str) -> bool {
    if direct_api_wildcard_detail_path_is_allowed(path) {
        return true;
    }
    let parts = path.split('/').collect::<Vec<_>>();
    matches!(
        parts.as_slice(),
        ["", "api", "v1", "results"]
            | ["", "api", "v1", "vulnerabilities"]
            | ["", "api", "v1", "cpes"]
            | ["", "api", "v1", "cves"]
            | ["", "api", "v1", "cert-bund-advisories"]
            | ["", "api", "v1", "dfn-cert-advisories"]
            | ["", "api", "v1", "nvts"]
            | ["", "api", "v1", "operating-systems"]
            | ["", "api", "v1", "hosts"]
            | ["", "api", "v1", "tls-certificates"]
            | ["", "api", "v1", "scanners"]
            | ["", "api", "v1", "scan-configs"]
            | ["", "api", "v1", "filters"]
            | ["", "api", "v1", "feeds"]
            | ["", "api", "v1", "alerts"]
            | ["", "api", "v1", "tags"]
            | ["", "api", "v1", "overrides"]
            | ["", "api", "v1", "port-lists"]
            | ["", "api", "v1", "schedules"]
            | ["", "api", "v1", "report-configs"]
            | ["", "api", "v1", "report-formats"]
            | ["", "api", "v1", "trashcan", "summary"]
            | ["", "api", "v1", "reports"]
            | ["", "api", "v1", "scopes"]
            | ["", "api", "v1", "targets"]
            | ["", "api", "v1", "tasks"]
            | ["", "api", "v1", "scope-reports"]
            | ["", "api", "v1", "results", _]
            | ["", "api", "v1", "cves", _]
            | ["", "api", "v1", "nvts", _]
            | ["", "api", "v1", "operating-systems", _]
            | ["", "api", "v1", "hosts", _]
            | ["", "api", "v1", "tls-certificates", _]
            | ["", "api", "v1", "scanners", _]
            | ["", "api", "v1", "scan-configs", _]
            | ["", "api", "v1", "filters", _]
            | ["", "api", "v1", "alerts", _]
            | ["", "api", "v1", "tags", _]
            | ["", "api", "v1", "overrides", _]
            | ["", "api", "v1", "port-lists", _]
            | ["", "api", "v1", "schedules", _]
            | ["", "api", "v1", "report-configs", _]
            | ["", "api", "v1", "report-formats", _]
            | ["", "api", "v1", "reports", _]
            | ["", "api", "v1", "reports", _, "results"]
            | ["", "api", "v1", "reports", _, "hosts"]
            | ["", "api", "v1", "reports", _, "ports"]
            | ["", "api", "v1", "reports", _, "applications"]
            | ["", "api", "v1", "reports", _, "operating-systems"]
            | ["", "api", "v1", "reports", _, "cves"]
            | ["", "api", "v1", "reports", _, "tls-certificates"]
            | ["", "api", "v1", "reports", _, "errors"]
            | ["", "api", "v1", "reports", _, "metrics"]
            | ["", "api", "v1", "scopes", _]
            | ["", "api", "v1", "targets", _]
            | ["", "api", "v1", "tasks", _]
            | ["", "api", "v1", "scope-reports", _]
            | ["", "api", "v1", "tags", _, "resources"]
            | ["", "api", "v1", "tags", "resource-names", _]
            | ["", "api", "v1", "scan-configs", _, "families"]
            if direct_api_segments_are_nonempty(&parts)
    ) || matches!(
        parts.as_slice(),
        ["", "api", "v1", "scopes", scope_id, "reports", scope_report_id, section]
            if direct_api_segments_are_nonempty(&parts)
                && matches!(
                    *section,
                    "results"
                        | "hosts"
                        | "ports"
                        | "applications"
                        | "operating-systems"
                        | "cves"
                        | "tls-certificates"
                        | "errors"
                        | "metrics"
                )
                && !scope_id.is_empty()
                && !scope_report_id.is_empty()
    )
}

fn direct_api_segments_are_nonempty(parts: &[&str]) -> bool {
    parts
        .iter()
        .skip(4)
        .all(|part| !part.is_empty() && *part != "." && *part != "..")
}

fn direct_api_wildcard_detail_path_is_allowed(path: &str) -> bool {
    [
        "/api/v1/cpes/",
        "/api/v1/cert-bund-advisories/",
        "/api/v1/dfn-cert-advisories/",
    ]
    .iter()
    .any(|prefix| {
        path.strip_prefix(prefix)
            .is_some_and(direct_api_wildcard_tail_is_allowed)
    })
}

fn direct_api_wildcard_tail_is_allowed(tail: &str) -> bool {
    !tail.is_empty()
        && tail
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
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
}
