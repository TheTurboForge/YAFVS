// SPDX-FileCopyrightText: 2026 TurboVAS contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, fs};

use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    auth::{DirectApiAuth, bearer_token_matches, direct_api_bearer_token_is_acceptable},
    errors::ApiError,
    request_ids::{attach_request_id_header, request_id_from_headers},
    request_shapes::direct_api_request_shape_is_allowed,
};

const DIRECT_API_BIND_ENV: &str = "TURBOVAS_API_DIRECT_BIND";
const DIRECT_API_BEARER_TOKEN_ENV: &str = "TURBOVAS_API_BEARER_TOKEN";
const DIRECT_API_BEARER_TOKEN_FILE_ENV: &str = "TURBOVAS_API_BEARER_TOKEN_FILE";

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
    Ok(Some((bind, DirectApiAuth { token })))
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
        return fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(|_| ApiError::Config)
            .and_then(|value| {
                if value.is_empty() {
                    Err(ApiError::Config)
                } else {
                    Ok(value)
                }
            });
    }
    token_env.ok_or(ApiError::Config)
}

pub(crate) async fn require_direct_api_auth(
    State(auth): State<DirectApiAuth>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request_id_from_headers(request.headers());
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let api_path = path.starts_with("/api/v1/") || path == "/api/v1";

    let mut response = if !api_path {
        next.run(request).await
    } else if bearer_token_matches(request.headers(), &auth.token) {
        if !direct_api_v1_path_is_allowed(&path) {
            ApiError::NotFound.into_response()
        } else if request.method() == Method::GET {
            if direct_api_request_shape_is_allowed(&request) {
                next.run(request).await
            } else {
                ApiError::RequestTooLarge.into_response()
            }
        } else {
            ApiError::MethodNotAllowed.into_response()
        }
    } else {
        tracing::warn!(request_id = %request_id, %method, path = %path, "direct native API bearer authentication failed");
        ApiError::Unauthorized.into_response()
    };

    let status = response.status();
    if status.is_server_error() {
        tracing::warn!(request_id = %request_id, %method, path = %path, status = status.as_u16(), "direct native API request completed with server error");
    }
    attach_request_id_header(&mut response, &request_id);
    response
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
    parts.iter().skip(4).all(|part| !part.is_empty())
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
    fn direct_api_bearer_token_rejects_empty_file_source() {
        let path = token_file("empty", "\n");
        let result = direct_api_bearer_token_from_sources(
            Some(path.clone()),
            Some("env-token-0123456789abcdef0123456789abcdef".to_string()),
        );
        fs::remove_file(path).ok();
        assert!(matches!(result, Err(ApiError::Config)));
    }
}
