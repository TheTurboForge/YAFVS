// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, fs::File, io::Read};

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, Uri, header},
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
    request_shapes::direct_api_request_shape_is_allowed_for_method,
};

#[cfg(test)]
use axum::http::Method;

pub(crate) use crate::direct_api_contract::{
    direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed,
};

const DIRECT_API_BIND_ENV: &str = "TURBOVAS_API_DIRECT_BIND";
const DIRECT_API_BEARER_TOKEN_ENV: &str = "TURBOVAS_API_BEARER_TOKEN";
const DIRECT_API_BEARER_TOKEN_FILE_ENV: &str = "TURBOVAS_API_BEARER_TOKEN_FILE";
const DIRECT_API_OPERATOR_UUID_ENV: &str = "TURBOVAS_API_OPERATOR_UUID";
const DIRECT_API_OPERATOR_NAME_ENV: &str = "TURBOVAS_API_OPERATOR_NAME";
const DIRECT_API_WRITE_CONTROL_ENV: &str = "TURBOVAS_API_DIRECT_WRITE_CONTROL";

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
    let write_control_enabled = direct_api_write_control_enabled()?;
    require_direct_api_write_control_operator(write_control_enabled, operator.as_ref())?;
    Ok(Some((
        bind,
        DirectApiAuth::new(token)
            .with_operator(operator)
            .with_write_control_enabled(write_control_enabled),
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

fn direct_api_write_control_enabled() -> Result<bool, ApiError> {
    direct_api_write_control_enabled_from_source(env_string(DIRECT_API_WRITE_CONTROL_ENV))
}

fn direct_api_write_control_enabled_from_source(value: Option<String>) -> Result<bool, ApiError> {
    let normalized = value.as_deref().map(str::to_ascii_lowercase);
    match normalized.as_deref() {
        None => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(_) => Err(ApiError::Config),
    }
}

fn require_direct_api_write_control_operator(
    write_control_enabled: bool,
    operator: Option<&DirectApiOperator>,
) -> Result<(), ApiError> {
    if write_control_enabled && operator.is_none() {
        Err(ApiError::Config)
    } else {
        Ok(())
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
        } else if direct_api_v1_method_is_allowed(&method, &path, auth.write_control_enabled()) {
            if direct_api_request_shape_is_allowed_for_method(&method, &request) {
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

#[cfg(test)]
#[path = "direct_api_tests.rs"]
mod direct_api_tests;
