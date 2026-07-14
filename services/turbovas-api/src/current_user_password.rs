// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    credential_write_validation::SensitiveBytes,
    errors::ApiError,
    gvmd_control::{
        ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response_bytes,
    },
};

pub(crate) const MAX_CURRENT_USER_PASSWORD_CHANGE_BODY_BYTES: usize = 32 * 1024;
const MAX_CURRENT_USER_PASSWORD_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentUserPasswordChangeRequest {
    old_password: SensitiveBytes,
    new_password: SensitiveBytes,
}

pub(crate) struct ValidatedCurrentUserPasswordChange {
    old_password: SensitiveBytes,
    new_password: SensitiveBytes,
}

pub(crate) async fn browser_proxy_change_current_user_password(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<CurrentUserPasswordChangeRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    let request =
        validate_current_user_password_change_request(parse_password_change_payload(payload)?)?;
    request_current_user_password_change(
        &gvmd_control_socket_path(),
        &gvmd_control_secret()?,
        &operator,
        &request,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_password_change_payload(
    payload: Result<Json<CurrentUserPasswordChangeRequest>, JsonRejection>,
) -> Result<CurrentUserPasswordChangeRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::RequestTooLarge
        } else {
            ApiError::BadRequest(
                "request body must be application/json matching CurrentUserPasswordChangeRequest"
                    .to_string(),
            )
        }
    })
}

pub(crate) fn validate_current_user_password_change_request(
    request: CurrentUserPasswordChangeRequest,
) -> Result<ValidatedCurrentUserPasswordChange, ApiError> {
    validate_password_field(&request.old_password, "old_password")?;
    validate_password_field(&request.new_password, "new_password")?;
    Ok(ValidatedCurrentUserPasswordChange {
        old_password: request.old_password,
        new_password: request.new_password,
    })
}

fn validate_password_field(value: &SensitiveBytes, field_name: &str) -> Result<(), ApiError> {
    let text = std::str::from_utf8(value.as_bytes()).map_err(|_| {
        ApiError::BadRequest(format!(
            "{field_name} must be non-empty text up to {MAX_CURRENT_USER_PASSWORD_BYTES} bytes without control characters"
        ))
    })?;
    if value.as_bytes().is_empty()
        || value.as_bytes().len() > MAX_CURRENT_USER_PASSWORD_BYTES
        || value.as_bytes().contains(&0)
        || text.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be non-empty text up to {MAX_CURRENT_USER_PASSWORD_BYTES} bytes without control characters"
        )));
    }
    Ok(())
}

async fn request_current_user_password_change(
    socket_path: &str,
    control_secret: &str,
    operator: &DirectApiOperator,
    request: &ValidatedCurrentUserPasswordChange,
) -> Result<(), ApiError> {
    let command = current_user_password_change_command(control_secret, operator, request);
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_current_user_password_change_response(&response)
}

pub(crate) fn current_user_password_change_command(
    control_secret: &str,
    operator: &DirectApiOperator,
    request: &ValidatedCurrentUserPasswordChange,
) -> ScrubbedControlFrame {
    let mut command = Vec::with_capacity(
        128 + control_secret.len()
            + operator.user_uuid().len()
            + encoded_len(request.old_password.as_bytes().len())
            + encoded_len(request.new_password.as_bytes().len()),
    );
    command.extend_from_slice(b"user-password-change ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(0x20);
    command.extend_from_slice(operator.user_uuid().as_bytes());
    command.push(0x20);
    append_base64(&mut command, request.old_password.as_bytes());
    command.push(0x20);
    append_base64(&mut command, request.new_password.as_bytes());
    command.push(0x0a);
    ScrubbedControlFrame::new(command)
}

fn encoded_len(value_len: usize) -> usize {
    value_len.div_ceil(3) * 4
}

fn append_base64(command: &mut Vec<u8>, value: &[u8]) {
    let start = command.len();
    command.resize(start + encoded_len(value.len()), 0);
    let written = STANDARD
        .encode_slice(value, &mut command[start..])
        .expect("preallocated base64 output must be sufficient");
    command.truncate(start + written);
}

pub(crate) fn parse_current_user_password_change_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 changed" => Ok(()),
        b"1 old_password_invalid" => Err(ApiError::OldPasswordInvalid),
        b"2 unsupported_auth_method" => Err(ApiError::UnsupportedAuthenticationMethod),
        b"3 new_password_rejected" => Err(ApiError::NewPasswordRejected),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The password-change control request was rejected.".to_string(),
        )),
        b"-1 internal" | _ => Err(ApiError::ControlFailure),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Method;
    use serde_json::json;

    use super::*;
    use crate::direct_api::direct_api_v1_method_is_allowed;

    const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OPERATOR_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn request(old_password: &str, new_password: &str) -> CurrentUserPasswordChangeRequest {
        serde_json::from_value(json!({
            "old_password": old_password,
            "new_password": new_password,
        }))
        .expect("test request must deserialize")
    }

    #[test]
    fn password_change_request_is_strict_bounded_and_secret_backed() {
        assert!(validate_current_user_password_change_request(request("old", "new")).is_ok());
        for (old_password, new_password) in [
            ("", "new"),
            ("old", ""),
            (&"o".repeat(MAX_CURRENT_USER_PASSWORD_BYTES + 1), "new"),
            ("old", &"n".repeat(MAX_CURRENT_USER_PASSWORD_BYTES + 1)),
            ("old\u{0000}", "new"),
            ("old", "new\npassword"),
        ] {
            assert!(
                validate_current_user_password_change_request(request(old_password, new_password))
                    .is_err()
            );
        }
        assert!(
            serde_json::from_value::<CurrentUserPasswordChangeRequest>(json!({
                "old_password": "old",
                "new_password": "new",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
            }))
            .is_err()
        );
    }

    #[test]
    fn password_change_control_frame_is_canonical_and_scrubbed() {
        let operator = DirectApiOperator::new(OPERATOR_UUID, None).unwrap();
        let request =
            validate_current_user_password_change_request(request("old password", "new password"))
                .unwrap();
        let frame = current_user_password_change_command(CONTROL_SECRET, &operator, &request);
        assert_eq!(
            frame.as_bytes(),
            format!(
                "user-password-change {CONTROL_SECRET} {OPERATOR_UUID} b2xkIHBhc3N3b3Jk bmV3IHBhc3N3b3Jk\n"
            )
            .as_bytes()
        );
    }

    #[test]
    fn password_change_response_mapping_is_exact_and_non_secret() {
        for (response, status, code) in [
            (
                b"1 old_password_invalid".as_slice(),
                StatusCode::FORBIDDEN,
                "old_password_invalid",
            ),
            (
                b"2 unsupported_auth_method",
                StatusCode::CONFLICT,
                "unsupported_auth_method",
            ),
            (
                b"3 new_password_rejected",
                StatusCode::BAD_REQUEST,
                "new_password_rejected",
            ),
            (b"99 forbidden", StatusCode::FORBIDDEN, "forbidden"),
            (b"-2 malformed", StatusCode::BAD_REQUEST, "bad_request"),
        ] {
            let error = parse_current_user_password_change_response(response).unwrap_err();
            assert_eq!(error.status_code(), status);
            assert_eq!(error.code(), code);
        }
        for response in [
            b"-1 internal".as_slice(),
            b"0 changed extra",
            b"unexpected",
            b"",
        ] {
            assert!(matches!(
                parse_current_user_password_change_response(response),
                Err(ApiError::ControlFailure)
            ));
        }
    }

    #[test]
    fn password_change_is_browser_proxy_only_and_resolves_current_operator() {
        let browser_routes = include_str!("browser_proxy_routes.rs");
        let direct_routes = include_str!("direct_api_routes.rs");
        let handler = include_str!("current_user_password.rs");
        assert!(browser_routes.contains("/api/v1/users/current/password"));
        assert!(browser_routes.contains("browser_proxy_change_current_user_password"));
        assert!(!direct_routes.contains("/api/v1/users/current/password"));
        assert!(!direct_api_v1_method_is_allowed(
            &Method::POST,
            "/api/v1/users/current/password",
            true,
        ));
        assert!(handler.contains("browser_proxy_operator_from_headers(&state, &auth, &headers)"));
        assert!(handler.contains("operator.user_uuid()"));
        assert!(handler.contains("ScrubbedControlFrame"));
    }

    #[test]
    fn gvmd_password_change_is_verified_atomic_and_cache_invalidating() {
        let control = include_str!("../../../components/gvmd/src/turbovas_control.c");
        let users = include_str!("../../../components/gvmd/src/manage_sql_users.c");

        for required in [
            "turbovas_control_parse_user_password_change_request",
            "turbovas_control_change_user_password",
            "current_user_change_password (request->old_password",
            "turbovas_control_user_password_change_request_clear",
        ] {
            assert!(
                control.contains(required),
                "gvmd control missing {required}"
            );
        }
        for required in [
            "sql_begin_immediate ()",
            "FOR UPDATE",
            "manage_authentication_verify (hash, old_password)",
            "set_password (current_credentials.username, current_credentials.uuid",
            "DELETE FROM auth_cache WHERE username = $1",
            "sql_commit ()",
            "sql_rollback ()",
        ] {
            assert!(
                users.contains(required),
                "gvmd password mutation missing {required}"
            );
        }
        assert!(!control.contains("request->old_password, \"password changed\""));
        assert!(!control.contains("request->new_password, \"password changed\""));
    }
}
