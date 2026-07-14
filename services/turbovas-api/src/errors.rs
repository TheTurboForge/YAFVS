// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    code: String,
    message: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("old password is invalid")]
    OldPasswordInvalid,
    #[error("authentication method does not support password changes")]
    UnsupportedAuthenticationMethod,
    #[error("new password was rejected")]
    NewPasswordRejected,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("request too large")]
    RequestTooLarge,
    #[error("report PDF is too large")]
    ReportPdfTooLarge,
    #[error("too many requests")]
    TooManyRequests,
    #[error("{0}")]
    BadRequest(String),
    #[error("resource not found")]
    NotFound,
    #[error("conflict")]
    Conflict(String),
    #[error("database error")]
    Database,
    #[error("configuration error")]
    Config,
    #[error("task stop requested but scanner absence is unverified")]
    TaskStopRequested,
    #[error("scanner control failed and scanner absence is unverified")]
    ScannerUnverified,
    #[error("control service failure")]
    ControlFailure,
    #[error("control service unavailable")]
    ControlUnavailable,
    #[error("mutation committed but response completion failed")]
    MutationCommittedResponseUnavailable,
    #[error("mutation outcome is indeterminate")]
    MutationOutcomeIndeterminate,
}

impl ApiError {
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::OldPasswordInvalid => StatusCode::FORBIDDEN,
            Self::UnsupportedAuthenticationMethod => StatusCode::CONFLICT,
            Self::NewPasswordRejected => StatusCode::BAD_REQUEST,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ReportPdfTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database | Self::Config => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TaskStopRequested => StatusCode::CONFLICT,
            Self::ScannerUnverified => StatusCode::BAD_GATEWAY,
            Self::ControlFailure => StatusCode::BAD_GATEWAY,
            Self::ControlUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::MutationCommittedResponseUnavailable => StatusCode::BAD_GATEWAY,
            Self::MutationOutcomeIndeterminate => StatusCode::BAD_GATEWAY,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::OldPasswordInvalid => "old_password_invalid",
            Self::UnsupportedAuthenticationMethod => "unsupported_auth_method",
            Self::NewPasswordRejected => "new_password_rejected",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestTooLarge => "request_too_large",
            Self::ReportPdfTooLarge => "report_pdf_too_large",
            Self::TooManyRequests => "too_many_requests",
            Self::BadRequest(_) => "bad_request",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Database => "database_error",
            Self::Config => "configuration_error",
            Self::TaskStopRequested => "stop_requested",
            Self::ScannerUnverified => "scanner_unverified",
            Self::ControlFailure => "control_failure",
            Self::ControlUnavailable => "control_unavailable",
            Self::MutationCommittedResponseUnavailable => "committed_response_unavailable",
            Self::MutationOutcomeIndeterminate => "mutation_outcome_indeterminate",
        }
    }

    pub(crate) fn public_message(&self) -> String {
        match self {
            Self::Unauthorized => "A valid bearer token is required.".to_string(),
            Self::Forbidden => {
                "The authenticated operator is not allowed to perform this action.".to_string()
            }
            Self::OldPasswordInvalid => "The current password is invalid.".to_string(),
            Self::UnsupportedAuthenticationMethod => {
                "This account authentication method does not support password changes.".to_string()
            }
            Self::NewPasswordRejected => "The new password was rejected.".to_string(),
            Self::MethodNotAllowed => {
                "Direct native API access does not currently allow this method/path.".to_string()
            }
            Self::RequestTooLarge => {
                "Direct native API requests must fit the bounded request shape.".to_string()
            }
            Self::ReportPdfTooLarge => {
                "The report exceeds the bounded native PDF download limit. Use the typed report evidence endpoints for the complete report data.".to_string()
            }
            Self::TooManyRequests => {
                "The direct native API listener is already handling the maximum number of in-flight requests."
                    .to_string()
            }
            Self::BadRequest(message) => message.clone(),
            Self::NotFound => "The requested resource was not found.".to_string(),
            Self::Conflict(message) => message.clone(),
            Self::Database => "The database query failed.".to_string(),
            Self::Config => "The API service is not configured correctly.".to_string(),
            Self::TaskStopRequested => {
                "The stop was requested, but scanner absence is not yet verified.".to_string()
            }
            Self::ScannerUnverified => {
                "The scanner control operation failed, so scanner absence is not verified."
                    .to_string()
            }
            Self::ControlFailure => "The control service failed.".to_string(),
            Self::ControlUnavailable => "The control service is temporarily unavailable.".to_string(),
            Self::MutationCommittedResponseUnavailable => {
                "The mutation committed, but its response could not be completed; verify current state before retrying."
                    .to_string()
            }
            Self::MutationOutcomeIndeterminate => {
                "The mutation may have committed, but no authoritative response was received; verify current state before retrying."
                    .to_string()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorBody {
            error: ErrorPayload {
                code: self.code().to_string(),
                message: self.public_message(),
            },
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_variants_keep_stable_public_contract() {
        let cases = [
            (
                ApiError::Unauthorized,
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "bearer token",
                &["secret", "password", "credential", "authorization"][..],
            ),
            (
                ApiError::Forbidden,
                StatusCode::FORBIDDEN,
                "forbidden",
                "operator",
                &["secret", "token", "password", "credential"][..],
            ),
            (
                ApiError::OldPasswordInvalid,
                StatusCode::FORBIDDEN,
                "old_password_invalid",
                "current password is invalid",
                &["secret", "token", "credential", "authorization"][..],
            ),
            (
                ApiError::UnsupportedAuthenticationMethod,
                StatusCode::CONFLICT,
                "unsupported_auth_method",
                "authentication method",
                &["secret", "token", "credential", "authorization"][..],
            ),
            (
                ApiError::NewPasswordRejected,
                StatusCode::BAD_REQUEST,
                "new_password_rejected",
                "new password was rejected",
                &["secret", "token", "credential", "authorization"][..],
            ),
            (
                ApiError::MethodNotAllowed,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method/path",
                &[],
            ),
            (
                ApiError::RequestTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "bounded request",
                &[],
            ),
            (
                ApiError::TooManyRequests,
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "maximum number",
                &[],
            ),
            (
                ApiError::BadRequest("bad input".to_string()),
                StatusCode::BAD_REQUEST,
                "bad_request",
                "bad input",
                &[],
            ),
            (
                ApiError::NotFound,
                StatusCode::NOT_FOUND,
                "not_found",
                "not found",
                &[],
            ),
            (
                ApiError::Conflict("scope is immutable".to_string()),
                StatusCode::CONFLICT,
                "conflict",
                "immutable",
                &["secret", "token", "password", "credential"][..],
            ),
            (
                ApiError::Database,
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "database query failed",
                &[
                    "secret",
                    "token",
                    "password",
                    "credential",
                    "connection string",
                ][..],
            ),
            (
                ApiError::Config,
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                "not configured correctly",
                &["secret", "token", "password", "credential", "environment"][..],
            ),
            (
                ApiError::TaskStopRequested,
                StatusCode::CONFLICT,
                "stop_requested",
                "not yet verified",
                &["secret", "token", "password", "credential"][..],
            ),
            (
                ApiError::ScannerUnverified,
                StatusCode::BAD_GATEWAY,
                "scanner_unverified",
                "absence is not verified",
                &["secret", "token", "password", "credential"][..],
            ),
            (
                ApiError::ControlFailure,
                StatusCode::BAD_GATEWAY,
                "control_failure",
                "control service failed",
                &[
                    "socket",
                    "path",
                    "secret",
                    "token",
                    "password",
                    "credential",
                ][..],
            ),
            (
                ApiError::ControlUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "control_unavailable",
                "temporarily unavailable",
                &[
                    "socket",
                    "path",
                    "secret",
                    "token",
                    "password",
                    "credential",
                ][..],
            ),
            (
                ApiError::MutationCommittedResponseUnavailable,
                StatusCode::BAD_GATEWAY,
                "committed_response_unavailable",
                "verify current state before retrying",
                &[
                    "socket",
                    "path",
                    "secret",
                    "token",
                    "password",
                    "credential",
                ][..],
            ),
            (
                ApiError::MutationOutcomeIndeterminate,
                StatusCode::BAD_GATEWAY,
                "mutation_outcome_indeterminate",
                "verify current state before retrying",
                &[
                    "socket",
                    "path",
                    "secret",
                    "token",
                    "password",
                    "credential",
                ][..],
            ),
        ];

        for (error, status, code, message_fragment, forbidden_fragments) in cases {
            let public_message = error.public_message();
            assert_eq!(error.status_code(), status, "{code} status");
            assert_eq!(error.code(), code, "{code} code");
            assert!(
                public_message.contains(message_fragment),
                "{code} message should contain {message_fragment:?}, got {public_message:?}"
            );
            let lower_message = public_message.to_ascii_lowercase();
            for forbidden in forbidden_fragments {
                assert!(
                    !lower_message.contains(forbidden),
                    "{code} message leaked forbidden fragment {forbidden:?}: {public_message:?}"
                );
            }
        }
    }

    #[test]
    fn api_error_into_response_preserves_status_code() {
        let response = ApiError::BadRequest("bad input".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
