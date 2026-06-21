// SPDX-FileCopyrightText: 2026 TurboVAS contributors
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
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("request too large")]
    RequestTooLarge,
    #[error("{0}")]
    BadRequest(String),
    #[error("resource not found")]
    NotFound,
    #[error("database error")]
    Database,
    #[error("configuration error")]
    Config,
}

impl ApiError {
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Database | Self::Config => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestTooLarge => "request_too_large",
            Self::BadRequest(_) => "bad_request",
            Self::NotFound => "not_found",
            Self::Database => "database_error",
            Self::Config => "configuration_error",
        }
    }

    pub(crate) fn public_message(&self) -> String {
        match self {
            Self::Unauthorized => "A valid bearer token is required.".to_string(),
            Self::MethodNotAllowed => {
                "Direct native API access currently allows read-only GET requests only.".to_string()
            }
            Self::RequestTooLarge => {
                "Direct native API requests must fit the bounded read-only request shape."
                    .to_string()
            }
            Self::BadRequest(message) => message.clone(),
            Self::NotFound => "The requested resource was not found.".to_string(),
            Self::Database => "The database query failed.".to_string(),
            Self::Config => "The API service is not configured correctly.".to_string(),
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
