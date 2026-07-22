// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::future::Future;
use std::time::Duration;

use axum::{
    extract::Request,
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::time::timeout;

use crate::errors::ApiError;

const NATIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) async fn enforce_native_request_deadline(request: Request, next: Next) -> Response {
    let mutation = method_may_mutate(request.method());
    response_with_deadline(NATIVE_REQUEST_TIMEOUT, mutation, next.run(request)).await
}

fn method_may_mutate(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

async fn response_with_deadline<F>(deadline: Duration, mutation: bool, response: F) -> Response
where
    F: Future<Output = Response>,
{
    match timeout(deadline, response).await {
        Ok(response) => response,
        Err(_) if mutation => ApiError::MutationOutcomeIndeterminate.into_response(),
        Err(_) => ApiError::RequestTimedOut.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn native_request_deadline_is_explicit_and_conservative() {
        assert_eq!(NATIVE_REQUEST_TIMEOUT, Duration::from_secs(120));
    }

    #[tokio::test]
    async fn deadline_returns_the_completed_response() {
        let response = response_with_deadline(Duration::from_secs(1), false, async {
            StatusCode::OK.into_response()
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn deadline_returns_stable_gateway_timeout() {
        let response = response_with_deadline(Duration::ZERO, false, std::future::pending()).await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn mutation_timeout_never_claims_that_commit_did_not_happen() {
        let response = response_with_deadline(Duration::ZERO, true, std::future::pending()).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn only_non_read_methods_have_indeterminate_timeout_outcomes() {
        assert!(!method_may_mutate(&Method::GET));
        assert!(!method_may_mutate(&Method::HEAD));
        assert!(!method_may_mutate(&Method::OPTIONS));
        assert!(method_may_mutate(&Method::POST));
        assert!(method_may_mutate(&Method::PUT));
        assert!(method_may_mutate(&Method::PATCH));
        assert!(method_may_mutate(&Method::DELETE));
    }
}
