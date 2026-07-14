// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    extract::Request,
    http::{Method, header},
};

use crate::scan_config_backup::MAX_SCAN_CONFIG_BACKUP_BODY_BYTES;

pub(crate) const MAX_DIRECT_API_QUERY_BYTES: usize = 8 * 1024;
pub(crate) const MAX_DIRECT_API_WRITE_BODY_BYTES: u64 = 256 * 1024;

#[cfg(test)]
pub(crate) fn direct_api_request_shape_is_allowed(request: &Request) -> bool {
    direct_api_request_shape_is_allowed_for_method(request.method(), request)
}

pub(crate) fn direct_api_request_shape_is_allowed_for_method(
    method: &Method,
    request: &Request,
) -> bool {
    if method != Method::GET && request.uri().query().is_some() {
        return false;
    }
    if method == Method::GET
        && request
            .uri()
            .query()
            .is_some_and(|query| query.len() > MAX_DIRECT_API_QUERY_BYTES)
    {
        return false;
    }
    if request.headers().get(header::TRANSFER_ENCODING).is_some() {
        return false;
    }
    let Some(length) = direct_api_content_length(request) else {
        return false;
    };
    if method == Method::GET || method == Method::DELETE {
        length == 0
    } else if matches!(method, &Method::POST | &Method::PATCH | &Method::PUT) {
        length <= direct_api_write_body_limit(request.uri().path())
    } else {
        false
    }
}

fn direct_api_write_body_limit(path: &str) -> u64 {
    if path == "/api/v1/scan-configs/import" {
        MAX_SCAN_CONFIG_BACKUP_BODY_BYTES as u64
    } else {
        MAX_DIRECT_API_WRITE_BODY_BYTES
    }
}

fn direct_api_content_length(request: &Request) -> Option<u64> {
    request
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| text.parse::<u64>().ok())
        })
        .unwrap_or(Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_api_request_shape_rejects_get_bodies_and_oversized_queries() {
        let allowed = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed(&allowed));

        let explicit_empty_body = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::CONTENT_LENGTH, "0")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed(&explicit_empty_body));

        let body = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::CONTENT_LENGTH, "1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&body));

        let chunked = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::TRANSFER_ENCODING, "chunked")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&chunked));

        let malformed_length = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::CONTENT_LENGTH, "not-a-number")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&malformed_length));

        let oversized_query = format!(
            "/api/v1/reports?filter={}",
            "a".repeat(MAX_DIRECT_API_QUERY_BYTES)
        );
        let oversized = Request::builder()
            .uri(oversized_query)
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&oversized));
    }

    #[test]
    fn direct_api_request_shape_allows_bounded_write_bodies_only_for_write_methods() {
        let post = Request::builder()
            .method("POST")
            .uri("/api/v1/scopes")
            .header(header::CONTENT_LENGTH, "128")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed_for_method(
            &Method::POST,
            &post
        ));

        let patch = Request::builder()
            .method("PATCH")
            .uri("/api/v1/scopes/12345678-1234-1234-1234-123456789abc")
            .header(
                header::CONTENT_LENGTH,
                MAX_DIRECT_API_WRITE_BODY_BYTES.to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed_for_method(
            &Method::PATCH,
            &patch
        ));

        let put = Request::builder()
            .method("PUT")
            .uri("/api/v1/alerts/12345678-1234-1234-1234-123456789abc/definition")
            .header(header::CONTENT_LENGTH, "128")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed_for_method(
            &Method::PUT,
            &put
        ));

        let patch_query = Request::builder()
            .method("PATCH")
            .uri("/api/v1/scopes/12345678-1234-1234-1234-123456789abc?unexpected=1")
            .header(header::CONTENT_LENGTH, "128")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed_for_method(
            &Method::PATCH,
            &patch_query
        ));

        let delete = Request::builder()
            .method("DELETE")
            .uri("/api/v1/scopes/12345678-1234-1234-1234-123456789abc")
            .header(header::CONTENT_LENGTH, "0")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed_for_method(
            &Method::DELETE,
            &delete
        ));

        let delete_body = Request::builder()
            .method("DELETE")
            .uri("/api/v1/scopes/12345678-1234-1234-1234-123456789abc")
            .header(header::CONTENT_LENGTH, "1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed_for_method(
            &Method::DELETE,
            &delete_body
        ));

        let oversized = Request::builder()
            .method("POST")
            .uri("/api/v1/scopes")
            .header(
                header::CONTENT_LENGTH,
                (MAX_DIRECT_API_WRITE_BODY_BYTES + 1).to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed_for_method(
            &Method::POST,
            &oversized
        ));

        let unsupported = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/scopes")
            .header(header::CONTENT_LENGTH, "0")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed_for_method(
            &Method::OPTIONS,
            &unsupported
        ));
    }

    #[test]
    fn scan_config_backup_import_has_a_bounded_endpoint_specific_body_limit() {
        let import = Request::builder()
            .method("POST")
            .uri("/api/v1/scan-configs/import")
            .header(
                header::CONTENT_LENGTH,
                MAX_SCAN_CONFIG_BACKUP_BODY_BYTES.to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed_for_method(
            &Method::POST,
            &import
        ));

        let oversized = Request::builder()
            .method("POST")
            .uri("/api/v1/scan-configs/import")
            .header(
                header::CONTENT_LENGTH,
                (MAX_SCAN_CONFIG_BACKUP_BODY_BYTES + 1).to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed_for_method(
            &Method::POST,
            &oversized
        ));
    }
}
