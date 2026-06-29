// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    extract::Request,
    http::{Method, header},
};

pub(crate) const MAX_DIRECT_API_QUERY_BYTES: usize = 8 * 1024;
pub(crate) const MAX_DIRECT_API_WRITE_BODY_BYTES: u64 = 256 * 1024;

pub(crate) fn direct_api_request_shape_is_allowed(request: &Request) -> bool {
    direct_api_request_shape_is_allowed_for_method(request.method(), request)
}

pub(crate) fn direct_api_request_shape_is_allowed_for_method(
    method: &Method,
    request: &Request,
) -> bool {
    if request
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
    if method == Method::GET {
        length == 0
    } else if matches!(method, &Method::POST | &Method::PATCH | &Method::DELETE) {
        length <= MAX_DIRECT_API_WRITE_BODY_BYTES
    } else {
        false
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
