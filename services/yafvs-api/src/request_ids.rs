// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    http::{HeaderMap, HeaderName, HeaderValue},
    response::Response,
};
use time::OffsetDateTime;

const DIRECT_API_REQUEST_ID_HEADER: &str = "x-request-id";
pub(crate) const MAX_REQUEST_ID_LENGTH: usize = 128;
static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) fn request_id_header_name() -> HeaderName {
    HeaderName::from_static(DIRECT_API_REQUEST_ID_HEADER)
}

pub(crate) fn request_id_from_headers(headers: &HeaderMap) -> String {
    headers
        .get(request_id_header_name())
        .and_then(|value| value.to_str().ok())
        .filter(|value| request_id_is_valid(value))
        .map(str::to_string)
        .unwrap_or_else(new_request_id)
}

pub(crate) fn request_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(crate) fn new_request_id() -> String {
    let counter = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    format!("tv-{timestamp:x}-{counter:x}")
}

pub(crate) fn attach_request_id_header(response: &mut Response, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response
            .headers_mut()
            .insert(request_id_header_name(), value);
    }
}
