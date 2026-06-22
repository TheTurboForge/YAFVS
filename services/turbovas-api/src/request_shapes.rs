// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{extract::Request, http::header};

pub(crate) const MAX_DIRECT_API_QUERY_BYTES: usize = 8 * 1024;

pub(crate) fn direct_api_request_shape_is_allowed(request: &Request) -> bool {
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
    match request.headers().get(header::CONTENT_LENGTH) {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .is_some_and(|length| length == 0),
        None => true,
    }
}
