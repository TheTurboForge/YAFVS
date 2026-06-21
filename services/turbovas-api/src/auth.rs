// SPDX-FileCopyrightText: 2026 TurboVAS contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::{HeaderMap, header};

const MIN_DIRECT_API_BEARER_TOKEN_LENGTH: usize = 32;

#[derive(Clone)]
pub(crate) struct DirectApiAuth {
    pub(crate) token: String,
}

pub(crate) fn direct_api_bearer_token_is_acceptable(token: &str) -> bool {
    token.len() >= MIN_DIRECT_API_BEARER_TOKEN_LENGTH
        && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

pub(crate) fn bearer_token_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let mut parts = value.splitn(2, ' ');
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(token) = parts.next() else {
        return false;
    };
    scheme.eq_ignore_ascii_case("Bearer") && constant_time_str_eq(token, expected)
}

pub(crate) fn constant_time_str_eq(candidate: &str, expected: &str) -> bool {
    let candidate = candidate.as_bytes();
    let expected = expected.as_bytes();
    let max_len = candidate.len().max(expected.len());
    let mut diff = candidate.len() ^ expected.len();
    for index in 0..max_len {
        let candidate_byte = candidate.get(index).copied().unwrap_or(0);
        let expected_byte = expected.get(index).copied().unwrap_or(0);
        diff |= usize::from(candidate_byte ^ expected_byte);
    }
    diff == 0
}
