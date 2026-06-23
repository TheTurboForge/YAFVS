// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::http::{HeaderMap, header};

const MIN_DIRECT_API_BEARER_TOKEN_LENGTH: usize = 32;
pub(crate) const MAX_DIRECT_API_BEARER_TOKEN_LENGTH: usize = 1024;
const DIRECT_API_MAX_IN_FLIGHT_REQUESTS: usize = 32;

#[derive(Clone)]
pub(crate) struct DirectApiAuth {
    pub(crate) token: String,
    in_flight_requests: Arc<AtomicUsize>,
    max_in_flight_requests: usize,
}

pub(crate) struct DirectApiRequestSlot {
    in_flight_requests: Arc<AtomicUsize>,
}

impl Drop for DirectApiRequestSlot {
    fn drop(&mut self) {
        self.in_flight_requests.fetch_sub(1, Ordering::Release);
    }
}

impl DirectApiAuth {
    pub(crate) fn new(token: String) -> Self {
        Self::with_max_in_flight_requests(token, DIRECT_API_MAX_IN_FLIGHT_REQUESTS)
    }

    pub(crate) fn with_max_in_flight_requests(
        token: String,
        max_in_flight_requests: usize,
    ) -> Self {
        Self {
            token,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
            max_in_flight_requests,
        }
    }

    pub(crate) fn try_acquire_request_slot(&self) -> Option<DirectApiRequestSlot> {
        let mut current = self.in_flight_requests.load(Ordering::Acquire);
        loop {
            if current >= self.max_in_flight_requests {
                return None;
            }
            match self.in_flight_requests.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(DirectApiRequestSlot {
                        in_flight_requests: Arc::clone(&self.in_flight_requests),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

pub(crate) fn direct_api_bearer_token_is_acceptable(token: &str) -> bool {
    token.len() >= MIN_DIRECT_API_BEARER_TOKEN_LENGTH
        && token.len() <= MAX_DIRECT_API_BEARER_TOKEN_LENGTH
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
