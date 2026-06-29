// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::http::{HeaderMap, header};

use crate::{errors::ApiError, path_ids::parse_uuid};

const MIN_DIRECT_API_BEARER_TOKEN_LENGTH: usize = 32;
pub(crate) const MAX_DIRECT_API_BEARER_TOKEN_LENGTH: usize = 1024;
const DIRECT_API_MAX_IN_FLIGHT_REQUESTS: usize = 32;

#[derive(Clone)]
pub(crate) struct DirectApiAuth {
    pub(crate) token: String,
    operator: Option<DirectApiOperator>,
    write_control_enabled: bool,
    in_flight_requests: Arc<AtomicUsize>,
    max_in_flight_requests: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectApiOperator {
    user_uuid: String,
    user_name: Option<String>,
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
            operator: None,
            write_control_enabled: false,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
            max_in_flight_requests,
        }
    }

    pub(crate) fn with_operator(mut self, operator: Option<DirectApiOperator>) -> Self {
        self.operator = operator;
        self
    }

    pub(crate) fn operator_uuid(&self) -> Option<&str> {
        self.operator.as_ref().map(DirectApiOperator::user_uuid)
    }

    pub(crate) fn operator(&self) -> Option<&DirectApiOperator> {
        self.operator.as_ref()
    }

    pub(crate) fn write_control_enabled(&self) -> bool {
        self.write_control_enabled
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

impl DirectApiOperator {
    pub(crate) fn new(user_uuid: &str, user_name: Option<String>) -> Result<Self, ApiError> {
        let parsed_uuid = parse_uuid(user_uuid.trim()).map_err(|_| ApiError::Config)?;
        let user_name = user_name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty());
        if user_name
            .as_deref()
            .is_some_and(|name| name.len() > 256 || name.chars().any(char::is_control))
        {
            return Err(ApiError::Config);
        }
        Ok(Self {
            user_uuid: parsed_uuid.to_string(),
            user_name,
        })
    }

    pub(crate) fn user_uuid(&self) -> &str {
        &self.user_uuid
    }

    #[cfg(test)]
    pub(crate) fn user_name(&self) -> Option<&str> {
        self.user_name.as_deref()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_api_operator_requires_valid_user_uuid() {
        let operator = DirectApiOperator::new(
            "12345678-1234-1234-1234-123456789abc",
            Some(" admin ".to_string()),
        )
        .expect("valid operator identity");

        assert_eq!(operator.user_uuid(), "12345678-1234-1234-1234-123456789abc");
        assert_eq!(operator.user_name(), Some("admin"));
        assert!(DirectApiOperator::new("not-a-uuid", None).is_err());
        assert!(
            DirectApiOperator::new(
                "12345678-1234-1234-1234-123456789abc",
                Some("bad\nname".to_string())
            )
            .is_err()
        );
    }

    #[test]
    fn direct_api_auth_carries_optional_operator_identity() {
        let token = "0123456789abcdef0123456789abcdef".to_string();
        let operator = DirectApiOperator::new("12345678-1234-1234-1234-123456789abc", None)
            .expect("valid operator identity");

        let without_operator = DirectApiAuth::new(token.clone());
        assert_eq!(without_operator.operator_uuid(), None);

        let with_operator = DirectApiAuth::new(token).with_operator(Some(operator));
        assert_eq!(
            with_operator.operator_uuid(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
    }
}
