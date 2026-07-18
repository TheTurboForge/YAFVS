// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::StatusCode;

use super::alert_test::{alert_test_command, parse_alert_test_response};
use crate::errors::ApiError;

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
const OPERATOR_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ALERT_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";

#[test]
fn alert_test_control_frame_is_bounded_and_canonical() {
    let frame = alert_test_command(CONTROL_SECRET, OPERATOR_UUID, ALERT_UUID).unwrap();
    assert_eq!(
        frame.as_bytes(),
        format!("alert-test {CONTROL_SECRET} {OPERATOR_UUID} {ALERT_UUID}\n").as_bytes()
    );
    let invalid_operator = match alert_test_command(CONTROL_SECRET, "not-a-uuid", ALERT_UUID) {
        Ok(_) => panic!("invalid operator UUID must reject the control frame"),
        Err(error) => error,
    };
    assert_eq!(invalid_operator.status_code(), StatusCode::BAD_REQUEST);
    let invalid_alert = match alert_test_command(CONTROL_SECRET, OPERATOR_UUID, "not-a-uuid") {
        Ok(_) => panic!("invalid alert UUID must reject the control frame"),
        Err(error) => error,
    };
    assert_eq!(invalid_alert.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn alert_test_response_maps_only_worker_contract_tokens() {
    assert!(parse_alert_test_response(b"0 tested").is_ok());
    assert_eq!(
        parse_alert_test_response(b"1 not_found")
            .unwrap_err()
            .status_code(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        parse_alert_test_response(b"99 forbidden")
            .unwrap_err()
            .status_code(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        parse_alert_test_response(b"-5 delivery_failed")
            .unwrap_err()
            .status_code(),
        StatusCode::BAD_GATEWAY
    );
    for response in [
        b"-2 report_format_not_found".as_slice(),
        b"-3 filter_not_found",
        b"-4 credential_not_found",
    ] {
        let error = parse_alert_test_response(response).unwrap_err();
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
        assert!(matches!(error, ApiError::Conflict(_)));
    }
    for response in [
        b"0 tested extra".as_slice(),
        b"-2 malformed",
        b"unexpected",
        b"",
    ] {
        assert_eq!(
            parse_alert_test_response(response)
                .unwrap_err()
                .status_code(),
            StatusCode::BAD_GATEWAY
        );
    }
}
