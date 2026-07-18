// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::StatusCode;

use super::alert_deliver_report::{
    AlertDeliverReportRequest, MAX_ALERT_DELIVER_REPORT_FILTER_BYTES, alert_deliver_report_command,
    parse_alert_deliver_report_response, validate_alert_deliver_report_request,
};
use crate::errors::ApiError;

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
const OPERATOR_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ALERT_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";
const REPORT_UUID: &str = "123e4567-e89b-12d3-a456-426614174002";
const FILTER_UUID: &str = "123e4567-e89b-12d3-a456-426614174003";

fn request(filter: Option<&str>, filter_id: Option<&str>) -> AlertDeliverReportRequest {
    AlertDeliverReportRequest {
        report_id: REPORT_UUID.to_string(),
        filter: filter.map(str::to_string),
        filter_id: filter_id.map(str::to_string),
    }
}

#[test]
fn alert_deliver_report_control_frame_is_canonical_and_scrubbed() {
    let filter_request =
        validate_alert_deliver_report_request(request(Some("severity>7"), None)).unwrap();
    let frame =
        alert_deliver_report_command(CONTROL_SECRET, OPERATOR_UUID, ALERT_UUID, &filter_request)
            .unwrap();
    assert_eq!(
        frame.as_bytes(),
        format!(
            "alert-deliver-report {CONTROL_SECRET} {OPERATOR_UUID} {ALERT_UUID} {REPORT_UUID} c2V2ZXJpdHk+Nw== -\n"
        )
        .as_bytes()
    );

    let request = validate_alert_deliver_report_request(request(None, Some(FILTER_UUID))).unwrap();
    let frame =
        alert_deliver_report_command(CONTROL_SECRET, OPERATOR_UUID, ALERT_UUID, &request).unwrap();
    assert_eq!(
        frame.as_bytes(),
        format!(
            "alert-deliver-report {CONTROL_SECRET} {OPERATOR_UUID} {ALERT_UUID} {REPORT_UUID} - {FILTER_UUID}\n"
        )
        .as_bytes()
    );
}

#[test]
fn alert_deliver_report_request_is_bounded_and_has_one_filter_selector() {
    let mutual =
        validate_alert_deliver_report_request(request(Some("severity>7"), Some(FILTER_UUID)))
            .unwrap_err();
    assert_eq!(mutual.status_code(), StatusCode::BAD_REQUEST);

    for invalid in [
        "",
        " \t",
        "severity\n>7",
        &"x".repeat(MAX_ALERT_DELIVER_REPORT_FILTER_BYTES + 1),
    ] {
        let error =
            validate_alert_deliver_report_request(request(Some(invalid), None)).unwrap_err();
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }
    let error =
        validate_alert_deliver_report_request(request(None, Some("not-a-uuid"))).unwrap_err();
    assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
}

#[test]
fn alert_deliver_report_request_rejects_ineffective_report_format_id() {
    let parsed = serde_json::from_str::<AlertDeliverReportRequest>(&format!(
        r#"{{"report_id":"{REPORT_UUID}","report_format_id":"{FILTER_UUID}"}}"#
    ));
    assert!(parsed.is_err());
}

#[test]
fn alert_deliver_report_response_maps_only_worker_contract_tokens() {
    assert!(parse_alert_deliver_report_response(b"0 delivered").is_ok());
    for response in [
        b"1 alert_not_found".as_slice(),
        b"2 report_not_found",
        b"3 filter_not_found",
    ] {
        assert_eq!(
            parse_alert_deliver_report_response(response)
                .unwrap_err()
                .status_code(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        parse_alert_deliver_report_response(b"-2 report_format_not_found")
            .unwrap_err()
            .status_code(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        parse_alert_deliver_report_response(b"-3 delivery_failed")
            .unwrap_err()
            .status_code(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        parse_alert_deliver_report_response(b"99 forbidden")
            .unwrap_err()
            .status_code(),
        StatusCode::FORBIDDEN
    );
    for response in [b"0 delivered extra".as_slice(), b"unexpected", b""] {
        assert!(matches!(
            parse_alert_deliver_report_response(response),
            Err(ApiError::ControlFailure)
        ));
    }
}
