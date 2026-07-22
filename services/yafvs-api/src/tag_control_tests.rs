// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::StatusCode;

use super::*;

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
const OPERATOR_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const TAG_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";

#[test]
fn tag_modify_control_frame_preserves_atomic_set_and_filter_selection() {
    let request = ValidatedTagPatch {
        name: Some("Renamed".to_string()),
        comment: Some(String::new()),
        value: None,
        active: Some(false),
        resource_type: Some("target".to_string()),
        resources: Some(ValidatedTagResourceUpdate {
            action: TagResourceUpdateAction::Set,
            resource_ids: Vec::new(),
            resource_filter: Some("rows=-1 name~production".to_string()),
            resource_selection: None,
        }),
    };
    let frame = tag_modify_command(CONTROL_SECRET, OPERATOR_UUID, TAG_UUID, &request).unwrap();
    let command = std::str::from_utf8(frame.as_bytes()).unwrap();
    assert!(command.starts_with(&format!(
        "tag-modify {CONTROL_SECRET} {OPERATOR_UUID} {TAG_UUID} "
    )));
    assert!(command.contains(" 0 "));
    assert!(command.contains(" set + +"));
    assert!(!command.contains("rows=-1"));
}

#[test]
fn tag_control_frames_reject_oversized_composite_payloads() {
    let request = ValidatedTagPatch {
        name: None,
        comment: None,
        value: None,
        active: None,
        resource_type: None,
        resources: Some(ValidatedTagResourceUpdate {
            action: TagResourceUpdateAction::Add,
            resource_ids: vec!["x".repeat(MAX_CONTROL_REQUEST_BYTES)],
            resource_filter: None,
            resource_selection: None,
        }),
    };
    let error = match tag_modify_command(CONTROL_SECRET, OPERATOR_UUID, TAG_UUID, &request) {
        Err(error) => error,
        Ok(_) => panic!("oversized control frame must fail"),
    };
    assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn tag_modify_response_maps_exact_outcomes() {
    assert!(parse_tag_modify_response(b"0 modified").is_ok());
    assert_eq!(
        parse_tag_modify_response(b"1 tag_not_found")
            .unwrap_err()
            .status_code(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        parse_tag_modify_response(b"3 invalid_action")
            .unwrap_err()
            .status_code(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        parse_tag_modify_response(b"unexpected")
            .unwrap_err()
            .status_code(),
        StatusCode::BAD_GATEWAY
    );
}
