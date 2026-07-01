// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    scanner_write_db::{ScannerWriteState, ensure_scanner_metadata_patch_allowed},
    scanner_write_sql::{scanner_update_metadata_sql, scanner_write_state_sql},
    scanner_write_validation::{
        MAX_SCANNER_TEXT_BYTES, ScannerPatchRequest, validate_scanner_patch_request,
    },
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> ScannerPatchRequest {
    ScannerPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn scanner_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_scanner_patch_request(patch_request(Some("  "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scanner_patch_request_allows_blank_comment_clear() {
    let patch = validate_scanner_patch_request(patch_request(None, Some("  ")))
        .expect("blank comment should clear after trimming");
    assert_eq!(patch.comment.as_deref(), Some(""));
}

#[test]
fn scanner_patch_request_rejects_empty_body_unknown_fields_and_controls() {
    assert!(matches!(
        validate_scanner_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(
        serde_json::from_value::<ScannerPatchRequest>(serde_json::json!({
            "name": "Scanner",
            "host": "127.0.0.1"
        }))
        .is_err()
    );
    assert!(matches!(
        validate_scanner_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_scanner_patch_request(ScannerPatchRequest {
            name: Some("s".repeat(MAX_SCANNER_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scanner_patch_blocks_builtin_or_unowned_scanners() {
    let mutable = ScannerWriteState {
        internal_id: 1,
        uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
        owner_id: Some(42),
    };
    assert!(ensure_scanner_metadata_patch_allowed(&mutable, 42).is_ok());

    let unowned = ScannerWriteState {
        internal_id: 1,
        uuid: mutable.uuid.clone(),
        owner_id: Some(7),
    };
    assert!(matches!(
        ensure_scanner_metadata_patch_allowed(&unowned, 42),
        Err(ApiError::Forbidden)
    ));

    for uuid in [
        "08b69003-5fc2-4037-a479-93b440211c73",
        "6acd0832-df90-11e4-b9d5-28d24461215b",
    ] {
        let builtin = ScannerWriteState {
            internal_id: 1,
            uuid: uuid.to_string(),
            owner_id: Some(42),
        };
        assert!(matches!(
            ensure_scanner_metadata_patch_allowed(&builtin, 42),
            Err(ApiError::Forbidden)
        ));
    }

    let null_owner = ScannerWriteState {
        internal_id: 1,
        uuid: mutable.uuid,
        owner_id: None,
    };
    assert!(matches!(
        ensure_scanner_metadata_patch_allowed(&null_owner, 42),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn scanner_patch_sql_is_metadata_only_and_preserves_secret_control_fields() {
    let state = scanner_write_state_sql();
    assert!(state.contains("owner::integer"));
    let update = scanner_update_metadata_sql();
    assert!(update.contains("SET name = coalesce($2, name)"));
    assert!(update.contains("comment = coalesce($3, comment)"));
    assert!(update.contains("modification_time = m_now()"));
    for forbidden in [
        "host",
        "port",
        "type",
        "ca_pub",
        "credential",
        "relay_host",
        "relay_port",
        "verify",
        "DELETE",
        "INSERT",
    ] {
        assert!(
            !update
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase()),
            "scanner metadata patch must not touch {forbidden}"
        );
    }
}
