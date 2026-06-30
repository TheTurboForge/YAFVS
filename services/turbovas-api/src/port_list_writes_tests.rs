// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn patch_request(name: Option<&str>, comment: Option<&str>) -> PortListPatchRequest {
    PortListPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn port_list_create_plan_validates_ranges_before_insert() {
    assert_eq!(
        port_list_create_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::InsertPortList,
            PortListWriteStep::ReplacePortRanges,
        ]
    );
}

#[test]
fn port_list_patch_request_trims_metadata_fields() {
    assert_eq!(
        validate_port_list_patch_request(patch_request(
            Some("  Web ports  "),
            Some("  operator-visible note  "),
        ))
        .unwrap(),
        ValidatedPortListPatch {
            name: Some("Web ports".to_string()),
            comment: Some("operator-visible note".to_string()),
        }
    );
}

#[test]
fn port_list_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_allows_blank_comment_to_clear_comment() {
    assert_eq!(
        validate_port_list_patch_request(patch_request(None, Some("   "))).unwrap(),
        ValidatedPortListPatch {
            name: None,
            comment: Some(String::new()),
        }
    );
}

#[test]
fn port_list_patch_request_rejects_control_characters() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_port_list_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_rejects_unknown_fields() {
    let request = serde_json::json!({"name": "Web ports", "predefined": false});
    assert!(serde_json::from_value::<PortListPatchRequest>(request).is_err());
}

#[test]
fn port_list_patch_request_rejects_oversized_metadata_fields() {
    let oversized = "a".repeat(MAX_PORT_LIST_TEXT_BYTES + 1);
    assert!(matches!(
        validate_port_list_patch_request(PortListPatchRequest {
            name: Some(oversized),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_sql_is_metadata_only() {
    let sql = port_list_update_metadata_sql();
    assert!(sql.contains("UPDATE port_lists"));
    assert!(sql.contains("name = coalesce"));
    assert!(sql.contains("comment = coalesce"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(!sql.contains("port_ranges"));
    assert!(!sql.contains("predefined"));
}

#[test]
fn port_list_patch_name_uniqueness_checks_live_and_trash_names() {
    let sql = port_list_unique_name_sql();
    assert!(sql.contains("FROM port_lists WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM port_lists_trash WHERE name = $1"));
}

#[test]
fn port_list_patch_plan_stays_metadata_only_and_blocks_predefined_lists() {
    assert_eq!(
        port_list_patch_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyNotPredefined,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::UpdatePortListMetadata,
        ]
    );
}

#[test]
fn port_list_delete_plan_keeps_range_target_and_tag_side_effects_explicit() {
    assert_eq!(
        port_list_delete_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::MovePortListToTrash,
            PortListWriteStep::MovePortRangesToTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ]
    );
}

#[test]
fn port_list_restore_plan_keeps_range_target_and_tag_side_effects_explicit() {
    assert_eq!(
        port_list_restore_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::RestorePortListFromTrash,
            PortListWriteStep::RestorePortRangesFromTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
