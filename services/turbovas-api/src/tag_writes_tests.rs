// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::tag_write_plans::*;
use crate::tag_write_validation::{
    MAX_TAG_RESOURCE_ID_BYTES, MAX_TAG_RESOURCE_WRITE_IDS, default_tag_active,
};

#[test]
fn tag_create_request_normalizes_metadata_only_contract() {
    let request: TagCreateRequest = serde_json::from_str(
        r#"{"name":"  owner:critical  ","resource_type":" TASK ","comment":" note ","value":" yes ","active":false}"#,
    )
    .expect("valid tag create request");
    let validated = validate_tag_create_request(request).expect("valid create request");
    assert_eq!(validated.name, "owner:critical");
    assert_eq!(validated.resource_type, "task");
    assert_eq!(validated.comment.as_deref(), Some("note"));
    assert_eq!(validated.value.as_deref(), Some("yes"));
    assert!(!validated.active);

    let default_active = validate_tag_create_request(TagCreateRequest {
        name: "owner:default".to_string(),
        resource_type: "target".to_string(),
        comment: None,
        value: None,
        active: default_tag_active(),
    })
    .expect("default active create request");
    assert!(default_active.active);
}

#[test]
fn tag_create_request_rejects_unknown_fields_bad_text_and_unsupported_types() {
    assert!(
        serde_json::from_str::<TagCreateRequest>(
            r#"{"name":"x","resource_type":"task","resource_ids":[]}"#
        )
        .is_err()
    );

    let empty_name = TagCreateRequest {
        name: " ".to_string(),
        resource_type: "task".to_string(),
        comment: None,
        value: None,
        active: true,
    };
    assert!(matches!(
        validate_tag_create_request(empty_name),
        Err(ApiError::BadRequest(_))
    ));

    let bad_type = TagCreateRequest {
        name: "owner:x".to_string(),
        resource_type: "credential".to_string(),
        comment: None,
        value: None,
        active: true,
    };
    assert!(matches!(
        validate_tag_create_request(bad_type),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_patch_request_is_metadata_only_and_requires_a_field() {
    let patch: TagPatchRequest = serde_json::from_str(
        r#"{"name":"  owner:patched ","comment":"","value":" v ","active":true}"#,
    )
    .expect("valid tag patch request");
    let validated = validate_tag_patch_request(patch).expect("valid patch request");
    assert_eq!(validated.name.as_deref(), Some("owner:patched"));
    assert_eq!(validated.comment.as_deref(), Some(""));
    assert_eq!(validated.value.as_deref(), Some("v"));
    assert_eq!(validated.active, Some(true));

    assert!(serde_json::from_str::<TagPatchRequest>(r#"{"resource_type":"target"}"#).is_err());
    let empty = TagPatchRequest {
        name: None,
        comment: None,
        value: None,
        active: None,
    };
    assert!(matches!(
        validate_tag_patch_request(empty),
        Err(ApiError::BadRequest(_))
    ));

    let empty_name = TagPatchRequest {
        name: Some(" ".to_string()),
        comment: None,
        value: None,
        active: None,
    };
    assert!(matches!(
        validate_tag_patch_request(empty_name),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_resource_update_request_is_explicit_ids_only() {
    let request: TagResourceUpdateRequest = serde_json::from_str(
        r#"{"action":"add","resource_ids":["12345678-1234-1234-1234-123456789abc","12345678-1234-1234-1234-123456789abc","cpe:/a:example:product:1"]}"#,
    )
    .expect("valid tag resource update request");
    let validated = validate_tag_resource_update_request(request).expect("valid resource update");
    assert_eq!(validated.action, TagResourceUpdateAction::Add);
    assert_eq!(
        validated.resource_ids,
        vec![
            "12345678-1234-1234-1234-123456789abc".to_string(),
            "cpe:/a:example:product:1".to_string(),
        ]
    );

    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(r#"{"action":"set","resource_ids":[]}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_ids":[],"resource_filter":"name~x"}"#,
        )
        .is_err()
    );
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: Vec::new(),
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Remove,
            resource_ids: vec!["bad\nresource".to_string()],
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: vec![
                "12345678-1234-1234-1234-123456789abc".to_string();
                MAX_TAG_RESOURCE_WRITE_IDS + 1
            ],
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_resource_update_request_rejects_implicit_selection_and_bad_ids() {
    assert!(serde_json::from_str::<TagResourceUpdateRequest>(r#"{"action":"add"}"#).is_err());
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_type":"target","resource_ids":["12345678-1234-1234-1234-123456789abc"]}"#,
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_ids":["12345678-1234-1234-1234-123456789abc"],"resource_filter":"name~prod"}"#,
        )
        .is_err()
    );
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: vec![" ".to_string()],
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: vec!["x".repeat(MAX_TAG_RESOURCE_ID_BYTES + 1)],
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_resource_direct_write_support_is_narrower_than_read_support() {
    assert!(ensure_tag_resource_direct_write_type_is_supported("target").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("task").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("cpe").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("cve").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("cert_bund_adv").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("dfn_cert_adv").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("nvt").is_ok());
    assert!(ensure_tag_resource_direct_write_type_is_supported("alert").is_ok());
    assert!(matches!(
        ensure_tag_resource_direct_write_type_is_supported("credential"),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_write_plans_are_metadata_only() {
    let create = ValidatedTagCreate {
        name: "owner:x".to_string(),
        resource_type: "task".to_string(),
        comment: None,
        value: None,
        active: true,
    };
    assert_eq!(
        tag_create_transaction_plan(&create),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::CreateMetadata,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::InsertMetadata,
            ],
        }
    );

    let patch = ValidatedTagPatch {
        name: Some("owner:y".to_string()),
        comment: None,
        value: None,
        active: None,
    };
    assert_eq!(
        tag_patch_transaction_plan(&patch),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::PatchMetadata,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::UpdateMetadata,
            ],
        }
    );

    assert_eq!(
        tag_delete_transaction_plan(),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::DeleteMetadata,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyTagUnassigned,
                TagWriteStep::DeleteMetadata,
            ],
        }
    );

    let resource_update = ValidatedTagResourceUpdate {
        action: TagResourceUpdateAction::Remove,
        resource_ids: vec!["12345678-1234-1234-1234-123456789abc".to_string()],
    };
    assert_eq!(
        tag_resource_update_transaction_plan(&resource_update),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::UpdateResourceAssignments,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::VerifyResourceExists,
                TagWriteStep::DeleteResourceAssignment,
                TagWriteStep::TouchMetadata,
            ],
        }
    );
}

#[test]
fn tag_write_sql_uses_parameterized_metadata_queries_only() {
    let insert = tag_insert_metadata_sql();
    assert!(insert.contains("INSERT INTO tags"));
    assert!(insert.contains("$1"));
    assert!(!insert.contains("tag_resources"));

    let update = tag_update_metadata_sql();
    assert!(update.contains("UPDATE tags"));
    assert!(update.contains("coalesce($2, name)"));
    assert!(!update.contains("resource_type ="));
    assert!(!update.contains("tag_resources"));

    let delete_state = tag_write_unassigned_state_sql();
    assert!(delete_state.contains("tag_resources_count"));
    assert!(!delete_state.contains("DELETE"));

    let delete = tag_delete_metadata_sql();
    assert!(delete.contains("DELETE FROM tags"));
    assert!(delete.contains("WHERE id = $1"));
    assert!(!delete.contains("tag_resources"));

    let add_resource = tag_resource_insert_sql();
    assert!(add_resource.contains("INSERT INTO tag_resources"));
    assert!(add_resource.contains("WHERE NOT EXISTS"));
    assert!(add_resource.contains("resource_location = 0"));

    let remove_resource = tag_resource_delete_sql();
    assert!(remove_resource.contains("DELETE FROM tag_resources"));
    assert!(remove_resource.contains("resource_type = $2"));
    assert!(remove_resource.contains("resource_location = 0"));

    let touch = tag_touch_metadata_sql();
    assert!(touch.contains("UPDATE tags SET modification_time"));
}

#[test]
fn tag_delete_rejects_assigned_tags() {
    assert!(ensure_tag_is_unassigned(0).is_ok());
    assert!(matches!(
        ensure_tag_is_unassigned(1),
        Err(ApiError::Conflict(_))
    ));
}
