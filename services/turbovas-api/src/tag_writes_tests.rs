// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::tag_write_plans::*;
use crate::tag_write_sql::*;
use crate::tag_write_validation::{
    MAX_TAG_RESOURCE_ID_BYTES, MAX_TAG_RESOURCE_WRITE_IDS, TagCloneRequest,
    TagResourceUpdateAction, ValidatedTagClone, ValidatedTagCreate, ValidatedTagPatch,
    ValidatedTagResourceUpdate, default_tag_active,
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
fn tag_write_rejects_operator_owner_mismatch() {
    assert!(ensure_tag_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_tag_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn tag_create_handler_requires_operator_before_insert() {
    let source = include_str!("tag_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn create_tag")
        .expect("create tag handler must exist")
        .1
        .split_once("pub(crate) async fn restore_tag")
        .expect("restore tag handler must follow create handler")
        .0;

    assert!(handler.contains("let operator = require_tag_write_operator(operator)?;"));
    assert!(
        handler.contains("let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;")
    );
    assert!(
        handler.find("resolve_tag_write_operator_owner").unwrap()
            < handler.find("execute_tag_create_transaction").unwrap(),
        "tag create must resolve operator owner before inserting tag"
    );
}

#[test]
fn tag_mutating_handlers_enforce_owner_and_type_guard_before_side_effects() {
    let source = include_str!("tag_writes.rs");
    for (label, start, end, owner_check, type_guard, side_effect) in [
        (
            "restore",
            "pub(crate) async fn restore_tag",
            "pub(crate) async fn hard_delete_tag",
            "ensure_tag_owner_matches_operator(trash.owner_id, operator_owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;",
            "execute_tag_restore_transaction",
        ),
        (
            "hard delete",
            "pub(crate) async fn hard_delete_tag",
            "pub(crate) async fn patch_tag",
            "ensure_tag_owner_matches_operator(trash.owner_id, operator_owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;",
            "execute_tag_hard_delete_transaction",
        ),
        (
            "patch",
            "pub(crate) async fn patch_tag",
            "pub(crate) async fn clone_tag",
            "ensure_tag_owner_matches_operator(state.owner_id, operator_owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;",
            "execute_tag_patch_transaction",
        ),
        (
            "clone",
            "pub(crate) async fn clone_tag",
            "pub(crate) async fn delete_tag",
            "ensure_tag_owner_matches_operator(source.owner_id, owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&source.resource_type)?;",
            "execute_tag_clone_transaction",
        ),
        (
            "delete",
            "pub(crate) async fn delete_tag",
            "pub(crate) async fn update_tag_resources",
            "ensure_tag_owner_matches_operator(state.owner_id, operator_owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;",
            "execute_tag_trash_transaction",
        ),
        (
            "resource update",
            "pub(crate) async fn update_tag_resources",
            "fn tag_write_location_headers",
            "ensure_tag_owner_matches_operator(state.owner_id, operator_owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;",
            "execute_tag_resource_update_transaction",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} tag handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} tag handler end marker must exist"))
            .0;

        assert!(
            handler.contains("require_tag_write_operator"),
            "{label} handler must require operator"
        );
        assert!(
            handler.contains(owner_check),
            "{label} handler must check owner"
        );
        assert!(
            handler.contains(type_guard),
            "{label} handler must check resource type support"
        );
        assert!(
            handler.find(owner_check).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check owner before side effects"
        );
        assert!(
            handler.find(type_guard).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check resource type before side effects"
        );
    }
}

#[test]
fn tag_resource_write_rejects_owner_mismatch_for_owner_bearing_types() {
    assert!(ensure_tag_resource_owner_matches_operator("target", Some(7), 7).is_ok());
    assert!(matches!(
        ensure_tag_resource_owner_matches_operator("target", Some(7), 8),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        ensure_tag_resource_owner_matches_operator("target", None, 8),
        Err(ApiError::Forbidden)
    ));
    assert!(ensure_tag_resource_owner_matches_operator("credential", Some(7), 7).is_ok());
    assert!(matches!(
        ensure_tag_resource_owner_matches_operator("credential", Some(7), 8),
        Err(ApiError::Forbidden)
    ));
    assert!(ensure_tag_resource_owner_matches_operator("cve", None, 8).is_ok());
    assert!(ensure_tag_resource_owner_matches_operator("nvt", None, 8).is_ok());
}

#[test]
fn tag_clone_request_accepts_optional_metadata_overrides() {
    let request: TagCloneRequest =
        serde_json::from_str(r#"{"name":"  cloned tag  ","comment":" copied "}"#)
            .expect("valid tag clone request");
    let validated = validate_tag_clone_request(request).expect("valid clone request");
    assert_eq!(validated.name.as_deref(), Some("cloned tag"));
    assert_eq!(validated.comment.as_deref(), Some("copied"));

    let default_clone = validate_tag_clone_request(TagCloneRequest {
        name: None,
        comment: None,
    })
    .expect("empty clone request uses inherited-style generated name");
    assert_eq!(default_clone.name, None);
    assert_eq!(default_clone.comment, None);
}

#[test]
fn tag_clone_request_rejects_unknown_fields_empty_name_and_bad_text() {
    assert!(serde_json::from_str::<TagCloneRequest>(r#"{"resource_ids":[]}"#).is_err());
    assert!(matches!(
        validate_tag_clone_request(TagCloneRequest {
            name: Some(" ".to_string()),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_clone_request(TagCloneRequest {
            name: None,
            comment: Some("bad\ncomment".to_string()),
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_create_request_rejects_unknown_fields_bad_text_and_unsupported_types() {
    assert!(
        serde_json::from_str::<TagCreateRequest>(
            r#"{"name":"x","resource_type":"task","resource_ids":[]}"#
        )
        .is_err()
    );

    let clone = ValidatedTagClone {
        name: None,
        comment: Some("copied".to_string()),
    };
    assert_eq!(
        tag_clone_transaction_plan(&clone),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::CloneMetadataAndAssignments,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::InsertMetadata,
                TagWriteStep::CopyResourceAssignments,
            ],
        }
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
        resource_type: "user".to_string(),
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
            r#"{"action":"replace","resource_ids":["12345678-1234-1234-1234-123456789abc"]}"#,
        )
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
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_ids":["12345678-1234-1234-1234-123456789abc"],"resources_filter":"name~prod"}"#,
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_ids":["12345678-1234-1234-1234-123456789abc"],"resources_action":"set"}"#,
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
    assert!(ensure_tag_resource_direct_write_type_is_supported("credential").is_ok());
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
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::UpdateMetadata,
            ],
        }
    );

    assert_eq!(
        tag_delete_transaction_plan(),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::MoveToTrash,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::InsertTrashMetadata,
                TagWriteStep::CopyResourceAssignments,
                TagWriteStep::MoveTagAsResourceLinks,
                TagWriteStep::DeleteResourceAssignment,
                TagWriteStep::DeleteLiveMetadata,
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
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::VerifyResourceExists,
                TagWriteStep::VerifyResourceOwnerMatch,
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
    assert!(update.contains("WHERE id = $1"));
    assert!(!update.contains("resource_type ="));
    assert!(!update.contains("tag_resources"));

    let delete_state = tag_write_unassigned_state_sql();
    assert!(delete_state.contains("owner::integer"));
    assert!(delete_state.contains("tag_resources_count"));
    assert!(!delete_state.contains("DELETE"));

    let trash_state = tag_trash_state_sql();
    assert!(trash_state.contains("owner::integer"));
    assert!(trash_state.contains("FROM tags_trash"));

    let trash = tag_trash_insert_sql();
    assert!(trash.contains("INSERT INTO tags_trash"));
    assert!(trash.contains("FROM tags"));

    let trash_resources = tag_trash_resources_insert_sql();
    assert!(trash_resources.contains("INSERT INTO tag_resources_trash"));
    assert!(trash_resources.contains("FROM tag_resources"));

    let restore = tag_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO tags"));
    assert!(restore.contains("FROM tags_trash"));

    let delete_live = tag_delete_live_metadata_sql();
    assert!(delete_live.contains("DELETE FROM tags"));
    assert!(delete_live.contains("WHERE id = $1"));

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

    let clone = tag_clone_metadata_sql();
    assert!(clone.contains("INSERT INTO tags"));
    assert!(clone.contains("coalesce($3, uniquify('tag', name, $2, ' Clone'))"));
    assert!(clone.contains("coalesce($4, comment)"));
    assert!(clone.contains("value"));
    assert!(clone.contains("resource_type"));
    assert!(clone.contains("active"));
    assert!(clone.contains("WHERE id = $1"));

    let clone_resources = tag_clone_resources_sql();
    assert!(clone_resources.contains("INSERT INTO tag_resources"));
    assert!(
        clone_resources
            .contains("SELECT $2, resource_type, resource, resource_uuid, resource_location")
    );
    assert!(clone_resources.contains("FROM tag_resources"));
    assert!(clone_resources.contains("WHERE tag = $1"));
}

#[test]
fn tag_delete_rejects_assigned_tags() {
    assert!(ensure_tag_is_unassigned(0).is_ok());
    assert!(matches!(
        ensure_tag_is_unassigned(1),
        Err(ApiError::Conflict(_))
    ));
}
