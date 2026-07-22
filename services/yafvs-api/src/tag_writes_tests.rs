// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::tag_write_plans::*;
use crate::tag_write_sql::*;
use crate::tag_write_validation::{
    MAX_TAG_RESOURCE_ID_BYTES, MAX_TAG_RESOURCE_WRITE_IDS, TagCloneRequest,
    TagResourceUpdateAction, ValidatedTagClone, ValidatedTagCreate, ValidatedTagPatch,
    ValidatedTagResourceSelection, ValidatedTagResourceUpdate, default_tag_active,
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
    assert!(validated.resource_ids.is_empty());
    assert_eq!(validated.comment.as_deref(), Some("note"));
    assert_eq!(validated.value.as_deref(), Some("yes"));
    assert!(!validated.active);

    let default_active = validate_tag_create_request(TagCreateRequest {
        name: "owner:default".to_string(),
        resource_type: "target".to_string(),
        resource_ids: Vec::new(),
        comment: None,
        value: None,
        active: default_tag_active(),
    })
    .expect("default active create request");
    assert!(default_active.active);
}

#[test]
fn tag_resource_selection_is_closed_bounded_and_exclusive() {
    let selected = validate_tag_resource_update_request(serde_json::from_str(
        r#"{"action":"add","resource_selection":{"resource_type":"port_list","search":"  Production  ","predefined":true,"expected_count":2}}"#,
    ).unwrap()).unwrap();
    let selection = selected.resource_selection.unwrap();
    assert_eq!(
        selection,
        ValidatedTagResourceSelection::PortList {
            search: Some("  Production  ".to_string()),
            predefined: Some(true),
            expected_count: 2,
        }
    );
    let credential = validate_tag_resource_update_request(
        serde_json::from_str(
            r#"{"action":"add","resource_selection":{"resource_type":"credential","search":"ops","credential_type":"up","expected_count":3}}"#,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        credential.resource_selection.unwrap(),
        ValidatedTagResourceSelection::Credential {
            search: Some("ops".to_string()),
            credential_type: Some("up".to_string()),
            expected_count: 3,
        }
    );
    for value in [
        r#"{"action":"add","resource_selection":{"resource_type":"target","expected_count":1}}"#,
        r#"{"action":"add","resource_selection":{"resource_type":"port_list","expected_count":1,"unknown":true}}"#,
        r#"{"action":"add","resource_selection":{"resource_type":"credential","expected_count":1,"predefined":true}}"#,
        r#"{"action":"add","resource_selection":{"resource_type":"credential","expected_count":1,"credential_type":"bad\ntype"}}"#,
        r#"{"action":"add","resource_selection":{"resource_type":"port_list","expected_count":0}}"#,
        r#"{"action":"add","resource_selection":{"resource_type":"port_list","expected_count":100001}}"#,
        r#"{"action":"add","resource_selection":{"resource_type":"port_list","search":"bad\nsearch","expected_count":1}}"#,
        r#"{"action":"add","resource_ids":[],"resource_selection":{"resource_type":"port_list","expected_count":1}}"#,
        r#"{"action":"remove","resource_selection":{"resource_type":"port_list","expected_count":1}}"#,
        r#"{"action":"set","resource_selection":{"resource_type":"port_list","expected_count":1}}"#,
    ] {
        assert!(
            match serde_json::from_str::<TagResourceUpdateRequest>(value) {
                Ok(request) => validate_tag_resource_update_request(request).is_err(),
                Err(_) => true,
            }
        );
    }
    let oversized = format!(
        r#"{{"action":"add","resource_selection":{{"resource_type":"port_list","search":"{}","expected_count":1}}}}"#,
        "x".repeat(crate::collections::MAX_COLLECTION_FILTER_LENGTH + 1)
    );
    assert!(
        match serde_json::from_str::<TagResourceUpdateRequest>(&oversized) {
            Ok(request) => validate_tag_resource_update_request(request).is_err(),
            Err(_) => true,
        }
    );
}

#[test]
fn tag_port_list_selection_stays_native_parameterized_and_pre_mutation() {
    let handlers = include_str!("tag_writes.rs");
    assert!(handlers.contains("resource_filter.is_some()"));
    assert!(handlers.contains("LOCK TABLE port_lists, tags, tag_resources"));
    let transactions = include_str!("tag_write_transactions.rs");
    assert!(transactions.contains("tag_port_list_selection_sql()"));
    assert!(transactions.contains("&[&search, &predefined, &selection_limit]"));
    assert!(transactions.contains("i64::from(MAX_TAG_RESOURCE_SELECTION_MATCHES) + 1"));
    assert!(transactions.contains("rows.len() as i64 != *expected_count"));
    let patch_transaction = transactions
        .split_once("pub(crate) async fn execute_tag_patch_transaction")
        .unwrap()
        .1;
    assert!(
        patch_transaction
            .find("resolve_tag_resource_update_records")
            .unwrap()
            < patch_transaction.find("query_tag_write_record").unwrap()
    );
    let selector = crate::port_list_query_sql::tag_port_list_selection_sql();
    assert!(selector.contains("LIMIT $3"));
    let collection = crate::port_list_query_sql::port_list_assets_sql("name ASC");
    for fragment in ["lower", "LIKE '%'", "predefined"] {
        assert!(selector.contains(fragment));
        assert!(collection.contains(fragment));
    }
    assert!(selector.contains("$1") && selector.contains("$2"));
}

#[test]
fn tag_credential_selection_uses_row_locks_before_tag_tables() {
    let handlers = include_str!("tag_writes.rs");
    assert!(!handlers.contains("LOCK TABLE credentials"));
    assert!(handlers.contains("LOCK TABLE users IN SHARE MODE"));
    let patch = handlers
        .split_once("pub(crate) async fn patch_tag")
        .unwrap()
        .1
        .split_once("pub(crate) async fn clone_tag")
        .unwrap()
        .0;
    assert!(
        patch
            .find("resolve_tag_credential_selection_records")
            .unwrap()
            < patch
                .find("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE")
                .unwrap()
    );
    let selector = crate::credential_query_sql::tag_credential_selection_sql();
    let collection = crate::credential_query_sql::credential_assets_sql("name ASC");
    let selector_predicate = crate::credential_query_sql::credential_collection_predicate_sql(
        "c.uuid",
        "coalesce(c.name, '')",
        "coalesce(c.comment, '')",
        "coalesce(u.name, '')",
        "coalesce(c.type, '')",
        "$1",
        "$2",
    );
    let collection_predicate = crate::credential_query_sql::credential_collection_predicate_sql(
        "credential_rows.id",
        "credential_rows.name",
        "credential_rows.comment",
        "credential_rows.owner_name",
        "credential_rows.credential_type",
        "$1",
        "$4",
    );
    assert!(selector.contains(&selector_predicate));
    assert!(collection.contains(&collection_predicate));
    assert!(selector.contains("LIMIT $3"));
    assert!(selector.contains("FOR UPDATE OF c"));
    assert!(selector.contains("$1") && selector.contains("$2"));
}

#[test]
fn tag_create_request_accepts_explicit_resource_ids_only() {
    let request: TagCreateRequest = serde_json::from_str(
        r#"{"name":"owner:selected","resource_type":"task","resource_ids":["12345678-1234-1234-1234-123456789abc","12345678-1234-1234-1234-123456789abc"]}"#,
    )
    .expect("valid explicit-resource tag create request");
    let validated = validate_tag_create_request(request).expect("valid create request");
    assert_eq!(
        validated.resource_ids,
        vec!["12345678-1234-1234-1234-123456789abc".to_string()]
    );
    assert_eq!(
        tag_create_transaction_plan(&validated),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::CreateMetadata,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::InsertMetadata,
                TagWriteStep::VerifyResourceExists,
                TagWriteStep::VerifyResourceOwnerMatch,
                TagWriteStep::InsertResourceAssignment,
            ],
        }
    );

    assert!(
        serde_json::from_str::<TagCreateRequest>(
            r#"{"name":"x","resource_type":"task","resource_filter":"name~x"}"#,
        )
        .is_err(),
        "filter-based creation is not part of the native tag contract"
    );
}

#[test]
fn tag_write_accepts_any_human_owner_and_rejects_ownerless_rows() {
    assert_eq!(ensure_tag_is_human_owned(Some(7)).unwrap(), 7);
    assert!(matches!(
        ensure_tag_is_human_owned(None),
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
fn tag_patch_resolves_explicit_resources_before_metadata_write() {
    let source = include_str!("tag_write_transactions.rs");
    let transaction = source
        .split_once("pub(crate) async fn execute_tag_patch_transaction")
        .expect("tag patch transaction must exist")
        .1
        .split_once("async fn resolve_tag_resource_write_record")
        .expect("resource resolver must follow tag patch transaction")
        .0;

    let resolve = transaction
        .find("resolve_tag_resource_update_records")
        .expect("tag patch must resolve explicit resources");
    let metadata_write = transaction
        .find("query_tag_write_record")
        .expect("tag patch must update metadata");
    assert!(
        resolve < metadata_write,
        "tag patch must resolve and authorize all explicit resources before writing metadata"
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
            "ensure_tag_is_human_owned(trash.owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;",
            "execute_tag_restore_transaction",
        ),
        (
            "hard delete",
            "pub(crate) async fn hard_delete_tag",
            "pub(crate) async fn patch_tag",
            "ensure_tag_is_human_owned(trash.owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;",
            "execute_tag_hard_delete_transaction",
        ),
        (
            "patch",
            "pub(crate) async fn patch_tag",
            "pub(crate) async fn clone_tag",
            "ensure_tag_is_human_owned(state.owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(effective_resource_type)?;",
            "execute_tag_patch_transaction",
        ),
        (
            "clone",
            "pub(crate) async fn clone_tag",
            "pub(crate) async fn delete_tag",
            "ensure_tag_is_human_owned(source.owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&source.resource_type)?;",
            "execute_tag_clone_transaction",
        ),
        (
            "delete",
            "pub(crate) async fn delete_tag",
            "pub(crate) async fn update_tag_resources",
            "ensure_tag_is_human_owned(state.owner_id)?;",
            "ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;",
            "execute_tag_trash_transaction",
        ),
        (
            "resource update",
            "pub(crate) async fn update_tag_resources",
            "fn tag_write_location_headers",
            "ensure_tag_is_human_owned(state.owner_id)?;",
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
fn tag_resource_write_accepts_human_owned_team_resources() {
    assert!(ensure_tag_resource_is_team_assignable("target", Some(7)).is_ok());
    assert!(ensure_tag_resource_is_team_assignable("target", Some(8)).is_ok());
    assert!(matches!(
        ensure_tag_resource_is_team_assignable("target", None),
        Err(ApiError::Forbidden)
    ));
    assert!(ensure_tag_resource_is_team_assignable("credential", Some(7)).is_ok());
    assert!(ensure_tag_resource_is_team_assignable("credential", Some(8)).is_ok());
    assert!(ensure_tag_resource_is_team_assignable("cve", None).is_ok());
    assert!(ensure_tag_resource_is_team_assignable("nvt", None).is_ok());
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
            r#"{"name":"x","resource_type":"task","resources_filter":"name~x"}"#
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
        resource_ids: Vec::new(),
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
        resource_type: "tag".to_string(),
        resource_ids: Vec::new(),
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
fn tag_patch_request_supports_atomic_resource_selection_and_requires_a_field() {
    let patch: TagPatchRequest = serde_json::from_str(
        r#"{"name":"  owner:patched ","comment":"","value":" v ","active":true}"#,
    )
    .expect("valid tag patch request");
    let validated = validate_tag_patch_request(patch).expect("valid patch request");
    assert_eq!(validated.name.as_deref(), Some("owner:patched"));
    assert_eq!(validated.comment.as_deref(), Some(""));
    assert_eq!(validated.value.as_deref(), Some("v"));
    assert_eq!(validated.active, Some(true));

    let type_only: TagPatchRequest = serde_json::from_str(r#"{"resource_type":"target"}"#).unwrap();
    assert!(matches!(
        validate_tag_patch_request(type_only),
        Err(ApiError::BadRequest(_))
    ));
    let type_and_set: TagPatchRequest = serde_json::from_str(
        r#"{"name":"renamed","resource_type":"target","resources":{"action":"set","resource_ids":[]}}"#,
    )
    .unwrap();
    let type_and_set =
        validate_tag_patch_request(type_and_set).expect("type change with atomic set validates");
    assert_eq!(type_and_set.resource_type.as_deref(), Some("target"));
    assert_eq!(
        type_and_set.resources.as_ref().map(|value| value.action),
        Some(TagResourceUpdateAction::Set)
    );
    let empty = TagPatchRequest {
        name: None,
        comment: None,
        value: None,
        active: None,
        resource_type: None,
        resources: None,
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
        resource_type: None,
        resources: None,
    };
    assert!(matches!(
        validate_tag_patch_request(empty_name),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_patch_uses_gvmd_control_only_for_filter_selection() {
    let metadata = validate_tag_patch_request(
        serde_json::from_str(r#"{"name":"renamed"}"#).expect("metadata patch"),
    )
    .expect("valid metadata patch");
    assert!(!tag_patch_requires_control(&metadata));

    let explicit_set = validate_tag_patch_request(
        serde_json::from_str(
            r#"{"resource_type":"target","resources":{"action":"set","resource_ids":["12345678-1234-1234-1234-123456789abc"]}}"#,
        )
        .expect("explicit resource patch"),
    )
    .expect("valid explicit resource patch");
    assert!(!tag_patch_requires_control(&explicit_set));

    let filtered = validate_tag_patch_request(
        serde_json::from_str(
            r#"{"resources":{"action":"add","resource_filter":"name~production"}}"#,
        )
        .expect("filtered resource patch"),
    )
    .expect("valid filtered resource patch");
    assert!(tag_patch_requires_control(&filtered));

    let typed = validate_tag_patch_request(
        serde_json::from_str(
            r#"{"resources":{"action":"add","resource_selection":{"resource_type":"port_list","expected_count":1}}}"#,
        )
        .expect("typed resource patch"),
    )
    .expect("valid typed resource patch");
    assert!(!tag_patch_requires_control(&typed));
}

#[test]
fn tag_resource_update_request_supports_explicit_ids_filters_and_empty_set() {
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

    let set_request: TagResourceUpdateRequest = serde_json::from_str(
        r#"{"action":"set","resource_ids":["12345678-1234-1234-1234-123456789abc"]}"#,
    )
    .expect("valid set tag resource update request");
    let set_validated =
        validate_tag_resource_update_request(set_request).expect("valid set resource update");
    assert_eq!(set_validated.action, TagResourceUpdateAction::Set);
    assert_eq!(
        set_validated.resource_ids,
        vec!["12345678-1234-1234-1234-123456789abc".to_string()]
    );

    let clear = validate_tag_resource_update_request(
        serde_json::from_str::<TagResourceUpdateRequest>(r#"{"action":"set","resource_ids":[]}"#)
            .expect("set action with empty ids deserializes"),
    )
    .expect("empty set clears assignments");
    assert!(clear.resource_ids.is_empty());
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"replace","resource_ids":["12345678-1234-1234-1234-123456789abc"]}"#,
        )
        .is_err()
    );
    let filtered = validate_tag_resource_update_request(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_filter":"name~x"}"#,
        )
        .expect("filter selection deserializes"),
    )
    .expect("filter selection validates");
    assert_eq!(filtered.resource_filter.as_deref(), Some("name~x"));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: Some(Vec::new()),
            resource_filter: None,
            resource_selection: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Remove,
            resource_ids: Some(vec!["bad\nresource".to_string()]),
            resource_filter: None,
            resource_selection: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: Some(vec![
                "12345678-1234-1234-1234-123456789abc".to_string();
                MAX_TAG_RESOURCE_WRITE_IDS + 1
            ]),
            resource_filter: None,
            resource_selection: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn tag_resource_update_request_rejects_ambiguous_selection_and_bad_ids() {
    let implicit: TagResourceUpdateRequest = serde_json::from_str(r#"{"action":"add"}"#).unwrap();
    assert!(matches!(
        validate_tag_resource_update_request(implicit),
        Err(ApiError::BadRequest(_))
    ));
    assert!(
        serde_json::from_str::<TagResourceUpdateRequest>(
            r#"{"action":"add","resource_type":"target","resource_ids":["12345678-1234-1234-1234-123456789abc"]}"#,
        )
        .is_err()
    );
    let mixed: TagResourceUpdateRequest = serde_json::from_str(
        r#"{"action":"add","resource_ids":["12345678-1234-1234-1234-123456789abc"],"resource_filter":"name~prod"}"#,
    )
    .unwrap();
    assert!(matches!(
        validate_tag_resource_update_request(mixed),
        Err(ApiError::BadRequest(_))
    ));
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
            resource_ids: Some(vec![" ".to_string()]),
            resource_filter: None,
            resource_selection: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_tag_resource_update_request(TagResourceUpdateRequest {
            action: TagResourceUpdateAction::Add,
            resource_ids: Some(vec!["x".repeat(MAX_TAG_RESOURCE_ID_BYTES + 1)]),
            resource_filter: None,
            resource_selection: None,
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
fn tag_write_plans_keep_mutation_steps_explicit() {
    let create = ValidatedTagCreate {
        name: "owner:x".to_string(),
        resource_type: "task".to_string(),
        resource_ids: Vec::new(),
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

    let set_resource_update = ValidatedTagResourceUpdate {
        action: TagResourceUpdateAction::Set,
        resource_ids: vec!["12345678-1234-1234-1234-123456789abc".to_string()],
        resource_filter: None,
        resource_selection: None,
    };
    assert_eq!(
        tag_resource_update_transaction_plan(&set_resource_update),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::UpdateResourceAssignments,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::VerifyResourceExists,
                TagWriteStep::VerifyResourceOwnerMatch,
                TagWriteStep::ClearResourceAssignments,
                TagWriteStep::InsertResourceAssignment,
                TagWriteStep::TouchMetadata,
            ],
        }
    );

    let patch = ValidatedTagPatch {
        name: Some("owner:y".to_string()),
        comment: None,
        value: None,
        active: None,
        resource_type: None,
        resources: None,
    };
    assert_eq!(
        tag_patch_transaction_plan(&patch),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::PatchMetadata,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::UpdateMetadata,
            ],
        }
    );

    let patch_with_resources = ValidatedTagPatch {
        name: Some("owner:z".to_string()),
        comment: None,
        value: None,
        active: None,
        resource_type: Some("target".to_string()),
        resources: Some(ValidatedTagResourceUpdate {
            action: TagResourceUpdateAction::Set,
            resource_ids: vec!["12345678-1234-1234-1234-123456789abc".to_string()],
            resource_filter: None,
            resource_selection: None,
        }),
    };
    assert_eq!(
        tag_patch_transaction_plan(&patch_with_resources),
        TagWriteTransactionPlan {
            operation: TagWriteOperation::PatchMetadataAndAssignments,
            steps: vec![
                TagWriteStep::ResolveOperatorOwner,
                TagWriteStep::VerifyTagExists,
                TagWriteStep::VerifyOwnerMatch,
                TagWriteStep::VerifyResourceTypeSupported,
                TagWriteStep::VerifyResourceExists,
                TagWriteStep::VerifyResourceOwnerMatch,
                TagWriteStep::UpdateMetadata,
                TagWriteStep::ClearResourceAssignments,
                TagWriteStep::InsertResourceAssignment,
                TagWriteStep::TouchMetadata,
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
        resource_filter: None,
        resource_selection: None,
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
    assert!(update.contains("resource_type = coalesce($6, resource_type)"));
    assert!(update.contains("WHERE id = $1"));
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

    let clear_resources = tag_resource_clear_sql();
    assert!(clear_resources.contains("DELETE FROM tag_resources"));
    assert!(clear_resources.contains("WHERE tag = $1"));
    assert!(!clear_resources.contains("resource_type"));
    assert!(!clear_resources.contains("resource_location"));

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

#[test]
fn tag_commit_failures_are_classified_as_indeterminate() {
    let handler = include_str!("tag_writes.rs");
    let database_helpers = include_str!("tag_write_db.rs");

    assert_eq!(handler.matches("map_tag_commit_error(error,").count(), 9);
    assert!(!handler.contains("map_tag_write_db_error(error, \"commit "));
    assert!(database_helpers.contains("ApiError::MutationOutcomeIndeterminate"));
}
