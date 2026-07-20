// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::scope_write_db::{
    ensure_scope_is_human_owned, ensure_scope_is_mutable, ensure_scope_write_references_visible,
};
use crate::scope_write_plans::*;
use crate::scope_write_sql::*;
use crate::scope_write_validation::{ValidatedScopeCreate, ValidatedScopePatch};

#[test]
fn scope_create_request_normalizes_defaults_and_membership_ids() {
    let request: ScopeCreateRequest = serde_json::from_str(
        r#"{
            "name": "  Example scope  ",
            "comment": "  retained  ",
            "protection_requirement": "Very High",
            "target_ids": ["12345678-1234-1234-1234-123456789ABC"],
            "host_ids": []
        }"#,
    )
    .expect("valid create DTO");

    let validated = validate_scope_create_request(request).expect("valid create request");

    assert_eq!(validated.name, "Example scope");
    assert_eq!(validated.comment.as_deref(), Some("retained"));
    assert_eq!(validated.protection_requirement, "very_high");
    assert_eq!(
        validated.target_ids,
        vec!["12345678-1234-1234-1234-123456789abc"]
    );
    assert!(validated.host_ids.is_empty());

    let defaulted = validate_scope_create_request(ScopeCreateRequest {
        name: "Defaulted".to_string(),
        comment: None,
        protection_requirement: None,
        target_ids: vec![],
        host_ids: vec![],
    })
    .expect("defaulted create request");
    assert_eq!(defaulted.protection_requirement, "normal");
}

#[test]
fn scope_write_accepts_any_human_owner_and_rejects_ownerless_scopes() {
    assert!(ensure_scope_is_human_owned(Some(7)).is_ok());
    assert!(ensure_scope_is_human_owned(Some(8)).is_ok());
    assert!(matches!(
        ensure_scope_is_human_owned(None),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn scope_write_dtos_reject_unknown_fields_bad_text_and_bad_enums() {
    assert!(serde_json::from_str::<ScopeCreateRequest>(r#"{"name":"x","extra":1}"#).is_err());

    let empty_name = ScopeCreateRequest {
        name: "   ".to_string(),
        comment: None,
        protection_requirement: None,
        target_ids: vec![],
        host_ids: vec![],
    };
    assert!(matches!(
        validate_scope_create_request(empty_name),
        Err(ApiError::BadRequest(_))
    ));

    let bad_enum = ScopeCreateRequest {
        name: "scope".to_string(),
        comment: None,
        protection_requirement: Some("critical".to_string()),
        target_ids: vec![],
        host_ids: vec![],
    };
    assert!(matches!(
        validate_scope_create_request(bad_enum),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scope_membership_validation_rejects_invalid_and_duplicate_uuids() {
    let duplicate = ScopeCreateRequest {
        name: "scope".to_string(),
        comment: None,
        protection_requirement: None,
        target_ids: vec![
            "12345678-1234-1234-1234-123456789abc".to_string(),
            "12345678-1234-1234-1234-123456789ABC".to_string(),
        ],
        host_ids: vec![],
    };
    assert!(matches!(
        validate_scope_create_request(duplicate),
        Err(ApiError::Conflict(_))
    ));

    let invalid = ScopePatchRequest {
        name: None,
        comment: None,
        protection_requirement: None,
        target_ids: None,
        host_ids: Some(vec!["not-a-uuid".to_string()]),
    };
    assert!(matches!(
        validate_scope_patch_request(invalid),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scope_patch_request_distinguishes_preserve_and_replace_membership() {
    let preserve = validate_scope_patch_request(ScopePatchRequest {
        name: None,
        comment: None,
        protection_requirement: None,
        target_ids: None,
        host_ids: None,
    })
    .expect("preserve-only patch");
    assert_eq!(preserve.target_ids, None);
    assert_eq!(preserve.host_ids, None);

    let replace = validate_scope_patch_request(ScopePatchRequest {
        name: Some("renamed".to_string()),
        comment: None,
        protection_requirement: Some("high".to_string()),
        target_ids: Some(vec![]),
        host_ids: Some(vec!["12345678-1234-1234-1234-123456789abc".to_string()]),
    })
    .expect("replace-membership patch");
    assert_eq!(replace.name.as_deref(), Some("renamed"));
    assert_eq!(replace.protection_requirement.as_deref(), Some("high"));
    assert_eq!(replace.target_ids, Some(vec![]));
    assert_eq!(
        replace.host_ids,
        Some(vec!["12345678-1234-1234-1234-123456789abc".to_string()])
    );
}

#[test]
fn scope_mutability_guard_blocks_global_or_predefined_scopes() {
    assert!(ensure_scope_is_mutable(false, false).is_ok());
    for (is_global, predefined) in [(true, false), (false, true), (true, true)] {
        assert!(matches!(
            ensure_scope_is_mutable(is_global, predefined),
            Err(ApiError::Conflict(_))
        ));
    }
}

#[test]
fn scope_reference_visibility_rejects_missing_or_unauthorized_membership() {
    let requested = vec![
        "12345678-1234-1234-1234-123456789abc".to_string(),
        "22345678-1234-1234-1234-123456789abc".to_string(),
    ];
    let visible = vec![
        "12345678-1234-1234-1234-123456789abc".to_string(),
        "22345678-1234-1234-1234-123456789abc".to_string(),
    ];
    assert!(ensure_scope_write_references_visible("target_ids", &requested, &visible).is_ok());

    let partial_visible = vec!["12345678-1234-1234-1234-123456789abc".to_string()];
    assert!(matches!(
        ensure_scope_write_references_visible("target_ids", &requested, &partial_visible),
        Err(ApiError::Forbidden)
    ));

    let empty: Vec<String> = vec![];
    assert!(ensure_scope_write_references_visible("host_ids", &empty, &partial_visible).is_ok());
}

#[test]
fn scope_write_transaction_plans_keep_validation_before_mutations() {
    let create = ValidatedScopeCreate {
        name: "scope".to_string(),
        comment: None,
        protection_requirement: "normal".to_string(),
        target_ids: vec!["12345678-1234-1234-1234-123456789abc".to_string()],
        host_ids: vec![],
    };
    assert_eq!(
        scope_create_transaction_plan(&create),
        ScopeWriteTransactionPlan {
            operation: ScopeWriteOperation::Create,
            steps: vec![
                ScopeWriteStep::ResolveOperatorOwner,
                ScopeWriteStep::VerifyReferenceVisibility,
                ScopeWriteStep::InsertScope,
                ScopeWriteStep::ReplaceTargetMembership,
                ScopeWriteStep::ReplaceHostMembership,
            ],
        }
    );

    let patch = ValidatedScopePatch {
        name: Some("renamed".to_string()),
        comment: None,
        protection_requirement: None,
        target_ids: Some(vec![]),
        host_ids: None,
    };
    assert_eq!(
        scope_patch_transaction_plan(&patch),
        ScopeWriteTransactionPlan {
            operation: ScopeWriteOperation::Patch,
            steps: vec![
                ScopeWriteStep::ResolveOperatorOwner,
                ScopeWriteStep::VerifyScopeMutable,
                ScopeWriteStep::VerifyHumanOwner,
                ScopeWriteStep::VerifyReferenceVisibility,
                ScopeWriteStep::UpdateScopeMetadata,
                ScopeWriteStep::ReplaceTargetMembership,
            ],
        }
    );

    assert_eq!(
        scope_delete_transaction_plan(),
        ScopeWriteTransactionPlan {
            operation: ScopeWriteOperation::Delete,
            steps: vec![
                ScopeWriteStep::ResolveOperatorOwner,
                ScopeWriteStep::VerifyScopeMutable,
                ScopeWriteStep::VerifyHumanOwner,
                ScopeWriteStep::VerifyNoScopeReportHistory,
                ScopeWriteStep::DeleteScopeMembership,
                ScopeWriteStep::DeleteScope,
            ],
        }
    );
}

#[test]
fn scope_write_scaffold_sql_is_read_only_and_targets_expected_tables() {
    for sql in [
        scope_write_operator_owner_sql(),
        scope_write_mutability_sql(),
        scope_write_report_history_sql(),
        scope_write_visible_targets_sql(),
        scope_write_visible_hosts_sql(),
    ] {
        let upper_sql = sql.trim_start().to_ascii_uppercase();
        assert!(
            upper_sql.starts_with("SELECT"),
            "non-SELECT scope read SQL: {sql}"
        );
    }
    assert!(scope_write_operator_owner_sql().contains("FROM users"));
    assert!(scope_write_mutability_sql().contains("FROM scopes"));
    assert!(scope_write_mutability_sql().contains("owner::integer"));
    assert!(scope_write_report_history_sql().contains("FROM scope_reports"));
    assert!(scope_write_mutability_sql().contains("FOR UPDATE"));
    assert!(scope_write_visible_targets_sql().contains("FROM targets"));
    assert!(scope_write_visible_hosts_sql().contains("FROM hosts"));
}

#[test]
fn scope_write_mutation_sql_is_parameterized_and_scope_bounded() {
    assert!(scope_by_internal_id_sql().contains("WHERE id = $1"));

    let insert = scope_insert_sql();
    assert!(insert.contains("INSERT INTO scopes"));
    assert!(insert.contains("VALUES (make_uuid(), $1, $2, $3, $4, 0, 0"));
    assert!(insert.contains("RETURNING id::integer, uuid::text"));

    let update = scope_update_metadata_sql();
    assert!(update.contains("UPDATE scopes"));
    assert!(update.contains("name = coalesce($2, name)"));
    assert!(update.contains("comment = coalesce($3, comment)"));
    assert!(update.contains("protection_requirement = coalesce($4, protection_requirement)"));
    assert!(update.contains("WHERE id = $1"));

    for (delete_sql, insert_sql, table, source_table) in [
        (
            scope_delete_targets_sql(),
            scope_insert_target_sql(),
            "scope_targets",
            "targets",
        ),
        (
            scope_delete_hosts_sql(),
            scope_insert_host_sql(),
            "scope_hosts",
            "hosts",
        ),
    ] {
        assert_eq!(delete_sql, format!("DELETE FROM {table} WHERE scope = $1;"));
        assert!(insert_sql.contains(table));
        assert!(insert_sql.contains(source_table));
        assert!(insert_sql.contains("WHERE uuid = $2"));
        assert!(insert_sql.contains("ON CONFLICT"));
    }

    assert_eq!(scope_delete_sql(), "DELETE FROM scopes WHERE id = $1;");
}

#[test]
fn scope_write_execution_helpers_stay_private_transaction_scaffold() {
    let _create = execute_scope_create_transaction;
    let _patch = execute_scope_patch_transaction;
    let _delete = execute_scope_delete_transaction;

    let source = include_str!("scope_write_transactions.rs");
    let create_body = source
        .split_once("pub(crate) async fn execute_scope_create_transaction")
        .expect("create executor must exist")
        .1
        .split_once("pub(crate) async fn execute_scope_patch_transaction")
        .expect("create executor must precede patch executor")
        .0;
    let patch_body = source
        .split_once("pub(crate) async fn execute_scope_patch_transaction")
        .expect("patch executor must exist")
        .1
        .split_once("pub(crate) async fn execute_scope_delete_transaction")
        .expect("patch executor must precede delete executor")
        .0;
    let delete_body = source
        .split_once("pub(crate) async fn execute_scope_delete_transaction")
        .expect("delete executor must exist")
        .1
        .split_once("async fn query_scope_write_record")
        .expect("delete executor must precede shared query helper")
        .0;

    assert!(create_body.contains("scope_insert_sql()"));
    assert!(create_body.contains("replace_scope_membership"));
    assert!(patch_body.contains("scope_update_metadata_sql()"));
    assert!(patch_body.contains("scope_by_internal_id_sql()"));
    assert!(delete_body.contains("scope_delete_targets_sql()"));
    assert!(delete_body.contains("scope_delete_hosts_sql()"));
    assert!(delete_body.contains("scope_delete_sql()"));
    for body in [create_body, patch_body, delete_body] {
        assert!(body.contains("tx,"));
        assert!(!body.contains("state.pool"));
        assert!(!body.contains("transaction().await"));
        assert!(!body.contains("commit().await"));
    }
}

#[test]
fn scope_write_location_header_points_to_native_scope_detail() {
    let headers = scope_write_location_headers("12345678-1234-1234-1234-123456789abc")
        .expect("valid location header");

    assert_eq!(
        headers
            .get(header::LOCATION)
            .expect("location header")
            .to_str()
            .expect("ascii location"),
        "/api/v1/scopes/12345678-1234-1234-1234-123456789abc"
    );
}

#[test]
fn scope_write_operator_guard_fails_closed_without_direct_context() {
    assert!(matches!(
        require_scope_write_operator(None),
        Err(ApiError::Forbidden)
    ));

    let operator = DirectApiOperator::new(
        "12345678-1234-1234-1234-123456789abc",
        Some("operator".to_string()),
    )
    .expect("valid direct operator");
    assert_eq!(
        require_scope_write_operator(Some(Extension(operator.clone()))).expect("operator"),
        operator
    );
}

#[test]
fn scope_write_handlers_require_operator_transactions_and_payload_reload() {
    let _create = create_scope;
    let _patch = patch_scope;
    let _delete = delete_scope;

    let source = include_str!("scope_writes.rs");
    let create_body = source
        .split_once("pub(crate) async fn create_scope")
        .expect("create handler must exist")
        .1
        .split_once("pub(crate) async fn patch_scope")
        .expect("create handler must precede patch handler")
        .0;
    let patch_body = source
        .split_once("pub(crate) async fn patch_scope")
        .expect("patch handler must exist")
        .1
        .split_once("pub(crate) async fn delete_scope")
        .expect("patch handler must precede delete handler")
        .0;
    let delete_body = source
        .split_once("pub(crate) async fn delete_scope")
        .expect("delete handler must exist")
        .1
        .split_once("fn scope_write_location_headers")
        .expect("delete handler must precede location header helper")
        .0;

    for body in [create_body, patch_body, delete_body] {
        assert!(body.contains("operator: Option<Extension<DirectApiOperator>>"));
        assert!(body.contains("let operator = require_scope_write_operator(operator)?;"));
        assert!(body.contains("state.pool.get()"));
        assert!(body.contains("client"));
        assert!(body.contains(".transaction()"));
        assert!(body.contains("resolve_scope_write_operator_owner(&tx, &operator).await?"));
        assert!(body.contains("tx.commit()"));
    }
    assert!(create_body.contains("verify_scope_write_references_visible"));
    assert!(patch_body.contains("load_mutable_scope_write_state"));
    assert!(patch_body.contains("ensure_scope_is_human_owned"));
    assert!(patch_body.contains("verify_scope_write_references_visible"));
    assert!(delete_body.contains("ensure_scope_is_human_owned"));
    assert!(delete_body.contains("ensure_scope_has_no_report_history"));
    assert!(
        delete_body
            .find("load_mutable_scope_write_state")
            .expect("scope delete must lock and load the scope")
            < delete_body
                .find("ensure_scope_has_no_report_history")
                .expect("scope delete must check report history after locking"),
        "scope delete must lock the scope before checking report history"
    );
    for body in [create_body, patch_body] {
        assert!(body.contains("load_scope_detail(&client"));
    }
}

#[test]
fn scope_write_scaffold_is_not_registered_as_a_live_route() {
    let main_source = include_str!("main.rs");
    let routes_source = include_str!("read_api_routes.rs");
    let router_block = routes_source
        .split_once("pub(crate) fn native_api_router() -> Router<AppState> {\n    Router::new()")
        .expect("router setup must exist")
        .1
        .split_once("\n}\n")
        .expect("base router setup must end")
        .0;

    assert!(main_source.contains("mod scope_writes;"));
    for forbidden in [
        "post(scope",
        "put(scope",
        "patch(scope",
        "delete(scope",
        "route(\"/api/v1/scopes\", post",
        "route(\"/api/v1/scopes/:scope_id\", patch",
        "route(\"/api/v1/scopes/:scope_id\", delete",
    ] {
        assert!(
            !router_block.contains(forbidden),
            "live scope write route: {forbidden}"
        );
    }
}
