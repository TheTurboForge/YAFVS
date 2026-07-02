// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::{
    errors::ApiError,
    filter_write_plans::*,
    filter_write_sql::*,
    filter_write_validation::{
        FilterCloneRequest, FilterPatchRequest, MAX_FILTER_TEXT_BYTES, ValidatedFilterPatch,
        validate_filter_clone_request, validate_filter_patch_request,
    },
};

fn clone_request(name: Option<&str>, comment: Option<&str>) -> FilterCloneRequest {
    FilterCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn patch_request(name: Option<&str>, comment: Option<&str>) -> FilterPatchRequest {
    FilterPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        filter_type: None,
        term: None,
    }
}

fn patch_request_with_term_type(
    name: Option<&str>,
    comment: Option<&str>,
    filter_type: Option<&str>,
    term: Option<&str>,
) -> FilterPatchRequest {
    FilterPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        filter_type: filter_type.map(str::to_string),
        term: term.map(str::to_string),
    }
}

#[test]
fn filter_write_rejects_operator_owner_mismatch() {
    assert!(ensure_filter_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_filter_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn filter_clone_handler_enforces_source_owner_check() {
    let source = include_str!("filter_writes.rs");
    let clone_handler = source
        .split_once("pub(crate) async fn clone_filter")
        .expect("clone filter handler must exist")
        .1
        .split_once("pub(crate) async fn restore_filter")
        .expect("restore handler must follow clone handler")
        .0;

    assert!(clone_handler.contains("let source = load_filter_write_state"));
    assert!(
        clone_handler.contains("ensure_filter_owner_matches_operator(source.owner_id, owner_id)?;")
    );
    assert!(
        clone_handler
            .find("ensure_filter_owner_matches_operator")
            .unwrap()
            < clone_handler
                .find("execute_filter_clone_transaction")
                .unwrap(),
        "clone source owner must be checked before cloning"
    );
}

#[test]
fn filter_destructive_handlers_enforce_owner_before_mutation() {
    let source = include_str!("filter_writes.rs");
    for (label, start, end, owner_check, side_effect) in [
        (
            "delete",
            "pub(crate) async fn delete_filter",
            "pub(crate) async fn clone_filter",
            "ensure_filter_owner_matches_operator(state.owner_id, operator_owner_id)?;",
            "ensure_filter_not_in_use_by_alerts",
        ),
        (
            "restore",
            "pub(crate) async fn restore_filter",
            "pub(crate) async fn hard_delete_filter",
            "ensure_filter_owner_matches_operator(trash.owner_id, operator_owner_id)?;",
            "execute_filter_restore_transaction",
        ),
        (
            "hard delete",
            "pub(crate) async fn hard_delete_filter",
            "pub(crate) async fn patch_filter",
            "ensure_filter_owner_matches_operator(trash.owner_id, operator_owner_id)?;",
            "ensure_filter_not_in_use_by_trash_alerts",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} handler end marker must exist"))
            .0;

        assert!(
            handler.contains(owner_check),
            "{label} handler must check owner"
        );
        assert!(
            handler.find(owner_check).unwrap() < handler.find(side_effect).unwrap(),
            "{label} owner check must happen before destructive side effects"
        );
    }
}

#[test]
fn filter_clone_request_accepts_default_or_metadata_override() {
    let default =
        validate_filter_clone_request(clone_request(None, None)).expect("default clone metadata");
    assert_eq!(default.name, None);
    assert_eq!(default.comment, None);

    let named = validate_filter_clone_request(clone_request(
        Some("  Operator filter copy  "),
        Some("  copied note  "),
    ))
    .expect("named clone");
    assert_eq!(named.name.as_deref(), Some("Operator filter copy"));
    assert_eq!(named.comment.as_deref(), Some("copied note"));

    let clear_comment = validate_filter_clone_request(clone_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(clear_comment.comment.as_deref(), Some(""));
}

#[test]
fn filter_clone_request_rejects_blank_name_control_characters_and_term_type_fields() {
    assert!(matches!(
        validate_filter_clone_request(clone_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_filter_clone_request(clone_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    for request in [
        serde_json::json!({"name": "copy", "term": "rows=100"}),
        serde_json::json!({"name": "copy", "type": "result"}),
        serde_json::json!({"name": "copy", "alerts": []}),
    ] {
        assert!(serde_json::from_value::<FilterCloneRequest>(request).is_err());
    }
}

#[test]
fn filter_clone_sql_copies_term_type_and_tags_without_term_mutation() {
    let metadata = filter_clone_metadata_sql();
    assert!(metadata.contains("INSERT INTO filters"));
    assert!(metadata.contains("coalesce($3, uniquify('filter', name, $2, ' Clone'))"));
    assert!(metadata.contains("coalesce($4, comment)"));
    assert!(metadata.contains("type,"));
    assert!(metadata.contains("term,"));
    assert!(metadata.contains("FROM filters"));
    assert!(metadata.contains("WHERE id = $1"));

    let tags = filter_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'filter'"));
    assert!(tags.contains("resource_location = 0"));

    for sql in [metadata, tags] {
        assert!(!sql.contains("filters_trash"));
        assert!(!sql.contains("alert"));
        assert!(!sql.contains("DELETE"));
    }
}

#[test]
fn filter_clone_plan_copies_metadata_and_tags_after_optional_name_check() {
    let named = validate_filter_clone_request(clone_request(Some("copy"), None))
        .expect("valid named clone");
    assert_eq!(
        filter_clone_transaction_plan(&named).steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::CloneFilterMetadata,
            FilterWriteStep::CloneFilterTags,
        ]
    );

    let default =
        validate_filter_clone_request(clone_request(None, None)).expect("valid default clone");
    assert_eq!(
        filter_clone_transaction_plan(&default).steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::CloneFilterMetadata,
            FilterWriteStep::CloneFilterTags,
        ]
    );
}

#[test]
fn filter_hard_delete_sql_guards_trash_alerts_and_deletes_only_trash_metadata_and_tags() {
    let direct_guard = filter_trash_alert_count_sql();
    assert!(direct_guard.contains("FROM alerts_trash"));
    assert!(direct_guard.contains("WHERE filter = $1"));
    assert!(direct_guard.contains("filter_location = 1"));

    let condition_guard = filter_trash_alert_condition_count_sql();
    assert!(condition_guard.contains("FROM alert_condition_data_trash"));
    assert!(condition_guard.contains("name = 'filter_id'"));
    assert!(condition_guard.contains("FROM filters_trash WHERE id = $1"));
    assert!(condition_guard.contains("condition IN (4, 5)"));

    for sql in [
        filter_trash_tag_delete_sql(),
        filter_trash_tag_trash_delete_sql(),
    ] {
        assert!(sql.contains("resource_type = 'filter'"));
        assert!(sql.contains("resource_location = 1"));
        assert!(sql.contains("resource = $1"));
    }

    let metadata_delete = filter_delete_trash_metadata_sql();
    assert_eq!(metadata_delete, "DELETE FROM filters_trash WHERE id = $1;");
    assert!(!metadata_delete.contains("DELETE FROM filters WHERE"));
}

#[test]
fn filter_create_plan_keeps_normalization_before_insert() {
    assert_eq!(
        filter_create_transaction_plan().steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::InsertFilter,
        ]
    );
}

#[test]
fn filter_hard_delete_plan_keeps_trash_safety_and_side_effects_explicit() {
    assert_eq!(
        filter_hard_delete_transaction_plan().steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::VerifyTrashAlertDeleteSafety,
            FilterWriteStep::RemoveTrashTagLinks,
            FilterWriteStep::HardDeleteFilterFromTrash,
        ]
    );
}

#[test]
fn filter_restore_sql_moves_metadata_trash_alerts_and_tags_to_live() {
    let state = filter_trash_state_sql();
    assert!(state.contains("FROM filters_trash"));
    assert!(state.contains("uuid = $1"));

    let restore = filter_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO filters"));
    assert!(restore.contains("SELECT uuid, owner, name, comment, type, term"));
    assert!(restore.contains("FROM filters_trash"));
    assert!(restore.contains("WHERE id = $1"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));

    let alert_relink = filter_trash_alert_relink_to_live_sql();
    assert!(alert_relink.contains("UPDATE alerts_trash"));
    assert!(alert_relink.contains("filter_location = 0"));
    assert!(alert_relink.contains("WHERE filter = $1"));
    assert!(alert_relink.contains("filter_location = 1"));

    for sql in [
        filter_tag_locations_to_live_sql(),
        filter_trash_tag_locations_to_live_sql(),
    ] {
        assert!(sql.contains("resource_type = 'filter'"));
        assert!(sql.contains("resource_location = 0"));
        assert!(sql.contains("resource = $1"));
        assert!(sql.contains("resource = $2"));
    }

    assert_eq!(
        filter_delete_trash_metadata_sql(),
        "DELETE FROM filters_trash WHERE id = $1;"
    );
}

#[test]
fn filter_restore_checks_live_owner_name_and_uuid_conflicts() {
    let unique_name = filter_unique_live_owner_name_sql();
    assert!(unique_name.contains("FROM filters"));
    assert!(unique_name.contains("WHERE name = $1"));
    assert!(unique_name.contains("owner = $2"));

    let uuid_conflict = filter_live_uuid_conflict_sql();
    assert!(uuid_conflict.contains("FROM filters"));
    assert!(uuid_conflict.contains("WHERE uuid = $1"));
}

#[test]
fn filter_restore_plan_keeps_trash_relocation_explicit() {
    assert_eq!(
        filter_restore_transaction_plan().steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::RestoreFilterFromTrash,
            FilterWriteStep::RelocateTrashAlerts,
            FilterWriteStep::RelocatePermissionsAndTags,
        ]
    );
}

#[test]
fn filter_patch_request_trims_metadata_fields() {
    assert_eq!(
        validate_filter_patch_request(patch_request(
            Some("  Results filter  "),
            Some("  operator-visible note  "),
        ))
        .unwrap(),
        ValidatedFilterPatch {
            name: Some("Results filter".to_string()),
            comment: Some("operator-visible note".to_string()),
            filter_type: None,
            term: None,
        }
    );
}

#[test]
fn filter_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_filter_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn filter_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_filter_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn filter_patch_request_allows_blank_comment_to_clear_comment() {
    assert_eq!(
        validate_filter_patch_request(patch_request(None, Some("   "))).unwrap(),
        ValidatedFilterPatch {
            name: None,
            comment: Some(String::new()),
            filter_type: None,
            term: None,
        }
    );
}

#[test]
fn filter_patch_request_rejects_control_characters() {
    assert!(matches!(
        validate_filter_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_filter_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn filter_patch_request_accepts_term_type_and_rejects_unknown_fields() {
    let validated = validate_filter_patch_request(patch_request_with_term_type(
        None,
        Some("  updated note  "),
        Some("scan config"),
        Some("  rows=100 sort=name  "),
    ))
    .expect("valid term/type patch");
    assert_eq!(validated.comment.as_deref(), Some("updated note"));
    assert_eq!(validated.filter_type.as_deref(), Some("config"));
    assert_eq!(validated.term.as_deref(), Some("rows=100 sort=name"));

    assert!(matches!(
        validate_filter_patch_request(patch_request_with_term_type(
            None,
            None,
            Some("banana"),
            None
        )),
        Err(ApiError::BadRequest(_))
    ));
    for request in [
        serde_json::json!({"name": "Results filter", "type": "result"}),
        serde_json::json!({"name": "Results filter", "trash": true}),
    ] {
        assert!(serde_json::from_value::<FilterPatchRequest>(request).is_err());
    }
}

#[test]
fn filter_patch_request_rejects_oversized_metadata_fields() {
    let oversized = "a".repeat(MAX_FILTER_TEXT_BYTES + 1);
    assert!(matches!(
        validate_filter_patch_request(FilterPatchRequest {
            name: Some(oversized),
            comment: None,
            filter_type: None,
            term: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn filter_patch_sql_updates_metadata_term_and_type_only() {
    let state = filter_write_state_sql();
    assert!(state.contains("owner::integer"));

    let sql = filter_update_metadata_sql();
    assert!(sql.contains("UPDATE filters"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("type = coalesce(lower($4), type)"));
    assert!(sql.contains("term = coalesce($5, term)"));
    assert!(sql.contains("modification_time = m_now()"));
    for forbidden in ["alert", "settings", "filters_trash"] {
        assert!(
            !sql.contains(forbidden),
            "filter metadata patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn filter_patch_uniqueness_checks_live_and_trash_names() {
    let sql = filter_unique_name_sql();
    assert!(sql.contains("FROM filters WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM filters_trash WHERE name = $1"));
}

#[test]
fn filter_patch_plan_adds_alert_guard_for_alert_sensitive_metadata_changes() {
    assert_eq!(
        filter_patch_transaction_plan(false).steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::UpdateFilterMetadata,
        ]
    );
    assert_eq!(
        filter_patch_transaction_plan(true).steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyAlertLinkedTypeChangeAllowed,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::UpdateFilterMetadata,
        ]
    );
}

#[test]
fn filter_delete_sql_guards_alerts_cleans_settings_and_moves_trash_links() {
    assert!(filter_live_alert_count_sql().contains("FROM alerts"));
    assert!(filter_live_alert_count_sql().contains("WHERE filter = $1"));

    let condition_guard = filter_alert_condition_count_sql();
    assert!(condition_guard.contains("FROM alert_condition_data"));
    assert!(condition_guard.contains("name = 'filter_id'"));
    assert!(condition_guard.contains("condition IN (4, 5)"));

    let settings_cleanup = filter_settings_cleanup_sql();
    assert!(settings_cleanup.contains("DELETE FROM settings"));
    assert!(settings_cleanup.contains("name ILIKE '% Filter'"));
    assert!(settings_cleanup.contains("value = $1"));

    let trash_insert = filter_trash_insert_sql();
    assert!(trash_insert.contains("INSERT INTO filters_trash"));
    assert!(trash_insert.contains("FROM filters"));
    assert!(trash_insert.contains("RETURNING id::integer, uuid::text"));

    let alert_relink = filter_trash_alert_relink_sql();
    assert!(alert_relink.contains("UPDATE alerts_trash"));
    assert!(alert_relink.contains("filter_location = 1"));
    assert!(alert_relink.contains("WHERE filter = $2"));

    for sql in [
        filter_tag_locations_to_trash_sql(),
        filter_trash_tag_locations_to_trash_sql(),
    ] {
        assert!(sql.contains("resource_type = 'filter'"));
        assert!(sql.contains("resource_location = 1"));
        assert!(sql.contains("resource = $1"));
        assert!(sql.contains("resource = $2"));
    }

    assert_eq!(
        filter_delete_metadata_sql(),
        "DELETE FROM filters WHERE id = $1;"
    );
}

#[test]
fn filter_delete_plan_keeps_trash_and_side_effects_explicit() {
    assert_eq!(
        filter_delete_transaction_plan().steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::MoveFilterToTrash,
            FilterWriteStep::CleanupFilterSettings,
            FilterWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
