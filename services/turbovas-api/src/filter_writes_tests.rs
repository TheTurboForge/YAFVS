// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::{
    errors::ApiError,
    filter_write_validation::{
        FilterPatchRequest, MAX_FILTER_TEXT_BYTES, ValidatedFilterPatch,
        validate_filter_patch_request,
    },
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> FilterPatchRequest {
    FilterPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
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
fn filter_patch_request_rejects_term_type_and_unknown_fields() {
    for request in [
        serde_json::json!({"name": "Results filter", "term": "rows=100"}),
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
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn filter_patch_sql_is_metadata_only() {
    let sql = filter_update_metadata_sql();
    assert!(sql.contains("UPDATE filters"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    for forbidden in ["term", "type", "alert", "settings", "filters_trash"] {
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
fn filter_patch_plan_adds_alert_guard_only_for_type_changes() {
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
