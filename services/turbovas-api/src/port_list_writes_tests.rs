// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::port_list_write_plans::*;
use crate::port_list_write_sql::*;
use crate::port_list_write_validation::{
    MAX_PORT_LIST_CREATE_RANGES, MAX_PORT_LIST_TEXT_BYTES, PortListCloneRequest,
    PortListCreateRangeRequest, PortListCreateRequest, PortListImportRequest, PortListPatchRequest,
    ValidatedPortListPatch, validate_port_list_clone_request, validate_port_list_create_request,
    validate_port_list_import_request, validate_port_list_patch_request,
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> PortListPatchRequest {
    PortListPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        port_ranges: None,
    }
}

fn patch_request_with_ranges(ranges: Vec<PortListCreateRangeRequest>) -> PortListPatchRequest {
    PortListPatchRequest {
        name: None,
        comment: None,
        port_ranges: Some(ranges),
    }
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> PortListCloneRequest {
    PortListCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn create_request(name: &str, ranges: Vec<PortListCreateRangeRequest>) -> PortListCreateRequest {
    PortListCreateRequest {
        name: name.to_string(),
        comment: Some("  created by native API  ".to_string()),
        port_ranges: ranges,
    }
}

#[test]
fn port_list_write_rejects_operator_owner_mismatch() {
    assert!(ensure_port_list_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_port_list_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn port_list_create_and_clone_handlers_require_operator_before_insert() {
    let source = include_str!("port_list_writes.rs");
    for (label, start, end, owner_resolution, side_effect) in [
        (
            "create",
            "pub(crate) async fn create_port_list",
            "pub(crate) async fn clone_port_list",
            "let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;",
            "execute_port_list_create_transaction",
        ),
        (
            "clone",
            "pub(crate) async fn clone_port_list",
            "pub(crate) async fn patch_port_list",
            "let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;",
            "execute_port_list_clone_transaction",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} port-list handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} port-list handler end marker must exist"))
            .0;

        assert!(
            handler.contains("require_port_list_write_operator"),
            "{label} handler must require operator"
        );
        assert!(handler.contains(owner_resolution));
        assert!(
            handler.find(owner_resolution).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must resolve operator owner before insert/clone"
        );
    }
}

#[test]
fn port_list_mutating_handlers_enforce_owner_and_safety_before_side_effects() {
    let source = include_str!("port_list_writes.rs");
    for (label, start, end, owner_check, safety_guard, side_effect) in [
        (
            "patch",
            "pub(crate) async fn patch_port_list",
            "pub(crate) async fn delete_port_list",
            "ensure_port_list_owner_matches_operator(state.owner_id, operator_owner_id)?;",
            "if state.predefined",
            "execute_port_list_patch_transaction",
        ),
        (
            "delete",
            "pub(crate) async fn delete_port_list",
            "pub(crate) async fn hard_delete_port_list",
            "ensure_port_list_owner_matches_operator(state.owner_id, operator_owner_id)?;",
            "ensure_port_list_not_in_use_by_live_targets",
            "execute_port_list_trash_transaction",
        ),
        (
            "hard delete",
            "pub(crate) async fn hard_delete_port_list",
            "pub(crate) async fn restore_port_list",
            "ensure_port_list_owner_matches_operator(trash.owner_id, operator_owner_id)?;",
            "ensure_port_list_not_in_use_by_trash_targets",
            "execute_port_list_hard_delete_transaction",
        ),
        (
            "restore",
            "pub(crate) async fn restore_port_list",
            "#[cfg(test)]",
            "ensure_port_list_owner_matches_operator(trash.owner_id, operator_owner_id)?;",
            "ensure_port_list_uuid_not_live",
            "execute_port_list_restore_transaction",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} port-list handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} port-list handler end marker must exist"))
            .0;

        assert!(
            handler.contains("require_port_list_write_operator"),
            "{label} handler must require operator"
        );
        assert!(
            handler.contains(owner_check),
            "{label} handler must check owner"
        );
        assert!(
            handler.contains(safety_guard),
            "{label} handler must check safety guard"
        );
        assert!(
            handler.find(owner_check).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check owner before side effects"
        );
        assert!(
            handler.find(safety_guard).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check safety guard before side effects"
        );
    }
}

#[test]
fn port_list_clone_request_accepts_default_or_metadata_override() {
    let default = validate_port_list_clone_request(clone_request(None, None))
        .expect("default clone metadata");
    assert_eq!(default.name, None);
    assert_eq!(default.comment, None);

    let named = validate_port_list_clone_request(clone_request(
        Some("  Operator copy  "),
        Some("  copied note  "),
    ))
    .expect("named clone");
    assert_eq!(named.name.as_deref(), Some("Operator copy"));
    assert_eq!(named.comment.as_deref(), Some("copied note"));

    let clear_comment = validate_port_list_clone_request(clone_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(clear_comment.comment.as_deref(), Some(""));
}

#[test]
fn port_list_clone_request_rejects_blank_name_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_port_list_clone_request(clone_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_port_list_clone_request(clone_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    let unknown = serde_json::json!({"name": "copy", "port_ranges": []});
    assert!(serde_json::from_value::<PortListCloneRequest>(unknown).is_err());
}

fn create_range(protocol: &str, start: i32, end: i32) -> PortListCreateRangeRequest {
    PortListCreateRangeRequest {
        protocol: protocol.to_string(),
        start,
        end,
        comment: Some("  operator range  ".to_string()),
    }
}

#[test]
fn port_list_clone_sql_copies_metadata_ranges_and_tags_without_range_mutation() {
    let metadata = port_list_clone_metadata_sql();
    assert!(metadata.contains("INSERT INTO port_lists"));
    assert!(metadata.contains("predefined, creation_time, modification_time"));
    assert!(metadata.contains("coalesce($3, uniquify('port_list', name, $2, ' Clone'))"));
    assert!(metadata.contains("coalesce($4, comment)"));
    assert!(metadata.contains("            0,\n            m_now(),"));
    assert!(!metadata.contains("SELECT uuid, owner, name, comment, predefined"));
    assert!(metadata.contains("FROM port_lists"));
    assert!(metadata.contains("WHERE id = $1"));

    let ranges = port_list_clone_ranges_sql();
    assert!(ranges.contains("INSERT INTO port_ranges"));
    assert!(ranges.contains("SELECT make_uuid(), $2, type, start"));
    assert!(ranges.contains("FROM port_ranges"));
    assert!(ranges.contains("WHERE port_list = $1"));

    let tags = port_list_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'port_list'"));
    assert!(tags.contains("resource_location = 0"));

    for sql in [metadata, ranges, tags] {
        assert!(!sql.contains("port_lists_trash"));
        assert!(!sql.contains("port_ranges_trash"));
        assert!(!sql.contains("DELETE"));
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
fn port_list_clone_plan_copies_metadata_ranges_and_tags_after_optional_name_check() {
    let named = validate_port_list_clone_request(clone_request(Some("copy"), None))
        .expect("valid named clone");
    assert_eq!(
        port_list_clone_transaction_plan(&named).steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::ClonePortListMetadata,
            PortListWriteStep::ClonePortListRanges,
            PortListWriteStep::ClonePortListTags,
        ]
    );

    let default =
        validate_port_list_clone_request(clone_request(None, None)).expect("valid default clone");
    assert_eq!(
        port_list_clone_transaction_plan(&default).steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::ClonePortListMetadata,
            PortListWriteStep::ClonePortListRanges,
            PortListWriteStep::ClonePortListTags,
        ]
    );
}

#[test]
fn port_list_create_request_normalizes_text_protocol_and_range_order() {
    let validated = validate_port_list_create_request(create_request(
        "  Web ports  ",
        vec![create_range("UDP", 53, 53), create_range("tcp", 80, 443)],
    ))
    .unwrap();
    assert_eq!(validated.name, "Web ports");
    assert_eq!(validated.imported_id, None);
    assert!(!validated.deduplicate_name);
    assert_eq!(validated.comment, "created by native API");
    assert_eq!(validated.port_ranges.len(), 2);
    assert_eq!(validated.port_ranges[0].protocol_id, 0);
    assert_eq!(validated.port_ranges[0].start, 80);
    assert_eq!(validated.port_ranges[0].end, 443);
    assert_eq!(validated.port_ranges[0].comment, "operator range");
    assert_eq!(validated.port_ranges[1].protocol_id, 1);
}

#[test]
fn port_list_import_request_parses_exported_xml_shape() {
    let validated = validate_port_list_import_request(PortListImportRequest {
        xml_file: r#"
          <get_port_lists_response>
            <port_list id="12345678-1234-4234-9234-123456789abc">
              <name> Imported Ports </name>
              <comment> imported note </comment>
              <port_ranges>
                <port_range><type>UDP</type><start>53</start><end>53</end></port_range>
                <port_range><type>TCP</type><start>80</start><end>443</end></port_range>
              </port_ranges>
            </port_list>
          </get_port_lists_response>
        "#
        .to_string(),
    })
    .expect("valid import XML");
    assert_eq!(
        validated.imported_id.as_deref(),
        Some("12345678-1234-4234-9234-123456789abc")
    );
    assert!(validated.deduplicate_name);
    assert_eq!(validated.name, "Imported Ports");
    assert_eq!(validated.comment, "imported note");
    assert_eq!(validated.port_ranges.len(), 2);
    assert_eq!(validated.port_ranges[0].protocol_id, 0);
    assert_eq!(validated.port_ranges[0].start, 80);
    assert_eq!(validated.port_ranges[1].protocol_id, 1);
}

#[test]
fn port_list_import_request_rejects_missing_uuid_or_implicit_default_ranges() {
    assert!(validate_port_list_import_request(PortListImportRequest {
        xml_file: "<get_port_lists_response><port_list><name>x</name></port_list></get_port_lists_response>".to_string(),
    })
    .is_err());
    assert!(validate_port_list_import_request(PortListImportRequest {
        xml_file: "<get_port_lists_response><port_list id=\"12345678-1234-4234-9234-123456789abc\"><name>x</name></port_list></get_port_lists_response>".to_string(),
    })
    .is_err());
}

#[test]
fn port_list_create_request_rejects_invalid_ranges() {
    for request in [
        create_request("Web ports", vec![]),
        create_request("Web ports", vec![create_range("icmp", 1, 1)]),
        create_request("Web ports", vec![create_range("tcp", 0, 1)]),
        create_request("Web ports", vec![create_range("tcp", 1, 65536)]),
        create_request("Web ports", vec![create_range("tcp", 443, 80)]),
        create_request(
            "Web ports",
            vec![create_range("tcp", 80, 90), create_range("tcp", 90, 100)],
        ),
    ] {
        assert!(validate_port_list_create_request(request).is_err());
    }
}

#[test]
fn port_list_create_request_rejects_too_many_ranges_and_unknown_fields() {
    let too_many = vec![create_range("tcp", 1, 1); MAX_PORT_LIST_CREATE_RANGES + 1];
    assert!(validate_port_list_create_request(create_request("Web ports", too_many)).is_err());
    let unknown = serde_json::json!({
        "name": "Web ports",
        "port_ranges": [{"protocol": "tcp", "start": 80, "end": 80, "exclude": true}],
    });
    assert!(serde_json::from_value::<PortListCreateRequest>(unknown).is_err());
}

#[test]
fn port_list_create_sql_is_live_metadata_and_range_only() {
    let metadata = port_list_create_metadata_sql();
    assert!(metadata.contains("INSERT INTO port_lists"));
    assert!(metadata.contains("predefined, creation_time, modification_time"));
    assert!(
        metadata.contains("VALUES (coalesce($4, make_uuid()), $1, $2, $3, 0, m_now(), m_now())")
    );
    assert!(metadata.contains("RETURNING id::integer, uuid::text"));

    let range = port_list_create_range_sql();
    assert!(range.contains("INSERT INTO port_ranges"));
    assert!(range.contains("VALUES (make_uuid(), $1, $2, $3, $4, $5, 0)"));
    for forbidden in ["port_lists_trash", "port_ranges_trash", "targets", "DELETE"] {
        assert!(!metadata.contains(forbidden));
        assert!(!range.contains(forbidden));
    }
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
            port_ranges: None,
        }
    );
}

#[test]
fn port_list_patch_request_accepts_replacement_ranges() {
    let validated = validate_port_list_patch_request(patch_request_with_ranges(vec![
        create_range("udp", 53, 53),
        create_range("tcp", 443, 443),
    ]))
    .expect("valid range replacement patch");
    let ranges = validated.port_ranges.expect("replacement ranges");
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].protocol_id, 0);
    assert_eq!(ranges[0].start, 443);
    assert_eq!(ranges[1].protocol_id, 1);
    assert_eq!(ranges[1].start, 53);
}

#[test]
fn port_list_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_rejects_empty_or_overlapping_replacement_ranges() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request_with_ranges(vec![])),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_port_list_patch_request(patch_request_with_ranges(vec![
            create_range("tcp", 80, 90),
            create_range("tcp", 90, 100),
        ])),
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
            port_ranges: None,
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
            port_ranges: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_sql_is_metadata_only() {
    let state = port_list_write_state_sql();
    assert!(state.contains("owner::integer"));

    let sql = port_list_update_metadata_sql();
    assert!(sql.contains("UPDATE port_lists"));
    assert!(sql.contains("name = coalesce"));
    assert!(sql.contains("comment = coalesce"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(!sql.contains("port_ranges"));
    assert!(!sql.contains("predefined"));
}

#[test]
fn port_list_patch_range_sql_replaces_live_ranges_only() {
    let live_target_guard = port_list_live_target_count_sql();
    assert!(live_target_guard.contains("FROM targets"));
    assert!(live_target_guard.contains("WHERE port_list = $1"));

    let trash_target_guard = port_list_live_location_trash_target_count_sql();
    assert!(trash_target_guard.contains("FROM targets_trash"));
    assert!(trash_target_guard.contains("port_list_location = 0"));

    let delete = port_list_delete_ranges_sql();
    assert!(delete.contains("DELETE FROM port_ranges WHERE port_list = $1"));

    let insert = port_list_create_range_sql();
    assert!(insert.contains("INSERT INTO port_ranges"));
    assert!(insert.contains("VALUES (make_uuid(), $1, $2, $3, $4, $5, 0)"));
    for sql in [delete, insert] {
        assert!(!sql.contains("port_ranges_trash"));
        assert!(!sql.contains("targets"));
    }
}

#[test]
fn port_list_delete_sql_moves_metadata_ranges_targets_and_tags_to_trash() {
    let target_guard = port_list_live_target_count_sql();
    assert!(target_guard.contains("FROM targets"));
    assert!(target_guard.contains("WHERE port_list = $1"));

    let trash = port_list_trash_insert_sql();
    assert!(trash.contains("INSERT INTO port_lists_trash"));
    assert!(trash.contains("FROM port_lists"));
    assert!(trash.contains("WHERE id = $1"));
    assert!(trash.contains("RETURNING id::integer, uuid::text"));

    let ranges = port_list_trash_ranges_insert_sql();
    assert!(ranges.contains("INSERT INTO port_ranges_trash"));
    assert!(ranges.contains("SELECT uuid, $1, type, start"));
    assert!(ranges.contains("FROM port_ranges"));
    assert!(ranges.contains("WHERE port_list = $2"));

    let targets = port_list_trash_target_relink_sql();
    assert!(targets.contains("UPDATE targets_trash"));
    assert!(targets.contains("port_list_location = 1"));
    assert!(targets.contains("WHERE port_list = $2"));
    assert!(targets.contains("port_list_location = 0"));

    let live_tags = port_list_tag_locations_to_trash_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_type = 'port_list'"));
    assert!(live_tags.contains("resource_location = 1"));

    let trash_tags = port_list_trash_tag_locations_to_trash_sql();
    assert!(trash_tags.contains("UPDATE tag_resources_trash"));
    assert!(trash_tags.contains("resource_type = 'port_list'"));
    assert!(trash_tags.contains("resource_location = 1"));

    assert!(port_list_delete_ranges_sql().contains("DELETE FROM port_ranges"));
    assert!(port_list_delete_metadata_sql().contains("DELETE FROM port_lists"));
}

#[test]
fn port_list_restore_sql_moves_metadata_ranges_targets_and_tags_to_live() {
    let state = port_list_trash_state_sql();
    assert!(state.contains("FROM port_lists_trash"));
    assert!(state.contains("owner::integer"));

    let name_conflict = port_list_unique_live_owner_name_sql();
    assert!(name_conflict.contains("FROM port_lists"));
    assert!(name_conflict.contains("name = $1"));
    assert!(name_conflict.contains("owner = $2"));

    let uuid_conflict = port_list_live_uuid_conflict_sql();
    assert!(uuid_conflict.contains("FROM port_lists"));
    assert!(uuid_conflict.contains("uuid = $1"));

    let restore = port_list_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO port_lists"));
    assert!(restore.contains("FROM port_lists_trash"));
    assert!(restore.contains("WHERE id = $1"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));

    let ranges = port_list_restore_ranges_sql();
    assert!(ranges.contains("INSERT INTO port_ranges"));
    assert!(ranges.contains("SELECT uuid, $2, type, start"));
    assert!(ranges.contains("FROM port_ranges_trash"));
    assert!(ranges.contains("WHERE port_list = $1"));

    let targets = port_list_restore_target_relink_sql();
    assert!(targets.contains("UPDATE targets_trash"));
    assert!(targets.contains("port_list = $2"));
    assert!(targets.contains("port_list_location = 0"));
    assert!(targets.contains("WHERE port_list = $1"));
    assert!(targets.contains("port_list_location = 1"));

    let live_tags = port_list_tag_locations_to_live_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_type = 'port_list'"));
    assert!(live_tags.contains("resource_location = 0"));

    let trash_tags = port_list_trash_tag_locations_to_live_sql();
    assert!(trash_tags.contains("UPDATE tag_resources_trash"));
    assert!(trash_tags.contains("resource_type = 'port_list'"));
    assert!(trash_tags.contains("resource_location = 0"));

    assert!(port_list_delete_trash_ranges_sql().contains("DELETE FROM port_ranges_trash"));
    assert!(port_list_delete_trash_metadata_sql().contains("DELETE FROM port_lists_trash"));
}

#[test]
fn port_list_hard_delete_sql_deletes_only_trash_metadata_ranges_and_tags() {
    let target_guard = port_list_trash_target_count_sql();
    assert!(target_guard.contains("FROM targets_trash"));
    assert!(target_guard.contains("WHERE port_list = $1"));
    assert!(target_guard.contains("port_list_location = 1"));

    let live_tag_cleanup = port_list_trash_tag_delete_sql();
    assert!(live_tag_cleanup.contains("DELETE FROM tag_resources"));
    assert!(live_tag_cleanup.contains("resource_type = 'port_list'"));
    assert!(live_tag_cleanup.contains("resource_location = 1"));

    let trash_tag_cleanup = port_list_trash_tag_trash_delete_sql();
    assert!(trash_tag_cleanup.contains("DELETE FROM tag_resources_trash"));
    assert!(trash_tag_cleanup.contains("resource_type = 'port_list'"));
    assert!(trash_tag_cleanup.contains("resource_location = 1"));

    let range_delete = port_list_delete_trash_ranges_sql();
    assert!(range_delete.contains("DELETE FROM port_ranges_trash"));
    assert!(!range_delete.contains("DELETE FROM port_ranges WHERE"));

    let metadata_delete = port_list_delete_trash_metadata_sql();
    assert!(metadata_delete.contains("DELETE FROM port_lists_trash"));
    assert!(!metadata_delete.contains("DELETE FROM port_lists WHERE"));
}

#[test]
fn port_list_patch_name_uniqueness_checks_live_and_trash_names() {
    let sql = port_list_unique_name_sql();
    assert!(sql.contains("FROM port_lists WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM port_lists_trash WHERE name = $1"));
}

#[test]
fn port_list_import_uuid_uniqueness_checks_live_and_trash_ids() {
    let sql = port_list_live_or_trash_uuid_conflict_sql();
    assert!(sql.contains("FROM port_lists WHERE uuid = $1"));
    assert!(sql.contains("FROM port_lists_trash WHERE uuid = $1"));
}

#[test]
fn port_list_patch_plan_stays_metadata_only_and_blocks_predefined_lists() {
    assert_eq!(
        port_list_patch_transaction_plan(false).steps,
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
fn port_list_patch_plan_replaces_ranges_only_after_reference_safety_checks() {
    assert_eq!(
        port_list_patch_transaction_plan(true).steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyNotPredefined,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::VerifyTrashTargetDeleteSafety,
            PortListWriteStep::UpdatePortListMetadata,
            PortListWriteStep::ReplacePortRanges,
        ]
    );
}

#[test]
fn port_list_hard_delete_plan_keeps_trash_safety_and_side_effects_explicit() {
    assert_eq!(
        port_list_hard_delete_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyTrashTargetDeleteSafety,
            PortListWriteStep::RemoveTrashTagLinks,
            PortListWriteStep::DeletePortRangesFromTrash,
            PortListWriteStep::HardDeletePortListFromTrash,
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
