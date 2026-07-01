// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::report_config_write_plans::*;
use crate::report_config_write_sql::*;
use crate::report_config_write_validation::{
    MAX_REPORT_CONFIG_PARAMS, ReportConfigCloneRequest, ReportConfigFormatParam,
    ReportConfigFormatState, ReportConfigParamWriteRequest, ValidatedReportConfigParamWrite,
};

#[test]
fn report_config_write_rejects_operator_owner_mismatch() {
    assert!(ensure_report_config_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_report_config_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn report_config_create_request_normalizes_metadata_and_params() {
    let request: ReportConfigCreateRequest = serde_json::from_str(
        r#"{
            "name": "  PDF summary  ",
            "comment": "  operator default  ",
            "report_format_id": "12345678-1234-1234-1234-123456789ABC",
            "params": [
                {"name":"  timezone ","value":"UTC"},
                {"name":"notes","value":"line one\nline two"}
            ]
        }"#,
    )
    .expect("valid create DTO");

    let validated = validate_report_config_create_request(request).expect("valid create");

    assert_eq!(validated.name, "PDF summary");
    assert_eq!(validated.comment.as_deref(), Some("operator default"));
    assert_eq!(
        validated.report_format_id,
        "12345678-1234-1234-1234-123456789abc"
    );
    assert_eq!(validated.params[0].name, "timezone");
    assert_eq!(validated.params[1].value, "line one\nline two");
}

#[test]
fn report_config_clone_request_accepts_default_or_named_clone() {
    let default = validate_report_config_clone_request(ReportConfigCloneRequest { name: None })
        .expect("default clone name");
    assert_eq!(default.name, None);

    let named = validate_report_config_clone_request(ReportConfigCloneRequest {
        name: Some("  Operator copy  ".to_string()),
    })
    .expect("named clone");
    assert_eq!(named.name.as_deref(), Some("Operator copy"));

    let empty = validate_report_config_clone_request(ReportConfigCloneRequest {
        name: Some("   ".to_string()),
    });
    assert!(matches!(empty, Err(ApiError::BadRequest(_))));
}

#[test]
fn report_config_create_rejects_unknown_fields_bad_ids_and_duplicate_params() {
    assert!(
        serde_json::from_str::<ReportConfigCreateRequest>(
            r#"{"name":"x","report_format_id":"12345678-1234-1234-1234-123456789abc","owner":"admin"}"#,
        )
        .is_err()
    );

    let bad_id = ReportConfigCreateRequest {
        name: "config".to_string(),
        comment: None,
        report_format_id: "not-a-uuid".to_string(),
        params: Vec::new(),
    };
    assert!(matches!(
        validate_report_config_create_request(bad_id),
        Err(ApiError::BadRequest(_))
    ));

    let duplicate_param = ReportConfigCreateRequest {
        name: "config".to_string(),
        comment: None,
        report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        params: vec![
            ReportConfigParamWriteRequest {
                name: "timezone".to_string(),
                value: "UTC".to_string(),
            },
            ReportConfigParamWriteRequest {
                name: " timezone ".to_string(),
                value: "CET".to_string(),
            },
        ],
    };
    assert!(matches!(
        validate_report_config_create_request(duplicate_param),
        Err(ApiError::Conflict(_))
    ));
}

#[test]
fn report_config_patch_request_requires_explicit_field_and_preserves_param_value() {
    let empty = ReportConfigPatchRequest {
        name: None,
        comment: None,
        params: None,
    };
    assert!(matches!(
        validate_report_config_patch_request(empty),
        Err(ApiError::BadRequest(_))
    ));

    let patch: ReportConfigPatchRequest = serde_json::from_str(
        r#"{
            "name":" Renamed ",
            "params":[{"name":"body","value":"  keep outer spaces  "}]
        }"#,
    )
    .expect("valid patch DTO");
    let validated = validate_report_config_patch_request(patch).expect("valid patch");

    assert_eq!(validated.name.as_deref(), Some("Renamed"));
    assert_eq!(
        validated.params.expect("params replacement")[0].value,
        "  keep outer spaces  "
    );

    assert!(
        serde_json::from_str::<ReportConfigPatchRequest>(
            r#"{"report_format_id":"12345678-1234-1234-1234-123456789abc"}"#,
        )
        .is_err(),
        "patch deliberately does not change the report format"
    );
}

#[test]
fn report_config_param_values_are_size_capped_and_reject_nul() {
    let nul = ReportConfigCreateRequest {
        name: "config".to_string(),
        comment: None,
        report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        params: vec![ReportConfigParamWriteRequest {
            name: "body".to_string(),
            value: "bad\0value".to_string(),
        }],
    };
    assert!(matches!(
        validate_report_config_create_request(nul),
        Err(ApiError::BadRequest(_))
    ));

    let too_many = ReportConfigCreateRequest {
        name: "config".to_string(),
        comment: None,
        report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        params: (0..=MAX_REPORT_CONFIG_PARAMS)
            .map(|index| ReportConfigParamWriteRequest {
                name: format!("param{index}"),
                value: "value".to_string(),
            })
            .collect(),
    };
    assert!(matches!(
        validate_report_config_create_request(too_many),
        Err(ApiError::BadRequest(_))
    ));
}

fn report_config_format_param(
    param_type: i32,
    min: i64,
    max: i64,
    options: &[&str],
) -> ReportConfigFormatParam {
    ReportConfigFormatParam {
        param_type,
        min,
        max,
        options: options.iter().map(|option| (*option).to_string()).collect(),
    }
}

#[test]
fn report_config_param_type_validation_accepts_supported_values() {
    let format = ReportConfigFormatState {
        params: std::collections::BTreeMap::from([
            (
                "copies".to_string(),
                report_config_format_param(1, 1, 10, &[]),
            ),
            (
                "style".to_string(),
                report_config_format_param(2, 0, 0, &["summary"]),
            ),
            (
                "subject".to_string(),
                report_config_format_param(3, 3, 20, &[]),
            ),
            (
                "formats".to_string(),
                report_config_format_param(5, 0, 0, &[]),
            ),
            (
                "sections".to_string(),
                report_config_format_param(6, 1, 2, &["summary", "details"]),
            ),
        ]),
    };

    let params = vec![
        ValidatedReportConfigParamWrite {
            name: "copies".to_string(),
            value: "3".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "style".to_string(),
            value: "summary".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "subject".to_string(),
            value: "Daily".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "formats".to_string(),
            value: "12345678-1234-1234-1234-123456789abc,abcdef".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "sections".to_string(),
            value: r#"["summary","details"]"#.to_string(),
        },
    ];

    validate_report_config_param_values(&params, &format).expect("supported values are valid");
}

#[test]
fn report_config_param_type_validation_rejects_bad_values() {
    let format = ReportConfigFormatState {
        params: std::collections::BTreeMap::from([
            (
                "copies".to_string(),
                report_config_format_param(1, 1, 3, &[]),
            ),
            (
                "style".to_string(),
                report_config_format_param(2, 0, 0, &["summary"]),
            ),
            (
                "subject".to_string(),
                report_config_format_param(3, 3, 5, &[]),
            ),
            (
                "formats".to_string(),
                report_config_format_param(5, 0, 0, &[]),
            ),
            (
                "sections".to_string(),
                report_config_format_param(6, 1, 1, &["summary"]),
            ),
        ]),
    };
    let cases = [
        ValidatedReportConfigParamWrite {
            name: "missing".to_string(),
            value: "x".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "copies".to_string(),
            value: "zero".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "copies".to_string(),
            value: "4".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "style".to_string(),
            value: "full".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "subject".to_string(),
            value: "too long".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "formats".to_string(),
            value: "abc/def".to_string(),
        },
        ValidatedReportConfigParamWrite {
            name: "sections".to_string(),
            value: r#"["summary","details"]"#.to_string(),
        },
    ];

    for param in cases {
        assert!(
            matches!(
                validate_report_config_param_values(std::slice::from_ref(&param), &format),
                Err(ApiError::BadRequest(_))
            ),
            "expected invalid param to fail: {param:?}"
        );
    }
}

#[test]
fn report_config_write_transaction_plans_keep_validation_before_mutation() {
    let create = validate_report_config_create_request(ReportConfigCreateRequest {
        name: "config".to_string(),
        comment: None,
        report_format_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        params: vec![ReportConfigParamWriteRequest {
            name: "timezone".to_string(),
            value: "UTC".to_string(),
        }],
    })
    .expect("valid create");
    assert_eq!(
        report_config_create_transaction_plan(&create).steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyReportFormatVisible,
            ReportConfigWriteStep::VerifyReportFormatParams,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::InsertReportConfig,
            ReportConfigWriteStep::ReplaceReportConfigParams,
        ]
    );

    let clone = validate_report_config_clone_request(ReportConfigCloneRequest {
        name: Some("copy".to_string()),
    })
    .expect("valid clone");
    assert_eq!(
        report_config_clone_transaction_plan(&clone).steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::CloneReportConfigMetadata,
            ReportConfigWriteStep::CloneReportConfigParams,
            ReportConfigWriteStep::CloneReportConfigTags,
        ]
    );

    let default_clone =
        validate_report_config_clone_request(ReportConfigCloneRequest { name: None })
            .expect("valid default clone");
    assert_eq!(
        report_config_clone_transaction_plan(&default_clone).steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::CloneReportConfigMetadata,
            ReportConfigWriteStep::CloneReportConfigParams,
            ReportConfigWriteStep::CloneReportConfigTags,
        ]
    );

    let patch = validate_report_config_patch_request(ReportConfigPatchRequest {
        name: Some("renamed".to_string()),
        comment: None,
        params: Some(vec![ReportConfigParamWriteRequest {
            name: "timezone".to_string(),
            value: "CET".to_string(),
        }]),
    })
    .expect("valid patch");
    assert_eq!(
        report_config_patch_transaction_plan(&patch).steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::VerifyReportFormatParams,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::UpdateReportConfigMetadata,
            ReportConfigWriteStep::ReplaceReportConfigParams,
        ]
    );

    assert_eq!(
        report_config_delete_transaction_plan().steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::MoveReportConfigToTrash,
        ]
    );

    assert_eq!(
        report_config_restore_transaction_plan().steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyTrashReportConfigRestorable,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::RestoreReportConfigFromTrash,
        ]
    );

    assert_eq!(
        report_config_hard_delete_transaction_plan().steps,
        vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyTrashReportConfigRestorable,
            ReportConfigWriteStep::VerifyTrashReportConfigDeleteSafety,
            ReportConfigWriteStep::RemoveTrashReportConfigTags,
            ReportConfigWriteStep::HardDeleteReportConfigFromTrash,
        ]
    );
}

#[test]
fn report_config_clone_sql_copies_metadata_params_and_active_tag_links() {
    let clone = report_config_clone_sql();
    for required in [
        "INSERT INTO report_configs",
        "SELECT make_uuid()",
        "coalesce($3, uniquify('report_config', name, $2, ' Clone'))",
        "comment",
        "report_format_id",
        "WHERE id = $1",
        "RETURNING id::integer, uuid::text",
    ] {
        assert!(clone.contains(required), "clone SQL missing {required}");
    }

    let params = report_config_clone_params_sql();
    assert!(params.contains("INSERT INTO report_config_params"));
    assert!(params.contains("SELECT $2, name, value"));
    assert!(params.contains("WHERE report_config = $1"));

    let tags = report_config_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'report_config'"));
    assert!(tags.contains("resource_location = 0"));
    assert!(tags.contains("SELECT tag, resource_type, $2, $3, resource_location"));
}

#[test]
fn report_config_delete_sql_moves_metadata_params_and_tags_to_trash() {
    let alert_guard = report_config_in_use_by_alerts_sql();
    assert!(alert_guard.contains("SELECT 0::bigint"));

    let state = report_config_write_state_sql();
    assert!(state.contains("owner::integer"));

    let trash = report_config_trash_insert_sql();
    assert!(trash.contains("INSERT INTO report_configs_trash"));
    assert!(trash.contains("SELECT uuid, owner, name, comment"));
    assert!(trash.contains("FROM report_configs"));
    assert!(trash.contains("WHERE id = $1"));
    assert!(trash.contains("RETURNING id::integer, uuid::text"));

    let params = report_config_trash_params_insert_sql();
    assert!(params.contains("INSERT INTO report_config_params_trash"));
    assert!(params.contains("SELECT $1, name, value"));
    assert!(params.contains("WHERE report_config = $2"));

    let tags = report_config_tag_locations_to_trash_sql();
    assert!(tags.contains("UPDATE tag_resources"));
    assert!(tags.contains("resource_location = 1"));
    assert!(tags.contains("resource_type = 'report_config'"));
    assert!(tags.contains("resource = $2"));

    assert!(report_config_delete_params_sql().contains("DELETE FROM report_config_params"));
    assert!(report_config_delete_metadata_sql().contains("DELETE FROM report_configs"));
}

#[test]
fn report_config_restore_sql_moves_metadata_params_and_tags_to_live() {
    let state = report_config_trash_state_sql();
    assert!(state.contains("FROM report_configs_trash"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(state.contains("owner::integer"));

    let owner_name = report_config_unique_live_owner_name_sql();
    assert!(owner_name.contains("FROM report_configs"));
    assert!(owner_name.contains("name = $1"));
    assert!(owner_name.contains("owner = $2"));

    let uuid_conflict = report_config_live_uuid_conflict_sql();
    assert!(uuid_conflict.contains("FROM report_configs"));
    assert!(uuid_conflict.contains("uuid = $1"));

    let restore = report_config_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO report_configs"));
    assert!(restore.contains("SELECT uuid, owner, name, comment"));
    assert!(restore.contains("FROM report_configs_trash"));
    assert!(restore.contains("WHERE id = $1"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));

    let params = report_config_restore_params_sql();
    assert!(params.contains("INSERT INTO report_config_params"));
    assert!(params.contains("SELECT $2, name, value"));
    assert!(params.contains("FROM report_config_params_trash"));
    assert!(params.contains("WHERE report_config = $1"));

    let tags = report_config_tag_locations_to_live_sql();
    assert!(tags.contains("UPDATE tag_resources"));
    assert!(tags.contains("resource_location = 0"));
    assert!(tags.contains("resource_type = 'report_config'"));
    assert!(tags.contains("resource = $1"));

    assert!(
        report_config_delete_trash_params_sql().contains("DELETE FROM report_config_params_trash")
    );
    assert!(report_config_delete_trash_metadata_sql().contains("DELETE FROM report_configs_trash"));
}

#[test]
fn report_config_hard_delete_sql_removes_trash_tags_params_and_metadata_only() {
    assert!(report_config_trash_in_use_by_alerts_sql().contains("SELECT 0::bigint"));

    let tags = report_config_trash_tag_delete_sql();
    assert!(tags.contains("DELETE FROM tag_resources"));
    assert!(tags.contains("resource_type = 'report_config'"));
    assert!(tags.contains("resource = $1"));
    assert!(tags.contains("resource_location = 1"));

    assert!(
        report_config_delete_trash_params_sql().contains("DELETE FROM report_config_params_trash")
    );
    assert!(report_config_delete_trash_metadata_sql().contains("DELETE FROM report_configs_trash"));

    for sql in [
        report_config_trash_tag_delete_sql(),
        report_config_delete_trash_params_sql(),
        report_config_delete_trash_metadata_sql(),
    ] {
        assert!(!sql.contains("report_configs WHERE"));
        assert!(!sql.contains("report_config_params WHERE"));
        assert!(!sql.contains("report_formats"));
    }
}
