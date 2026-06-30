// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::report_config_write_plans::*;
use crate::report_config_write_validation::{
    MAX_REPORT_CONFIG_PARAMS, ReportConfigCloneRequest, ReportConfigParamWriteRequest,
};

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
