// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

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
        report_format_id: None,
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
    assert_eq!(validated.report_format_id, None);
    assert_eq!(
        validated.params.expect("params replacement")[0].value,
        "  keep outer spaces  "
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

    let patch = validate_report_config_patch_request(ReportConfigPatchRequest {
        name: Some("renamed".to_string()),
        comment: None,
        report_format_id: Some("12345678-1234-1234-1234-123456789abc".to_string()),
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
            ReportConfigWriteStep::VerifyReportFormatVisible,
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
