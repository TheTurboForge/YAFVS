// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    report_format_write_db::{ReportFormatWriteState, ensure_report_format_metadata_patch_allowed},
    report_format_write_sql::report_format_update_metadata_sql,
    report_format_write_validation::{
        ReportFormatPatchRequest, validate_report_format_patch_request,
    },
};

fn patch_request(
    name: Option<&str>,
    summary: Option<&str>,
    active: Option<bool>,
) -> ReportFormatPatchRequest {
    ReportFormatPatchRequest {
        name: name.map(str::to_string),
        summary: summary.map(str::to_string),
        active,
    }
}

#[test]
fn report_format_metadata_patch_requires_owner_and_blocks_predefined() {
    let mutable = ReportFormatWriteState {
        internal_id: 1,
        owner_id: Some(7),
        predefined: false,
    };
    assert!(ensure_report_format_metadata_patch_allowed(&mutable, 7).is_ok());

    let unowned = ReportFormatWriteState {
        owner_id: Some(8),
        ..mutable.clone()
    };
    assert!(matches!(
        ensure_report_format_metadata_patch_allowed(&unowned, 7),
        Err(ApiError::Forbidden)
    ));

    let builtin = ReportFormatWriteState {
        predefined: true,
        ..mutable.clone()
    };
    assert!(matches!(
        ensure_report_format_metadata_patch_allowed(&builtin, 7),
        Err(ApiError::Forbidden)
    ));

    let null_owner = ReportFormatWriteState {
        owner_id: None,
        ..mutable
    };
    assert!(matches!(
        ensure_report_format_metadata_patch_allowed(&null_owner, 7),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn report_format_metadata_patch_validation_is_narrow() {
    let patch = validate_report_format_patch_request(patch_request(
        Some("  custom report  "),
        Some("  summary  "),
        Some(false),
    ))
    .expect("valid report-format metadata patch");
    assert_eq!(patch.name.as_deref(), Some("custom report"));
    assert_eq!(patch.summary.as_deref(), Some("summary"));
    assert_eq!(patch.active, Some(false));

    assert!(validate_report_format_patch_request(patch_request(None, None, None)).is_err());
    assert!(validate_report_format_patch_request(patch_request(Some("  "), None, None)).is_err());
    assert!(
        validate_report_format_patch_request(patch_request(Some("bad\nname"), None, None)).is_err()
    );
}

#[test]
fn report_format_metadata_patch_sql_stays_metadata_only() {
    let sql = report_format_update_metadata_sql();
    for required in [
        "name = coalesce",
        "summary = coalesce",
        "flags = CASE",
        "modification_time",
    ] {
        assert!(sql.contains(required), "patch SQL missing {required}");
    }
    for forbidden in [
        "report_format_params",
        "report_format_param_options",
        "permissions",
        "tags",
        "alert_method_data",
        "DELETE",
        "INSERT",
    ] {
        assert!(
            !sql.contains(forbidden),
            "report-format metadata patch SQL must not touch {forbidden}"
        );
    }
}
