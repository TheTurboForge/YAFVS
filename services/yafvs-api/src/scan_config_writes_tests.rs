// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::errors::ApiError;
use crate::gvmd_control::MAX_CONTROL_REQUEST_BYTES;
use crate::scan_config_write_db::{
    ScanConfigPreferenceDefinition, ScanConfigWriteState, ensure_scan_config_clone_source_allowed,
    ensure_scan_config_family_is_not_whole_only, ensure_scan_config_is_human_owned,
    ensure_scan_config_not_predefined,
};
use crate::scan_config_write_sql::*;
use crate::scan_config_write_transactions::{
    canonical_scan_config_preference_value, scan_config_family_nvt_selector_exclude,
};
use crate::scan_config_write_validation::*;
use crate::scan_config_writes::{
    DiagnosticNvtSelectionOutcome, diagnostic_nvt_selection_command,
    parse_diagnostic_nvt_selection_response,
};

fn create_request(
    name: &str,
    base_scan_config_id: &str,
    comment: Option<&str>,
) -> ScanConfigCreateRequest {
    ScanConfigCreateRequest {
        name: name.to_string(),
        base_scan_config_id: base_scan_config_id.to_string(),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn scan_config_preference_mutations_are_strict_typed_and_secret_safe() {
    let request = serde_json::json!({
        "preferences": [
            {
                "scope": "scanner",
                "name": "safe_checks",
                "action": "set",
                "value": "yes"
            },
            {
                "scope": "nvt",
                "name": "credential",
                "action": "set",
                "value": "secret",
                "nvt": {
                    "oid": "1.3.6.1.4.1.25623.1.0.100001",
                    "id": 2,
                    "type": "password"
                }
            },
            {
                "scope": "nvt",
                "name": "timeout",
                "action": "reset",
                "nvt": {
                    "oid": "1.3.6.1.4.1.25623.1.0.100001",
                    "id": 0,
                    "type": "entry"
                }
            }
        ]
    });
    let validated = validate_scan_config_patch_request(
        serde_json::from_value(request).expect("strict preference request"),
    )
    .expect("valid preference mutations");
    let preferences = validated.preferences.expect("preferences");
    assert_eq!(preferences.len(), 3);
    assert_eq!(preferences[0].scope, ScanConfigPreferenceScope::Scanner);
    assert_eq!(
        preferences[1].value.as_ref().map(|value| value.as_str()),
        Some("secret")
    );
    assert_eq!(preferences[2].action, ScanConfigPreferenceAction::Reset);
    assert!(preferences[2].value.is_none());

    for invalid in [
        serde_json::json!({"preferences": []}),
        serde_json::json!({"preferences": [{
            "scope": "scanner", "name": "safe_checks", "action": "set"
        }]}),
        serde_json::json!({"preferences": [{
            "scope": "scanner", "name": "safe_checks", "action": "reset", "value": "yes"
        }]}),
        serde_json::json!({"preferences": [{
            "scope": "scanner", "name": "safe_checks", "action": "set", "value": "yes",
            "nvt": {"oid": "1.3.6.1.4.1", "id": 1, "type": "entry"}
        }]}),
        serde_json::json!({"preferences": [{
            "scope": "nvt", "name": "timeout", "action": "reset"
        }]}),
        serde_json::json!({"preferences": [{
            "scope": "nvt", "name": "choice", "action": "set", "value": "",
            "nvt": {"oid": "1.3.6.1.4.1", "id": 1, "type": "radio"}
        }]}),
    ] {
        let request =
            serde_json::from_value::<ScanConfigPatchRequest>(invalid).expect("request shape");
        assert!(matches!(
            validate_scan_config_patch_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
}

#[test]
fn scan_config_preference_mutations_reject_duplicates_and_oversized_values() {
    let duplicate = serde_json::json!({"preferences": [
        {"scope": "scanner", "name": "safe_checks", "action": "set", "value": "yes"},
        {"scope": "scanner", "name": "safe_checks", "action": "reset"}
    ]});
    assert!(matches!(
        validate_scan_config_patch_request(
            serde_json::from_value(duplicate).expect("duplicate request shape")
        ),
        Err(ApiError::BadRequest(_))
    ));

    let oversized = ScanConfigPatchRequest {
        name: None,
        comment: None,
        family_selection: None,
        preferences: Some(vec![ScanConfigPreferenceMutationRequest {
            scope: ScanConfigPreferenceScope::Scanner,
            name: "safe_checks".to_string(),
            action: ScanConfigPreferenceAction::Set,
            value: Some(SensitiveScanConfigPreferenceValue::from_string(
                "x".repeat(MAX_SCAN_CONFIG_PREFERENCE_VALUE_BYTES + 1),
            )),
            nvt: None,
        }]),
    };
    assert!(matches!(
        validate_scan_config_patch_request(oversized),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_preference_sql_is_parameterized_and_catalog_validated() {
    let definition = scan_config_preference_definition_sql();
    for required in [
        "FROM nvt_preferences",
        "np.pref_nvt IS NULL",
        "np.pref_nvt = $3",
        "coalesce(np.pref_id, 0) = $4",
        "coalesce(np.pref_type, '') = $5",
        "coalesce(np.pref_name, '') = $2",
    ] {
        assert!(
            definition.contains(required),
            "definition SQL missing {required}"
        );
    }
    let delete = scan_config_delete_preference_override_sql();
    assert!(delete.contains("config = $1"));
    assert!(delete.contains("type = $2"));
    assert!(delete.contains("name = $3"));
    let insert = scan_config_insert_preference_override_sql();
    assert!(insert.contains("VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"));
    assert!(!format!("{definition}{delete}{insert}").contains("format!("));
}

#[test]
fn scan_config_radio_values_are_canonicalized_from_feed_options() {
    let mutation = ValidatedScanConfigPreferenceMutation {
        scope: ScanConfigPreferenceScope::Nvt,
        name: "Mode".to_string(),
        action: ScanConfigPreferenceAction::Set,
        value: Some(SensitiveScanConfigPreferenceValue::from_string(
            "third".to_string(),
        )),
        nvt: Some(ValidatedScanConfigPreferenceNvtIdentity {
            oid: "1.3.6.1.4.1.25623.1.0.100001".to_string(),
            id: 3,
            preference_type: "radio".to_string(),
        }),
    };
    let definition = ScanConfigPreferenceDefinition {
        canonical_name: "1.3.6.1.4.1.25623.1.0.100001:3:radio:Mode".to_string(),
        default_value: "first;second;third".to_string(),
        nvt_oid: "1.3.6.1.4.1.25623.1.0.100001".to_string(),
        preference_id: 3,
        preference_type: "radio".to_string(),
        preference_name: "Mode".to_string(),
    };
    assert_eq!(
        canonical_scan_config_preference_value(&mutation, &definition)
            .expect("known radio option")
            .as_str(),
        "third;first;second"
    );
    let unknown = ValidatedScanConfigPreferenceMutation {
        value: Some(SensitiveScanConfigPreferenceValue::from_string(
            "unknown".to_string(),
        )),
        ..mutation
    };
    assert!(matches!(
        canonical_scan_config_preference_value(&unknown, &definition),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_preference_patch_is_atomic_human_owner_and_task_guarded() {
    let source = include_str!("scan_config_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_scan_config")
        .expect("patch handler")
        .1
        .split_once("pub(crate) fn parse_scan_config_patch_payload")
        .expect("patch handler end")
        .0;
    for required in [
        "config_preferences, nvt_preferences",
        "ensure_scan_config_is_human_owned",
        "ensure_scan_config_not_predefined",
        "ensure_scan_config_not_referenced_by_any_task",
        "execute_scan_config_preference_mutations_transaction",
        "tx.commit()",
    ] {
        assert!(
            handler.contains(required),
            "patch handler missing {required}"
        );
    }
    assert!(
        handler
            .find("ensure_scan_config_not_referenced_by_any_task")
            .expect("task guard")
            < handler
                .find("execute_scan_config_preference_mutations_transaction")
                .expect("preference write")
    );
}

#[test]
fn scan_config_patch_accepts_complete_family_selection_without_metadata() {
    let request = serde_json::json!({
        "family_selection": {
            "families_growing": true,
            "families": [
                {"name": "Port scanners", "growing": false, "selected": true},
                {"name": "Ubuntu Local Security Checks", "growing": true, "selected": true}
            ]
        }
    });
    let request = serde_json::from_value::<ScanConfigPatchRequest>(request)
        .expect("strict family selection request");
    let validated = validate_scan_config_patch_request(request)
        .expect("family selection is a valid patch field");
    let selection = validated.family_selection.expect("family selection");
    assert!(selection.families_growing);
    assert_eq!(selection.families.len(), 2);
}

#[test]
fn scan_config_family_selection_is_bounded_unique_and_strict() {
    let duplicate = ScanConfigFamilySelectionRequest {
        families_growing: true,
        families: vec![
            ScanConfigFamilySelectionItem {
                name: "Port scanners".to_string(),
                growing: true,
                selected: true,
            },
            ScanConfigFamilySelectionItem {
                name: "Port scanners".to_string(),
                growing: false,
                selected: false,
            },
        ],
    };
    assert!(matches!(
        validate_scan_config_family_selection_request(duplicate),
        Err(ApiError::BadRequest(_))
    ));

    let oversized = ScanConfigFamilySelectionRequest {
        families_growing: false,
        families: (0..=MAX_SCAN_CONFIG_FAMILY_SELECTIONS)
            .map(|index| ScanConfigFamilySelectionItem {
                name: format!("Family {index}"),
                growing: false,
                selected: false,
            })
            .collect(),
    };
    assert!(matches!(
        validate_scan_config_family_selection_request(oversized),
        Err(ApiError::BadRequest(_))
    ));

    for request in [
        serde_json::json!({"families_growing": true, "families": [], "extra": true}),
        serde_json::json!({
            "families_growing": true,
            "families": [{"name": "Port scanners", "growing": true, "selected": true, "extra": true}]
        }),
    ] {
        assert!(serde_json::from_value::<ScanConfigFamilySelectionRequest>(request).is_err());
    }
}

#[test]
fn scan_config_whole_only_families_allow_only_growing_all_or_static_empty() {
    assert_eq!(WHOLE_ONLY_SCAN_CONFIG_FAMILIES.len(), 26);
    for family in [
        "Ubuntu Local Security Checks",
        "VMware Local Security Checks",
        "Windows : Microsoft Bulletins",
    ] {
        for (growing, selected) in [(true, true), (false, false)] {
            let request = ScanConfigFamilySelectionRequest {
                families_growing: growing,
                families: vec![ScanConfigFamilySelectionItem {
                    name: family.to_string(),
                    growing,
                    selected,
                }],
            };
            assert!(validate_scan_config_family_selection_request(request).is_ok());
        }
        for (growing, selected) in [(false, true), (true, false)] {
            let request = ScanConfigFamilySelectionRequest {
                families_growing: growing,
                families: vec![ScanConfigFamilySelectionItem {
                    name: family.to_string(),
                    growing,
                    selected,
                }],
            };
            assert!(matches!(
                validate_scan_config_family_selection_request(request),
                Err(ApiError::Conflict(_))
            ));
        }
    }
}

#[test]
fn scan_config_family_selection_requires_exact_live_inventory() {
    let request = ValidatedScanConfigFamilySelection {
        families_growing: true,
        families: vec![
            ScanConfigFamilySelectionItem {
                name: "General".to_string(),
                growing: true,
                selected: true,
            },
            ScanConfigFamilySelectionItem {
                name: "Port scanners".to_string(),
                growing: false,
                selected: false,
            },
        ],
    };
    assert!(
        ensure_scan_config_family_selection_is_complete(
            &request,
            &["Port scanners".to_string(), "General".to_string()]
        )
        .is_ok()
    );
    for stale in [
        vec!["General".to_string()],
        vec![
            "General".to_string(),
            "Port scanners".to_string(),
            "Unknown".to_string(),
        ],
    ] {
        assert!(matches!(
            ensure_scan_config_family_selection_is_complete(&request, &stale),
            Err(ApiError::Conflict(_))
        ));
    }
}

#[test]
fn scan_config_family_selection_sql_rebuilds_canonical_rows_from_materialized_state() {
    let inventory = scan_config_known_family_names_sql();
    assert!(inventory.contains("SELECT DISTINCT n.family"));
    assert!(inventory.contains("n.family != 'Credentials'"));
    assert!(inventory.contains("ORDER BY n.family"));

    let sql = scan_config_replace_family_selection_sql();
    for required in [
        "unnest($4::text[], $5::boolean[], $6::boolean[])",
        "current_family_state AS MATERIALIZED",
        "current_nvt_state AS MATERIALIZED",
        "current_counts AS MATERIALIZED",
        "WHEN current.desired_all_selected THEN true",
        "WHEN counts.selected_nvt_count = counts.max_nvt_count",
        "DELETE FROM nvt_selectors",
        "INSERT INTO nvt_selectors",
        "0::integer AS type",
        "1,",
        "2,",
        "SET families_growing = $3::integer",
    ] {
        assert!(
            sql.contains(required),
            "family replacement SQL missing {required}"
        );
    }
    assert!(!sql.contains("format!("));
}

#[test]
fn scan_config_family_selection_handler_guards_before_atomic_commit() {
    let source = include_str!("scan_config_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_scan_config(")
        .expect("scan-config patch handler")
        .1
        .split_once("pub(crate) fn parse_scan_config_patch_payload")
        .expect("scan-config patch parser boundary")
        .0;
    for required in [
        "parse_scan_config_patch_payload(payload)?",
        "configs, configs_trash, nvt_selectors, tasks, nvts",
        "ensure_scan_config_is_human_owned",
        "ensure_scan_config_not_predefined",
        "ensure_unique_scan_config_name",
        "ensure_scan_config_not_referenced_by_any_task",
        "ensure_scan_config_selector_is_private",
        "load_scan_config_known_family_names",
        "ensure_scan_config_family_selection_is_complete",
        "execute_scan_config_family_selection_transaction",
        "tx.commit()",
    ] {
        assert!(
            handler.contains(required),
            "family patch handler missing {required}"
        );
    }
    assert!(
        handler.find("ensure_unique_scan_config_name")
            < handler.find("execute_scan_config_family_selection_transaction")
    );

    let browser = include_str!("browser_proxy_scan_config.rs");
    let browser_handler = browser
        .split_once("pub(crate) async fn browser_proxy_patch_scan_config")
        .expect("browser patch handler")
        .1
        .split_once("pub(crate) async fn browser_proxy_clone_scan_config")
        .expect("browser patch handler boundary")
        .0;
    assert!(browser_handler.contains("Result<Json<ScanConfigPatchRequest>, JsonRejection>"));
    assert!(browser_handler.contains("patch_scan_config("));
}

#[test]
fn scan_config_family_nvt_patch_request_is_strict_bounded_and_duplicate_free() {
    let request = serde_json::json!({
        "changes": [
            {"oid": "1.3.6.1.4.1.25623.1.0.100001", "selected": true},
            {"oid": "1.3.6.1.4.1.25623.1.0.100002", "selected": false}
        ]
    });
    let request = serde_json::from_value::<ScanConfigFamilyNvtsPatchRequest>(request)
        .expect("family NVT patch request shape");
    let validated =
        validate_scan_config_family_nvts_patch_request(request).expect("bounded unique changes");
    assert_eq!(validated.changes.len(), 2);
    assert_eq!(validated.changes[0].oid, "1.3.6.1.4.1.25623.1.0.100001");
    assert!(validated.changes[0].selected);
    assert!(!validated.changes[1].selected);

    for request in [
        serde_json::json!({"changes": []}),
        serde_json::json!({"changes": [{"oid": "1.3.6.a", "selected": true}]}),
        serde_json::json!({"changes": [
            {"oid": "1.3.6.1", "selected": true},
            {"oid": "1.3.6.1", "selected": false}
        ]}),
    ] {
        let request = serde_json::from_value::<ScanConfigFamilyNvtsPatchRequest>(request)
            .expect("JSON request shape must deserialize before validation");
        assert!(matches!(
            validate_scan_config_family_nvts_patch_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
    assert!(
        serde_json::from_value::<ScanConfigFamilyNvtsPatchRequest>(
            serde_json::json!({"changes": [{"oid": "1.3.6.1", "selected": true, "extra": 1}]})
        )
        .is_err()
    );

    let too_many = ScanConfigFamilyNvtsPatchRequest {
        changes: (0..=MAX_SCAN_CONFIG_FAMILY_NVT_SELECTION_CHANGES)
            .map(|index| ScanConfigFamilyNvtSelectionChange {
                oid: format!("1.3.6.1.{index}"),
                selected: true,
            })
            .collect(),
    };
    assert!(matches!(
        validate_scan_config_family_nvts_patch_request(too_many),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_family_nvt_patch_uses_static_include_and_growing_exclude_polarity() {
    assert_eq!(scan_config_family_nvt_selector_exclude(false, false), None);
    assert_eq!(
        scan_config_family_nvt_selector_exclude(false, true),
        Some(0)
    );
    assert_eq!(scan_config_family_nvt_selector_exclude(true, true), None);
    assert_eq!(
        scan_config_family_nvt_selector_exclude(true, false),
        Some(1)
    );
}

#[test]
fn diagnostic_nvt_selection_request_is_exact_and_strictly_bounded() {
    let request = serde_json::json!({"nvt_id": "1.3.6.1.4.1.25623.1.0.100001"});
    let request = serde_json::from_value::<DiagnosticNvtSelectionRequest>(request)
        .expect("diagnostic NVT selection request shape");
    let validated =
        validate_diagnostic_nvt_selection_request(request).expect("bounded numeric dotted NVT OID");
    assert_eq!(validated.nvt_id, "1.3.6.1.4.1.25623.1.0.100001");

    for nvt_id in [
        "",
        "1",
        "1.3.6.",
        "1.3.6.a",
        "1.3.6.1\n",
        &format!("1.{}", "2".repeat(128)),
    ] {
        assert!(matches!(
            validate_diagnostic_nvt_selection_request(DiagnosticNvtSelectionRequest {
                nvt_id: nvt_id.to_string(),
            }),
            Err(ApiError::BadRequest(_))
        ));
    }
    let unknown = serde_json::json!({"nvt_id": "1.3.6", "extra": true});
    assert!(serde_json::from_value::<DiagnosticNvtSelectionRequest>(unknown).is_err());
}

#[test]
fn diagnostic_nvt_selection_control_frame_is_exact_scrubbed_and_capped() {
    let mut frame = diagnostic_nvt_selection_command(
        "0123456789abcdef0123456789abcdef",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "1.3.6.1.4.1.25623.1.0.100001",
    );
    assert_eq!(
        frame.as_bytes(),
        b"scan-config-nvt-diagnostic 0123456789abcdef0123456789abcdef 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 1.3.6.1.4.1.25623.1.0.100001\n"
    );
    assert!(frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    frame.scrub();
    assert!(frame.as_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn diagnostic_nvt_selection_response_parser_maps_only_documented_gvmd_statuses() {
    assert!(matches!(
        parse_diagnostic_nvt_selection_response(b"0 selected"),
        Ok(DiagnosticNvtSelectionOutcome::Selected)
    ));
    for (response, expected_status, expected_code) in [
        (b"1 in_use".as_slice(), 409, "conflict"),
        (b"2 whole_only", 409, "conflict"),
        (b"3 config_not_found", 404, "not_found"),
        (b"4 nvt_not_found", 404, "not_found"),
        (b"5 prerequisite_not_found", 409, "conflict"),
        (b"6 shared_selector", 409, "conflict"),
        (b"99 forbidden", 403, "forbidden"),
        (b"-2 malformed", 400, "bad_request"),
        (
            b"-3 committed_indeterminate",
            502,
            "committed_response_unavailable",
        ),
        (b"-1 internal", 502, "control_failure"),
        (b"unexpected", 502, "mutation_outcome_indeterminate"),
    ] {
        let error = parse_diagnostic_nvt_selection_response(response).unwrap_err();
        assert_eq!(error.status_code().as_u16(), expected_status);
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn diagnostic_nvt_selection_handler_is_operator_authenticated_and_gvmd_authoritative() {
    let source = include_str!("scan_config_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn select_diagnostic_nvt")
        .unwrap()
        .1
        .split_once("pub(crate) fn parse_diagnostic_nvt_selection_payload")
        .unwrap()
        .0;
    for required in [
        "require_scan_config_write_operator(operator)?",
        "parse_uuid(&scan_config_id)?",
        "parse_diagnostic_nvt_selection_payload(payload)?",
        "validate_diagnostic_nvt_selection_request(request)?",
        "operator.user_uuid()",
        "request_diagnostic_nvt_selection(",
    ] {
        assert!(handler.contains(required), "handler missing {required}");
    }
    for forbidden in ["state.pool", "transaction()", "unsafe"] {
        assert!(
            !handler.contains(forbidden),
            "handler must delegate selector authority to gvmd, not {forbidden}"
        );
    }
}

#[test]
fn diagnostic_nvt_selection_openapi_contract_is_direct_guarded_and_minimal() {
    let openapi = include_str!("../../../api/openapi/yafvs-v1.yaml");
    let block = openapi
        .split_once("  /scan-configs/{scan_config_id}/diagnostic-nvt-selection:\n")
        .unwrap()
        .1
        .split_once("  /scan-configs/{scan_config_id}/clone:\n")
        .unwrap()
        .0;
    for expected in [
        "operationId: postScanConfigsByScanConfigIdDiagnosticNvtSelection",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: scan-config-nvt-selector-write",
        "$ref: '#/components/schemas/DiagnosticNvtSelectionRequest'",
        "$ref: '#/components/schemas/DiagnosticNvtSelectionAcknowledgement'",
        "'502':",
        "'503':",
    ] {
        assert!(
            block.contains(expected),
            "diagnostic selection OpenAPI missing {expected}"
        );
    }
    let schema = openapi
        .split_once("    DiagnosticNvtSelectionAcknowledgement:\n")
        .unwrap()
        .1
        .split_once("    ScheduleCloneRequest:\n")
        .unwrap()
        .0;
    for expected in ["config_id:", "nvt_id:", "status:", "enum: [selected]"] {
        assert!(
            schema.contains(expected),
            "acknowledgement schema missing {expected}"
        );
    }
    for forbidden in ["feed", "name", "family", "secret"] {
        assert!(
            !schema.contains(forbidden),
            "acknowledgement schema must not disclose {forbidden} data"
        );
    }
}

fn patch_request(name: Option<&str>, comment: Option<&str>) -> ScanConfigPatchRequest {
    ScanConfigPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        family_selection: None,
        preferences: None,
    }
}

#[test]
fn scan_config_create_request_requires_name_and_base_uuid() {
    let validated = validate_scan_config_create_request(create_request(
        "  copied scan  ",
        "12345678-1234-1234-1234-123456789abc",
        Some("  copied comment  "),
    ))
    .expect("valid scan-config create-from-base");
    assert_eq!(validated.name, "copied scan");
    assert_eq!(
        validated.base_scan_config_id,
        "12345678-1234-1234-1234-123456789abc"
    );
    assert_eq!(validated.comment, "copied comment");
    assert_eq!(
        validate_scan_config_create_request(create_request(
            "copied scan",
            "12345678-1234-1234-1234-123456789abc",
            None,
        ))
        .expect("default scan-config create comment")
        .comment,
        ""
    );
    assert!(matches!(
        validate_scan_config_create_request(create_request(
            "   ",
            "12345678-1234-1234-1234-123456789abc",
            None,
        )),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_scan_config_create_request(create_request("copied scan", "not-a-uuid", None)),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({
        "name": "copy",
        "base_scan_config_id": "12345678-1234-1234-1234-123456789abc",
        "preference": "not yet",
    });
    assert!(serde_json::from_value::<ScanConfigCreateRequest>(request).is_err());
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> ScanConfigCloneRequest {
    ScanConfigCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn scan_config_create_from_base_sql_copies_source_without_import_or_preference_mutation_payloads() {
    let metadata = scan_config_create_from_base_metadata_sql();
    assert!(metadata.contains("INSERT INTO configs"));
    assert!(metadata.contains("make_uuid()"));
    assert!(metadata.contains("$3,"));
    assert!(metadata.contains("$4,"));
    assert!(metadata.contains("families_growing, nvts_growing, predefined, creation_time"));
    assert!(metadata.contains("            0,\n            m_now(),"));
    assert!(metadata.contains("'scan'"));
    assert!(metadata.contains("FROM configs"));
    assert!(metadata.contains("WHERE id = $1"));
    assert!(!metadata.contains("uniquify"));
    assert!(!metadata.contains("coalesce($3"));

    let prefs = scan_config_clone_preferences_sql();
    assert!(prefs.contains("INSERT INTO config_preferences"));
    let selectors = scan_config_clone_selectors_sql();
    assert!(selectors.contains("INSERT INTO nvt_selectors"));
    let tags = scan_config_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
}

#[test]
fn scan_config_write_accepts_any_human_owner_and_rejects_ownerless_configs() {
    assert_eq!(ensure_scan_config_is_human_owned(Some(7)).unwrap(), 7);
    assert_eq!(ensure_scan_config_is_human_owned(Some(8)).unwrap(), 8);
    assert!(matches!(
        ensure_scan_config_is_human_owned(None),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn scan_config_create_and_clone_handlers_guard_source_before_insert() {
    let source = include_str!("scan_config_writes.rs");
    for (label, start, end, source_guard, side_effect) in [
        (
            "create",
            "pub(crate) async fn create_scan_config",
            "pub(crate) async fn clone_scan_config",
            "ensure_scan_config_clone_source_allowed(&config_state)?;",
            "execute_scan_config_create_from_base_transaction",
        ),
        (
            "clone",
            "pub(crate) async fn clone_scan_config",
            "pub(crate) async fn delete_scan_config",
            "ensure_scan_config_clone_source_allowed(&config_state)?;",
            "execute_scan_config_clone_transaction",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} scan-config handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} scan-config handler end marker must exist"))
            .0;

        assert!(
            handler.contains("require_scan_config_write_operator"),
            "{label} handler must require operator"
        );
        assert!(
            handler.contains(source_guard),
            "{label} handler must guard source"
        );
        assert!(
            handler.find(source_guard).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must verify source before inserting scan config"
        );
    }
}

#[test]
fn scan_config_mutating_handlers_enforce_human_ownership_and_protection_before_side_effects() {
    let source = include_str!("scan_config_writes.rs");
    for (label, start, end, owner_check, protection_guard, side_effect) in [
        (
            "delete",
            "pub(crate) async fn delete_scan_config",
            "pub(crate) async fn hard_delete_scan_config",
            "ensure_scan_config_is_human_owned(config_state.owner_id)?;",
            "ensure_scan_config_not_predefined(&config_state)?;",
            "execute_scan_config_trash_transaction",
        ),
        (
            "hard delete",
            "pub(crate) async fn hard_delete_scan_config",
            "pub(crate) async fn restore_scan_config",
            "ensure_scan_config_is_human_owned(trash.owner_id)?;",
            "ensure_scan_config_not_in_use_by_trash_tasks",
            "execute_scan_config_hard_delete_transaction",
        ),
        (
            "restore",
            "pub(crate) async fn restore_scan_config",
            "fn scan_config_write_location_headers",
            "ensure_scan_config_is_human_owned(trash.owner_id)?;",
            "ensure_scan_config_trash_scanner_is_live(&trash)?;",
            "execute_scan_config_restore_transaction",
        ),
        (
            "patch",
            "pub(crate) async fn patch_scan_config(\n",
            "tx.commit().await.map_err",
            "ensure_scan_config_is_human_owned(config_state.owner_id)?;",
            "ensure_scan_config_not_predefined(&config_state)?;",
            "execute_scan_config_metadata_patch_transaction",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} scan-config handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} scan-config handler end marker must exist"))
            .0;

        assert!(
            handler.contains("require_scan_config_write_operator"),
            "{label} handler must require operator"
        );
        assert!(
            handler.contains(owner_check),
            "{label} handler must check human ownership"
        );
        assert!(
            handler.contains(protection_guard),
            "{label} handler must check protection guard"
        );
        assert!(
            handler.find(owner_check).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check human ownership before side effects"
        );
        assert!(
            handler.find(protection_guard).unwrap() < handler.find(side_effect).unwrap(),
            "{label} handler must check protection guard before side effects"
        );
    }
}

#[test]
fn scan_config_clone_source_allows_predefined_or_any_human_owned_source() {
    let human_owned = ScanConfigWriteState {
        internal_id: 1,
        owner_id: Some(7),
        predefined: false,
        nvt_selector: "selector-1".to_string(),
        families_growing: 0,
    };
    assert!(ensure_scan_config_clone_source_allowed(&human_owned).is_ok());

    let predefined = ScanConfigWriteState {
        predefined: true,
        owner_id: None,
        ..human_owned.clone()
    };
    assert!(ensure_scan_config_clone_source_allowed(&predefined).is_ok());

    let ownerless_custom = ScanConfigWriteState {
        predefined: false,
        ..predefined
    };
    assert!(matches!(
        ensure_scan_config_clone_source_allowed(&ownerless_custom),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn scan_config_clone_request_trims_optional_name_and_rejects_unknown_fields() {
    let validated = validate_scan_config_clone_request(clone_request(
        Some("  copied scan  "),
        Some("  copied comment  "),
    ))
    .expect("valid scan-config clone");
    assert_eq!(validated.name.as_deref(), Some("copied scan"));
    assert_eq!(validated.comment.as_deref(), Some("copied comment"));
    assert_eq!(
        validate_scan_config_clone_request(clone_request(None, None))
            .expect("default scan-config clone name")
            .name,
        None
    );
    assert!(matches!(
        validate_scan_config_clone_request(clone_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "copy", "selector": "not yet"});
    assert!(serde_json::from_value::<ScanConfigCloneRequest>(request).is_err());
}

#[test]
fn scan_config_write_blocks_predefined_live_mutations() {
    let mutable = ScanConfigWriteState {
        internal_id: 1,
        owner_id: Some(7),
        predefined: false,
        nvt_selector: "selector-1".to_string(),
        families_growing: 0,
    };
    assert!(ensure_scan_config_not_predefined(&mutable).is_ok());

    let predefined = ScanConfigWriteState {
        predefined: true,
        ..mutable
    };
    assert!(matches!(
        ensure_scan_config_not_predefined(&predefined),
        Err(ApiError::Conflict(_))
    ));
}

#[test]
fn scan_config_family_nvt_patch_sql_normalizes_rows_and_recomputes_caches() {
    let delete = scan_config_delete_family_nvt_selector_rows_sql();
    assert!(delete.contains("DELETE FROM nvt_selectors"));
    assert!(delete.contains("name = $1"));
    assert!(delete.contains("type = 2"));
    assert!(delete.contains("family = $2"));
    assert!(delete.contains("family_or_nvt = ANY($3::text[])"));

    let insert = scan_config_insert_family_nvt_selector_rows_sql();
    assert!(insert.contains("INSERT INTO nvt_selectors"));
    assert!(insert.contains("SELECT $1, $3, 2, oid, $2"));
    assert!(insert.contains("unnest($4::text[])"));

    let cache = scan_config_recalculate_family_nvt_caches_sql();
    for required in [
        "FROM nvts n",
        "FROM nvt_selectors ns",
        "count(DISTINCT ns.family_or_nvt)",
        "family_count = cache_values.family_count",
        "nvt_count = cache_values.nvt_count",
        "nvts_growing = cache_values.nvts_growing",
        "modification_time = m_now()",
    ] {
        assert!(cache.contains(required), "cache refresh missing {required}");
    }
    assert!(!cache.contains("SET families_growing ="));

    let tasks = scan_config_any_task_count_sql();
    assert!(tasks.contains("coalesce(config_location, 0) = 0"));
    assert!(!tasks.contains("hidden"));

    let shared = scan_config_selector_reference_count_sql();
    assert!(shared.contains("FROM configs WHERE nvt_selector = $1"));
    assert!(shared.contains("FROM configs_trash WHERE nvt_selector = $1"));
}

#[test]
fn scan_config_family_nvt_patch_rejects_canonical_whole_only_families() {
    for family in [
        "Ubuntu Local Security Checks",
        "VMware Local Security Checks",
        "Windows : Microsoft Bulletins",
    ] {
        assert!(matches!(
            ensure_scan_config_family_is_not_whole_only(family),
            Err(ApiError::Conflict(_))
        ));
    }
    assert!(ensure_scan_config_family_is_not_whole_only("Port scanners").is_ok());
}

#[test]
fn scan_config_family_nvt_patch_handler_guards_and_normalizes_before_commit() {
    let source = include_str!("scan_config_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_scan_config_family_nvts")
        .expect("family NVT patch handler must exist")
        .1
        .split_once("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
        .expect("family NVT patch handler must end before diagnostic type")
        .0;
    for required in [
        "require_scan_config_write_operator(operator)?",
        "validate_scan_config_family(&family)?",
        "parse_scan_config_family_nvts_patch_payload(payload)?",
        "validate_scan_config_family_nvts_patch_request(request)?",
        "LOCK TABLE configs, configs_trash, nvt_selectors, tasks, nvts",
        "ensure_scan_config_is_human_owned",
        "ensure_scan_config_not_predefined",
        "ensure_scan_config_not_referenced_by_any_task",
        "ensure_scan_config_selector_is_private",
        "ensure_scan_config_family_nvt_change_oids_exist",
        "ensure_scan_config_family_is_not_whole_only",
        "scan_config_family_nvt_default_selected",
        "execute_scan_config_family_nvts_patch_transaction",
        "commit patch scan-config family NVT transaction",
    ] {
        assert!(
            handler.contains(required),
            "family NVT patch handler missing {required}"
        );
    }
    assert!(
        handler
            .find("ensure_scan_config_selector_is_private")
            .unwrap()
            < handler
                .find("execute_scan_config_family_nvts_patch_transaction")
                .unwrap()
    );
    let browser = include_str!("browser_proxy_scan_config.rs");
    assert!(
        browser.contains("payload: Result<Json<ScanConfigFamilyNvtsPatchRequest>, JsonRejection>")
    );
    assert!(source.contains(
        "request body must be application/json matching ScanConfigFamilyNvtsPatchRequest"
    ));
}

#[test]
fn scan_config_clone_sql_copies_preferences_selectors_tags_and_makes_user_owned_scan_config() {
    let metadata = scan_config_clone_metadata_sql();
    assert!(metadata.contains("INSERT INTO configs"));
    assert!(metadata.contains("make_uuid()"));
    assert!(metadata.contains("coalesce($3, uniquify('config', name, $2, ' Clone'))"));
    assert!(metadata.contains("coalesce($4, comment)"));
    assert!(metadata.contains("families_growing, nvts_growing, predefined, creation_time"));
    assert!(metadata.contains("            0,\n            m_now(),"));
    assert!(!metadata.contains("nvts_growing,\n            predefined"));
    assert!(metadata.contains("'scan'"));
    assert!(metadata.contains("RETURNING id::integer, uuid::text"));

    let prefs = scan_config_clone_preferences_sql();
    assert!(prefs.contains("INSERT INTO config_preferences"));
    assert!(prefs.contains("SELECT $2, type, name, value, default_value"));
    assert!(prefs.contains("FROM config_preferences"));

    let selectors = scan_config_clone_selectors_sql();
    assert!(selectors.contains("INSERT INTO nvt_selectors"));
    assert!(selectors.contains("SELECT (SELECT nvt_selector FROM configs WHERE id = $2)"));
    assert!(selectors.contains("WHERE name = (SELECT nvt_selector FROM configs WHERE id = $1)"));

    let tags = scan_config_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'config'"));
    assert!(tags.contains("resource_location = 0"));
}

#[test]
fn scan_config_patch_request_trims_metadata_fields() {
    let validated = validate_scan_config_patch_request(patch_request(
        Some("  web config  "),
        Some("  comment  "),
    ))
    .expect("valid scan-config patch");
    assert_eq!(validated.name.as_deref(), Some("web config"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn scan_config_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_scan_config_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn scan_config_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Scan", "nvt_selector": "changed"});
    assert!(serde_json::from_value::<ScanConfigPatchRequest>(request).is_err());
}

#[test]
fn scan_config_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_scan_config_patch_request(ScanConfigPatchRequest {
            name: Some("x".repeat(MAX_SCAN_CONFIG_TEXT_BYTES + 1)),
            comment: None,
            family_selection: None,
            preferences: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_patch_sql_is_metadata_only() {
    let sql = scan_config_update_metadata_sql();
    assert!(sql.contains("UPDATE configs"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("RETURNING id::integer, uuid::text"));
    for forbidden in [
        "nvt_selector",
        "family_count",
        "nvt_count",
        "families_growing",
        "nvts_growing",
        "config_preferences",
        "nvt_selectors",
        "tasks",
        "configs_trash",
    ] {
        assert!(
            !sql.contains(forbidden),
            "scan-config patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn scan_config_patch_state_blocks_predefined_and_non_scan_configs() {
    let state = scan_config_write_state_sql();
    assert!(state.contains("owner::integer"));
    assert!(state.contains("coalesce(predefined, 0)::integer"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));
}

#[test]
fn scan_config_patch_uniqueness_checks_live_and_trash_names() {
    let sql = scan_config_unique_name_sql();
    assert!(sql.contains("FROM configs WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM configs_trash WHERE name = $1"));
}

#[test]
fn scan_config_trash_sql_copies_metadata_preferences_and_relinks_dependents() {
    let insert = scan_config_trash_insert_sql();
    assert!(insert.contains("INSERT INTO configs_trash"));
    assert!(insert.contains("nvt_selector"));
    assert!(insert.contains("scanner_location, usage_type"));
    assert!(insert.contains("modification_time, 0, usage_type"));
    assert!(insert.contains("RETURNING id::integer, uuid::text"));

    let prefs = scan_config_preferences_trash_insert_sql();
    assert!(prefs.contains("INSERT INTO config_preferences_trash"));
    assert!(prefs.contains("SELECT $1, type, name, value, default_value"));
    assert!(prefs.contains("FROM config_preferences"));

    let tasks = scan_config_task_relink_to_trash_sql();
    assert!(tasks.contains("UPDATE tasks"));
    assert!(tasks.contains("config_location = 1"));
    assert!(tasks.contains("config_location = 0"));

    let live_tags = scan_config_tag_locations_to_trash_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_type = 'config'"));
    assert!(live_tags.contains("resource_location = 1"));

    let trash_tags = scan_config_trash_tag_locations_to_trash_sql();
    assert!(trash_tags.contains("UPDATE tag_resources_trash"));
    assert!(trash_tags.contains("resource_type = 'config'"));
    assert!(trash_tags.contains("resource_location = 1"));

    assert!(scan_config_delete_preferences_sql().contains("DELETE FROM config_preferences"));
    assert!(scan_config_delete_metadata_sql().contains("DELETE FROM configs"));
}

#[test]
fn scan_config_restore_sql_copies_metadata_preferences_and_relinks_dependents() {
    let state = scan_config_trash_state_sql();
    assert!(state.contains("FROM configs_trash"));
    assert!(state.contains("owner::integer"));
    assert!(state.contains("coalesce(scanner_location, 0)::integer"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));

    let name_conflict = scan_config_unique_live_name_sql();
    assert!(name_conflict.contains("FROM configs"));
    assert!(name_conflict.contains("name = $1"));
    assert!(!name_conflict.contains("owner ="));

    let restore = scan_config_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO configs"));
    assert!(restore.contains("nvt_selector"));
    assert!(restore.contains("FROM configs_trash"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));

    let prefs = scan_config_preferences_restore_sql();
    assert!(prefs.contains("INSERT INTO config_preferences"));
    assert!(prefs.contains("FROM config_preferences_trash"));

    let tasks = scan_config_task_relink_to_live_sql();
    assert!(tasks.contains("UPDATE tasks"));
    assert!(tasks.contains("config_location = 0"));
    assert!(tasks.contains("config_location = 1"));

    let live_tags = scan_config_tag_locations_to_live_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_location = 0"));

    let trash_tags = scan_config_trash_tag_locations_to_live_sql();
    assert!(trash_tags.contains("UPDATE tag_resources_trash"));
    assert!(trash_tags.contains("resource_location = 0"));

    assert!(
        scan_config_delete_trash_preferences_sql().contains("DELETE FROM config_preferences_trash")
    );
    assert!(scan_config_delete_trash_metadata_sql().contains("DELETE FROM configs_trash"));
}

#[test]
fn scan_config_hard_delete_sql_is_trash_only_and_preserves_shared_selector() {
    let task_guard = scan_config_trash_task_count_sql();
    assert!(task_guard.contains("FROM tasks"));
    assert!(task_guard.contains("config_location = 1"));
    assert!(!task_guard.contains("hidden = 0"));

    let selector = scan_config_delete_trash_selector_sql();
    assert!(selector.contains("DELETE FROM nvt_selectors"));
    assert!(selector.contains("configs_trash"));
    assert!(selector.contains("54b45713-d4f4-4435-b20d-304c175ed8c5"));
    assert!(!selector.contains("configs WHERE"));

    let live_tags = scan_config_trash_tag_delete_sql();
    assert!(live_tags.contains("DELETE FROM tag_resources"));
    assert!(live_tags.contains("resource_type = 'config'"));
    assert!(live_tags.contains("resource_location = 1"));

    let trash_tags = scan_config_trash_tag_trash_delete_sql();
    assert!(trash_tags.contains("DELETE FROM tag_resources_trash"));
    assert!(trash_tags.contains("resource_type = 'config'"));
    assert!(trash_tags.contains("resource_location = 1"));
}

#[test]
fn scan_config_delete_guard_blocks_live_task_references_only() {
    let sql = scan_config_live_task_count_sql();
    assert!(sql.contains("FROM tasks"));
    assert!(sql.contains("config_location = 0"));
    assert!(sql.contains("hidden = 0"));
}
