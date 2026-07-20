// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde_json::{Value, json};

use super::{
    alert_definition_db::{
        AlertDefinitionWriteState, alert_definition_filter_is_retained,
        ensure_alert_definition_is_human_owned, ensure_alert_definition_revision_matches,
        ensure_snmp_community_preserve_allowed,
    },
    alert_definition_payloads::{
        AlertDefinitionBase, AlertDefinitionReplaceRequest, build_alert_definition,
        validate_alert_definition_replace_request,
    },
};

use super::alert_definition_db::ensure_alert_definition_name_count_is_unique;
use super::alert_definition_transactions::alert_definition_active_database_value;

fn parse_and_validate(
    value: Value,
) -> super::alert_definition_payloads::ValidatedAlertDefinitionReplace {
    validate_alert_definition_replace_request(replacement_request(value))
        .unwrap()
        .1
}

fn replacement_request(value: Value) -> AlertDefinitionReplaceRequest {
    serde_json::from_value(json!({
        "expected_revision": "7",
        "definition": value,
    }))
    .unwrap()
}

#[test]
fn retained_definition_maps_boolean_active_to_the_legacy_integer_column() {
    assert_eq!(alert_definition_active_database_value(false), 0);
    assert_eq!(alert_definition_active_database_value(true), 1);
}

#[test]
fn alert_definition_accepts_any_human_owner_and_rejects_ownerless_rows() {
    assert_eq!(ensure_alert_definition_is_human_owned(Some(7)).unwrap(), 7);
    assert_eq!(ensure_alert_definition_is_human_owned(Some(8)).unwrap(), 8);
    assert!(ensure_alert_definition_is_human_owned(None).is_err());
}

#[test]
fn retained_definition_accepts_both_legacy_and_native_no_filter_encodings() {
    assert!(alert_definition_filter_is_retained(None));
    assert!(alert_definition_filter_is_retained(Some(0)));
    assert!(!alert_definition_filter_is_retained(Some(1)));
}

fn common(method: &str) -> Value {
    json!({
        "method": method,
        "name": "Definition",
        "comment": "retained",
        "active": true,
        "status": "Done"
    })
}

#[test]
fn retained_method_replace_shapes_validate_for_cross_method_transitions() {
    let mut email = common("EMAIL");
    email.as_object_mut().unwrap().extend([
        ("to_address".to_string(), json!("ops@example.test")),
        ("subject".to_string(), json!("Scan complete")),
        ("notice".to_string(), json!("simple")),
    ]);
    let mut smb = common("SMB");
    smb.as_object_mut().unwrap().extend([
        (
            "smb_credential_id".to_string(),
            json!("11111111-1111-1111-1111-111111111111"),
        ),
        ("smb_share_path".to_string(), json!(r"\\server\share")),
        ("smb_file_path".to_string(), json!("reports/result.xml")),
        (
            "report_format_id".to_string(),
            json!("22222222-2222-2222-2222-222222222222"),
        ),
    ]);
    let syslog = common("SYSLOG");
    let mut snmp = common("SNMP");
    snmp.as_object_mut().unwrap().extend([
        ("snmp_agent".to_string(), json!("192.0.2.10")),
        ("snmp_community_mode".to_string(), json!("replace")),
        ("snmp_community".to_string(), json!("write-only")),
        ("snmp_message".to_string(), json!("Scan complete")),
    ]);
    let mut scp = common("SCP");
    scp.as_object_mut().unwrap().extend([
        (
            "scp_credential_id".to_string(),
            json!("33333333-3333-3333-3333-333333333333"),
        ),
        ("scp_host".to_string(), json!("archive.example.test")),
        ("scp_port".to_string(), json!(22)),
        ("scp_known_hosts".to_string(), json!("host ssh-ed25519 key")),
        ("scp_path".to_string(), json!("/srv/reports")),
        (
            "report_format_id".to_string(),
            json!("44444444-4444-4444-4444-444444444444"),
        ),
    ]);
    let mut start_task = common("START_TASK");
    start_task.as_object_mut().unwrap().insert(
        "task_id".to_string(),
        json!("55555555-5555-5555-5555-555555555555"),
    );

    for request in [email, smb, syslog, snmp, scp, start_task] {
        parse_and_validate(request);
    }
}

#[test]
fn name_collision_is_rejected_but_the_target_name_is_available() {
    assert!(ensure_alert_definition_name_count_is_unique(0).is_ok());
    assert!(ensure_alert_definition_name_count_is_unique(1).is_err());
}

#[test]
fn snmp_preserve_requires_existing_nonempty_snmp_secret() {
    let mut preserve = common("SNMP");
    preserve.as_object_mut().unwrap().extend([
        ("snmp_agent".to_string(), json!("192.0.2.10")),
        ("snmp_community_mode".to_string(), json!("preserve")),
        ("snmp_message".to_string(), json!("Scan complete")),
    ]);
    let request = parse_and_validate(preserve.clone());
    let eligible = AlertDefinitionWriteState {
        internal_id: 1,
        owner_id: Some(7),
        revision: "7".to_string(),
        method: 9,
        snmp_community_configured: true,
    };
    assert!(ensure_snmp_community_preserve_allowed(&eligible, &request).is_ok());

    for state in [
        AlertDefinitionWriteState {
            method: 1,
            ..eligible.clone()
        },
        AlertDefinitionWriteState {
            snmp_community_configured: false,
            ..eligible.clone()
        },
    ] {
        assert!(ensure_snmp_community_preserve_allowed(&state, &request).is_err());
    }

    preserve
        .as_object_mut()
        .unwrap()
        .insert("snmp_community".to_string(), json!("must-not-be-read"));
    let parsed = replacement_request(preserve);
    assert!(validate_alert_definition_replace_request(parsed).is_err());
}

#[test]
fn snmp_replace_requires_bounded_nonempty_write_only_community() {
    for community in [None, Some(""), Some("   ")] {
        let mut replace = common("SNMP");
        replace.as_object_mut().unwrap().extend([
            ("snmp_agent".to_string(), json!("192.0.2.10")),
            ("snmp_community_mode".to_string(), json!("replace")),
            ("snmp_message".to_string(), json!("Scan complete")),
        ]);
        if let Some(community) = community {
            replace
                .as_object_mut()
                .unwrap()
                .insert("snmp_community".to_string(), json!(community));
        }
        let parsed = replacement_request(replace);
        assert!(validate_alert_definition_replace_request(parsed).is_err());
    }
}

#[test]
fn strict_definition_rejects_unknown_or_duplicate_method_keys() {
    let base = || AlertDefinitionBase {
        revision: "7".to_string(),
        name: "Alert".to_string(),
        comment: String::new(),
        active: true,
        status: "Done".to_string(),
    };
    let event = || vec![("status".to_string(), Some("Done".to_string()))];
    assert!(
        build_alert_definition(
            base(),
            5,
            0,
            false,
            event(),
            vec![
                ("submethod".to_string(), Some("syslog".to_string())),
                ("unknown".to_string(), Some("value".to_string())),
            ],
        )
        .is_err()
    );
    assert!(
        build_alert_definition(
            base(),
            5,
            0,
            false,
            event(),
            vec![
                ("submethod".to_string(), Some("syslog".to_string())),
                ("submethod".to_string(), Some("syslog".to_string())),
            ],
        )
        .is_err()
    );
}

#[test]
fn snmp_definition_serialization_never_contains_community_value() {
    let definition = build_alert_definition(
        AlertDefinitionBase {
            revision: "7".to_string(),
            name: "SNMP".to_string(),
            comment: String::new(),
            active: true,
            status: "Done".to_string(),
        },
        9,
        0,
        true,
        vec![("status".to_string(), Some("Done".to_string()))],
        vec![
            ("snmp_agent".to_string(), Some("192.0.2.10".to_string())),
            ("snmp_community".to_string(), None),
            ("snmp_message".to_string(), Some("complete".to_string())),
        ],
    )
    .unwrap();
    let value = serde_json::to_value(definition).unwrap();
    assert_eq!(value["method"], "SNMP");
    assert_eq!(value["snmp_community_configured"], true);
    assert!(value.get("snmp_community").is_none());
    assert!(!value.to_string().contains("write-only"));
}

#[test]
fn snmp_definition_rejects_missing_empty_and_duplicate_community_rows() {
    let base = || AlertDefinitionBase {
        revision: "7".to_string(),
        name: "SNMP".to_string(),
        comment: String::new(),
        active: true,
        status: "Done".to_string(),
    };
    let event = || vec![("status".to_string(), Some("Done".to_string()))];
    let fields = || {
        vec![
            ("snmp_agent".to_string(), Some("192.0.2.10".to_string())),
            ("snmp_message".to_string(), Some("complete".to_string())),
        ]
    };

    assert!(build_alert_definition(base(), 9, 0, false, event(), fields()).is_err());

    let mut empty = fields();
    empty.push(("snmp_community".to_string(), None));
    assert!(build_alert_definition(base(), 9, 0, false, event(), empty).is_err());

    let mut duplicate = fields();
    duplicate.push(("snmp_community".to_string(), None));
    duplicate.push(("snmp_community".to_string(), None));
    assert!(build_alert_definition(base(), 9, 0, false, event(), duplicate).is_err());
}

#[test]
fn full_replacement_rejects_stale_or_malformed_revisions() {
    let state = AlertDefinitionWriteState {
        internal_id: 1,
        owner_id: Some(7),
        revision: "42".to_string(),
        method: 5,
        snmp_community_configured: false,
    };
    assert!(ensure_alert_definition_revision_matches(&state, "42").is_ok());
    assert!(ensure_alert_definition_revision_matches(&state, "41").is_err());

    let malformed: Result<AlertDefinitionReplaceRequest, _> = serde_json::from_value(json!({
        "expected_revision": "not-a-revision",
        "definition": common("SYSLOG"),
    }));
    assert!(
        validate_alert_definition_replace_request(malformed.unwrap()).is_err(),
        "opaque revisions must be bounded decimal strings"
    );
}
