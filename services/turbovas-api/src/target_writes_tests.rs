// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    target_write_db::ensure_target_owner_matches_operator,
    target_write_sql::*,
    target_write_validation::{
        MAX_TARGET_HOSTS, MAX_TARGET_TEXT_BYTES, TargetPatchRequest, validate_alive_tests,
        validate_target_patch_request,
    },
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> TargetPatchRequest {
    TargetPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
        alive_tests: None,
        allow_simultaneous_ips: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        port_list_id: None,
        hosts: None,
        exclude_hosts: None,
    }
}

fn alive_patch_request(values: &[&str]) -> TargetPatchRequest {
    TargetPatchRequest {
        name: None,
        comment: None,
        alive_tests: Some(values.iter().map(|value| value.to_string()).collect()),
        allow_simultaneous_ips: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        port_list_id: None,
        hosts: None,
        exclude_hosts: None,
    }
}

fn scan_settings_patch_request(
    allow_simultaneous_ips: Option<bool>,
    reverse_lookup_only: Option<bool>,
    reverse_lookup_unify: Option<bool>,
) -> TargetPatchRequest {
    TargetPatchRequest {
        name: None,
        comment: None,
        alive_tests: None,
        allow_simultaneous_ips,
        reverse_lookup_only,
        reverse_lookup_unify,
        port_list_id: None,
        hosts: None,
        exclude_hosts: None,
    }
}

fn port_list_patch_request(port_list_id: &str) -> TargetPatchRequest {
    TargetPatchRequest {
        name: None,
        comment: None,
        alive_tests: None,
        allow_simultaneous_ips: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        port_list_id: Some(port_list_id.to_string()),
        hosts: None,
        exclude_hosts: None,
    }
}

fn hosts_patch_request(hosts: &[&str], exclude_hosts: &[&str]) -> TargetPatchRequest {
    TargetPatchRequest {
        name: None,
        comment: None,
        alive_tests: None,
        allow_simultaneous_ips: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        port_list_id: None,
        hosts: Some(hosts.iter().map(|value| value.to_string()).collect()),
        exclude_hosts: Some(
            exclude_hosts
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ),
    }
}

#[test]
fn target_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_target_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_target_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn target_patch_request_trims_metadata_fields() {
    let validated =
        validate_target_patch_request(patch_request(Some("  scan target  "), Some("  comment  ")))
            .expect("valid target patch");
    assert_eq!(validated.name.as_deref(), Some("scan target"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn target_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_target_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_target_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_target_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn target_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_target_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Target", "hosts": "192.0.2.1"});
    assert!(serde_json::from_value::<TargetPatchRequest>(request).is_err());
}

#[test]
fn target_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_target_patch_request(TargetPatchRequest {
            name: Some("x".repeat(MAX_TARGET_TEXT_BYTES + 1)),
            comment: None,
            alive_tests: None,
            allow_simultaneous_ips: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            port_list_id: None,
            hosts: None,
            exclude_hosts: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_validates_simple_host_lists() {
    let validated = validate_target_patch_request(hosts_patch_request(
        &["  192.168.001.010  ", "host-one", "host-one", "2001:db8::1"],
        &["192.168.1.10"],
    ))
    .expect("valid simple hosts patch");
    assert_eq!(
        validated.hosts.as_deref(),
        Some("192.168.1.10, host-one, 2001:db8::1")
    );
    assert_eq!(validated.exclude_hosts.as_deref(), Some("192.168.1.10"));
    assert!(validated.changes_task_in_use_guarded_scan_inputs());

    assert!(matches!(
        validate_target_patch_request(TargetPatchRequest {
            name: None,
            comment: None,
            alive_tests: None,
            allow_simultaneous_ips: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            port_list_id: None,
            hosts: None,
            exclude_hosts: Some(vec!["192.0.2.1".to_string()]),
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(hosts_patch_request(&["192.0.2.1/24"], &[])),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(hosts_patch_request(&["192.0.2.1-10"], &[])),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(hosts_patch_request(&["invalid-host-!!!"], &[])),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(hosts_patch_request(&["192.0.2.1"], &["192.0.2.1"])),
        Err(ApiError::BadRequest(_))
    ));
    let too_many = (0..=MAX_TARGET_HOSTS)
        .map(|index| format!("host-{index}"))
        .collect::<Vec<_>>();
    let too_many_refs = too_many.iter().map(String::as_str).collect::<Vec<_>>();
    assert!(matches!(
        validate_target_patch_request(hosts_patch_request(&too_many_refs, &[])),
        Err(ApiError::BadRequest(_))
    ));
    let oversized = "x".repeat(MAX_TARGET_TEXT_BYTES + 1);
    assert!(matches!(
        validate_target_patch_request(hosts_patch_request(&[oversized.as_str()], &[])),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_validates_guarded_scan_settings() {
    let validated = validate_target_patch_request(scan_settings_patch_request(
        Some(false),
        Some(true),
        Some(false),
    ))
    .expect("valid guarded target scan settings patch");
    assert_eq!(validated.allow_simultaneous_ips, Some(0));
    assert_eq!(validated.reverse_lookup_only, Some(1));
    assert_eq!(validated.reverse_lookup_unify, Some(0));
    assert!(validated.changes_task_in_use_guarded_scan_inputs());

    let alive_only = validate_target_patch_request(alive_patch_request(&["ICMP Ping"]))
        .expect("alive-only patch");
    assert!(!alive_only.changes_task_in_use_guarded_scan_inputs());

    let port_list = validate_target_patch_request(port_list_patch_request(
        "12345678-1234-1234-1234-123456789abc",
    ))
    .expect("valid port-list reference patch");
    assert_eq!(
        port_list.port_list_id.as_deref(),
        Some("12345678-1234-1234-1234-123456789abc")
    );
    assert!(port_list.changes_task_in_use_guarded_scan_inputs());

    assert!(matches!(
        validate_target_patch_request(port_list_patch_request("not-a-uuid")),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_validates_alive_test_bitfields() {
    let validated = validate_target_patch_request(alive_patch_request(&[
        "ICMP Ping",
        "TCP-ACK Service Ping",
        "TCP-SYN Service Ping",
    ]))
    .expect("valid alive-test patch");
    assert_eq!(validated.alive_test, Some(19));
    assert_eq!(
        validate_alive_tests(Some(vec![])).expect("empty default"),
        Some(0)
    );
    assert_eq!(
        validate_alive_tests(Some(vec!["Scan Config Default".to_string()])).expect("default"),
        Some(0)
    );
    assert_eq!(
        validate_alive_tests(Some(vec!["Consider Alive".to_string()])).expect("consider alive"),
        Some(8)
    );
}

#[test]
fn target_patch_request_rejects_ambiguous_alive_test_values() {
    assert!(matches!(
        validate_target_patch_request(alive_patch_request(&["Banana Ping"])),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(alive_patch_request(&["Scan Config Default", "ICMP Ping"])),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(alive_patch_request(&["Consider Alive", "ARP Ping"])),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_sql_is_metadata_only() {
    let sql = target_update_metadata_sql();
    assert!(sql.contains("UPDATE targets"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("alive_test = coalesce($4, alive_test)"));
    assert!(sql.contains("allow_simultaneous_ips = coalesce($5, allow_simultaneous_ips)"));
    assert!(sql.contains("reverse_lookup_only = coalesce($6, reverse_lookup_only)"));
    assert!(sql.contains("reverse_lookup_unify = coalesce($7, reverse_lookup_unify)"));
    assert!(sql.contains("port_list = coalesce($8, port_list)"));
    assert!(sql.contains("hosts = coalesce($9, hosts)"));
    assert!(sql.contains("exclude_hosts = coalesce($10, exclude_hosts)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("RETURNING uuid::text"));
    for forbidden in [
        "targets_login_data",
        "targets_trash",
        "tasks",
        "credentials",
        "ssh",
        "smb",
        "snmp",
        "krb5",
        "esxi",
    ] {
        assert!(
            !sql.contains(forbidden),
            "target patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn target_patch_state_and_uniqueness_are_live_metadata_only() {
    let state = target_write_state_sql();
    assert!(state.contains("FROM targets"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(state.contains("owner::integer"));
    assert!(!state.contains("targets_login_data"));
    assert!(!state.contains("targets_trash"));

    let unique = target_unique_name_sql();
    assert!(unique.contains("FROM targets"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(unique.contains("owner = $3"));
    assert!(!unique.contains("targets_login_data"));
    assert!(!unique.contains("targets_trash"));

    let in_use = target_in_use_sql();
    assert!(in_use.contains("FROM tasks"));
    assert!(in_use.contains("target = $1"));
    assert!(in_use.contains("target_location = 0"));
    assert!(in_use.contains("hidden = 0"));
    assert!(!in_use.contains("targets_login_data"));

    let assignable_port_list = target_assignable_port_list_state_sql();
    assert!(assignable_port_list.contains("FROM port_lists"));
    assert!(assignable_port_list.contains("owner::integer"));
    assert!(assignable_port_list.contains("coalesce(predefined, 0)::integer"));
}
