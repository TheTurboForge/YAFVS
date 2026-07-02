// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    target_write_db::ensure_target_owner_matches_operator,
    target_write_sql::*,
    target_write_validation::{
        MAX_TARGET_HOSTS, MAX_TARGET_TEXT_BYTES, TargetCloneRequest, TargetCreateRequest,
        TargetCredentialLinkPatchRequest, TargetCredentialsCreateRequest,
        TargetCredentialsPatchRequest, TargetPatchRequest, ValidatedCredentialPatchAction,
        validate_alive_tests, validate_target_clone_request, validate_target_create_request,
        validate_target_patch_request,
    },
};

fn create_request() -> TargetCreateRequest {
    TargetCreateRequest {
        name: "target-one".to_string(),
        comment: Some("temporary target".to_string()),
        alive_tests: vec!["ICMP Ping".to_string()],
        allow_simultaneous_ips: true,
        reverse_lookup_only: false,
        reverse_lookup_unify: true,
        port_list_id: "12345678-1234-1234-1234-123456789abc".to_string(),
        hosts: vec!["192.0.2.42".to_string(), "host-one".to_string()],
        exclude_hosts: Some(vec!["192.0.2.43".to_string()]),
        credentials: None,
    }
}

fn credential_link(id: &str, port: Option<i32>) -> TargetCredentialLinkPatchRequest {
    TargetCredentialLinkPatchRequest {
        id: id.to_string(),
        port,
    }
}

fn credentials_patch_request(credentials: TargetCredentialsPatchRequest) -> TargetPatchRequest {
    TargetPatchRequest {
        name: None,
        comment: None,
        alive_tests: None,
        allow_simultaneous_ips: None,
        reverse_lookup_only: None,
        reverse_lookup_unify: None,
        port_list_id: None,
        hosts: None,
        exclude_hosts: None,
        credentials: Some(credentials),
    }
}

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
        credentials: None,
    }
}

#[test]
fn target_patch_request_validates_credential_link_actions() {
    let ssh_id = "12345678-1234-1234-1234-123456789abc";
    let elevate_id = "12345678-1234-1234-1234-123456789abd";
    let validated =
        validate_target_patch_request(credentials_patch_request(TargetCredentialsPatchRequest {
            ssh: Some(
                crate::target_write_validation::TargetCredentialPatchFieldRequest::Set(
                    credential_link(ssh_id, None),
                ),
            ),
            ssh_elevate: Some(
                crate::target_write_validation::TargetCredentialPatchFieldRequest::Set(
                    credential_link(elevate_id, None),
                ),
            ),
            smb: Some(crate::target_write_validation::TargetCredentialPatchFieldRequest::Clear),
            ..Default::default()
        }))
        .expect("valid credential link patch");
    assert!(validated.changes_credential_links());
    assert!(!validated.changes_task_in_use_guarded_scan_inputs());
    match validated.credentials.ssh {
        Some(ValidatedCredentialPatchAction::Set(link)) => {
            assert_eq!(link.id, ssh_id);
            assert_eq!(link.port, Some(22));
        }
        _ => panic!("ssh credential should be set"),
    }
    match validated.credentials.ssh_elevate {
        Some(ValidatedCredentialPatchAction::Set(link)) => {
            assert_eq!(link.id, elevate_id);
            assert_eq!(link.port, None);
        }
        _ => panic!("elevate credential should be set"),
    }
    assert!(matches!(
        validated.credentials.smb,
        Some(ValidatedCredentialPatchAction::Clear)
    ));
}

#[test]
fn target_patch_request_rejects_unsafe_credential_link_shapes() {
    assert!(matches!(
        validate_target_patch_request(credentials_patch_request(
            TargetCredentialsPatchRequest::default()
        )),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(credentials_patch_request(TargetCredentialsPatchRequest {
            ssh: Some(
                crate::target_write_validation::TargetCredentialPatchFieldRequest::Set(
                    credential_link("12345678-1234-1234-1234-123456789abc", Some(0)),
                )
            ),
            ..Default::default()
        })),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(credentials_patch_request(TargetCredentialsPatchRequest {
            smb: Some(
                crate::target_write_validation::TargetCredentialPatchFieldRequest::Set(
                    credential_link("12345678-1234-1234-1234-123456789abc", Some(445)),
                )
            ),
            ..Default::default()
        })),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_target_patch_request(credentials_patch_request(TargetCredentialsPatchRequest {
            snmp: Some(
                crate::target_write_validation::TargetCredentialPatchFieldRequest::Set(
                    credential_link("not-a-uuid", None),
                )
            ),
            ..Default::default()
        })),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn target_patch_request_deserializes_null_credential_link_as_clear() {
    let request = serde_json::json!({
        "credentials": {
            "ssh": null
        }
    });
    let request = serde_json::from_value::<TargetPatchRequest>(request)
        .expect("explicit null credential link should deserialize");
    let validated = validate_target_patch_request(request).expect("clear credential link patch");
    assert!(matches!(
        validated.credentials.ssh,
        Some(ValidatedCredentialPatchAction::Clear)
    ));
}

#[test]
fn target_create_request_requires_explicit_safe_scan_inputs() {
    let validated = validate_target_create_request(create_request()).expect("valid create target");
    assert_eq!(validated.name, "target-one");
    assert_eq!(validated.comment.as_deref(), Some("temporary target"));
    assert_eq!(validated.alive_test, 2);
    assert_eq!(validated.allow_simultaneous_ips, 1);
    assert_eq!(validated.reverse_lookup_only, 0);
    assert_eq!(validated.reverse_lookup_unify, 1);
    assert_eq!(
        validated.port_list_id,
        "12345678-1234-1234-1234-123456789abc"
    );
    assert_eq!(validated.hosts, "192.0.2.42, host-one");
    assert_eq!(validated.exclude_hosts, "192.0.2.43");
    assert!(!validated.credentials.has_changes());
}

#[test]
fn target_create_request_accepts_secret_free_credential_references() {
    let ssh_id = "12345678-1234-1234-1234-123456789abc";
    let snmp_id = "12345678-1234-1234-1234-123456789abd";
    let mut request = create_request();
    request.credentials = Some(TargetCredentialsCreateRequest {
        ssh: Some(credential_link(ssh_id, Some(2222))),
        snmp: Some(credential_link(snmp_id, None)),
        ..Default::default()
    });
    let validated = validate_target_create_request(request).expect("valid create target");
    match validated.credentials.ssh {
        Some(ValidatedCredentialPatchAction::Set(link)) => {
            assert_eq!(link.id, ssh_id);
            assert_eq!(link.port, Some(2222));
        }
        _ => panic!("ssh credential should be set"),
    }
    match validated.credentials.snmp {
        Some(ValidatedCredentialPatchAction::Set(link)) => {
            assert_eq!(link.id, snmp_id);
            assert_eq!(link.port, None);
        }
        _ => panic!("snmp credential should be set"),
    }
}

#[test]
fn target_create_request_rejects_unsafe_or_missing_inputs() {
    let mut request = create_request();
    request.hosts = vec!["192.0.2.0/24".to_string()];
    assert!(matches!(
        validate_target_create_request(request),
        Err(ApiError::BadRequest(_))
    ));

    let mut request = create_request();
    request.port_list_id = "not-a-uuid".to_string();
    assert!(matches!(
        validate_target_create_request(request),
        Err(ApiError::BadRequest(_))
    ));

    let request = serde_json::json!({
        "name": "target-one",
        "hosts": ["192.0.2.42"],
        "port_list_id": "12345678-1234-1234-1234-123456789abc",
        "credential_id": "12345678-1234-1234-1234-123456789abc"
    });
    assert!(serde_json::from_value::<TargetCreateRequest>(request).is_err());

    let mut request = create_request();
    request.credentials = Some(TargetCredentialsCreateRequest::default());
    assert!(matches!(
        validate_target_create_request(request),
        Err(ApiError::BadRequest(_))
    ));
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
        credentials: None,
    }
}

#[test]
fn target_create_metadata_sql_is_metadata_only_and_credential_free() {
    let sql = target_create_metadata_sql();
    assert!(sql.contains("INSERT INTO targets"));
    assert!(sql.contains("make_uuid()"));
    assert!(sql.contains("port_list"));
    assert!(sql.contains("alive_test"));
    assert!(!sql.contains("targets_login_data"));
    assert!(!sql.contains("credentials_data"));
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
        credentials: None,
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
        credentials: None,
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
        credentials: None,
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
            credentials: None,
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
            credentials: None,
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
fn target_clone_request_allows_only_optional_metadata_overrides() {
    let validated = validate_target_clone_request(TargetCloneRequest {
        name: Some("  cloned target  ".to_string()),
        comment: Some("  copied safely  ".to_string()),
    })
    .expect("valid target clone request");
    assert_eq!(validated.name.as_deref(), Some("cloned target"));
    assert_eq!(validated.comment.as_deref(), Some("copied safely"));

    assert!(matches!(
        validate_target_clone_request(TargetCloneRequest {
            name: Some("   ".to_string()),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Clone", "hosts": ["192.0.2.1"]});
    assert!(serde_json::from_value::<TargetCloneRequest>(request).is_err());
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
fn target_clone_sql_copies_metadata_credential_references_and_active_tags_only() {
    let clone = target_clone_metadata_sql();
    assert!(clone.contains("INSERT INTO targets"));
    assert!(clone.contains("(uuid, owner, name, hosts"));
    assert!(clone.contains("make_uuid()"));
    assert!(clone.contains("SELECT make_uuid(),\n            $2,"));
    assert!(clone.contains("coalesce($3, uniquify('target', name, $2, ' Clone'))"));
    assert!(!clone.contains("SELECT uuid, owner, name"));
    for required in [
        "hosts",
        "exclude_hosts",
        "port_list",
        "reverse_lookup_only",
        "reverse_lookup_unify",
        "alive_test",
        "allow_simultaneous_ips",
        "m_now()",
    ] {
        assert!(
            clone.contains(required),
            "target clone SQL missing {required}"
        );
    }
    for forbidden in [
        "tasks",
        "permissions",
        "credentials_data",
        "password",
        "secret",
    ] {
        assert!(
            !clone.contains(forbidden),
            "target clone metadata SQL must not touch {forbidden}"
        );
    }

    let login = target_clone_login_data_sql();
    assert!(login.contains("INSERT INTO targets_login_data"));
    assert!(login.contains("SELECT $2, type, credential, port"));
    assert!(login.contains("WHERE target = $1"));
    assert!(!login.contains("credentials_data"));

    let tags = target_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'target'"));
    assert!(tags.contains("resource_location = 0"));

    let port_list_guard = target_source_port_list_is_assignable_sql();
    assert!(port_list_guard.contains("JOIN port_lists"));
    assert!(port_list_guard.contains("coalesce(pl.predefined, 0) != 0 OR pl.owner = $2"));

    let credential_guard = target_source_unassignable_credential_count_sql();
    assert!(credential_guard.contains("JOIN credentials"));
    assert!(credential_guard.contains("c.owner != $2"));
    assert!(!credential_guard.contains("credentials_data"));
}

#[test]
fn target_lifecycle_sql_moves_metadata_references_and_tags_without_secrets() {
    let trash = target_trash_insert_sql();
    assert!(trash.contains("INSERT INTO targets_trash"));
    assert!(trash.contains("port_list_location"));
    assert!(trash.contains("RETURNING id::integer, uuid::text"));

    let trash_login = target_trash_login_data_insert_sql();
    assert!(trash_login.contains("INSERT INTO targets_trash_login_data"));
    assert!(trash_login.contains("credential_location"));
    assert!(trash_login.contains("FROM targets_login_data"));
    assert!(!trash_login.contains("credentials_data"));

    let restore = target_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO targets"));
    assert!(restore.contains("FROM targets_trash"));

    let restore_login = target_restore_login_data_sql();
    assert!(restore_login.contains("INSERT INTO targets_login_data"));
    assert!(restore_login.contains("FROM targets_trash_login_data"));
    assert!(!restore_login.contains("credentials_data"));

    for sql in [
        target_trash_task_relink_sql(),
        target_restore_task_relink_sql(),
    ] {
        assert!(sql.contains("UPDATE tasks"));
        assert!(sql.contains("target_location"));
    }

    for sql in [
        target_tag_locations_to_trash_sql(),
        target_trash_tag_locations_to_trash_sql(),
        target_tag_locations_to_live_sql(),
        target_trash_tag_locations_to_live_sql(),
    ] {
        assert!(sql.contains("resource_type = 'target'"));
        assert!(sql.contains("resource_location"));
    }

    assert!(target_scope_membership_count_sql().contains("FROM scope_targets"));
    assert!(target_trash_task_count_sql().contains("target_location = 1"));
    assert!(target_trash_blocked_reference_count_sql().contains("credential_location = 1"));
    assert!(target_trash_blocked_reference_count_sql().contains("port_list_location = 1"));
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

#[test]
fn target_credential_link_sql_is_reference_only_and_secret_free() {
    let assignable = target_assignable_credential_state_sql();
    assert!(assignable.contains("FROM credentials"));
    assert!(assignable.contains("owner::integer"));
    assert!(assignable.contains("type"));
    assert!(!assignable.contains("credentials_data"));
    assert!(!assignable.contains("secret"));
    assert!(!assignable.contains("password"));

    let current = target_current_credential_sql();
    assert!(current.contains("FROM targets_login_data"));
    assert!(current.contains("target = $1"));
    assert!(current.contains("type = $2"));

    let delete = target_delete_login_data_by_type_sql();
    assert!(delete.contains("DELETE FROM targets_login_data"));
    assert!(delete.contains("target = $1"));
    assert!(delete.contains("type = $2"));

    let insert = target_insert_login_data_sql();
    assert!(insert.contains("INSERT INTO targets_login_data"));
    assert!(insert.contains("target, type, credential, port"));
    assert!(!insert.contains("credentials_data"));
    assert!(!insert.contains("secret"));
    assert!(!insert.contains("password"));
}
