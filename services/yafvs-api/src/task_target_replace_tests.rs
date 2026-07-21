// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    task_status::TaskStatus,
    task_target_replace_db::{
        TaskTargetReplaceTaskState, ensure_task_target_replace_ownership,
        ensure_task_target_replace_state,
    },
    task_target_replace_sql::*,
    task_target_replace_validation::{
        TaskTargetReplaceRequest, validate_task_target_replace_request,
    },
};

fn replacement_request(hosts: &[&str], exclude_hosts: Option<&[&str]>) -> TaskTargetReplaceRequest {
    TaskTargetReplaceRequest {
        hosts: hosts.iter().map(|value| (*value).to_string()).collect(),
        exclude_hosts: exclude_hosts
            .map(|values| values.iter().map(|value| (*value).to_string()).collect()),
    }
}

fn replaceable_task_state() -> TaskTargetReplaceTaskState {
    TaskTargetReplaceTaskState {
        internal_id: 7,
        owner_id: Some(11),
        target_internal_id: Some(13),
        run_status: TaskStatus::New,
        target_location: 0,
        hidden: 0,
        usage_type: "scan".to_string(),
    }
}

#[test]
fn task_target_replace_validation_reuses_target_host_rules() {
    let request = replacement_request(&[" 192.0.2.10 ", "192.0.2.10", "host.example"], None);
    let validated = validate_task_target_replace_request(request).expect("valid hosts");
    assert_eq!(validated.hosts, "192.0.2.10, host.example");
    assert_eq!(validated.exclude_hosts, "");

    for request in [
        replacement_request(&[], None),
        replacement_request(&["192.0.2.10/24"], None),
        replacement_request(&["192.0.2.10"], Some(&["192.0.2.10"])),
    ] {
        assert!(matches!(
            validate_task_target_replace_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }

    assert!(
        serde_json::from_value::<TaskTargetReplaceRequest>(serde_json::json!({
            "hosts": ["192.0.2.10"],
            "unexpected": true
        }))
        .is_err()
    );
}

#[test]
fn task_target_replace_requires_exactly_new_live_scan_task_with_live_target() {
    assert!(matches!(
        ensure_task_target_replace_state(&replaceable_task_state()),
        Ok(13)
    ));

    for task in [
        TaskTargetReplaceTaskState {
            run_status: TaskStatus::Done,
            ..replaceable_task_state()
        },
        TaskTargetReplaceTaskState {
            target_location: 1,
            ..replaceable_task_state()
        },
        TaskTargetReplaceTaskState {
            hidden: 2,
            ..replaceable_task_state()
        },
        TaskTargetReplaceTaskState {
            usage_type: "container".to_string(),
            ..replaceable_task_state()
        },
    ] {
        assert!(matches!(
            ensure_task_target_replace_state(&task),
            Err(ApiError::Conflict(_))
        ));
    }

    assert!(matches!(
        ensure_task_target_replace_state(&TaskTargetReplaceTaskState {
            target_internal_id: None,
            ..replaceable_task_state()
        }),
        Err(ApiError::Conflict(_))
    ));
}

#[test]
fn task_target_replace_accepts_different_human_owners_and_rejects_ownerless_resources() {
    assert!(ensure_task_target_replace_ownership(Some(11), Some(11)).is_ok());
    assert!(ensure_task_target_replace_ownership(Some(11), Some(12)).is_ok());
    assert!(matches!(
        ensure_task_target_replace_ownership(None, Some(11)),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        ensure_task_target_replace_ownership(Some(11), None),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn task_target_replace_sql_preserves_source_settings_and_rebinds_only_the_task() {
    let clone = task_target_replace_clone_metadata_sql();
    for retained_column in [
        "reverse_lookup_only",
        "reverse_lookup_unify",
        "comment",
        "port_list",
        "alive_test",
        "allow_simultaneous_ips",
    ] {
        assert!(clone.contains(retained_column));
    }
    assert!(clone.contains("uniquify('target', name, $2, ' Clone')"));
    assert!(clone.contains("$3"));
    assert!(clone.contains("$4"));

    let rebind = task_target_replace_task_rebind_sql();
    assert!(rebind.contains("SET target = $2"));
    assert!(rebind.contains("target = $3"));
    assert!(rebind.contains("target_location = 0"));
    assert!(rebind.contains("modification_time = m_now()"));
    assert!(rebind.contains("coalesce(run_status, $4) = $5"));
    assert!(task_target_replace_report_count_sql().contains("FROM reports WHERE task = $1"));
    assert!(task_target_replace_live_task_reference_count_sql().contains("hidden, 0) = 0"));
    assert!(task_target_replace_scope_reference_count_sql().contains("scope_targets"));
}

#[test]
fn task_target_replace_handler_is_authenticated_locked_and_atomic() {
    let source = include_str!("task_target_replace.rs");
    assert!(source.contains("require_task_write_operator(operator)?"));
    assert!(source.contains("resolve_task_write_operator_owner(&tx, &operator).await?"));
    assert!(source.contains("LOCK TABLE port_lists, credentials, targets, targets_login_data"));
    for table in [
        "port_lists",
        "credentials",
        "tasks",
        "reports",
        "scope_targets",
        "tag_resources",
        "tag_resources_trash",
    ] {
        assert!(
            source.contains(table),
            "replacement lock must include {table}"
        );
    }
    for guard in [
        "ensure_task_target_replace_state(&task)?;",
        "ensure_task_target_replace_ownership(",
        "ensure_target_source_port_list_assignable",
        "ensure_target_source_credentials_assignable",
        "ensure_task_target_replace_has_no_reports",
    ] {
        assert!(
            source.contains(guard),
            "replacement handler must apply {guard}"
        );
    }
    assert!(
        source
            .find("execute_task_target_replace_transaction")
            .unwrap()
            < source.find("tx.commit()").unwrap()
    );
    assert!(!source.contains("start_task("));
    assert!(!source.contains("stop_task("));
}

#[test]
fn target_write_and_replace_locks_use_the_port_list_first_order() {
    let source = include_str!("target_writes.rs");
    for (label, start, end, lock) in [
        (
            "create",
            "pub(crate) async fn create_target",
            "pub(crate) async fn clone_target",
            "LOCK TABLE port_lists, credentials, targets, targets_login_data",
        ),
        (
            "clone",
            "pub(crate) async fn clone_target",
            "pub(crate) async fn delete_target",
            "LOCK TABLE port_lists, credentials, targets, targets_login_data, tag_resources",
        ),
        (
            "patch",
            "pub(crate) async fn patch_target",
            "fn target_write_location_headers",
            "LOCK TABLE port_lists, credentials, targets, targets_login_data",
        ),
    ] {
        let handler = source
            .split_once(start)
            .unwrap_or_else(|| panic!("{label} target handler must exist"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("{label} target handler must end"))
            .0;
        assert!(
            handler.contains(lock),
            "{label} target lock order must be canonical"
        );
    }

    let replacement = include_str!("task_target_replace.rs");
    assert!(replacement.contains(
        "LOCK TABLE port_lists, credentials, targets, targets_login_data, targets_trash"
    ));
}

#[test]
fn task_target_replace_transaction_clones_rebinds_then_trashes_only_when_unreferenced() {
    let source = include_str!("task_target_replace_transactions.rs");
    for action in [
        "clone replacement target metadata",
        "clone replacement target credential references",
        "clone replacement target tags",
        "rebind task to replacement target",
        "task_target_replace_source_is_unreferenced",
        "execute_target_trash_transaction",
    ] {
        assert!(source.contains(action));
    }
    assert!(
        source.find("clone replacement target tags").unwrap()
            < source.find("rebind task to replacement target").unwrap()
    );
    assert!(
        source.find("rebind task to replacement target").unwrap()
            < source.rfind("execute_target_trash_transaction").unwrap()
    );
}
