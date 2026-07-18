// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    task_write_db::{
        ensure_task_configuration_mutable, ensure_task_not_in_use_for_native_trash,
        ensure_task_owner_matches_operator,
    },
    task_write_sql::*,
    task_write_validation::{
        MAX_TASK_ALERTS, MAX_TASK_TEXT_BYTES, TaskCreateRequest, TaskHostsOrdering,
        TaskPatchRequest, TaskReplaceRequest, validate_task_create_request,
        validate_task_patch_request, validate_task_replace_request,
    },
};

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const GVMD_OSP: &str = include_str!("../../../components/gvmd/src/manage_osp.c");
const GVMD_OPENVASD: &str = include_str!("../../../components/gvmd/src/manage_openvasd.c");
const VALID_TARGET_ID: &str = "11111111-1111-4111-8111-111111111111";
const VALID_CONFIG_ID: &str = "22222222-2222-4222-8222-222222222222";
const VALID_SCANNER_ID: &str = "33333333-3333-4333-8333-333333333333";
const VALID_SCHEDULE_ID: &str = "44444444-4444-4444-8444-444444444444";
const VALID_ALERT_ID: &str = "55555555-5555-4555-8555-555555555555";
const VALID_TAG_ID: &str = "66666666-6666-4666-8666-666666666666";

fn create_request(name: &str) -> TaskCreateRequest {
    TaskCreateRequest {
        name: name.to_string(),
        comment: Some("  comment  ".to_string()),
        target_id: VALID_TARGET_ID.to_string(),
        config_id: VALID_CONFIG_ID.to_string(),
        scanner_id: VALID_SCANNER_ID.to_string(),
        schedule_id: None,
        alert_ids: Vec::new(),
        hosts_ordering: None,
        schedule_periods: 0,
        apply_overrides: true,
        max_checks: 4,
        max_hosts: 20,
        min_qod: 70,
        tag_id: None,
    }
}

fn patch_request(name: Option<&str>, comment: Option<&str>) -> TaskPatchRequest {
    TaskPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn replace_request(name: &str) -> TaskReplaceRequest {
    TaskReplaceRequest {
        name: name.to_string(),
        comment: Some("comment".to_string()),
        target_id: VALID_TARGET_ID.to_string(),
        config_id: VALID_CONFIG_ID.to_string(),
        scanner_id: VALID_SCANNER_ID.to_string(),
        schedule_id: Some(VALID_SCHEDULE_ID.to_string()),
        alert_ids: vec![VALID_ALERT_ID.to_string()],
        hosts_ordering: TaskHostsOrdering::Random,
        schedule_periods: 1,
        apply_overrides: false,
        max_checks: 8,
        max_hosts: 12,
        min_qod: 65,
    }
}

#[test]
fn task_create_request_trims_metadata_and_normalizes_references() {
    let validated = validate_task_create_request(TaskCreateRequest {
        name: "  scan task  ".to_string(),
        ..create_request("ignored")
    })
    .expect("valid task create");
    assert_eq!(validated.name, "scan task");
    assert_eq!(validated.comment.as_deref(), Some("comment"));
    assert_eq!(validated.target_id, VALID_TARGET_ID);
    assert_eq!(validated.config_id, VALID_CONFIG_ID);
    assert_eq!(validated.scanner_id, VALID_SCANNER_ID);
    assert_eq!(validated.schedule_id, None);
    assert!(validated.alert_ids.is_empty());
    assert_eq!(validated.hosts_ordering, "random");
}

#[test]
fn task_create_request_rejects_blank_name_invalid_ids_and_unknown_fields() {
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            name: "   ".to_string(),
            ..create_request("ignored")
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            target_id: "not-a-uuid".to_string(),
            ..create_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            schedule_id: Some("not-a-uuid".to_string()),
            ..create_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            alert_ids: vec!["not-a-uuid".to_string()],
            ..create_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({
        "name": "Task",
        "target_id": VALID_TARGET_ID,
        "config_id": VALID_CONFIG_ID,
        "scanner_id": VALID_SCANNER_ID,
        "unexpected": true,
    });
    assert!(serde_json::from_value::<TaskCreateRequest>(request).is_err());
}

#[test]
fn task_create_request_accepts_optional_schedule_and_alerts() {
    let validated = validate_task_create_request(TaskCreateRequest {
        schedule_id: Some(format!("  {VALID_SCHEDULE_ID}  ")),
        alert_ids: vec![format!("  {VALID_ALERT_ID}  ")],
        hosts_ordering: Some(TaskHostsOrdering::Reverse),
        ..create_request("task")
    })
    .expect("valid schedule and alerts");

    assert_eq!(validated.schedule_id.as_deref(), Some(VALID_SCHEDULE_ID));
    assert_eq!(validated.alert_ids, [VALID_ALERT_ID]);
    assert_eq!(validated.hosts_ordering, "reverse");
}

#[test]
fn task_create_request_defaults_optional_references_to_empty() {
    let request = serde_json::json!({
        "name": "Task",
        "target_id": VALID_TARGET_ID,
        "config_id": VALID_CONFIG_ID,
        "scanner_id": VALID_SCANNER_ID,
    });
    let request =
        serde_json::from_value::<TaskCreateRequest>(request).expect("legacy request body");
    assert!(request.schedule_id.is_none());
    assert!(request.alert_ids.is_empty());
    assert!(request.hosts_ordering.is_none());
    assert_eq!(request.schedule_periods, 0);
    assert!(request.apply_overrides);
    assert_eq!(request.max_checks, 4);
    assert_eq!(request.max_hosts, 20);
    assert_eq!(request.min_qod, 70);
    assert!(request.tag_id.is_none());
}

#[test]
fn task_create_request_accepts_retained_preferences_and_task_tag() {
    let validated = validate_task_create_request(TaskCreateRequest {
        schedule_periods: 2,
        apply_overrides: false,
        max_checks: 8,
        max_hosts: 12,
        min_qod: 65,
        tag_id: Some(VALID_TAG_ID.to_string()),
        ..create_request("task")
    })
    .expect("retained task configuration");
    assert_eq!(validated.schedule_periods, 2);
    assert!(!validated.apply_overrides);
    assert_eq!(validated.max_checks, 8);
    assert_eq!(validated.max_hosts, 12);
    assert_eq!(validated.min_qod, 65);
    assert_eq!(validated.tag_id.as_deref(), Some(VALID_TAG_ID));
}

#[test]
fn task_create_request_rejects_invalid_retained_preferences() {
    for request in [
        TaskCreateRequest {
            schedule_periods: -1,
            ..create_request("task")
        },
        TaskCreateRequest {
            max_checks: -1,
            ..create_request("task")
        },
        TaskCreateRequest {
            max_hosts: -1,
            ..create_request("task")
        },
        TaskCreateRequest {
            min_qod: 101,
            ..create_request("task")
        },
    ] {
        assert!(matches!(
            validate_task_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
}

#[test]
fn task_replace_request_validates_complete_configuration() {
    let validated = validate_task_replace_request(replace_request(" task "))
        .expect("complete task replacement");
    assert_eq!(validated.name, "task");
    assert_eq!(validated.schedule_id.as_deref(), Some(VALID_SCHEDULE_ID));
    assert_eq!(validated.alert_ids, [VALID_ALERT_ID]);
    assert_eq!(validated.hosts_ordering, "random");
    assert!(!validated.apply_overrides);
    assert_eq!(validated.max_checks, 8);
    assert_eq!(validated.max_hosts, 12);
    assert_eq!(validated.min_qod, 65);

    assert!(matches!(
        validate_task_replace_request(TaskReplaceRequest {
            min_qod: 101,
            ..replace_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_create_request_accepts_only_typed_host_ordering_values() {
    for (input, expected) in [
        ("random", "random"),
        ("sequential", "sequential"),
        ("reverse", "reverse"),
    ] {
        let request = serde_json::json!({
            "name": "Task",
            "target_id": VALID_TARGET_ID,
            "config_id": VALID_CONFIG_ID,
            "scanner_id": VALID_SCANNER_ID,
            "hosts_ordering": input,
        });
        let request =
            serde_json::from_value::<TaskCreateRequest>(request).expect("typed host ordering");
        let validated = validate_task_create_request(request).expect("valid host ordering");
        assert_eq!(validated.hosts_ordering, expected);
    }

    for invalid in ["RANDOM", "randomized", ""] {
        let request = serde_json::json!({
            "name": "Task",
            "target_id": VALID_TARGET_ID,
            "config_id": VALID_CONFIG_ID,
            "scanner_id": VALID_SCANNER_ID,
            "hosts_ordering": invalid,
        });
        assert!(serde_json::from_value::<TaskCreateRequest>(request).is_err());
    }
}

#[test]
fn task_create_request_rejects_duplicate_or_excess_alerts() {
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            alert_ids: vec![VALID_ALERT_ID.to_string(), VALID_ALERT_ID.to_string()],
            ..create_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));

    let alert_ids = (0..=MAX_TASK_ALERTS)
        .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
        .collect();
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            alert_ids,
            ..create_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_create_openapi_contract_covers_optional_schedule_alerts_and_ordering() {
    let schema = OPENAPI
        .split_once("    TaskCreateRequest:")
        .expect("task create schema")
        .1
        .split_once("    TaskPatchRequest:")
        .expect("task patch schema boundary")
        .0;

    for required in [
        "schedule_id:",
        "description: Optional schedule owned by the direct API operator.",
        "alert_ids:",
        "maxItems: 5",
        "uniqueItems: true",
        "default: []",
        "description: Optional distinct alerts owned by the direct API operator.",
        "hosts_ordering:",
        "enum: [random, sequential, reverse]",
        "forwarded to OSP/OpenVASD",
        "schedule_periods:",
        "apply_overrides:",
        "max_checks:",
        "max_hosts:",
        "min_qod:",
        "tag_id:",
    ] {
        assert!(
            schema.contains(required),
            "task create OpenAPI schema missing {required}"
        );
    }
}

#[test]
fn task_replace_openapi_contract_is_complete_and_scanner_control_classified() {
    let schema = OPENAPI
        .split_once("    TaskReplaceRequest:")
        .expect("task replace schema")
        .1
        .split_once("    TaskTargetReplaceRequest:")
        .expect("task target replacement schema boundary")
        .0;
    for required in [
        "required: [name, target_id, config_id, scanner_id",
        "schedule_id:",
        "nullable: true",
        "alert_ids:",
        "hosts_ordering:",
        "schedule_periods:",
        "apply_overrides:",
        "max_checks:",
        "max_hosts:",
        "min_qod:",
    ] {
        assert!(
            schema.contains(required),
            "task replace schema missing {required}"
        );
    }
}

#[test]
fn task_create_request_rejects_control_characters_and_oversized_text() {
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            name: "bad\nname".to_string(),
            ..create_request("ignored")
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_task_create_request(TaskCreateRequest {
            comment: Some("x".repeat(MAX_TASK_TEXT_BYTES + 1)),
            ..create_request("task")
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_create_handler_requires_operator_references_and_uniqueness_before_insert() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn create_task")
        .expect("create task handler must exist")
        .1;

    for required in [
        "let operator = require_task_write_operator(operator)?;",
        "validate_task_create_request(request)?",
        "resolve_task_write_operator_owner(&tx, &operator).await?",
        "LOCK TABLE targets, configs, scanners, schedules, alerts, task_alerts, tasks, task_preferences",
        "ensure_unique_task_name(&tx, &request.name, -1, operator_owner_id).await?;",
        "load_assignable_task_target(&tx, &request.target_id, operator_owner_id).await?;",
        "load_assignable_task_config(&tx, &request.config_id, operator_owner_id).await?;",
        "load_assignable_task_scanner(&tx, &request.scanner_id, operator_owner_id).await?;",
        "load_assignable_task_schedule(&tx, schedule_id, operator_owner_id).await?;",
        "load_assignable_task_alert(&tx, alert_id, operator_owner_id).await?;",
        "execute_task_create_transaction",
        "StatusCode::CREATED",
        "task_write_location_headers(&record.uuid)?",
    ] {
        assert!(
            handler.contains(required),
            "create task handler missing {required}"
        );
    }
    assert!(
        handler.find("load_assignable_task_alert").unwrap()
            < handler.find("execute_task_create_transaction").unwrap(),
        "task create must validate every assignable reference before insert"
    );
}

#[test]
fn task_clone_uses_authoritative_control_and_verifies_committed_owner() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn clone_task")
        .expect("clone task handler must exist")
        .1
        .split_once("pub(crate) async fn create_task")
        .expect("clone task handler boundary")
        .0;

    for required in [
        "let operator = require_task_write_operator(operator)?;",
        "request_task_clone(",
        "operator.user_uuid()",
        "load_committed_task_detail_for_operator(&state, &cloned_task_id, &operator).await?",
        "StatusCode::CREATED",
        "task_write_location_headers(&cloned_task_id)?",
    ] {
        assert!(
            handler.contains(required),
            "clone task handler missing {required}"
        );
    }

    let committed_loader = source
        .split_once("async fn load_committed_task_detail_for_operator")
        .expect("committed task detail loader")
        .1;
    for required in [
        "load_task_detail_for_operator(&client, task_id, operator.user_uuid())",
        "ApiError::MutationCommittedResponseUnavailable",
    ] {
        assert!(
            committed_loader.contains(required),
            "committed task owner check missing {required}"
        );
    }
    assert!(!committed_loader.contains("SELECT 1 FROM tasks"));

    let task_handlers = include_str!("task_handlers.rs");
    let owner_loader = task_handlers
        .split_once("pub(crate) async fn load_task_detail_for_operator")
        .expect("operator-owned task detail loader")
        .1;
    assert!(owner_loader.contains("lower(uuid) = lower($1) AND lower(owner_id) = lower($2)"));
    assert!(owner_loader.contains("query_opt(&sql, &[&task_id, &operator_uuid])"));
}

#[test]
fn task_create_schedule_and_alert_loaders_require_operator_ownership() {
    let source = include_str!("task_write_db.rs");

    for required in [
        "pub(crate) async fn load_assignable_task_schedule",
        "task_assignable_schedule_state_sql()",
        "if owner_id == Some(operator_owner_id)",
        "direct API task create operator cannot assign schedule",
        "pub(crate) async fn load_assignable_task_alert",
        "task_assignable_alert_state_sql()",
        "direct API task create operator cannot assign alert",
        "Err(ApiError::Forbidden)",
    ] {
        assert!(
            source.contains(required),
            "task reference ownership guard missing {required}"
        );
    }
}

#[test]
fn task_create_sql_writes_schedule_alerts_and_inherited_defaults() {
    let target = task_assignable_target_state_sql();
    assert!(target.contains("FROM targets"));
    assert!(target.contains("WHERE uuid = $1"));

    let config = task_assignable_config_state_sql();
    assert!(config.contains("FROM configs"));
    assert!(config.contains("coalesce(predefined, 0)::integer"));
    assert!(config.contains("coalesce(usage_type, 'scan') = 'scan'"));

    let scanner = task_assignable_scanner_state_sql();
    assert!(scanner.contains("FROM scanners"));
    assert!(scanner.contains("coalesce(type, 0)::integer"));

    let schedule = task_assignable_schedule_state_sql();
    assert!(schedule.contains("FROM schedules"));
    assert!(schedule.contains("owner::integer"));
    assert!(schedule.contains("next_time_ical(icalendar, m_now()::bigint"));
    assert!(schedule.contains("timezone), 0)::integer"));

    let alert = task_assignable_alert_state_sql();
    assert!(alert.contains("FROM alerts"));
    assert!(alert.contains("owner::integer"));

    let create = task_create_metadata_sql();
    assert!(create.contains("INSERT INTO tasks"));
    assert!(create.contains("run_status"));
    assert!(create.contains("VALUES (make_uuid(), $1, $2, 0, coalesce($3, ''), 1, $4, $5"));
    assert!(create.contains("$7, $8, $9, $6, 0, 0, 0, 0, 1"));
    assert!(create.contains("schedule_periods"));
    assert!(create.contains("schedule_location"));
    assert!(create.contains("alterable"));
    assert!(create.contains("RETURNING id::integer, uuid::text"));
    for forbidden in [
        "task_alerts",
        "schedules",
        "credentials",
        "reports",
        "results",
        "start_time",
        "end_time",
        "upload_result_count",
    ] {
        assert!(
            !create.contains(forbidden),
            "task create SQL must not touch {forbidden}"
        );
    }

    let prefs = task_insert_preference_sql();
    assert!(prefs.contains("INSERT INTO task_preferences"));
    assert!(prefs.contains("VALUES ($1, $2, $3)"));

    let alerts = task_insert_alert_sql();
    assert!(alerts.contains("INSERT INTO task_alerts"));
    assert!(alerts.contains("(task, alert, alert_location)"));
    assert!(alerts.contains("VALUES ($1, $2, 0)"));
}

#[test]
fn task_create_transaction_attaches_alerts_after_task_insert() {
    let source = include_str!("task_write_transactions.rs");
    let transaction = source
        .split_once("pub(crate) async fn execute_task_create_transaction")
        .expect("create transaction must exist")
        .1;

    assert!(transaction.contains("alert_internal_ids: &[i32]"));
    assert!(transaction.contains("for alert_internal_id in alert_internal_ids"));
    assert!(transaction.contains("task_mutable_preference_values("));
    assert!(transaction.contains("&request.hosts_ordering"));
    assert!(transaction.contains(r#"("hosts_ordering", hosts_ordering.to_string())"#));
    assert!(transaction.contains("tag_internal_id: Option<i32>"));
    assert!(transaction.contains("task_insert_tag_resource_sql()"));
    assert!(
        transaction.find("task_create_metadata_sql()").unwrap()
            < transaction.find("task_insert_alert_sql()").unwrap()
    );
}

#[test]
fn task_replace_is_state_guarded_and_transactional() {
    assert!(ensure_task_configuration_mutable(1, false).is_ok());
    assert!(ensure_task_configuration_mutable(2, true).is_ok());
    assert!(matches!(
        ensure_task_configuration_mutable(2, false),
        Err(ApiError::Conflict(_))
    ));

    let update = task_replace_configuration_sql();
    for required in [
        "target = $4",
        "config = $5",
        "scanner = $6",
        "schedule = $7",
        "schedule_next_time = $8",
        "schedule_periods = $9",
        "RETURNING uuid::text",
    ] {
        assert!(
            update.contains(required),
            "task replacement SQL missing {required}"
        );
    }
    assert!(task_delete_alerts_sql().contains("DELETE FROM task_alerts"));
    assert!(task_delete_managed_preferences_sql().contains("assets_apply_overrides"));

    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn replace_task")
        .expect("task replacement handler")
        .1
        .split_once("pub(crate) async fn delete_task")
        .expect("task replacement handler end")
        .0;
    for required in [
        "require_task_write_operator(operator)?",
        "ensure_task_owner_matches_operator",
        "ensure_task_configuration_mutable",
        "ensure_unique_task_name",
        "load_assignable_task_target",
        "load_assignable_task_config",
        "load_assignable_task_scanner",
        "load_assignable_task_schedule",
        "load_assignable_task_alert",
        "execute_task_replace_transaction",
        "tx.commit()",
    ] {
        assert!(
            handler.contains(required),
            "task replacement handler missing {required}"
        );
    }
}

#[test]
fn task_host_ordering_preference_is_forwarded_to_both_scanner_transports() {
    for (name, source) in [("OSP", GVMD_OSP), ("OpenVASD", GVMD_OPENVASD)] {
        assert!(
            source.contains(r#"hosts_ordering = task_preference_value (task, "hosts_ordering");"#),
            "{name} launch path must load task host ordering"
        );
        assert!(
            source
                .contains(r#"g_hash_table_insert (scanner_options, g_strdup ("hosts_ordering"),"#),
            "{name} launch path must forward host ordering to scanner options"
        );
    }
}

#[test]
fn task_delete_rejects_in_use_run_statuses_before_trash_move() {
    for status in [0, 3, 4, 10, 11, 14, 16, 17, 18, 19] {
        assert!(
            matches!(
                ensure_task_not_in_use_for_native_trash(status),
                Err(ApiError::Conflict(_))
            ),
            "run status {status} must stay on inherited scanner-aware delete path"
        );
    }
    for status in [1, 2, 12, 13, 99] {
        assert!(
            ensure_task_not_in_use_for_native_trash(status).is_ok(),
            "non-active run status {status} should be eligible for native trash move"
        );
    }
}

#[test]
fn task_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_task_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_task_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn task_patch_handler_requires_operator_and_owner_before_mutation() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_task")
        .expect("patch task handler must exist")
        .1;

    let owner_check =
        "ensure_task_owner_matches_operator(task_state.owner_id, operator_owner_id)?;";
    assert!(handler.contains("let operator = require_task_write_operator(operator)?;"));
    assert!(handler.contains("resolve_task_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_task_patch_transaction").unwrap(),
        "task patch must verify owner before metadata mutation"
    );
}

#[test]
fn task_patch_request_trims_metadata_fields() {
    let validated =
        validate_task_patch_request(patch_request(Some("  scan task  "), Some("  comment  ")))
            .expect("valid task patch");
    assert_eq!(validated.name.as_deref(), Some("scan task"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn task_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_task_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_task_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_task_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn task_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_task_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_task_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Task", "target_id": "target"});
    assert!(serde_json::from_value::<TaskPatchRequest>(request).is_err());
}

#[test]
fn task_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_task_patch_request(TaskPatchRequest {
            name: Some("x".repeat(MAX_TASK_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn task_patch_sql_is_metadata_only() {
    let sql = task_update_metadata_sql();
    assert!(sql.contains("UPDATE tasks"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("coalesce(hidden, 0) = 0"));
    assert!(sql.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(sql.contains("RETURNING uuid::text"));
    for forbidden in [
        "target =",
        "config =",
        "schedule =",
        "scanner =",
        "run_status",
        "start_time",
        "end_time",
        "schedule_next_time",
        "schedule_periods",
        "alterable",
        "upload_result_count",
        "task_alerts",
        "task_preferences",
        "reports",
        "results",
        "credentials",
    ] {
        assert!(
            !sql.contains(forbidden),
            "task patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn task_patch_state_and_uniqueness_are_live_scan_metadata_only() {
    let state = task_write_state_sql();
    assert!(state.contains("FROM tasks"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(state.contains("owner::integer"));
    assert!(state.contains("coalesce(hidden, 0) = 0"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(!state.contains("task_alerts"));
    assert!(!state.contains("task_preferences"));

    let unique = task_unique_name_sql();
    assert!(unique.contains("FROM tasks"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(unique.contains("owner = $3"));
    assert!(unique.contains("coalesce(hidden, 0) = 0"));
    assert!(unique.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(!unique.contains("task_alerts"));
    assert!(!unique.contains("task_preferences"));
}

#[test]
fn task_delete_handler_requires_operator_owner_and_in_use_check_before_trash_move() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn delete_task")
        .expect("delete task handler must exist")
        .1;

    let owner_check =
        "ensure_task_owner_matches_operator(task_state.owner_id, operator_owner_id)?;";
    let in_use_check = "ensure_task_not_in_use_for_native_trash(task_state.run_status)?;";
    assert!(handler.contains("let operator = require_task_write_operator(operator)?;"));
    assert!(handler.contains("resolve_task_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(handler.contains(in_use_check));
    assert!(handler.contains("LOCK TABLE tasks, reports, report_counts, results, results_trash, tag_resources, tag_resources_trash"));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_task_trash_transaction").unwrap(),
        "task delete must verify owner before trash mutation"
    );
    assert!(
        handler.find(in_use_check).unwrap()
            < handler.find("execute_task_trash_transaction").unwrap(),
        "task delete must reject in-use tasks before trash mutation"
    );
    assert!(handler.contains("StatusCode::NO_CONTENT"));
}

#[test]
fn task_delete_sql_matches_inherited_safe_trash_subset() {
    let state = task_write_state_sql();
    assert!(state.contains("coalesce(run_status, 1)::integer"));
    assert!(state.contains("coalesce(hidden, 0) = 0"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));

    for sql in [
        task_trash_task_tag_locations_sql(),
        task_trash_task_trash_tag_locations_sql(),
        task_trash_report_tag_locations_sql(),
        task_trash_report_trash_tag_locations_sql(),
        task_trash_result_tag_locations_sql(),
        task_trash_result_trash_tag_locations_sql(),
    ] {
        assert!(sql.contains("UPDATE tag_resources") || sql.contains("UPDATE tag_resources_trash"));
        assert!(sql.contains("SET resource_location = 1"));
    }

    let insert_results = task_trash_results_insert_sql();
    assert!(insert_results.contains("INSERT INTO results_trash"));
    assert!(insert_results.contains("FROM results"));
    assert!(insert_results.contains("WHERE report IN (SELECT id FROM reports WHERE task = $1)"));

    let delete_results = task_delete_live_results_sql();
    assert!(delete_results.contains("DELETE FROM results"));
    assert!(delete_results.contains("WHERE report IN (SELECT id FROM reports WHERE task = $1)"));

    let delete_counts = task_delete_report_counts_sql();
    assert!(delete_counts.contains("DELETE FROM report_counts"));
    assert!(delete_counts.contains("WHERE report IN (SELECT id FROM reports WHERE task = $1)"));

    let mark_hidden = task_mark_hidden_trash_sql();
    assert!(mark_hidden.contains("UPDATE tasks"));
    assert!(mark_hidden.contains("hidden = 2"));
    assert!(mark_hidden.contains("modification_time = m_now()"));
    assert!(mark_hidden.contains("coalesce(hidden, 0) = 0"));
    assert!(mark_hidden.contains("coalesce(usage_type, 'scan') = 'scan'"));
    assert!(mark_hidden.contains("RETURNING uuid::text"));
}
