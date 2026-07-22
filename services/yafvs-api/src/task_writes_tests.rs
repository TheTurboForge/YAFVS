// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    errors::ApiError,
    task_status::TaskStatus,
    task_write_db::{
        ensure_task_configuration_mutable, ensure_task_is_human_owned,
        ensure_task_not_in_use_for_native_trash, ensure_task_restore_references_are_live,
        task_report_delete_status,
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
const GVMD_MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const GVMD_MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
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

#[test]
fn task_restore_rejects_active_state_and_any_nonlive_reference() {
    assert!(ensure_task_restore_references_are_live(true).is_ok());
    assert!(matches!(
        ensure_task_restore_references_are_live(false),
        Err(ApiError::Conflict(_))
    ));
    assert!(matches!(
        ensure_task_not_in_use_for_native_trash(TaskStatus::Running),
        Err(ApiError::Conflict(_))
    ));

    let state = task_trash_state_sql();
    for required in [
        "coalesce(hidden, 0) = 2",
        "coalesce(target_location, -1) = 0",
        "coalesce(config_location, -1) = 0",
        "coalesce(schedule_location, -1) = 0",
        "coalesce(scanner_location, -1) = 0",
        "coalesce(alert_location, -1) <> 0",
    ] {
        assert!(
            state.contains(required),
            "task trash state missing {required}"
        );
    }
}

#[test]
fn task_restore_handler_is_operator_guarded_and_transactional() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn restore_task")
        .expect("restore task handler must exist")
        .1;
    for required in [
        "require_task_write_operator(operator)?",
        "resolve_task_write_operator_owner(&tx, &operator).await?",
        "LOCK TABLE tasks, task_alerts, reports, report_counts, results, results_trash, tag_resources, tag_resources_trash",
        "load_task_trash_state",
        "ensure_task_is_human_owned",
        "ensure_task_not_in_use_for_native_trash",
        "ensure_task_restore_references_are_live",
        "execute_task_restore_transaction",
        "tx.commit()",
        "load_task_detail",
    ] {
        assert!(
            handler.contains(required),
            "task restore handler missing {required}"
        );
    }
    assert!(
        handler
            .find("ensure_task_restore_references_are_live")
            .unwrap()
            < handler.find("execute_task_restore_transaction").unwrap()
    );
}

#[test]
fn task_restore_sql_matches_imported_manager_authority_and_fails_closed() {
    let inherited = GVMD_MANAGE_SQL
        .split_once("  /* Task. */")
        .expect("inherited task restore block")
        .1
        .split_once("  sql_rollback ();\n  return 2;")
        .expect("inherited task restore end")
        .0;
    for required in [
        "target_location",
        "config_location",
        "schedule_location",
        "scanner_location",
        "alert_location",
        "permissions_set_locations (\"task\"",
        "tags_set_locations (\"task\"",
        "INSERT INTO results",
        "FROM results_trash",
        "DELETE FROM results_trash",
        "DELETE FROM report_counts",
        "UPDATE tasks SET hidden = 0",
    ] {
        assert!(
            inherited.contains(required),
            "imported restore authority missing {required}"
        );
    }

    for sql in [
        task_restore_task_tag_locations_sql(),
        task_restore_task_trash_tag_locations_sql(),
        task_restore_report_tag_locations_sql(),
        task_restore_report_trash_tag_locations_sql(),
    ] {
        assert!(sql.contains("resource_location = 0"));
    }
    for sql in [
        task_restore_result_tag_locations_sql(),
        task_restore_result_trash_tag_locations_sql(),
    ] {
        assert!(sql.contains("resource_location = 0"));
        assert!(sql.contains("resource = restored.id"));
        assert!(sql.contains("link.resource_uuid = restored.uuid"));
        assert!(sql.contains("FROM results AS restored"));
        assert!(sql.contains("restored.task = $1"));
        assert!(!sql.contains("SELECT id FROM results_trash"));
    }
    for marker in [
        "CREATE TABLE IF NOT EXISTS results\"",
        "CREATE TABLE IF NOT EXISTS results_trash\"",
    ] {
        let table = GVMD_MANAGE_PG
            .split_once(marker)
            .unwrap_or_else(|| panic!("imported schema must define {marker}"))
            .1;
        assert!(
            table.starts_with("\n       \" (id SERIAL PRIMARY KEY,"),
            "{marker} must independently allocate row identities"
        );
    }
    assert!(task_restore_results_insert_sql().contains("INSERT INTO results"));
    assert!(task_restore_results_insert_sql().contains("FROM results_trash"));
    assert!(task_delete_trash_results_sql().contains("DELETE FROM results_trash"));
    assert!(task_mark_live_restored_sql().contains("hidden = 0"));
    assert!(task_mark_live_restored_sql().contains("coalesce(hidden, 0) = 2"));

    let transaction = include_str!("task_write_transactions.rs")
        .split_once("pub(crate) async fn execute_task_restore_transaction")
        .expect("task restore transaction")
        .1;
    assert!(
        transaction.find("task_restore_results_insert_sql").unwrap()
            < transaction
                .find("task_restore_result_tag_locations_sql")
                .unwrap()
    );
    assert!(
        transaction
            .find("task_restore_result_tag_locations_sql")
            .unwrap()
            < transaction.find("task_delete_trash_results_sql").unwrap()
    );
    assert!(
        transaction.find("task_delete_report_counts_sql").unwrap()
            < transaction.find("task_mark_live_restored_sql").unwrap()
    );
    assert!(
        !transaction.contains("permissions"),
        "retired inherited row-level permission mutations must not be reintroduced"
    );
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
        "description: Optional human-owned schedule.",
        "alert_ids:",
        "maxItems: 5",
        "uniqueItems: true",
        "default: []",
        "description: Optional distinct human-owned alerts.",
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
        "type: [string, 'null']",
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
        "mutation_committed_response_unavailable(error, \"create task response header\")",
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
fn task_create_reference_loaders_allow_human_owned_resources_only() {
    let source = include_str!("task_write_db.rs");

    for required in [
        "pub(crate) async fn load_assignable_task_schedule",
        "task_assignable_schedule_state_sql()",
        "if owner_id.is_some()",
        "direct API task create rejects an ownerless schedule",
        "pub(crate) async fn load_assignable_task_alert",
        "task_assignable_alert_state_sql()",
        "direct API task create rejects an ownerless alert",
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
    assert!(create.contains("VALUES (make_uuid(), $1, $2, 0, coalesce($3, ''), $10, $4, $5"));
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
    assert!(ensure_task_configuration_mutable(TaskStatus::New, false).is_ok());
    assert!(ensure_task_configuration_mutable(TaskStatus::Done, true).is_ok());
    assert!(matches!(
        ensure_task_configuration_mutable(TaskStatus::Done, false),
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
        "ensure_task_is_human_owned",
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
fn native_task_status_numbers_match_the_inherited_database_contract() {
    assert_eq!(TaskStatus::Done.as_i32(), 1);
    assert_eq!(TaskStatus::New.as_i32(), 2);
    assert!(
        task_create_metadata_sql()
            .contains("VALUES (make_uuid(), $1, $2, 0, coalesce($3, ''), $10, $4, $5")
    );
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
    for status in TaskStatus::ALL
        .iter()
        .filter_map(|(_, status)| status.blocks_native_trash().then_some(*status))
    {
        assert!(
            matches!(
                ensure_task_not_in_use_for_native_trash(status),
                Err(ApiError::Conflict(_))
            ),
            "run status {status:?} must stay on inherited scanner-aware delete path"
        );
    }
    for status in [
        TaskStatus::Done,
        TaskStatus::New,
        TaskStatus::Stopped,
        TaskStatus::Interrupted,
    ] {
        assert!(
            ensure_task_not_in_use_for_native_trash(status).is_ok(),
            "non-active run status {status:?} should be eligible for native trash move"
        );
    }
}

#[test]
fn task_writes_accept_any_human_owner_and_reject_ownerless_tasks() {
    assert!(ensure_task_is_human_owned(Some(7)).is_ok());
    assert!(ensure_task_is_human_owned(Some(8)).is_ok());
    assert!(matches!(
        ensure_task_is_human_owned(None),
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

    let owner_check = "ensure_task_is_human_owned(task_state.owner_id)?;";
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

    let owner_check = "ensure_task_is_human_owned(task_state.owner_id)?;";
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
    assert!(state.contains("run_status::integer"));
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

#[test]
fn task_hard_delete_characterization_is_anchored_to_imported_manager() {
    for required in [
        "if (find_trash_task (task_id, &task))",
        "if (delete_reports (task))",
        "DELETE FROM results WHERE task = %llu",
        "DELETE FROM task_alerts WHERE task = %llu",
        "DELETE FROM task_files WHERE task = %llu",
        "DELETE FROM task_preferences WHERE task = %llu",
        "DELETE FROM tasks WHERE id = %llu",
        "SELECT count(*) FROM scope_report_sources",
        "WHERE source_report = %llu",
    ] {
        assert!(
            GVMD_MANAGE_SQL.contains(required),
            "imported task hard-delete authority missing {required}"
        );
    }
}

#[test]
fn task_hard_delete_handler_is_trash_only_guarded_and_transactional() {
    let source = include_str!("task_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn hard_delete_task")
        .expect("task hard-delete handler must exist")
        .1
        .split_once("fn task_write_location_headers")
        .expect("task hard-delete handler end")
        .0;
    for required in [
        "require_task_write_operator(operator)?",
        "resolve_task_write_operator_owner(&tx, &operator).await?",
        "LOCK TABLE tasks, task_alerts, task_files, task_preferences, reports, report_hosts, report_host_details, scope_report_sources, report_counts, result_nvt_reports, results, results_trash, tag_resources, tag_resources_trash",
        "load_task_trash_state",
        "ensure_task_is_human_owned",
        "ensure_task_not_in_use_for_native_trash",
        "ensure_task_reports_are_deletable",
        "execute_task_hard_delete_transaction",
        "tx.commit()",
        "StatusCode::NO_CONTENT",
    ] {
        assert!(
            handler.contains(required),
            "task hard-delete handler missing {required}"
        );
    }
    for guard in [
        "ensure_task_is_human_owned",
        "ensure_task_not_in_use_for_native_trash",
        "ensure_task_reports_are_deletable",
    ] {
        assert!(
            handler.find(guard).unwrap()
                < handler
                    .find("execute_task_hard_delete_transaction")
                    .unwrap(),
            "{guard} must run before task hard-delete mutation"
        );
    }
}

#[test]
fn task_hard_delete_sql_removes_descendants_before_trash_metadata() {
    let state = task_trash_state_sql();
    assert!(state.contains("coalesce(hidden, 0) = 2"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));

    let guards = task_report_delete_guards_sql();
    assert!(guards.contains("reports.scan_run_status::integer"));
    assert!(guards.contains("FROM scope_report_sources"));
    assert!(guards.contains("source_report = reports.id"));

    for sql in [
        task_hard_delete_report_host_details_sql(),
        task_hard_delete_report_hosts_sql(),
        task_hard_delete_live_results_sql(),
        task_hard_delete_trash_results_sql(),
        task_delete_report_counts_sql(),
        task_hard_delete_result_nvt_reports_sql(),
        task_hard_delete_reports_sql(),
        task_hard_delete_alerts_sql(),
        task_hard_delete_files_sql(),
        task_hard_delete_preferences_sql(),
    ] {
        assert!(sql.starts_with("DELETE FROM"));
        assert!(sql.contains("$1"));
    }
    for sql in [
        task_hard_delete_result_tag_links_sql(),
        task_hard_delete_trash_result_tag_links_sql(),
    ] {
        assert!(sql.contains("resource_type = 'result'"));
        assert!(sql.contains("resource_uuid IN"));
        assert!(sql.contains("SELECT uuid FROM results WHERE task = $1"));
        assert!(sql.contains("SELECT uuid FROM results_trash WHERE task = $1"));
    }
    let metadata = task_hard_delete_metadata_sql();
    assert!(metadata.contains("DELETE FROM tasks"));
    assert!(metadata.contains("coalesce(hidden, 0) = 2"));
    assert!(metadata.contains("RETURNING uuid::text"));

    let transaction = include_str!("task_write_transactions.rs")
        .split_once("pub(crate) async fn execute_task_hard_delete_transaction")
        .expect("task hard-delete transaction must exist")
        .1;
    assert!(
        transaction.find("task_hard_delete_reports_sql").unwrap()
            < transaction.find("task_hard_delete_metadata_sql").unwrap()
    );
    assert!(
        transaction
            .find("task_hard_delete_preferences_sql")
            .unwrap()
            < transaction.find("task_hard_delete_metadata_sql").unwrap()
    );
}

#[test]
fn task_hard_delete_report_status_guard_fails_closed_as_conflict() {
    assert!(matches!(
        task_report_delete_status(None),
        Err(ApiError::Conflict(_))
    ));
    assert!(matches!(
        task_report_delete_status(Some(99)),
        Err(ApiError::Conflict(_))
    ));
    assert_eq!(
        task_report_delete_status(Some(TaskStatus::Done.as_i32())).unwrap(),
        TaskStatus::Done
    );
}

#[test]
fn task_hard_delete_openapi_contract_is_native_trash_only() {
    let block = OPENAPI
        .split_once("/tasks/{task_id}/trash:")
        .expect("task hard-delete OpenAPI path")
        .1
        .split_once("/tasks/{task_id}/clone:")
        .expect("task hard-delete OpenAPI block end")
        .0;
    for required in [
        "operationId: deleteTasksByTaskIdTrash",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: task-trash-hard-delete",
        "x-yafvs-team-authority: authenticated-stack-operator",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: metadata-delete",
        "'204':",
        "'409':",
    ] {
        assert!(
            block.contains(required),
            "task hard-delete contract missing {required}"
        );
    }
}
