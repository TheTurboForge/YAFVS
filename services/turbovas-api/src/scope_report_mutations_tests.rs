// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn scope_report_generation_state_locks_scope_without_rejecting_global_scope() {
    let sql = scope_report_generation_state_sql();
    assert!(sql.contains("coalesce(is_global, 0)::integer"));
    assert!(sql.contains("WHERE lower(uuid) = lower($1)"));
    assert!(sql.contains("FOR UPDATE"));
    assert!(!sql.contains("is_global = 0"));
    assert!(!sql.contains("predefined = 0"));
}

#[test]
fn scope_report_generation_selects_latest_completed_scan_report_per_target() {
    let sql = scope_report_generation_sources_sql();
    for required in [
        "FROM targets t",
        "FROM scope_targets st",
        "JOIN LATERAL",
        "coalesce(tasks.usage_type, 'scan') = 'scan'",
        "reports.scan_run_status = 1",
        "ORDER BY coalesce(reports.end_time, reports.creation_time) DESC",
        "reports.id DESC",
        "LIMIT 1",
        "selected_time",
    ] {
        assert!(
            sql.contains(required),
            "source selection SQL missing {required}"
        );
    }
    for forbidden in ["INSERT INTO reports", "UPDATE tasks", "scan_queue"] {
        assert!(!sql.contains(forbidden));
    }
}

#[test]
fn scope_report_generation_rebuilds_counts_and_metrics_from_snapshot_sources() {
    let counts = scope_report_generation_counts_sql();
    for required in [
        "scope_report_sources",
        "count(DISTINCT target_uuid)",
        "scope_hosts",
        "report_hosts",
        "coalesce(r.severity, 0) != -3.0",
        "greatest(member_summary.member_host_count - evidence_hosts.evidence_host_count, 0)",
        "excluded_candidate_host_count",
        "modification_time = m_now()",
    ] {
        assert!(
            counts.contains(required),
            "count rebuild SQL missing {required}"
        );
    }
    let systems = scope_report_generation_system_metrics_sql();
    for required in [
        "INSERT INTO scope_report_system_metrics",
        "targets_login_data",
        "report_host_details",
        "authentication_failed",
        "no_credential_path",
    ] {
        assert!(
            systems.contains(required),
            "system metric SQL missing {required}"
        );
    }
    let vulnerabilities = scope_report_generation_vulnerability_metrics_sql();
    for required in [
        "INSERT INTO scope_report_vulnerability_metrics",
        "affected_system_count",
        "average_contribution",
        "count(DISTINCT source_report)",
    ] {
        assert!(
            vulnerabilities.contains(required),
            "vulnerability metric SQL missing {required}"
        );
    }
    let summary = scope_report_generation_metric_summary_sql();
    assert!(summary.contains("metric_authenticated_scan_coverage"));
}

#[test]
fn scope_report_generation_handler_checks_owner_before_snapshot_insert() {
    let source = include_str!("scope_report_mutations.rs");
    let body = source
        .split_once("pub(crate) async fn generate_scope_report")
        .expect("generation handler must exist")
        .1
        .split_once("async fn load_scope_report_generation_state")
        .expect("generation handler must precede loader")
        .0;
    for required in [
        "require_scope_write_operator",
        "resolve_scope_write_operator_owner",
        "load_scope_report_generation_state",
        "ensure_scope_owner_matches_operator",
        "execute_scope_report_generation_transaction",
        "tx.commit()",
        "scope_report_detail",
    ] {
        assert!(
            body.contains(required),
            "generation handler missing {required}"
        );
    }
    assert!(
        body.find("ensure_scope_owner_matches_operator").unwrap()
            < body
                .find("execute_scope_report_generation_transaction")
                .unwrap()
    );
}

#[test]
fn scope_report_delete_state_sql_resolves_owner_through_scope() {
    let sql = scope_report_delete_state_sql();
    assert!(sql.contains("FROM scope_reports sr"));
    assert!(sql.contains("JOIN scopes s ON s.id = sr.scope"));
    assert!(sql.contains("sr.id::integer"));
    assert!(sql.contains("s.owner::integer"));
    assert!(sql.contains("WHERE sr.uuid = $1"));
}

#[test]
fn scope_report_delete_sql_removes_only_snapshot_tables() {
    assert_eq!(
        scope_report_delete_sources_sql(),
        "DELETE FROM scope_report_sources WHERE scope_report = $1;"
    );
    assert_eq!(
        scope_report_delete_snapshot_sql(),
        "DELETE FROM scope_reports WHERE id = $1;"
    );
    let combined = format!(
        "{}\n{}",
        scope_report_delete_sources_sql(),
        scope_report_delete_snapshot_sql()
    );
    for forbidden in [
        "DELETE FROM reports",
        "DELETE FROM results",
        "DELETE FROM report_hosts",
    ] {
        assert!(!combined.contains(forbidden));
    }
}

#[test]
fn scope_report_delete_handler_checks_owner_before_delete_sql() {
    let source = include_str!("scope_report_mutations.rs");
    let body = source
        .split_once("pub(crate) async fn delete_scope_report")
        .expect("delete handler must exist")
        .1
        .split_once("async fn load_scope_report_delete_state")
        .expect("delete handler must precede loader")
        .0;
    assert!(body.contains("require_scope_write_operator"));
    assert!(body.contains("resolve_scope_write_operator_owner"));
    assert!(body.contains("load_scope_report_delete_state"));
    assert!(body.contains("ensure_scope_owner_matches_operator"));
    assert!(body.contains("execute_scope_report_delete_transaction"));
    assert!(
        body.find("ensure_scope_owner_matches_operator").unwrap()
            < body
                .find("execute_scope_report_delete_transaction")
                .unwrap()
    );
}
