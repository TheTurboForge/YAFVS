// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn scope_report_delete_state_sql_resolves_owner_through_scope() {
    let sql = scope_report_delete_state_sql();
    assert!(sql.contains("FROM scope_reports sr"));
    assert!(sql.contains("JOIN scopes s ON s.id = sr.scope"));
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
