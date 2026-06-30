// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    collections::{REPORT_RESULT_DEFAULT_SORT, REPORT_RESULT_SORT_FIELDS},
    direct_api::direct_api_v1_path_is_allowed,
    query::sort_clause,
    scope_report_results::scope_report_results_sql,
    scope_report_retention::scope_report_retention_sources_sql,
};

#[test]
fn scope_report_results_sql_is_source_scoped_and_deduplicated() {
    let sort_sql = sort_clause(REPORT_RESULT_DEFAULT_SORT, REPORT_RESULT_SORT_FIELDS).unwrap();
    let sql = scope_report_results_sql(&sort_sql);

    assert!(sql.contains("WHERE sr.uuid = $1 AND sr.scope_uuid = $2"));
    assert!(sql.contains("JOIN scope_report_sources srs ON srs.scope_report = sr.id"));
    assert!(sql.contains("JOIN selected_hosts sh"));
    assert!(sql.contains("WHERE coalesce(r.severity, 0) != -3.0"));
    assert!(sql.contains("row_number () OVER"));
    assert!(sql.contains("PARTITION BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))"));
    assert!(sql.contains("FROM ranked WHERE rn = 1"));
    assert!(sql.contains("srs.source_report_uuid AS source_report_id"));
    assert!(sql.contains("JOIN results r ON r.report = srs.source_report"));
}

#[test]
fn scope_report_retention_preview_marks_only_non_latest_sources() {
    let sql = scope_report_retention_sources_sql();
    let upper_sql = sql.to_uppercase();

    assert!(sql.contains("WITH latest_completed AS"));
    assert!(sql.contains("SELECT DISTINCT ON (task.target)"));
    assert!(sql.contains("coalesce(task.usage_type, 'scan') = 'scan'"));
    assert!(sql.contains("reports.scan_run_status = 1"));
    assert!(sql.contains("ORDER BY task.target, coalesce(reports.end_time, reports.creation_time) DESC, reports.id DESC"));
    assert!(sql.contains("SELECT srs.source_report, srs.source_report_uuid, srs.target,"));
    assert!(sql.contains("FROM scope_report_sources srs"));
    assert!(sql.contains("(lc.source_report = srs.source_report) AS kept_as_latest"));
    assert!(sql.contains("WHERE srs.scope_report = $1"));
    assert!(sql.contains("SELECT sr.source_report_uuid::text, sr.target_uuid::text"));
    assert!(sql.contains("sr.task_uuid::text, coalesce(sr.task_name, '')::text AS task_name"));
    assert!(sql.contains("coalesce(sr.kept_as_latest, false) AS kept_as_latest"));
    assert!(sql.contains("FROM source_rows sr"));
    assert!(sql.contains("LEFT JOIN results res ON res.report = sr.source_report"));
    assert!(
        sql.contains(
            "GROUP BY sr.source_report_uuid, sr.target_uuid, sr.target_name, sr.task_uuid,"
        )
    );
    assert!(
        sql.find("FROM source_rows sr").unwrap()
            < sql
                .find("LEFT JOIN results res ON res.report = sr.source_report")
                .unwrap()
    );
    assert!(!upper_sql.contains("INSERT"));
    assert!(!upper_sql.contains("UPDATE"));
    assert!(!upper_sql.contains("DELETE"));
    assert!(direct_api_v1_path_is_allowed(
        "/api/v1/scopes/scope-id/reports/report-id/retention-plan"
    ));
}

#[test]
fn scope_report_retention_plan_remains_dry_run_read_only_preview() {
    let source = include_str!("scope_report_retention.rs");
    let body = source
        .split_once("async fn scope_report_retention_plan(")
        .expect("scope report retention plan handler must exist")
        .1
        .split_once("fn scope_report_retention_sources_sql")
        .expect("retention plan handler must precede retention SQL helper")
        .0;
    let upper_body = body.to_ascii_uppercase();

    assert!(body.contains("mode: \"dry_run_preview\".to_string()"));
    assert!(body.contains("destructive_actions: false"));
    assert!(body.contains("latest_completed_raw_report_retains_full_detail: true"));
    assert!(body.contains("detail_compacted_field: \"detail_compacted\".to_string()"));
    assert!(body.contains("aggregate_only_field: \"aggregate_only\".to_string()"));
    assert!(body.contains("detail_compacted_count: 0"));
    assert!(body.contains("aggregate_only_count: 0"));
    for forbidden in ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP"] {
        assert!(
            !upper_body.contains(forbidden),
            "retention preview handler must stay read-only and non-destructive"
        );
    }
}

#[test]
fn scope_report_metrics_reads_persisted_snapshot_tables_and_not_live_results() {
    let source = include_str!("metrics.rs");
    let start = "pub(crate) async fn scope_report_metrics(";
    let end = "\n}\n\npub(crate) async fn report_metrics";
    let body = source
        .split_once(start)
        .expect("scope_report_metrics handler must exist")
        .1
        .split_once(end)
        .expect("scope_report_metrics handler must precede retention plan")
        .0;
    let upper_body = body.to_ascii_uppercase();

    assert!(body.contains("coalesce(sr.metric_total_system_cvss_load, 0)"));
    assert!(body.contains("coalesce(sr.metric_authenticated_scan_coverage, 0)"));
    assert!(body.contains("SELECT count(*) FROM scope_report_vulnerability_metrics"));
    assert!(body.contains("FROM scope_report_system_metrics"));
    assert!(body.contains("FROM scope_report_vulnerability_metrics"));
    assert!(body.contains("WHERE sr.uuid = $1 AND sr.scope_uuid = $2"));
    assert!(body.contains("ORDER BY cvss_load DESC, host ASC"));
    assert!(body.contains("ORDER BY cvss_load DESC, cvss_score DESC, nvt_name ASC"));
    assert!(!upper_body.contains("JOIN RESULTS"));
    assert!(!upper_body.contains("FROM RESULTS"));
}

#[test]
fn scope_report_list_and_detail_expose_persisted_metrics_summary() {
    let source = include_str!("scope_reports.rs");

    for required in [
        "metric_total_system_cvss_load",
        "metric_average_system_cvss_load",
        "metric_authenticated_scan_coverage",
        "metric_alive_system_count",
        "metric_authenticated_system_count",
        "metric_auth_failed_system_count",
        "metric_no_credential_path_system_count",
        "metric_unknown_authentication_system_count",
    ] {
        assert!(
            source.contains(required),
            "scope reports should expose {required}"
        );
    }
    assert!(
        source
            .matches("SELECT count(*) FROM scope_report_vulnerability_metrics")
            .count()
            >= 2,
        "list and detail should expose the same metrics vulnerability-count source"
    );
}

#[test]
fn scope_report_native_routes_remain_get_only_read_paths() {
    let source = include_str!("routes.rs");
    let start = ".route(\"/api/v1/scope-reports\", get(scope_reports))";
    let end = "\n}\n\npub(crate) fn direct_native_api_router";
    let routes = source
        .split_once(start)
        .expect("scope report routes must be registered")
        .1
        .split_once(end)
        .expect("scope report routes must precede app state")
        .0;

    for path in [
        "/api/v1/scope-reports/:scope_report_id",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/results",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/hosts",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/ports",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/applications",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/operating-systems",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/cves",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/tls-certificates",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/errors",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/metrics",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan",
    ] {
        assert!(routes.contains(path));
    }
    for handler in [
        "get(scope_report_detail)",
        "get(scope_report_results)",
        "get(scope_report_hosts)",
        "get(scope_report_ports)",
        "get(scope_report_applications)",
        "get(scope_report_operating_systems)",
        "get(scope_report_cves)",
        "get(scope_report_tls_certificates)",
        "get(scope_report_errors)",
        "get(scope_report_metrics)",
        "get(scope_report_retention_plan)",
    ] {
        assert!(routes.contains(handler));
    }
    for forbidden in [
        "post(scope_report",
        "put(scope_report",
        "patch(scope_report",
        "delete(scope_report",
        "start_task",
        "resume_task",
    ] {
        assert!(!routes.contains(forbidden));
    }
}

#[test]
fn scope_reports_do_not_trigger_scanner_or_task_control() {
    let source = [
        include_str!("scope_report_results.rs"),
        include_str!("scope_report_applications.rs"),
        include_str!("scope_report_cves.rs"),
        include_str!("scope_report_errors.rs"),
        include_str!("scope_reports.rs"),
        include_str!("scope_report_hosts.rs"),
        include_str!("scope_report_operating_systems.rs"),
        include_str!("scope_report_ports.rs"),
        include_str!("scope_report_tls_certificates.rs"),
        include_str!("scope_report_lookup.rs"),
    ]
    .join("\n");
    let start = "pub(crate) async fn scope_report_results(";
    let end = "\npub(crate) async fn scope_report_exists(";
    let handlers = source
        .split_once(start)
        .expect("scope report handlers must exist")
        .1
        .split_once(end)
        .expect("scope report handlers must precede tests")
        .0;
    let lower_handlers = handlers.to_ascii_lowercase();

    for forbidden in [
        "start_task",
        "resume_task",
        "stop_task",
        "osp_",
        "create_report",
        "insert into reports",
        "update tasks",
        "delete from reports",
    ] {
        assert!(
            !lower_handlers.contains(forbidden),
            "scope report read handlers must not trigger scanner or task control: {forbidden}"
        );
    }
}
