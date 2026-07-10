// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_SQL_SCOPES_C: &str = include_str!("../../../components/gvmd/src/manage_sql_scopes.c");
const MANAGE_SQL_METRICS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_metrics.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_VALIDATOR_C: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GSA_SCOPES_TS: &str = include_str!("../../../components/gsa/src/gmp/commands/scopes.ts");
const GSA_SCOPE_DETAILS_TSX: &str =
    include_str!("../../../components/gsa/src/web/pages/scopes/ScopeDetailsPage.tsx");
const GSA_SCOPE_LIST_TSX: &str =
    include_str!("../../../components/gsa/src/web/pages/scopes/ScopeListPage.tsx");
const GSA_SCOPE_REPORT_LIST_TSX: &str =
    include_str!("../../../components/gsa/src/web/pages/scope-reports/ScopeReportListPage.tsx");

fn inherited_function(source: &str, name: &str) -> String {
    let marker = format!("\n{name} (");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} function marker must exist"));
    let tail = &source[start..];
    let end = tail.find("\n/**").unwrap_or(tail.len());
    tail[..end].to_string()
}

#[test]
fn inherited_scope_report_generation_snapshots_latest_completed_reports_and_metrics() {
    let generate = inherited_function(MANAGE_SQL_SCOPES_C, "generate_scope_report");
    for required in [
        "scope_id_by_uuid (scope_uuid)",
        "scope_is_global (scope)",
        "scope_target_filter (scope, global)",
        "sql_begin_immediate ();",
        "INSERT INTO scope_reports",
        "generated_by",
        "(SELECT id FROM users WHERE uuid = '%s')",
        "INSERT INTO scope_report_sources",
        "JOIN (%s) selected_targets ON selected_targets.target = t.id",
        "JOIN LATERAL (",
        "reports.scan_run_status = %i",
        "ORDER BY coalesce (reports.end_time, reports.creation_time) DESC,",
        "reports.id DESC",
        "LIMIT 1",
        "update_scope_report_counts (scope_report, scope, global)",
        "rebuild_scope_report_metrics (scope_report, scope, global)",
        "sql_commit ();",
        "SELECT uuid FROM scope_reports WHERE id = %llu;",
    ] {
        assert!(
            generate.contains(required),
            "generate_scope_report missing {required}"
        );
    }
}

#[test]
fn inherited_scope_report_aggregates_depend_on_hosts_results_and_metric_tables() {
    let counts = inherited_function(MANAGE_SQL_SCOPES_C, "update_scope_report_counts");
    for required in [
        "custom_host_match_clause (scope, global)",
        "SELECT count (*) FROM scope_report_sources",
        "SELECT count (DISTINCT target_uuid) FROM scope_report_sources",
        "SELECT count (*) FROM scope_hosts WHERE scope = %llu",
        "FROM report_hosts rh",
        "JOIN scope_report_sources s ON s.source_report = rh.report",
        "FROM results r",
        "SCOPE_REPORT_FINDING_CLAUSE",
        "excluded_candidate_host_count",
        "UPDATE scope_reports",
    ] {
        assert!(
            counts.contains(required),
            "scope report counts missing {required}"
        );
    }

    let rebuild = inherited_function(MANAGE_SQL_METRICS_C, "rebuild_scope_report_metrics");
    for required in [
        "DELETE FROM scope_report_system_metrics",
        "DELETE FROM scope_report_vulnerability_metrics",
        "INSERT INTO scope_report_system_metrics",
        "INSERT INTO scope_report_vulnerability_metrics",
        "metric_authenticated_scan_coverage",
        "metric_total_system_cvss_load",
        "metric_average_system_cvss_load",
    ] {
        assert!(
            rebuild.contains(required),
            "scope report metric rebuild missing {required}"
        );
    }
}

#[test]
fn inherited_scope_report_delete_removes_only_snapshot_rows_and_relies_on_cascades() {
    let delete = inherited_function(MANAGE_SQL_SCOPES_C, "delete_scope_report");
    for required in [
        "scope_report_id_by_uuid (scope_report_uuid)",
        "DELETE FROM scope_report_sources WHERE scope_report = %llu;",
        "DELETE FROM scope_reports WHERE id = %llu;",
    ] {
        assert!(
            delete.contains(required),
            "delete_scope_report missing {required}"
        );
    }
    for forbidden in [
        "DELETE FROM reports",
        "DELETE FROM results",
        "DELETE FROM report_hosts",
    ] {
        assert!(
            !delete.contains(forbidden),
            "delete_scope_report must not delete raw report evidence via {forbidden}"
        );
    }
}

#[test]
fn inherited_gsa_gsad_gvmd_surface_keeps_scope_report_mutations_on_gmp() {
    for (source, label) in [
        (GSA_SCOPE_DETAILS_TSX, "scope details page"),
        (GSA_SCOPE_LIST_TSX, "scope list page"),
        (GSA_SCOPE_REPORT_LIST_TSX, "scope report list page"),
    ] {
        assert!(
            source.contains("gmp.scopes.generateReport"),
            "{label} must keep explicit scope-report generation callsite characterized"
        );
    }

    for required in [
        "cmd: 'generate_scope_report'",
        "cmd: 'delete_scope_report'",
        "scope_report_id: id",
    ] {
        assert!(
            GSA_SCOPES_TS.contains(required),
            "GSA scopes command missing {required}"
        );
    }

    for (source, name, required) in [
        (
            GSAD_GMP_C,
            "generate_scope_report_gmp",
            "<generate_scope_report",
        ),
        (
            GSAD_GMP_C,
            "delete_scope_report_gmp",
            "<delete_scope_report",
        ),
        (GMP_C, "handle_generate_scope_report", "XML_OK_CREATED_ID"),
        (GMP_C, "handle_delete_scope_report", "XML_OK"),
    ] {
        let body = inherited_function(source, name);
        assert!(body.contains(required), "{name} missing {required}");
    }

    for command in ["|(generate_scope_report)", "|(delete_scope_report)"] {
        assert!(
            GSAD_VALIDATOR_C.contains(command),
            "validator missing {command}"
        );
    }
}

#[test]
fn native_direct_api_gates_scope_report_generation_and_delete_on_write_control() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/scope-reports",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/scope-reports/12345678-1234-1234-1234-123456789abc",
        false,
    ));

    let generation_path = "/api/v1/scopes/12345678-1234-1234-1234-123456789abc/reports";
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        generation_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        generation_path,
        true
    ));

    let delete_path = "/api/v1/scope-reports/12345678-1234-1234-1234-123456789abc";
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        delete_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        delete_path,
        true
    ));
}
