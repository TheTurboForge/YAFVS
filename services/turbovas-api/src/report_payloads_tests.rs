// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::{
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
    report_cve_query_sql::report_cves_sql,
    report_error_query_sql::report_errors_sql,
    report_host_query_sql::report_hosts_sql,
    report_operating_system_query_sql::report_operating_systems_sql,
    report_payloads::raw_report_sql,
    report_port_query_sql::report_ports_sql,
    report_tls_certificate_query_sql::report_tls_certificates_sql,
};

const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");

fn openapi_path_block(path: &str) -> String {
    let marker = format!("  {path}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{path} path block must exist"));
    let tail = &OPENAPI[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("  /") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn raw_report_payload_exposes_report_progress_without_control_paths() {
    let sql = raw_report_sql("lower(uuid) = lower($1)", "creation_time DESC", "");
    let upper_sql = sql.to_ascii_uppercase();

    assert!(sql.contains("report_progress(report_pk)"));
    assert!(sql.contains("WHEN status = 'Done' THEN 100"));
    assert!(sql.contains("least(greatest(coalesce(report_progress(report_pk), 0), 0), 100)"));
    assert!(sql.contains("SELECT b.report_pk, b.uuid"));
    assert!(sql.contains("AS progress"));
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "START_TASK", "STOP_TASK"] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report read SQL must not include control/mutation path: {forbidden}"
        );
    }
}

#[test]
fn native_raw_report_routes_are_get_only_and_exclude_xml_export_generation() {
    let raw_report_paths = [
        "/api/v1/reports",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/results",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/hosts",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/ports",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/applications",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/operating-systems",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/cves",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/tls-certificates",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/errors",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/metrics",
    ];
    for path in raw_report_paths {
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "raw report read path must allow GET: {path}"
        );
        for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "raw report read path must remain GET-only even with write-control enabled: {method} {path}"
            );
        }
    }

    for path in [
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/export",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/raw-xml",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/xml",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/results/extra",
        "/api/v1/reports/../results",
        "/api/v1/reports/./metrics",
        "/api/v1/reports//hosts",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/../metrics",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "raw report direct classifier must reject XML/export or malformed path: {path}"
        );
    }
}

#[test]
fn openapi_documents_raw_report_reads_without_generation_or_export_contract() {
    for (path, replacement) in [
        ("/reports", "raw-report-list-read"),
        ("/reports/{report_id}", "raw-report-detail-summary-read"),
        (
            "/reports/{report_id}/results",
            "raw-report-result-evidence-read",
        ),
        (
            "/reports/{report_id}/hosts",
            "raw-report-host-evidence-read",
        ),
        (
            "/reports/{report_id}/ports",
            "raw-report-port-evidence-read",
        ),
        (
            "/reports/{report_id}/applications",
            "raw-report-application-evidence-read",
        ),
        (
            "/reports/{report_id}/operating-systems",
            "raw-report-operating-system-evidence-read",
        ),
        ("/reports/{report_id}/cves", "raw-report-cve-evidence-read"),
        (
            "/reports/{report_id}/tls-certificates",
            "raw-report-tls-certificate-evidence-read",
        ),
        (
            "/reports/{report_id}/errors",
            "raw-report-error-message-evidence-read",
        ),
        ("/reports/{report_id}/metrics", "raw-report-metrics-read"),
    ] {
        let block = openapi_path_block(path);
        for required in [
            "get:",
            "x-turbovas-direct: true",
            "x-turbovas-exposure: direct-read",
            "x-turbovas-maturity: live-read",
            replacement,
            "x-turbovas-inherited-still-owns: raw-report-generation-xml-export-retention-and-mutations",
        ] {
            assert!(
                block.contains(required),
                "{path} OpenAPI block missing {required}"
            );
        }
        for forbidden in [
            "x-turbovas-exposure: direct-write",
            "x-turbovas-safety-contract: write-control-v1",
            "\n    post:",
            "\n    patch:",
            "\n    put:",
            "\n    delete:",
        ] {
            assert!(
                !block.contains(forbidden),
                "{path} must not expose raw-report generation/XML export/retention/mutation behavior: {forbidden}"
            );
        }
    }
}

#[test]
fn raw_report_operating_system_sql_is_report_scoped_read_only() {
    let sql = report_operating_systems_sql("max_severity DESC");
    let upper_sql = sql.to_ascii_uppercase();

    for required in [
        "SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)",
        "JOIN report_hosts rh ON rh.report = sr.id",
        "os_cpe.name = 'best_os_cpe'",
        "os_txt.name = 'best_os_txt'",
        "LEFT JOIN results r",
        "AND lower(coalesce(nullif(r.host, ''), r.hostname, '')) = oi.host_key",
        "FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count",
        "count(*) OVER()::bigint AS total",
        "ORDER BY max_severity DESC, name ASC LIMIT $3 OFFSET $4",
    ] {
        assert!(
            sql.contains(required),
            "raw report operating-system SQL missing {required}"
        );
    }
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "START_TASK", "STOP_TASK"] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report operating-system SQL must not include control/mutation path: {forbidden}"
        );
    }
}

#[test]
fn raw_report_error_sql_is_report_scoped_error_message_read_only() {
    let sql = report_errors_sql("created_at_unix DESC");
    let upper_sql = sql.to_ascii_uppercase();

    for required in [
        "SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)",
        "JOIN results r ON r.report = sr.id",
        "WHERE (r.type = 'Error Message' OR coalesce(r.severity, 0) = -3)",
        "AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''",
        "count(*) OVER()::bigint AS total",
        "ORDER BY created_at_unix DESC, id ASC LIMIT $3 OFFSET $4",
    ] {
        assert!(
            sql.contains(required),
            "raw report error SQL missing {required}"
        );
    }
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "START_TASK", "STOP_TASK"] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report error SQL must not include control/mutation path: {forbidden}"
        );
    }
}

#[test]
fn raw_report_host_sql_is_report_scoped_auth_state_read_only() {
    let sql = report_hosts_sql("host ASC");
    let upper_sql = sql.to_ascii_uppercase();

    for required in [
        "SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)",
        "JOIN report_hosts rh ON rh.report = sr.id",
        "LEFT JOIN report_host_details rhd ON rhd.report_host = hb.report_host_id",
        "JOIN results r ON r.report = sr.id",
        "CASE WHEN coalesce(dr.auth_success, false) THEN 'authenticated'",
        "WHEN coalesce(dr.auth_failure, false) THEN 'authentication_failed'",
        "WHEN coalesce(dr.has_credential_path, false) THEN 'unknown'",
        "ELSE 'no_credential_path' END AS authentication_state",
        "count(*) OVER()::bigint AS total",
        "ORDER BY host ASC, host ASC LIMIT $3 OFFSET $4",
    ] {
        assert!(
            sql.contains(required),
            "raw report host SQL missing {required}"
        );
    }
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "START_TASK", "STOP_TASK"] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report host SQL must not include control/mutation path: {forbidden}"
        );
    }
}

#[test]
fn raw_report_tls_certificate_sql_is_report_scoped_metadata_read_only() {
    let sql = report_tls_certificates_sql("not_after_unix DESC");
    let upper_sql = sql.to_ascii_uppercase();

    for required in [
        "SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)",
        "JOIN report_hosts rh ON rh.report = sr.id",
        "JOIN tls_certificate_origins origin",
        "origin.origin_type = 'Report'",
        "JOIN tls_certificate_sources src ON src.origin = origin.id",
        "JOIN tls_certificates c ON c.id = src.tls_certificate",
        "JOIN tls_certificate_locations loc ON loc.id = src.location",
        "coalesce(c.sha256_fingerprint, '') AS fingerprint_sha256",
        "count(*) OVER()::bigint AS total",
        "ORDER BY not_after_unix DESC, id ASC LIMIT $3 OFFSET $4",
    ] {
        assert!(
            sql.contains(required),
            "raw report TLS certificate SQL missing {required}"
        );
    }
    for forbidden in [
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "START_TASK",
        "STOP_TASK",
        "PRIVATE_KEY",
        "CERTIFICATE_PEM",
        "CERTIFICATE_BLOB",
    ] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report TLS certificate SQL must not include control/mutation or key material path: {forbidden}"
        );
    }
}

#[test]
fn raw_report_port_sql_is_report_scoped_visible_port_read_only() {
    let sql = report_ports_sql("max_severity DESC");
    let upper_sql = sql.to_ascii_uppercase();

    for required in [
        "SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)",
        "JOIN results r ON r.report = sr.id",
        "WHERE coalesce(r.severity, 0) != -3.0",
        "AND coalesce(r.port, '') <> ''",
        "FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count",
        "count(*) OVER()::bigint AS total",
        "ORDER BY max_severity DESC, port ASC LIMIT $3 OFFSET $4",
    ] {
        assert!(
            sql.contains(required),
            "raw report port SQL missing {required}"
        );
    }
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "START_TASK", "STOP_TASK"] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report port SQL must not include control/mutation path: {forbidden}"
        );
    }
}

#[test]
fn raw_report_cve_sql_is_report_scoped_positive_vulnerability_read_only() {
    let sql = report_cves_sql("max_severity DESC");
    let upper_sql = sql.to_ascii_uppercase();

    for required in [
        "SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)",
        "JOIN results r ON r.report = sr.id",
        "JOIN vt_refs vr ON vr.vt_oid = r.nvt AND vr.type = 'cve'",
        "WHERE coalesce(r.severity, 0) > 0",
        "count(*) OVER()::bigint AS total",
        "ORDER BY max_severity DESC, id ASC LIMIT $3 OFFSET $4",
    ] {
        assert!(
            sql.contains(required),
            "raw report CVE SQL missing {required}"
        );
    }
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "START_TASK", "STOP_TASK"] {
        assert!(
            !upper_sql.contains(forbidden),
            "raw report CVE SQL must not include control/mutation path: {forbidden}"
        );
    }
}
