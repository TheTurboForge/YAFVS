// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{report_cve_query_sql::report_cves_sql, report_payloads::raw_report_sql};

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
