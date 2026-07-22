// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::{normalize_authentication_state, unix_ts_to_rfc3339};

#[derive(Debug, Serialize)]
pub(crate) struct ReportSeverityCounts {
    pub(crate) critical: i64,
    pub(crate) high: i64,
    pub(crate) medium: i64,
    pub(crate) low: i64,
    pub(crate) log: i64,
    pub(crate) false_positive: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct HostItem {
    host: String,
    scope_membership: String,
    source_report_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    authenticated_scan_state: String,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PortItem {
    port: String,
    protocol: String,
    host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ApplicationItem {
    name: String,
    version: String,
    cpe: String,
    host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OperatingSystemItem {
    name: String,
    cpe: String,
    host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CveItem {
    id: String,
    affected_system_count: i64,
    result_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TlsCertificateItem {
    id: String,
    fingerprint_sha256: String,
    subject: String,
    issuer: String,
    serial: String,
    not_before: Option<String>,
    not_after: Option<String>,
    host_count: i64,
    port_count: i64,
    result_count: i64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportHostItem {
    host: String,
    hostname: Option<String>,
    best_os_cpe: Option<String>,
    best_os_txt: Option<String>,
    ports_count: i64,
    applications_count: i64,
    distance: Option<i64>,
    authentication_state: String,
    start_time: Option<String>,
    end_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    severity: ReportSeverityCounts,
    max_severity: f64,
    source_report_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorMessageItem {
    id: String,
    host: String,
    port: String,
    nvt_oid: String,
    description: String,
    source_report_id: String,
    created_at: Option<String>,
}

pub(crate) fn host_from_row(row: &Row) -> HostItem {
    HostItem {
        host: row.get(1),
        scope_membership: row.get(2),
        source_report_count: row.get(3),
        result_count: row.get(4),
        vulnerability_count: row.get(5),
        authenticated_scan_state: normalize_authentication_state(&row.get::<_, String>(6)),
        source_report_ids: row.get(7),
    }
}

pub(crate) fn port_from_row(row: &Row) -> PortItem {
    PortItem {
        port: row.get(1),
        protocol: row.get(2),
        host_count: row.get(3),
        result_count: row.get(4),
        vulnerability_count: row.get(5),
        max_severity: row.get(6),
        source_report_ids: row.get(7),
    }
}

pub(crate) fn application_from_row(row: &Row) -> ApplicationItem {
    ApplicationItem {
        name: row.get(1),
        version: row.get(2),
        cpe: row.get(3),
        host_count: row.get(4),
        result_count: row.get(5),
        vulnerability_count: row.get(6),
        max_severity: row.get(7),
        source_report_ids: row.get(8),
    }
}

pub(crate) fn operating_system_from_row(row: &Row) -> OperatingSystemItem {
    OperatingSystemItem {
        name: row.get(1),
        cpe: row.get(2),
        host_count: row.get(3),
        result_count: row.get(4),
        vulnerability_count: row.get(5),
        max_severity: row.get(6),
        source_report_ids: row.get(7),
    }
}

pub(crate) fn cve_from_row(row: &Row) -> CveItem {
    CveItem {
        id: row.get(1),
        affected_system_count: row.get(2),
        result_count: row.get(3),
        max_severity: row.get(4),
        source_report_ids: row.get(5),
    }
}

pub(crate) fn tls_certificate_from_row(row: &Row) -> TlsCertificateItem {
    TlsCertificateItem {
        id: row.get(1),
        fingerprint_sha256: row.get(2),
        subject: row.get(3),
        issuer: row.get(4),
        serial: row.get(5),
        not_before: unix_ts_to_rfc3339(row.get(6)),
        not_after: unix_ts_to_rfc3339(row.get(7)),
        host_count: row.get(8),
        port_count: row.get(9),
        result_count: row.get(10),
        source_report_ids: row.get(11),
    }
}

pub(crate) fn report_host_from_row(row: &Row) -> ReportHostItem {
    ReportHostItem {
        host: row.get("host"),
        hostname: row.get("hostname"),
        best_os_cpe: row.get("best_os_cpe"),
        best_os_txt: row.get("best_os_txt"),
        ports_count: row.get("ports_count"),
        applications_count: row.get("applications_count"),
        distance: row.get("distance"),
        authentication_state: normalize_authentication_state(
            &row.get::<_, String>("authentication_state"),
        ),
        start_time: unix_ts_to_rfc3339(row.get("start_time_unix")),
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        result_count: row.get("result_count"),
        vulnerability_count: row.get("vulnerability_count"),
        severity: ReportSeverityCounts {
            critical: row.get("severity_critical"),
            high: row.get("severity_high"),
            medium: row.get("severity_medium"),
            low: row.get("severity_low"),
            log: row.get("severity_log"),
            false_positive: row.get("severity_false_positive"),
        },
        max_severity: row.get("max_severity"),
        source_report_id: row.get("source_report_id"),
    }
}

pub(crate) fn error_message_from_row(row: &Row) -> ErrorMessageItem {
    ErrorMessageItem {
        id: row.get(1),
        host: row.get(2),
        port: row.get(3),
        nvt_oid: row.get(4),
        description: row.get(5),
        source_report_id: row.get(6),
        created_at: unix_ts_to_rfc3339(row.get(7)),
    }
}
