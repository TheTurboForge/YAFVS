// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::normalize_authentication_state;

#[derive(Debug, Serialize)]
pub(crate) struct MetricsSummary {
    total_system_cvss_load: f64,
    average_system_cvss_load: f64,
    authenticated_scan_coverage_percent: f64,
    alive_system_count: i64,
    vulnerability_count: i64,
    authenticated_system_count: i64,
    authentication_failed_system_count: i64,
    no_credential_path_system_count: i64,
    unknown_authentication_system_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsSystem {
    host: String,
    cvss_load: f64,
    max_cvss: f64,
    vulnerability_count: i64,
    authentication_state: String,
    source_report_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsVulnerability {
    nvt_oid: String,
    name: String,
    cvss_score: f64,
    affected_system_count: i64,
    cvss_load: f64,
    average_contribution: f64,
    source_report_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsPayload {
    pub(crate) id: String,
    pub(crate) summary: MetricsSummary,
    pub(crate) systems: Vec<MetricsSystem>,
    pub(crate) vulnerabilities: Vec<MetricsVulnerability>,
}

pub(crate) fn metrics_summary_from_row(row: &Row) -> MetricsSummary {
    MetricsSummary {
        total_system_cvss_load: row.get(2),
        average_system_cvss_load: row.get(3),
        authenticated_scan_coverage_percent: row.get(4),
        alive_system_count: row.get(5),
        vulnerability_count: row.get(6),
        authenticated_system_count: row.get(7),
        authentication_failed_system_count: row.get(8),
        no_credential_path_system_count: row.get(9),
        unknown_authentication_system_count: row.get(10),
    }
}

pub(crate) fn metrics_system_from_row(row: &Row) -> MetricsSystem {
    MetricsSystem {
        host: row.get(0),
        cvss_load: row.get(1),
        max_cvss: row.get(2),
        vulnerability_count: row.get(3),
        authentication_state: normalize_authentication_state(&row.get::<_, String>(4)),
        source_report_count: row.get(5),
    }
}

pub(crate) fn metrics_vulnerability_from_row(row: &Row) -> MetricsVulnerability {
    MetricsVulnerability {
        nvt_oid: row.get(0),
        name: row.get(1),
        cvss_score: row.get(2),
        affected_system_count: row.get(3),
        cvss_load: row.get(4),
        average_contribution: row.get(5),
        source_report_count: row.get(6),
    }
}

pub(crate) fn summarize_metrics(
    systems: &[MetricsSystem],
    vulnerability_count: i64,
) -> MetricsSummary {
    let alive_system_count = systems.len() as i64;
    let total_system_cvss_load = systems.iter().map(|system| system.cvss_load).sum::<f64>();
    let authenticated_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Authenticated")
        .count() as i64;
    let authentication_failed_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Authentication Failed")
        .count() as i64;
    let no_credential_path_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "No Credential Path")
        .count() as i64;
    let unknown_authentication_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Unknown")
        .count() as i64;
    MetricsSummary {
        total_system_cvss_load,
        average_system_cvss_load: if alive_system_count > 0 {
            total_system_cvss_load / alive_system_count as f64
        } else {
            0.0
        },
        authenticated_scan_coverage_percent: if alive_system_count > 0 {
            (100.0 * authenticated_system_count as f64) / alive_system_count as f64
        } else {
            0.0
        },
        alive_system_count,
        vulnerability_count,
        authenticated_system_count,
        authentication_failed_system_count,
        no_credential_path_system_count,
        unknown_authentication_system_count,
    }
}
