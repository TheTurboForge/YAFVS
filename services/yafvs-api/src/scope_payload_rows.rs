// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::{normalize_protection_requirement, unix_ts_to_rfc3339};

#[derive(Debug, Serialize)]
pub(crate) struct ScopeSummary {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportItem {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) status: String,
    pub(crate) scope: ScopeSummary,
    pub(crate) protection_requirement: String,
    pub(crate) source_report_count: i64,
    pub(crate) source_target_count: i64,
    pub(crate) member_host_count: i64,
    pub(crate) evidence_host_count: i64,
    pub(crate) missing_host_count: i64,
    pub(crate) result_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) severity: SeverityCounts,
    pub(crate) max_severity: f64,
    pub(crate) latest_evidence_time: Option<String>,
    pub(crate) excluded_candidate_host_count: i64,
    pub(crate) creation_time: Option<String>,
    pub(crate) modification_time: Option<String>,
    pub(crate) metrics_summary: ScopeReportMetricsSummary,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportMetricsSummary {
    pub(crate) total_system_cvss_load: f64,
    pub(crate) average_system_cvss_load: f64,
    pub(crate) authenticated_scan_coverage_percent: f64,
    pub(crate) alive_system_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) authenticated_system_count: i64,
    pub(crate) authentication_failed_system_count: i64,
    pub(crate) no_credential_path_system_count: i64,
    pub(crate) unknown_authentication_system_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportDetail {
    #[serde(flatten)]
    pub(crate) report: ScopeReportItem,
    pub(crate) sources: Vec<ScopeReportSourceItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportSourceItem {
    pub(crate) id: String,
    pub(crate) source_report_id: String,
    pub(crate) target_id: String,
    pub(crate) target_name: String,
    pub(crate) task_id: String,
    pub(crate) task_name: String,
    pub(crate) scan_end: Option<String>,
    pub(crate) selected: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionPolicyPreview {
    pub(crate) mode: String,
    pub(crate) destructive_actions: bool,
    pub(crate) latest_completed_raw_report_retains_full_detail: bool,
    pub(crate) detail_compacted_field: String,
    pub(crate) aggregate_only_field: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionSummary {
    pub(crate) source_report_count: i64,
    pub(crate) current_full_fidelity_count: i64,
    pub(crate) future_tiered_retention_candidate_count: i64,
    pub(crate) detail_compacted_count: i64,
    pub(crate) aggregate_only_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionSource {
    pub(crate) source_report_id: String,
    pub(crate) target_id: String,
    pub(crate) target_name: String,
    pub(crate) task_id: String,
    pub(crate) task_name: String,
    pub(crate) scan_start: Option<String>,
    pub(crate) scan_end: Option<String>,
    pub(crate) selected_time: Option<String>,
    pub(crate) result_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) max_severity: f64,
    pub(crate) retention_state: String,
    pub(crate) detail_compacted: bool,
    pub(crate) aggregate_only: bool,
    pub(crate) kept_as_latest: bool,
    pub(crate) pinned_by_scope_report: bool,
    pub(crate) future_tiered_retention_candidate: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionPlan {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) scope: ScopeSummary,
    pub(crate) generated_at: Option<String>,
    pub(crate) policy: ScopeReportRetentionPolicyPreview,
    pub(crate) summary: ScopeReportRetentionSummary,
    pub(crate) sources: Vec<ScopeReportRetentionSource>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeEntity {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeCandidateHost {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) target_id: Option<String>,
    pub(crate) target_name: Option<String>,
    pub(crate) source_report_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportReference {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) creation_time: Option<String>,
    pub(crate) latest_evidence_time: Option<String>,
    pub(crate) source_report_count: i64,
    pub(crate) member_host_count: i64,
    pub(crate) evidence_host_count: i64,
    pub(crate) missing_host_count: i64,
    pub(crate) result_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) max_severity: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeItem {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) protection_requirement: String,
    pub(crate) protection_requirement_label: String,
    pub(crate) predefined: bool,
    pub(crate) global: bool,
    pub(crate) creation_time: Option<String>,
    pub(crate) modification_time: Option<String>,
    pub(crate) target_count: i64,
    pub(crate) host_count: i64,
    pub(crate) scope_report_count: i64,
    pub(crate) targets: Vec<ScopeEntity>,
    pub(crate) hosts: Vec<ScopeEntity>,
    pub(crate) candidate_hosts: Vec<ScopeCandidateHost>,
    pub(crate) scope_reports: Vec<ScopeReportReference>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SeverityCounts {
    pub(crate) high: i64,
    pub(crate) medium: i64,
    pub(crate) low: i64,
    pub(crate) log: i64,
    pub(crate) false_positive: i64,
}

pub(crate) fn scope_from_row(
    row: &Row,
    targets: Vec<ScopeEntity>,
    hosts: Vec<ScopeEntity>,
    candidate_hosts: Vec<ScopeCandidateHost>,
    scope_reports: Vec<ScopeReportReference>,
) -> ScopeItem {
    let protection = row.get::<_, String>(5);
    let predefined: i32 = row.get(6);
    let global: i32 = row.get(7);
    ScopeItem {
        id: row.get(2),
        name: row.get(3),
        comment: row.get(4),
        protection_requirement: protection.clone(),
        protection_requirement_label: normalize_protection_requirement(&protection),
        predefined: predefined != 0,
        global: global != 0,
        creation_time: unix_ts_to_rfc3339(row.get(8)),
        modification_time: unix_ts_to_rfc3339(row.get(9)),
        target_count: row.get(10),
        host_count: row.get(11),
        scope_report_count: row.get(12),
        targets,
        hosts,
        candidate_hosts,
        scope_reports,
    }
}

pub(crate) fn scope_entity_from_row(row: &Row) -> ScopeEntity {
    ScopeEntity {
        id: row.get(0),
        name: row.get(1),
    }
}

pub(crate) fn scope_candidate_host_from_row(row: &Row) -> ScopeCandidateHost {
    let name: String = row.get(0);
    ScopeCandidateHost {
        id: name.clone(),
        name,
        target_id: row.get(1),
        target_name: row.get(2),
        source_report_id: row.get(3),
    }
}

pub(crate) fn scope_report_reference_from_row(row: &Row) -> ScopeReportReference {
    let scope_name: String = row.get(1);
    ScopeReportReference {
        id: row.get(0),
        name: format!("{scope_name} scope report"),
        creation_time: unix_ts_to_rfc3339(row.get(2)),
        latest_evidence_time: unix_ts_to_rfc3339(row.get(3)),
        source_report_count: row.get(4),
        member_host_count: row.get(5),
        evidence_host_count: row.get(6),
        missing_host_count: row.get(7),
        result_count: row.get(8),
        vulnerability_count: row.get(9),
        max_severity: row.get(10),
    }
}

pub(crate) fn scope_report_from_row(row: &Row) -> ScopeReportItem {
    let scope_name: String = row.get(3);
    ScopeReportItem {
        id: row.get(1),
        name: format!("{scope_name} scope report"),
        status: "Done".to_string(),
        scope: ScopeSummary {
            id: row.get(2),
            name: scope_name,
        },
        protection_requirement: normalize_protection_requirement(&row.get::<_, String>(4)),
        source_report_count: row.get(5),
        source_target_count: row.get(6),
        member_host_count: row.get(7),
        evidence_host_count: row.get(8),
        missing_host_count: row.get(9),
        result_count: row.get(10),
        vulnerability_count: row.get(11),
        max_severity: row.get(12),
        severity: SeverityCounts {
            high: row.get(17),
            medium: row.get(18),
            low: row.get(19),
            log: row.get(20),
            false_positive: row.get(21),
        },
        latest_evidence_time: unix_ts_to_rfc3339(row.get(13)),
        excluded_candidate_host_count: row.get(14),
        creation_time: unix_ts_to_rfc3339(row.get(15)),
        modification_time: unix_ts_to_rfc3339(row.get(16)),
        metrics_summary: ScopeReportMetricsSummary {
            total_system_cvss_load: row.get(22),
            average_system_cvss_load: row.get(23),
            authenticated_scan_coverage_percent: row.get(24),
            alive_system_count: row.get(25),
            vulnerability_count: row.get(26),
            authenticated_system_count: row.get(27),
            authentication_failed_system_count: row.get(28),
            no_credential_path_system_count: row.get(29),
            unknown_authentication_system_count: row.get(30),
        },
    }
}

pub(crate) fn scope_report_source_from_row(row: &Row) -> ScopeReportSourceItem {
    let id: i64 = row.get("id");
    ScopeReportSourceItem {
        id: id.to_string(),
        source_report_id: row.get("source_report_id"),
        target_id: row.get("target_id"),
        target_name: row.get("target_name"),
        task_id: row.get("task_id"),
        task_name: row.get("task_name"),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        selected: true,
    }
}

pub(crate) fn scope_report_retention_source_from_row(row: &Row) -> ScopeReportRetentionSource {
    let kept_as_latest: bool = row.get("kept_as_latest");
    ScopeReportRetentionSource {
        source_report_id: row.get("source_report_uuid"),
        target_id: row.get("target_uuid"),
        target_name: row.get("target_name"),
        task_id: row.get("task_uuid"),
        task_name: row.get("task_name"),
        scan_start: unix_ts_to_rfc3339(row.get("scan_start")),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        selected_time: unix_ts_to_rfc3339(row.get("selected_time")),
        result_count: row.get("result_count"),
        vulnerability_count: row.get("vulnerability_count"),
        max_severity: row.get("max_severity"),
        retention_state: if kept_as_latest {
            "current_full_fidelity".to_string()
        } else {
            "future_tiered_retention_candidate".to_string()
        },
        detail_compacted: false,
        aggregate_only: false,
        kept_as_latest,
        pinned_by_scope_report: true,
        future_tiered_retention_candidate: !kept_as_latest,
    }
}
