// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    formatters::unix_ts_to_rfc3339,
    nvt_payloads::{NvtEpssItem, nvt_epss_from_row, nvt_max_severity_from_row},
    report_payloads::{ReportReference, report_reference},
    row_helpers::{optional_row_string, optional_row_strings},
    user_tags::ReportUserTag,
};

#[derive(Debug, Serialize)]
struct ResultOverrideNvtReference {
    id: String,
    name: String,
    #[serde(rename = "type")]
    nvt_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResultOverrideItem {
    id: String,
    nvt: ResultOverrideNvtReference,
    text: String,
    text_excerpt: bool,
    hosts: String,
    port: String,
    severity: Option<f64>,
    new_severity: Option<f64>,
    active: bool,
    end_time: Option<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResultItem {
    id: String,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_asset_id: Option<String>,
    hostname: Option<String>,
    port: String,
    nvt_oid: String,
    name: String,
    nvt_family: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cves: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cert_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    description_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution: Option<String>,
    severity: f64,
    qod: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_nvt_version: Option<String>,
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<ReportReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ReportReference>,
    source_report_id: String,
    raw_evidence_href: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) overrides: Vec<ResultOverrideItem>,
}

pub(crate) fn result_from_row(row: &Row) -> ResultItem {
    let id: String = row.get("id");
    let source_report_id: String = row.get("source_report_id");
    ResultItem {
        raw_evidence_href: format!("/result/{id}"),
        id,
        host: row.get("host"),
        host_asset_id: optional_row_string(row, "host_asset_id"),
        hostname: row.get("hostname"),
        port: row.get("port"),
        nvt_oid: row.get("nvt_oid"),
        name: row.get("name"),
        nvt_family: row.get("nvt_family"),
        cves: optional_row_strings(row, "cves"),
        cert_refs: optional_row_strings(row, "cert_refs"),
        xrefs: optional_row_strings(row, "xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        description: optional_row_string(row, "description"),
        description_excerpt: row.get("description_excerpt"),
        summary: optional_row_string(row, "summary"),
        insight: optional_row_string(row, "insight"),
        affected: optional_row_string(row, "affected"),
        impact: optional_row_string(row, "impact"),
        detection: optional_row_string(row, "detection"),
        solution_type: optional_row_string(row, "solution_type"),
        solution: optional_row_string(row, "solution"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        scan_nvt_version: optional_row_string(row, "scan_nvt_version"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        report: report_reference(
            optional_row_string(row, "source_report_id"),
            optional_row_string(row, "source_report_name"),
        ),
        task: report_reference(
            optional_row_string(row, "task_id"),
            optional_row_string(row, "task_name"),
        ),
        source_report_id,
        user_tags: Vec::new(),
        overrides: result_overrides_from_row(row),
    }
}

fn result_overrides_from_row(row: &Row) -> Vec<ResultOverrideItem> {
    let ids = optional_row_strings(row, "override_ids");
    let nvt_ids = optional_row_strings(row, "override_nvt_ids");
    let nvt_names = optional_row_strings(row, "override_nvt_names");
    let nvt_types = optional_row_strings(row, "override_nvt_types");
    let texts = optional_row_strings(row, "override_texts");
    let hosts = optional_row_strings(row, "override_hosts");
    let ports = optional_row_strings(row, "override_ports");
    let severities = row
        .try_get::<_, Vec<Option<f64>>>("override_severities")
        .unwrap_or_default();
    let new_severities = row
        .try_get::<_, Vec<Option<f64>>>("override_new_severities")
        .unwrap_or_default();
    let created_at = row
        .try_get::<_, Vec<i64>>("override_created_at_unix")
        .unwrap_or_default();
    let modified_at = row
        .try_get::<_, Vec<i64>>("override_modified_at_unix")
        .unwrap_or_default();
    let end_times = row
        .try_get::<_, Vec<i64>>("override_end_time_unix")
        .unwrap_or_default();
    let active_ints = row
        .try_get::<_, Vec<i32>>("override_active_ints")
        .unwrap_or_default();

    ids.into_iter()
        .enumerate()
        .map(|(index, id)| ResultOverrideItem {
            id,
            nvt: ResultOverrideNvtReference {
                id: nvt_ids.get(index).cloned().unwrap_or_default(),
                name: nvt_names.get(index).cloned().unwrap_or_default(),
                nvt_type: nvt_types
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| "nvt".to_string()),
            },
            text: texts.get(index).cloned().unwrap_or_default(),
            text_excerpt: false,
            hosts: hosts.get(index).cloned().unwrap_or_default(),
            port: ports.get(index).cloned().unwrap_or_default(),
            severity: severities.get(index).copied().unwrap_or(None),
            new_severity: new_severities.get(index).copied().unwrap_or(None),
            active: active_ints.get(index).copied().unwrap_or_default() != 0,
            end_time: unix_ts_to_rfc3339(end_times.get(index).copied().unwrap_or_default()),
            created_at: unix_ts_to_rfc3339(created_at.get(index).copied().unwrap_or_default()),
            modified_at: unix_ts_to_rfc3339(modified_at.get(index).copied().unwrap_or_default()),
        })
        .collect()
}

pub(crate) fn result_override_from_row(row: &Row) -> ResultOverrideItem {
    ResultOverrideItem {
        id: row.get("id"),
        nvt: ResultOverrideNvtReference {
            id: row.get("nvt_id"),
            name: row.get("nvt_name"),
            nvt_type: row.get("nvt_type"),
        },
        text: row.get("text"),
        text_excerpt: false,
        hosts: row.get("hosts"),
        port: row.get("port"),
        severity: row.get("severity"),
        new_severity: row.get("new_severity"),
        active: row.get::<_, i32>("active_int") != 0,
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
