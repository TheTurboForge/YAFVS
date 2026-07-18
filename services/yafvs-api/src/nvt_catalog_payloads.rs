// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    formatters::unix_ts_to_rfc3339,
    nvt_payloads::{NvtEpssItem, nvt_epss_from_row, nvt_max_severity_from_row},
    user_tags::ReportUserTag,
};

#[derive(Debug, Serialize)]
pub(crate) struct NvtCatalogItem {
    id: String,
    oid: String,
    name: String,
    family: String,
    category: String,
    discovery: i64,
    severity: f64,
    qod: i64,
    qod_type: String,
    solution_type: String,
    solution_method: String,
    solution: String,
    tags: String,
    cve_refs: i64,
    cves: Vec<String>,
    cert_refs: Vec<String>,
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NvtCatalogDetail {
    #[serde(flatten)]
    catalog: NvtCatalogItem,
    comment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_timeout: Option<String>,
    summary: String,
    insight: String,
    affected: String,
    impact: String,
    detection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    preferences: Vec<NvtCatalogPreference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NvtCatalogPreference {
    id: i64,
    name: String,
    hr_name: String,
    #[serde(rename = "type")]
    preference_type: String,
    value: String,
    default: String,
}

pub(crate) fn nvt_catalog_from_row(row: &Row) -> NvtCatalogItem {
    NvtCatalogItem {
        id: row.get("id"),
        oid: row.get("oid"),
        name: row.get("name"),
        family: row.get("family"),
        category: row.get("category"),
        discovery: row.get("discovery"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        qod_type: row.get("qod_type"),
        solution_type: row.get("solution_type"),
        solution_method: row.get("solution_method"),
        solution: row.get("solution"),
        tags: row.get("tags"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        cert_refs: row.get("cert_refs"),
        xrefs: row.get("xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn nvt_catalog_detail_from_row(
    row: &Row,
    default_timeout: Option<String>,
    preferences: Vec<NvtCatalogPreference>,
    user_tags: Vec<ReportUserTag>,
) -> NvtCatalogDetail {
    NvtCatalogDetail {
        catalog: nvt_catalog_from_row(row),
        comment: row.get("comment"),
        default_timeout,
        summary: row.get("summary"),
        insight: row.get("insight"),
        affected: row.get("affected"),
        impact: row.get("impact"),
        detection: row.get("detection"),
        preferences,
        user_tags,
    }
}

pub(crate) fn nvt_catalog_preference_from_row(row: &Row) -> NvtCatalogPreference {
    NvtCatalogPreference {
        id: row.get("id"),
        name: row.get("name"),
        hr_name: row.get("hr_name"),
        preference_type: row.get("type"),
        value: row.get("value"),
        default: row.get("default"),
    }
}
