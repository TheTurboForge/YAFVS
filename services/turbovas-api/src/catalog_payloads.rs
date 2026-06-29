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
struct CatalogEpssItem {
    score: f64,
    percentile: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveCertReference {
    pub(crate) name: String,
    pub(crate) title: String,
    #[serde(rename = "type")]
    pub(crate) cert_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveNvtReference {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveItem {
    id: String,
    name: String,
    comment: String,
    description: String,
    cvss_base_vector: String,
    severity: f64,
    products: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) cert_refs: Vec<CatalogCveCertReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) nvt_refs: Vec<CatalogCveNvtReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss: Option<CatalogEpssItem>,
    published_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveDetail {
    #[serde(flatten)]
    pub(crate) item: CatalogCveItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeCveItem {
    id: String,
    severity: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    cpe_name_id: String,
    deprecated: bool,
    deprecated_by: Option<String>,
    severity: f64,
    cve_refs: i64,
    cves: Vec<CatalogCpeCveItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeDetail {
    #[serde(flatten)]
    pub(crate) item: CatalogCpeItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NvtCatalogItem {
    id: String,
    oid: String,
    name: String,
    family: String,
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
    summary: String,
    insight: String,
    affected: String,
    impact: String,
    detection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

fn split_catalog_products(value: String) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|product| !product.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn catalog_cve_from_row(row: &Row) -> CatalogCveItem {
    let epss_score: Option<f64> = row.get("epss_score");
    let epss_percentile: Option<f64> = row.get("epss_percentile");
    CatalogCveItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        description: row.get("description"),
        cvss_base_vector: row.get("cvss_base_vector"),
        severity: row.get("severity"),
        products: split_catalog_products(row.get("products")),
        cert_refs: Vec::new(),
        nvt_refs: Vec::new(),
        epss: epss_score
            .zip(epss_percentile)
            .map(|(score, percentile)| CatalogEpssItem { score, percentile }),
        published_at: unix_ts_to_rfc3339(row.get("published_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn catalog_cpe_cve_from_row(row: &Row) -> CatalogCpeCveItem {
    CatalogCpeCveItem {
        id: row.get("id"),
        severity: row.get("severity"),
    }
}

pub(crate) fn catalog_cpe_from_row(
    row: &Row,
    cves: Vec<CatalogCpeCveItem>,
    deprecated_by: Option<String>,
) -> CatalogCpeItem {
    let deprecated_int: i32 = row.get("deprecated_int");
    CatalogCpeItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        cpe_name_id: row.get("cpe_name_id"),
        deprecated: deprecated_int != 0,
        deprecated_by,
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn nvt_catalog_from_row(row: &Row) -> NvtCatalogItem {
    NvtCatalogItem {
        id: row.get("id"),
        oid: row.get("oid"),
        name: row.get("name"),
        family: row.get("family"),
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
    user_tags: Vec<ReportUserTag>,
) -> NvtCatalogDetail {
    NvtCatalogDetail {
        catalog: nvt_catalog_from_row(row),
        comment: row.get("comment"),
        summary: row.get("summary"),
        insight: row.get("insight"),
        affected: row.get("affected"),
        impact: row.get("impact"),
        detection: row.get("detection"),
        user_tags,
    }
}
