// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

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
pub(crate) struct CatalogCveReference {
    pub(crate) url: String,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveMatchedCpe {
    #[serde(rename = "_id")]
    pub(crate) id: String,
    pub(crate) deprecated: i32,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveMatchedCpes {
    pub(crate) cpe: Vec<CatalogCveMatchedCpe>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveMatchString {
    pub(crate) criteria: String,
    pub(crate) vulnerable: i32,
    pub(crate) status: String,
    pub(crate) version_start_including: String,
    pub(crate) version_start_excluding: String,
    pub(crate) version_end_including: String,
    pub(crate) version_end_excluding: String,
    pub(crate) matched_cpes: CatalogCveMatchedCpes,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveConfigurationNode {
    pub(crate) operator: String,
    pub(crate) negate: i32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) match_string: Vec<CatalogCveMatchString>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) node: Vec<CatalogCveConfigurationNode>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveConfigurationNodes {
    pub(crate) node: Vec<CatalogCveConfigurationNode>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) references: Vec<CatalogCveReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) configuration_nodes: Option<CatalogCveConfigurationNodes>,
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
        references: Vec::new(),
        configuration_nodes: None,
        epss: epss_score
            .zip(epss_percentile)
            .map(|(score, percentile)| CatalogEpssItem { score, percentile }),
        published_at: unix_ts_to_rfc3339(row.get("published_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
