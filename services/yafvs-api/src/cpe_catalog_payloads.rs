// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeCveItem {
    id: String,
    severity: f64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct CatalogCpeReference {
    pub(crate) url: String,
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
    pub(crate) references: Vec<CatalogCpeReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
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
