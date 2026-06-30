// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Debug, Serialize)]
pub(crate) struct DfnCertAdvisoryItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    summary: String,
    severity: f64,
    cve_refs: i64,
    cves: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DfnCertAdvisoryDetail {
    #[serde(flatten)]
    pub(crate) item: DfnCertAdvisoryItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertBundAdvisoryItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    summary: String,
    severity: f64,
    cve_refs: i64,
    cves: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertBundAdvisoryDetail {
    #[serde(flatten)]
    pub(crate) item: CertBundAdvisoryItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) fn dfn_cert_advisory_from_row(row: &Row) -> DfnCertAdvisoryItem {
    DfnCertAdvisoryItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        summary: row.get("summary"),
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn cert_bund_advisory_from_row(row: &Row) -> CertBundAdvisoryItem {
    CertBundAdvisoryItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        summary: row.get("summary"),
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
