// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rich_detail: Option<DfnCertAdvisoryRichDetail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct DfnCertAdvisoryRichDetail {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) links: Vec<DfnCertLink>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DfnCertLink {
    pub(crate) href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rel: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rich_detail: Option<CertBundAdvisoryRichDetail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct CertBundAdvisoryRichDetail {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) additional_information: Vec<CertBundAdvisoryAdditionalInformation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) categories: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) description: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) effect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reference_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reference_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) remote_attack: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) revision_history: Vec<CertBundAdvisoryRevision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) software: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertBundAdvisoryAdditionalInformation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct CertBundAdvisoryRevision {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) number: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) date: Option<String>,
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
