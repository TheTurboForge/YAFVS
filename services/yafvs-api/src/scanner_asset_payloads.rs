// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Serialize)]
struct ScannerAssetCredential {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct ScannerAssetItem {
    id: String,
    name: String,
    comment: String,
    host: String,
    port: i64,
    scanner_type: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ca_pub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<ScannerAssetCredential>,
    relay_host: Option<String>,
    relay_port: i64,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ScannerTaskReference {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) usage_type: String,
}

#[derive(Serialize)]
pub(crate) struct ScannerAssetDetail {
    #[serde(flatten)]
    pub(crate) asset: ScannerAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tasks: Vec<ScannerTaskReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) fn scanner_asset_from_row(row: &Row) -> ScannerAssetItem {
    let credential_id: Option<String> = row.get("credential_id");
    let credential_name: Option<String> = row.get("credential_name");
    ScannerAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        host: row.get("host"),
        port: row.get("port"),
        scanner_type: row.get("scanner_type"),
        ca_pub: row.get("ca_pub"),
        credential: credential_id.map(|id| ScannerAssetCredential {
            id,
            name: credential_name.unwrap_or_default(),
        }),
        relay_host: row.get("relay_host"),
        relay_port: row.get("relay_port"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
