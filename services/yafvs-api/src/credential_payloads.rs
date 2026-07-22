// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::unix_ts_to_rfc3339;

#[derive(Debug, Serialize)]
pub(crate) struct CredentialUsageReference {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CredentialAssetItem {
    id: String,
    name: String,
    comment: String,
    owner_id: Option<String>,
    owner: String,
    credential_type: String,
    smb_compatible: bool,
    allow_insecure: bool,
    target_count: i64,
    scanner_count: i64,
    targets: Vec<CredentialUsageReference>,
    scanners: Vec<CredentialUsageReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn credential_usage_reference_from_row(row: &Row) -> CredentialUsageReference {
    CredentialUsageReference {
        id: row.get("id"),
        name: row.get("name"),
        use_type: row.get("use_type"),
        port: row.get("port"),
    }
}

pub(crate) fn credential_asset_from_row(
    row: &Row,
    targets: Vec<CredentialUsageReference>,
    scanners: Vec<CredentialUsageReference>,
) -> CredentialAssetItem {
    CredentialAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner_id: row.get("owner_id"),
        owner: row.get("owner_name"),
        credential_type: row.get("credential_type"),
        smb_compatible: row.get("smb_compatible"),
        allow_insecure: row.get::<_, i32>("allow_insecure_int") != 0,
        target_count: row.get("target_count"),
        scanner_count: row.get("scanner_count"),
        targets,
        scanners,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
