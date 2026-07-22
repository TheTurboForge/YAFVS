// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Serialize)]
pub(crate) struct OperatingSystemAssetItem {
    id: String,
    name: String,
    title: String,
    latest_severity: Option<f64>,
    highest_severity: Option<f64>,
    average_severity: Option<f64>,
    hosts: i64,
    all_hosts: i64,
    created_at: Option<String>,
    modified_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) fn operating_system_asset_from_row(row: &Row) -> OperatingSystemAssetItem {
    OperatingSystemAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        title: row.get("title"),
        latest_severity: row.get("latest_severity"),
        highest_severity: row.get("highest_severity"),
        average_severity: row.get("average_severity"),
        hosts: row.get("hosts"),
        all_hosts: row.get("all_hosts"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        user_tags: Vec::new(),
    }
}
