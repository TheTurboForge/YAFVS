// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::unix_ts_to_rfc3339;

#[derive(Serialize)]
pub(crate) struct FilterAlertReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct FilterAssetItem {
    id: String,
    name: String,
    comment: String,
    filter_type: String,
    term: String,
    alert_count: i64,
    alerts: Vec<FilterAlertReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn filter_alert_from_row(row: &Row) -> FilterAlertReference {
    FilterAlertReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

pub(crate) fn filter_asset_from_row(
    row: &Row,
    alerts: Vec<FilterAlertReference>,
) -> FilterAssetItem {
    FilterAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        filter_type: row.get("filter_type"),
        term: row.get("term"),
        alert_count: row.get("alert_count"),
        alerts,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
