// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::unix_ts_to_rfc3339;

#[derive(Serialize)]
struct AlertOwner {
    name: String,
}

#[derive(Serialize)]
pub(crate) struct AlertReference {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Serialize)]
struct AlertTypeLabel {
    #[serde(rename = "type")]
    type_name: String,
}

#[derive(Serialize)]
pub(crate) struct AlertAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: AlertOwner,
    active: bool,
    in_use: bool,
    task_count: i64,
    event: AlertTypeLabel,
    condition: AlertTypeLabel,
    method: AlertTypeLabel,
    method_data_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<AlertReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tasks: Vec<AlertReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn alert_asset_from_row(row: &Row) -> AlertAssetItem {
    let filter_id: Option<String> = row.get("filter_id");
    let filter = filter_id.map(|id| AlertReference {
        name: row
            .get::<_, Option<String>>("filter_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        id,
    });
    let task_count: i64 = row.get("task_count");

    AlertAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: AlertOwner {
            name: row.get("owner_name"),
        },
        active: row.get::<_, i32>("active_int") != 0,
        in_use: task_count > 0,
        task_count,
        event: AlertTypeLabel {
            type_name: row.get("event_type"),
        },
        condition: AlertTypeLabel {
            type_name: row.get("condition_type"),
        },
        method: AlertTypeLabel {
            type_name: row.get("method_type"),
        },
        method_data_redacted: true,
        filter,
        tasks: Vec::new(),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
