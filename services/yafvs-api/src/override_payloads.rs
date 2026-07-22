// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::unix_ts_to_rfc3339;

#[derive(Serialize)]
struct OverrideOwner {
    name: String,
}

#[derive(Serialize)]
struct OverrideNvtReference {
    id: String,
    name: String,
    #[serde(rename = "type")]
    nvt_type: String,
}

#[derive(Serialize)]
struct OverrideTaskReference {
    id: String,
    name: String,
    trash: bool,
}

#[derive(Serialize)]
struct OverrideReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct OverrideAssetItem {
    id: String,
    owner: OverrideOwner,
    nvt: OverrideNvtReference,
    text: String,
    text_excerpt: bool,
    hosts: String,
    port: String,
    severity: Option<f64>,
    new_severity: Option<f64>,
    writable: bool,
    in_use: bool,
    orphan: bool,
    active: bool,
    end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<OverrideTaskReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<OverrideReference>,
    permissions: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn override_asset_from_row(row: &Row) -> OverrideAssetItem {
    let task_id: Option<String> = row.get("task_id");
    let task = task_id.map(|id| OverrideTaskReference {
        name: row
            .get::<_, Option<String>>("task_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        trash: false,
        id,
    });
    let result_id: Option<String> = row.get("result_id");
    let result = result_id.map(|id| OverrideReference {
        name: row
            .get::<_, Option<String>>("result_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        id,
    });

    OverrideAssetItem {
        id: row.get("id"),
        owner: OverrideOwner {
            name: row.get("owner_name"),
        },
        nvt: OverrideNvtReference {
            id: row.get("nvt_id"),
            name: row.get("nvt_name"),
            nvt_type: row.get("nvt_type"),
        },
        text: row.get("text"),
        text_excerpt: false,
        hosts: row.get("hosts"),
        port: row.get("port"),
        severity: row.get("severity"),
        new_severity: row.get("new_severity"),
        writable: true,
        in_use: false,
        orphan: row.get::<_, i32>("orphan_int") != 0,
        active: row.get::<_, i32>("active_int") != 0,
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        task,
        result,
        permissions: vec![
            "get_overrides".to_string(),
            "modify_override".to_string(),
            "delete_override".to_string(),
            "create_override".to_string(),
        ],
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
