// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, query::PageInfo};

#[derive(Serialize)]
pub(crate) struct TagOwner {
    name: String,
}

#[derive(Serialize)]
pub(crate) struct TagResourceCount {
    total: i64,
}

#[derive(Serialize)]
pub(crate) struct TagResourcesSummary {
    #[serde(rename = "type")]
    resource_type: String,
    count: TagResourceCount,
}

#[derive(Serialize)]
pub(crate) struct TagAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: TagOwner,
    resource_type: String,
    resource_count: i64,
    resources: TagResourcesSummary,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    writable: bool,
    in_use: bool,
    orphan: bool,
    trash: bool,
    permissions: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct TagResourceItem {
    id: String,
    #[serde(rename = "type")]
    resource_type: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct TagResourceCollection {
    pub(crate) tag_id: String,
    pub(crate) resource_type: String,
    pub(crate) page: PageInfo,
    pub(crate) items: Vec<TagResourceItem>,
}

pub(crate) fn tag_asset_from_row(row: &Row) -> TagAssetItem {
    let resource_type: String = row.get("resource_type");
    let resource_count: i64 = row.get("resource_count");
    let raw_value: String = row.get("value");
    let value = if raw_value.trim().is_empty() {
        None
    } else {
        Some(raw_value)
    };
    TagAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: TagOwner {
            name: row.get("owner_name"),
        },
        resource_type: resource_type.clone(),
        resource_count,
        resources: TagResourcesSummary {
            resource_type,
            count: TagResourceCount {
                total: resource_count,
            },
        },
        active: row.get::<_, i32>("active_int") != 0,
        value,
        writable: true,
        in_use: false,
        orphan: false,
        trash: false,
        permissions: vec![
            "get_tags".to_string(),
            "modify_tag".to_string(),
            "delete_tag".to_string(),
            "create_tag".to_string(),
        ],
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn tag_resource_from_row(row: &Row) -> TagResourceItem {
    TagResourceItem {
        id: row.get("id"),
        resource_type: row.get("resource_type"),
        name: row.get("name"),
    }
}
