// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Serialize)]
pub(crate) struct PortRangeItem {
    id: String,
    protocol: String,
    start: i64,
    end: i64,
    comment: String,
}

#[derive(Serialize)]
struct PortCountItem {
    all: i64,
    tcp: i64,
    udp: i64,
}

#[derive(Serialize)]
pub(crate) struct PortListTargetReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct PortListAssetItem {
    id: String,
    name: String,
    comment: String,
    port_count: PortCountItem,
    port_ranges: Vec<PortRangeItem>,
    targets: Vec<PortListTargetReference>,
    predefined: bool,
    deprecated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct PortListAssetDetail {
    #[serde(flatten)]
    asset: PortListAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

pub(crate) fn port_range_from_row(row: &Row) -> PortRangeItem {
    PortRangeItem {
        id: row.get("id"),
        protocol: row.get("protocol"),
        start: row.get("start"),
        end: row.get("end"),
        comment: row.get("comment"),
    }
}

pub(crate) fn port_list_target_from_row(row: &Row) -> PortListTargetReference {
    PortListTargetReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

pub(crate) fn port_list_asset_from_row(
    row: &Row,
    port_ranges: Vec<PortRangeItem>,
    targets: Vec<PortListTargetReference>,
) -> PortListAssetItem {
    PortListAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        port_count: PortCountItem {
            all: row.get("port_count_all"),
            tcp: row.get("port_count_tcp"),
            udp: row.get("port_count_udp"),
        },
        port_ranges,
        targets,
        predefined: row.get::<_, i32>("predefined_int") != 0,
        deprecated: row.get::<_, i32>("deprecated_int") != 0,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn port_list_asset_detail_payload(
    asset: PortListAssetItem,
    user_tags: Vec<ReportUserTag>,
) -> PortListAssetDetail {
    PortListAssetDetail { asset, user_tags }
}
