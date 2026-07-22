// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Serialize)]
pub(crate) struct HostIdentifierItem {
    id: String,
    name: String,
    value: String,
    source_type: String,
    source_id: String,
    source_data: String,
}

#[derive(Serialize)]
pub(crate) struct HostAssetItem {
    id: String,
    name: String,
    comment: String,
    hostname: Option<String>,
    ip: Option<String>,
    best_os_cpe: Option<String>,
    best_os_txt: Option<String>,
    severity: f64,
    identifiers: Vec<HostIdentifierItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct HostAssetDetailIdentifier {
    id: String,
    name: String,
    value: String,
    source_type: String,
    source_id: String,
    source_data: String,
    source_data_truncated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct HostAssetOperatingSystemItem {
    id: String,
    name: String,
    comment: String,
    operating_system_id: String,
    operating_system_name: String,
    title: String,
    source_type: String,
    source_id: String,
    source_data: String,
    source_data_truncated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct HostAssetDetailItem {
    name: String,
    value: String,
    value_truncated: bool,
    source_type: String,
    source_id: String,
    detail_source_type: String,
    detail_source_name: String,
    detail_source_description: String,
    detail_source_description_truncated: bool,
}

#[derive(Serialize)]
pub(crate) struct HostAssetDetail {
    pub(crate) asset: HostAssetItem,
    pub(crate) identifiers: Vec<HostAssetDetailIdentifier>,
    pub(crate) operating_systems: Vec<HostAssetOperatingSystemItem>,
    pub(crate) details: Vec<HostAssetDetailItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

fn host_identifier_from_row(
    row: &Row,
    id_field: &str,
    name: &str,
    value: Option<String>,
    source_type_field: &str,
    source_id_field: &str,
    source_data_field: &str,
) -> Option<HostIdentifierItem> {
    let id: Option<String> = row.get(id_field);
    let value = value?;
    id.map(|id| HostIdentifierItem {
        id,
        name: name.to_string(),
        value,
        source_type: row
            .get::<_, Option<String>>(source_type_field)
            .unwrap_or_default(),
        source_id: row
            .get::<_, Option<String>>(source_id_field)
            .unwrap_or_default(),
        source_data: row
            .get::<_, Option<String>>(source_data_field)
            .unwrap_or_default(),
    })
}

pub(crate) fn host_asset_from_row(row: &Row) -> HostAssetItem {
    let hostname: Option<String> = row.get("hostname");
    let ip: Option<String> = row.get("ip");
    let hostname_identifier_name: Option<String> = row.get("hostname_identifier_name");
    let mut identifiers = Vec::new();
    if let Some(identifier) = host_identifier_from_row(
        row,
        "ip_identifier_id",
        "ip",
        ip.clone(),
        "ip_source_type",
        "ip_source_id",
        "ip_source_data",
    ) {
        identifiers.push(identifier);
    }
    if let Some(identifier) = host_identifier_from_row(
        row,
        "hostname_identifier_id",
        hostname_identifier_name.as_deref().unwrap_or("hostname"),
        hostname.clone(),
        "hostname_source_type",
        "hostname_source_id",
        "hostname_source_data",
    ) {
        identifiers.push(identifier);
    }
    HostAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        hostname,
        ip,
        best_os_cpe: row.get("best_os_cpe"),
        best_os_txt: row.get("best_os_txt"),
        severity: row.get("severity"),
        identifiers,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn host_asset_detail_identifier_from_row(row: &Row) -> HostAssetDetailIdentifier {
    HostAssetDetailIdentifier {
        id: row.get("id"),
        name: row.get("name"),
        value: row.get("value"),
        source_type: row.get("source_type"),
        source_id: row.get("source_id"),
        source_data: row.get("source_data"),
        source_data_truncated: row.get("source_data_truncated"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn host_asset_operating_system_from_row(row: &Row) -> HostAssetOperatingSystemItem {
    HostAssetOperatingSystemItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        operating_system_id: row.get("operating_system_id"),
        operating_system_name: row.get("operating_system_name"),
        title: row.get("title"),
        source_type: row.get("source_type"),
        source_id: row.get("source_id"),
        source_data: row.get("source_data"),
        source_data_truncated: row.get("source_data_truncated"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn host_asset_detail_item_from_row(row: &Row) -> HostAssetDetailItem {
    HostAssetDetailItem {
        name: row.get("name"),
        value: row.get("value"),
        value_truncated: row.get("value_truncated"),
        source_type: row.get("source_type"),
        source_id: row.get("source_id"),
        detail_source_type: row.get("detail_source_type"),
        detail_source_name: row.get("detail_source_name"),
        detail_source_description: row.get("detail_source_description"),
        detail_source_description_truncated: row.get("detail_source_description_truncated"),
    }
}
