// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    formatters::unix_ts_to_rfc3339,
    row_helpers::{boolean_int, optional_row_string},
    user_tags::ReportUserTag,
};

#[derive(Serialize)]
struct TlsCertificateSourceLocation {
    id: String,
    host_ip: String,
    port: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_asset_id: Option<String>,
}

#[derive(Serialize)]
struct TlsCertificateSourceOrigin {
    id: String,
    origin_type: String,
    origin_id: String,
    origin_data: String,
}

#[derive(Serialize)]
pub(crate) struct TlsCertificateSourceItem {
    id: String,
    timestamp: Option<String>,
    tls_versions: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<TlsCertificateSourceLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<TlsCertificateSourceOrigin>,
}

#[derive(Serialize)]
pub(crate) struct TlsCertificateAssetItem {
    id: String,
    name: String,
    comment: String,
    subject_dn: String,
    issuer_dn: String,
    serial: String,
    md5_fingerprint: String,
    sha256_fingerprint: String,
    activation_time: Option<String>,
    expiration_time: Option<String>,
    last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_status: Option<String>,
    source_host_count: i64,
    source_port_count: i64,
    source_count: i64,
    in_use: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct TlsCertificateAssetDetail {
    #[serde(flatten)]
    pub(crate) asset: TlsCertificateAssetItem,
    pub(crate) sources: Vec<TlsCertificateSourceItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
pub(crate) struct TlsCertificatePemPayload {
    pub(crate) id: String,
    pub(crate) certificate: String,
}

pub(crate) fn tls_certificate_asset_from_row(row: &Row) -> TlsCertificateAssetItem {
    let source_count = row.get("source_count");
    TlsCertificateAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        subject_dn: row.get("subject_dn"),
        issuer_dn: row.get("issuer_dn"),
        serial: row.get("serial"),
        md5_fingerprint: row.get("md5_fingerprint"),
        sha256_fingerprint: row.get("sha256_fingerprint"),
        activation_time: unix_ts_to_rfc3339(row.get("activation_time_unix")),
        expiration_time: unix_ts_to_rfc3339(row.get("expiration_time_unix")),
        last_seen: unix_ts_to_rfc3339(row.get("last_seen_unix")),
        valid: row
            .try_get::<_, Option<i32>>("valid_int")
            .ok()
            .flatten()
            .map(boolean_int),
        trust: row
            .try_get::<_, Option<i32>>("trust_int")
            .ok()
            .flatten()
            .map(boolean_int),
        time_status: optional_row_string(row, "time_status"),
        source_host_count: row.get("source_host_count"),
        source_port_count: row.get("source_port_count"),
        source_count,
        in_use: source_count > 0,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn tls_certificate_source_from_row(row: &Row) -> TlsCertificateSourceItem {
    let location_id: Option<String> = row.get("location_id");
    let origin_uuid: Option<String> = row.get("origin_uuid");
    TlsCertificateSourceItem {
        id: row.get("id"),
        timestamp: unix_ts_to_rfc3339(row.get("timestamp_unix")),
        tls_versions: row.get("tls_versions"),
        location: location_id.map(|id| TlsCertificateSourceLocation {
            id,
            host_ip: row
                .get::<_, Option<String>>("location_host_ip")
                .unwrap_or_default(),
            port: row
                .get::<_, Option<String>>("location_port")
                .unwrap_or_default(),
            host_asset_id: row.get("host_asset_id"),
        }),
        origin: origin_uuid.map(|id| TlsCertificateSourceOrigin {
            id,
            origin_type: row
                .get::<_, Option<String>>("origin_type")
                .unwrap_or_default(),
            origin_id: row
                .get::<_, Option<String>>("origin_resource_id")
                .unwrap_or_default(),
            origin_data: row
                .get::<_, Option<String>>("origin_data")
                .unwrap_or_default(),
        }),
    }
}
