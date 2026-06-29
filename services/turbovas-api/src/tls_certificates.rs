// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    collections::{TLS_CERTIFICATE_ASSET_DEFAULT_SORT, TLS_CERTIFICATE_ASSET_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    row_helpers::{boolean_int, optional_row_string},
    user_tags::ReportUserTag,
};

pub(crate) async fn tls_certificate_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, TLS_CERTIFICATE_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TLS_CERTIFICATE_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH tls_rows AS (
             SELECT c.uuid AS id,
                    coalesce(nullif(c.subject_dn, ''), c.uuid) AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.subject_dn, '') AS subject_dn,
                    coalesce(c.issuer_dn, '') AS issuer_dn,
                    coalesce(c.serial, '') AS serial,
                    coalesce(c.md5_fingerprint, '') AS md5_fingerprint,
                    coalesce(c.sha256_fingerprint, '') AS sha256_fingerprint,
                    coalesce(c.activation_time, 0)::bigint AS activation_time_unix,
                    coalesce(c.expiration_time, 0)::bigint AS expiration_time_unix,
                    coalesce(max(src.timestamp), 0)::bigint AS last_seen_unix,
                    count(DISTINCT lower(loc.host_ip))::bigint AS source_host_count,
                    count(DISTINCT loc.port)::bigint AS source_port_count,
                    count(DISTINCT src.uuid)::bigint AS source_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM tls_certificates c
               LEFT JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
              GROUP BY c.id, c.uuid, c.subject_dn, c.comment, c.issuer_dn,
                       c.serial, c.md5_fingerprint, c.sha256_fingerprint,
                       c.activation_time, c.expiration_time,
                       c.creation_time, c.modification_time
         ),
         filtered AS (
             SELECT * FROM tls_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(subject_dn) LIKE '%' || lower($1) || '%'
                     OR lower(issuer_dn) LIKE '%' || lower($1) || '%'
                     OR lower(serial) LIKE '%' || lower($1) || '%'
                     OR lower(md5_fingerprint) LIKE '%' || lower($1) || '%'
                     OR lower(sha256_fingerprint) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, subject_dn ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tls_certificate_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn tls_certificate_asset_detail(
    State(state): State<AppState>,
    Path(certificate_id): Path<String>,
) -> Result<Json<TlsCertificateAssetDetail>, ApiError> {
    parse_uuid(&certificate_id)?;
    let certificate_id = certificate_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.uuid AS id,
                    coalesce(nullif(c.subject_dn, ''), c.uuid) AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.subject_dn, '') AS subject_dn,
                    coalesce(c.issuer_dn, '') AS issuer_dn,
                    coalesce(c.serial, '') AS serial,
                    coalesce(c.md5_fingerprint, '') AS md5_fingerprint,
                    coalesce(c.sha256_fingerprint, '') AS sha256_fingerprint,
                    coalesce(c.activation_time, 0)::bigint AS activation_time_unix,
                    coalesce(c.expiration_time, 0)::bigint AS expiration_time_unix,
                    CAST (((coalesce(c.expiration_time, 0) >= m_now()
                             OR coalesce(c.expiration_time, 0) = -1)
                            AND (coalesce(c.activation_time, 0) <= m_now()
                                 OR coalesce(c.activation_time, 0) = -1)) AS integer) AS valid_int,
                    coalesce(c.trust, 0)::integer AS trust_int,
                    (CASE WHEN (coalesce(c.activation_time, 0) = -1)
                                OR (coalesce(c.expiration_time, 0) = 1)
                          THEN 'unknown'
                          WHEN (coalesce(c.expiration_time, 0) < m_now()
                                AND coalesce(c.expiration_time, 0) != 0)
                          THEN 'expired'
                          WHEN (coalesce(c.activation_time, 0) > m_now())
                          THEN 'inactive'
                          ELSE 'valid' END) AS time_status,
                    coalesce(max(src.timestamp), 0)::bigint AS last_seen_unix,
                    count(DISTINCT lower(loc.host_ip))::bigint AS source_host_count,
                    count(DISTINCT loc.port)::bigint AS source_port_count,
                    count(DISTINCT src.uuid)::bigint AS source_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM tls_certificates c
               LEFT JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
              WHERE c.uuid = $1
              GROUP BY c.id, c.uuid, c.subject_dn, c.comment, c.issuer_dn,
                       c.serial, c.md5_fingerprint, c.sha256_fingerprint,
                       c.activation_time, c.expiration_time,
                       c.creation_time, c.modification_time
              LIMIT 1;"#,
            &[&certificate_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let source_rows = client
        .query(
            r#"SELECT src.uuid AS id,
                    coalesce(src.timestamp, 0)::bigint AS timestamp_unix,
                    coalesce(src.tls_versions, '') AS tls_versions,
                    loc.uuid AS location_id,
                    coalesce(loc.host_ip, '') AS location_host_ip,
                    coalesce(loc.port, '') AS location_port,
                    host_asset.uuid AS host_asset_id,
                    origin.uuid AS origin_uuid,
                    coalesce(origin.origin_type, '') AS origin_type,
                    coalesce(origin.origin_id, '') AS origin_resource_id,
                    coalesce(origin.origin_data, '') AS origin_data
               FROM tls_certificates c
               JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
               LEFT JOIN tls_certificate_origins origin ON origin.id = src.origin
               LEFT JOIN LATERAL (
                    SELECT h.uuid
                      FROM host_identifiers hi
                      JOIN hosts h ON h.id = hi.host
                     WHERE hi.name = 'ip'
                       AND hi.value = loc.host_ip
                       AND hi.source_id = origin.origin_id
                     ORDER BY hi.modification_time DESC NULLS LAST, hi.id DESC
                     LIMIT 1
               ) host_asset ON true
              WHERE c.uuid = $1
              ORDER BY src.timestamp DESC NULLS LAST, src.uuid ASC;"#,
            &[&certificate_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset source query failed");
            ApiError::Database
        })?;
    let user_tags = tls_certificate_user_tags(&client, &certificate_id).await?;
    Ok(Json(TlsCertificateAssetDetail {
        asset: tls_certificate_asset_from_row(&row),
        sources: source_rows
            .iter()
            .map(tls_certificate_source_from_row)
            .collect(),
        user_tags,
    }))
}

pub(crate) fn tls_certificate_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN tls_certificates ON tls_certificates.id = tr.resource
        WHERE lower(tls_certificates.uuid) = lower($1)
          AND tr.resource_type = 'tls_certificate'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn tls_certificate_user_tags(
    client: &tokio_postgres::Client,
    certificate_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(tls_certificate_user_tags_sql(), &[&certificate_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

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
