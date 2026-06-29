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
    collections::{HOST_ASSET_DEFAULT_SORT, HOST_ASSET_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn host_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<HostAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, HOST_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, HOST_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH latest_ip AS (
             SELECT DISTINCT ON (host)
                    host, uuid, value, source_type, source_id, source_data
               FROM host_identifiers
              WHERE name = 'ip'
              ORDER BY host, modification_time DESC, id DESC
         ),
         latest_hostname AS (
             SELECT DISTINCT ON (host)
                    host, name, uuid, value, source_type, source_id, source_data
               FROM host_identifiers
              WHERE name IN ('hostname', 'DNS-via-TargetDefinition')
              ORDER BY host,
                       CASE WHEN name = 'hostname' THEN 0 ELSE 1 END,
                       modification_time DESC,
                       id DESC
         ),
         latest_best_os_cpe AS (
             SELECT DISTINCT ON (host) host, value
               FROM host_details
              WHERE name = 'best_os_cpe'
              ORDER BY host, id DESC
         ),
         latest_best_os_txt AS (
             SELECT DISTINCT ON (host) host, value
               FROM host_details
              WHERE name = 'best_os_txt'
              ORDER BY host, id DESC
         ),
         latest_severity AS (
             SELECT DISTINCT ON (host)
                    host,
                    round(CAST(severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities
              ORDER BY host, creation_time DESC, id DESC
         ),
         host_rows AS (
             SELECT h.uuid AS id,
                    coalesce(h.name, '') AS name,
                    coalesce(h.comment, '') AS comment,
                    nullif(lh.value, '') AS hostname,
                    nullif(li.value, '') AS ip,
                    nullif(lbo.value, '') AS best_os_cpe,
                    nullif(lbt.value, '') AS best_os_txt,
                    coalesce(ls.severity, 0)::double precision AS severity,
                    coalesce(h.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(h.modification_time, 0)::bigint AS modified_at_unix,
                    li.uuid AS ip_identifier_id,
                    li.source_type AS ip_source_type,
                    li.source_id AS ip_source_id,
                    left(coalesce(li.source_data, ''), 512) AS ip_source_data,
                    lh.name AS hostname_identifier_name,
                    lh.uuid AS hostname_identifier_id,
                    lh.source_type AS hostname_source_type,
                    lh.source_id AS hostname_source_id,
                    left(coalesce(lh.source_data, ''), 512) AS hostname_source_data
               FROM hosts h
               LEFT JOIN latest_ip li ON li.host = h.id
               LEFT JOIN latest_hostname lh ON lh.host = h.id
               LEFT JOIN latest_best_os_cpe lbo ON lbo.host = h.id
               LEFT JOIN latest_best_os_txt lbt ON lbt.host = h.id
               LEFT JOIN latest_severity ls ON ls.host = h.id
         ),
         filtered AS (
             SELECT * FROM host_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(ip, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(best_os_cpe, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(best_os_txt, '')) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "host asset list")
            .await?;
    let items = rows.iter().map(host_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn host_asset_detail(
    State(state): State<AppState>,
    Path(host_id): Path<String>,
) -> Result<Json<HostAssetDetail>, ApiError> {
    parse_uuid(&host_id)?;
    let host_id = host_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"WITH latest_ip AS (
                 SELECT DISTINCT ON (host)
                        host, uuid, value, source_type, source_id, source_data
                   FROM host_identifiers
                  WHERE name = 'ip'
                  ORDER BY host, modification_time DESC, id DESC
             ),
             latest_hostname AS (
                 SELECT DISTINCT ON (host)
                        host, name, uuid, value, source_type, source_id, source_data
                   FROM host_identifiers
                  WHERE name IN ('hostname', 'DNS-via-TargetDefinition')
                  ORDER BY host,
                           CASE WHEN name = 'hostname' THEN 0 ELSE 1 END,
                           modification_time DESC,
                           id DESC
             ),
             latest_best_os_cpe AS (
                 SELECT DISTINCT ON (host) host, value
                   FROM host_details
                  WHERE name = 'best_os_cpe'
                  ORDER BY host, id DESC
             ),
             latest_best_os_txt AS (
                 SELECT DISTINCT ON (host) host, value
                   FROM host_details
                  WHERE name = 'best_os_txt'
                  ORDER BY host, id DESC
             ),
             latest_severity AS (
                 SELECT DISTINCT ON (host)
                        host,
                        round(CAST(severity AS numeric), 1)::double precision AS severity
                   FROM host_max_severities
                  ORDER BY host, creation_time DESC, id DESC
             )
             SELECT h.uuid AS id,
                    coalesce(h.name, '') AS name,
                    coalesce(h.comment, '') AS comment,
                    nullif(lh.value, '') AS hostname,
                    nullif(li.value, '') AS ip,
                    nullif(lbo.value, '') AS best_os_cpe,
                    nullif(lbt.value, '') AS best_os_txt,
                    coalesce(ls.severity, 0)::double precision AS severity,
                    coalesce(h.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(h.modification_time, 0)::bigint AS modified_at_unix,
                    li.uuid AS ip_identifier_id,
                    li.source_type AS ip_source_type,
                    li.source_id AS ip_source_id,
                    li.source_data AS ip_source_data,
                    lh.name AS hostname_identifier_name,
                    lh.uuid AS hostname_identifier_id,
                    lh.source_type AS hostname_source_type,
                    lh.source_id AS hostname_source_id,
                    lh.source_data AS hostname_source_data
               FROM hosts h
               LEFT JOIN latest_ip li ON li.host = h.id
               LEFT JOIN latest_hostname lh ON lh.host = h.id
               LEFT JOIN latest_best_os_cpe lbo ON lbo.host = h.id
               LEFT JOIN latest_best_os_txt lbt ON lbt.host = h.id
               LEFT JOIN latest_severity ls ON ls.host = h.id
              WHERE h.uuid = $1
              LIMIT 1;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let identifier_rows = client
        .query(
            r#"SELECT hi.uuid AS id,
                    coalesce(hi.name, '') AS name,
                    coalesce(hi.value, '') AS value,
                    coalesce(hi.source_type, '') AS source_type,
                    coalesce(hi.source_id, '') AS source_id,
                    left(coalesce(hi.source_data, ''), 512) AS source_data,
                    (length(coalesce(hi.source_data, '')) > 512) AS source_data_truncated,
                    coalesce(hi.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(hi.modification_time, 0)::bigint AS modified_at_unix
               FROM hosts h
               JOIN host_identifiers hi ON hi.host = h.id
              WHERE h.uuid = $1
                AND hi.name IN ('ip', 'hostname', 'DNS-via-TargetDefinition', 'MAC', 'OS')
              ORDER BY CASE hi.name
                         WHEN 'ip' THEN 0
                         WHEN 'hostname' THEN 1
                         WHEN 'DNS-via-TargetDefinition' THEN 2
                         WHEN 'MAC' THEN 3
                         WHEN 'OS' THEN 4
                         ELSE 5
                       END,
                       hi.modification_time DESC NULLS LAST,
                       hi.id DESC;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset identifier detail query failed");
            ApiError::Database
        })?;
    let operating_system_rows = client
        .query(
            r#"SELECT ho.uuid AS id,
                    coalesce(ho.name, '') AS name,
                    coalesce(ho.comment, '') AS comment,
                    oss.uuid AS operating_system_id,
                    oss.name AS operating_system_name,
                    coalesce(cpe_title(oss.name), '') AS title,
                    coalesce(ho.source_type, '') AS source_type,
                    coalesce(ho.source_id, '') AS source_id,
                    left(coalesce(ho.source_data, ''), 512) AS source_data,
                    (length(coalesce(ho.source_data, '')) > 512) AS source_data_truncated,
                    coalesce(ho.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(ho.modification_time, 0)::bigint AS modified_at_unix
               FROM hosts h
               JOIN host_oss ho ON ho.host = h.id
               JOIN oss ON oss.id = ho.os
              WHERE h.uuid = $1
              ORDER BY ho.modification_time DESC NULLS LAST, ho.id DESC;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset operating-system detail query failed");
            ApiError::Database
        })?;
    let detail_rows = client
        .query(
            r#"WITH latest_details AS (
                 SELECT DISTINCT ON (hd.name)
                        coalesce(hd.name, '') AS name,
                        left(coalesce(hd.value, ''), 4096) AS value,
                        (length(coalesce(hd.value, '')) > 4096) AS value_truncated,
                        coalesce(hd.source_type, '') AS source_type,
                        coalesce(hd.source_id, '') AS source_id,
                        coalesce(hd.detail_source_type, '') AS detail_source_type,
                        coalesce(hd.detail_source_name, '') AS detail_source_name,
                        left(coalesce(hd.detail_source_description, ''), 1024) AS detail_source_description,
                        (length(coalesce(hd.detail_source_description, '')) > 1024) AS detail_source_description_truncated
                   FROM hosts h
                   JOIN host_details hd ON hd.host = h.id
                  WHERE h.uuid = $1
                    AND hd.name IN ('best_os_cpe', 'best_os_txt', 'traceroute')
                  ORDER BY hd.name, hd.id DESC
             )
             SELECT * FROM latest_details
              ORDER BY CASE name
                         WHEN 'best_os_cpe' THEN 0
                         WHEN 'best_os_txt' THEN 1
                         WHEN 'traceroute' THEN 2
                         ELSE 3
                       END;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset safe detail query failed");
            ApiError::Database
        })?;
    let user_tags = host_user_tags(&client, &host_id).await?;
    Ok(Json(HostAssetDetail {
        asset: host_asset_from_row(&row),
        identifiers: identifier_rows
            .iter()
            .map(host_asset_detail_identifier_from_row)
            .collect(),
        operating_systems: operating_system_rows
            .iter()
            .map(host_asset_operating_system_from_row)
            .collect(),
        details: detail_rows
            .iter()
            .map(host_asset_detail_item_from_row)
            .collect(),
        user_tags,
    }))
}

pub(crate) fn host_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN hosts ON hosts.id = tr.resource
        WHERE lower(hosts.uuid) = lower($1)
          AND tr.resource_type = 'host'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn host_user_tags(
    client: &tokio_postgres::Client,
    host_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(host_user_tags_sql(), &[&host_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host user-tag query failed");
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
