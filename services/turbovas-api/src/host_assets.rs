// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{HOST_ASSET_DEFAULT_SORT, HOST_ASSET_SORT_FIELDS},
    errors::ApiError,
    host_asset_payloads::{
        HostAssetDetail, HostAssetItem, host_asset_detail_identifier_from_row,
        host_asset_detail_item_from_row, host_asset_from_row, host_asset_operating_system_from_row,
    },
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

pub(crate) async fn host_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<HostAssetDetail>, ApiError> {
    host_asset_detail(state, path).await
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
