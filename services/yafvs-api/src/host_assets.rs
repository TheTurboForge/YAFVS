// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::host_user_tags_sql,
    collections::{HOST_ASSET_DEFAULT_SORT, HOST_ASSET_SORT_FIELDS},
    errors::ApiError,
    host_asset_payloads::{
        HostAssetDetail, HostAssetItem, host_asset_detail_identifier_from_row,
        host_asset_detail_item_from_row, host_asset_from_row, host_asset_operating_system_from_row,
    },
    host_asset_query_sql::{
        host_asset_identifiers_sql, host_asset_operating_systems_sql, host_asset_safe_details_sql,
    },
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, normalize_optional_exact_query, sort_clause,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn host_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<HostAssetItem>>, ApiError> {
    let name_filter = normalize_optional_exact_query(query.name.as_deref(), "name")?;
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
                AND ($4 = '' OR lower(name) = lower($4))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &name_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset list query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[
            &params.filter,
            &probe_page_size,
            &probe_offset,
            &name_filter,
        ],
        "host asset list",
    )
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
        .query(host_asset_identifiers_sql(), &[&host_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset identifier detail query failed");
            ApiError::Database
        })?;
    let operating_system_rows = client
        .query(host_asset_operating_systems_sql(), &[&host_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset operating-system detail query failed");
            ApiError::Database
        })?;
    let detail_rows = client
        .query(host_asset_safe_details_sql(), &[&host_id])
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
