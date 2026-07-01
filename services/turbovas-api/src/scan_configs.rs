// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use tokio_postgres::Client;

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::scan_config_user_tags_sql,
    collections::{SCAN_CONFIG_ASSET_DEFAULT_SORT, SCAN_CONFIG_ASSET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    scan_config_payloads::{
        ScanConfigAssetDetail, ScanConfigAssetItem, ScanConfigTaskReference,
        scan_config_asset_from_row, scan_config_task_reference_from_row,
    },
    scan_config_query_sql::{scan_config_asset_detail_sql, scan_config_task_references_sql},
    user_tags::ReportUserTag,
};

pub(crate) async fn scan_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScanConfigAssetItem>>, ApiError> {
    let predefined_filter = query.predefined.clone().unwrap_or_default();
    if !matches!(predefined_filter.as_str(), "" | "0" | "1") {
        return Err(ApiError::BadRequest("invalid predefined filter".into()));
    }
    let params = normalize_collection_query(query, SCAN_CONFIG_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCAN_CONFIG_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH scan_config_rows AS (
             SELECT c.id AS internal_id,
                    c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.family_count, 0)::bigint AS family_count,
                    coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                    coalesce(c.families_growing, 0)::integer AS families_growing,
                    coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                    coalesce(c.predefined, 0)::integer AS predefined_int,
                    coalesce(c.usage_type, 'scan') AS usage_type,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM tasks t
                        WHERE t.config = c.id
                          AND t.config_location = 0
                          AND t.hidden = 0
                    ) THEN 1 ELSE 0 END AS in_use_int,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM deprecated_feed_data d
                        WHERE d.type = 'config' AND d.uuid = c.uuid
                    ) THEN 1 ELSE 0 END AS deprecated_int,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM configs c
          LEFT JOIN users u ON u.id = c.owner
              WHERE coalesce(c.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM scan_config_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND predefined_int = 1)
                     OR ($4 = '0' AND predefined_int = 0))
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
                &predefined_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset list query failed");
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
            &predefined_filter,
        ],
        "scan config asset list",
    )
    .await?;
    let items = rows.iter().map(scan_config_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scan_config_asset_detail(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &scan_config_id).await?,
    ))
}

pub(crate) async fn export_scan_config_metadata(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &scan_config_id).await?,
    ))
}

pub(crate) async fn load_scan_config_asset_detail(
    client: &Client,
    scan_config_id: &str,
) -> Result<ScanConfigAssetDetail, ApiError> {
    parse_uuid(scan_config_id)?;
    let row = client
        .query_opt(scan_config_asset_detail_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    let tasks = scan_config_task_references(&client, &scan_config_id).await?;
    let user_tags = scan_config_user_tags(&client, &scan_config_id).await?;
    Ok(ScanConfigAssetDetail {
        asset: scan_config_asset_from_row(&row),
        tasks,
        user_tags,
    })
}

async fn scan_config_task_references(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ScanConfigTaskReference>, ApiError> {
    let rows = client
        .query(scan_config_task_references_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(scan_config_task_reference_from_row)
        .collect())
}

async fn scan_config_user_tags(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scan_config_user_tags_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config user-tag query failed");
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
