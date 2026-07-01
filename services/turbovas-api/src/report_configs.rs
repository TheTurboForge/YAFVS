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
    collections::{REPORT_CONFIG_DEFAULT_SORT, REPORT_CONFIG_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    report_config_payloads::{ReportConfigAssetItem, report_config_asset_from_row},
};

pub(crate) async fn report_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportConfigAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_CONFIG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_CONFIG_SORT_FIELDS)?;
    let sql = format!(
        r#"SELECT count(*) OVER()::bigint AS total,
                  rc.id::integer AS internal_id,
                  rc.uuid AS id,
                  coalesce(rc.name, '') AS name,
                  coalesce(rc.comment, '') AS comment,
                  coalesce(u.name, '') AS owner_name,
                  coalesce(rc.report_format_id, '') AS report_format_id,
                  coalesce(rf.id, 0)::integer AS report_format_rowid,
                  coalesce(rf.name, '') AS report_format_name,
                  CASE WHEN coalesce(rf.name, '') = '' THEN 1 ELSE 0 END AS orphan,
                  coalesce(rc.creation_time, 0)::bigint AS created_at_unix,
                  coalesce(rc.modification_time, 0)::bigint AS modified_at_unix
             FROM report_configs rc
        LEFT JOIN users u ON u.id = rc.owner
        LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id
            WHERE ($1 = ''
                   OR lower(rc.uuid) LIKE '%' || lower($1) || '%'
                   OR lower(rc.name) LIKE '%' || lower($1) || '%'
                   OR lower(rc.comment) LIKE '%' || lower($1) || '%'
                   OR lower(rf.name) LIKE '%' || lower($1) || '%')
         ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let mut items = Vec::new();
    for row in &rows {
        items.push(report_config_asset_from_row(&client, row).await?);
    }
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_config_asset_detail(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_report_config_asset_detail(&client, &report_config_id).await?,
    ))
}

pub(crate) async fn export_report_config_metadata(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_report_config_asset_detail(&client, &report_config_id).await?,
    ))
}

pub(crate) async fn load_report_config_asset_detail(
    client: &Client,
    report_config_id: &str,
) -> Result<ReportConfigAssetItem, ApiError> {
    parse_uuid(&report_config_id)?;
    let row = client
        .query_opt(
            r#"SELECT rc.id::integer AS internal_id,
                      rc.uuid AS id,
                      coalesce(rc.name, '') AS name,
                      coalesce(rc.comment, '') AS comment,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(rc.report_format_id, '') AS report_format_id,
                      coalesce(rf.id, 0)::integer AS report_format_rowid,
                      coalesce(rf.name, '') AS report_format_name,
                      CASE WHEN coalesce(rf.name, '') = '' THEN 1 ELSE 0 END AS orphan,
                      coalesce(rc.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(rc.modification_time, 0)::bigint AS modified_at_unix
                 FROM report_configs rc
            LEFT JOIN users u ON u.id = rc.owner
            LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id
                WHERE rc.uuid = $1
                LIMIT 1;"#,
            &[&report_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    report_config_asset_from_row(client, &row).await
}
