// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::port_list_user_tags_sql,
    collections::{PORT_LIST_DEFAULT_SORT, PORT_LIST_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    port_list_payloads::{
        PortListAssetDetail, PortListAssetItem, port_list_asset_detail_payload,
        port_list_asset_from_row, port_list_target_from_row, port_range_from_row,
    },
    port_list_query_sql::{
        port_list_asset_detail_sql, port_list_assets_sql, port_list_ranges_sql,
        port_list_targets_sql,
    },
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn port_list_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortListAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, PORT_LIST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, PORT_LIST_SORT_FIELDS)?;
    let sql = port_list_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "port list asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| port_list_asset_from_row(row, Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn port_list_asset_detail(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_port_list_asset_detail(&client, &port_list_id).await?,
    ))
}

pub(crate) async fn export_port_list_metadata(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_port_list_asset_detail(&client, &port_list_id).await?,
    ))
}

pub(crate) async fn load_port_list_asset_detail(
    client: &tokio_postgres::Client,
    port_list_id: &str,
) -> Result<PortListAssetDetail, ApiError> {
    parse_uuid(&port_list_id)?;
    let row = client
        .query_opt(port_list_asset_detail_sql(), &[&port_list_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let ranges = client
        .query(port_list_ranges_sql(), &[&internal_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list range query failed");
            ApiError::Database
        })?
        .iter()
        .map(port_range_from_row)
        .collect();
    let targets = client
        .query(port_list_targets_sql(), &[&internal_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list target backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(port_list_target_from_row)
        .collect();
    let user_tags = port_list_user_tags(&client, &port_list_id).await?;
    Ok(port_list_asset_detail_payload(
        port_list_asset_from_row(&row, ranges, targets),
        user_tags,
    ))
}

async fn port_list_user_tags(
    client: &tokio_postgres::Client,
    port_list_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(port_list_user_tags_sql(), &[&port_list_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list user-tag query failed");
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
