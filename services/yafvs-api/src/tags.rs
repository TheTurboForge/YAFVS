// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{
        TAG_DEFAULT_SORT, TAG_RESOURCE_DEFAULT_SORT, TAG_RESOURCE_NAME_MAX_PAGE_SIZE,
        TAG_RESOURCE_SORT_FIELDS, TAG_SORT_FIELDS,
    },
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    tag_payloads::{
        TagAssetItem, TagResourceCollection, TagResourceItem, tag_asset_from_row,
        tag_resource_from_row,
    },
    tag_query_sql::{tag_asset_detail_sql, tag_assets_sql, tag_resource_lookup_sql},
    tag_resource_helpers::{
        normalize_tag_resource_type, tag_resource_collection_sql, tag_resource_name_collection_sql,
        tag_resource_name_filter,
    },
};

pub(crate) async fn tag_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TagAssetItem>>, ApiError> {
    let active_filter = query.active.clone().unwrap_or_default();
    let resource_type_filter = query.resource_type.clone().unwrap_or_default();
    let value_filter = query.value.clone().unwrap_or_default();
    let params = normalize_collection_query(query, TAG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TAG_SORT_FIELDS)?;
    let sql = tag_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &active_filter,
                &resource_type_filter,
                &value_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag asset list query failed");
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
            &active_filter,
            &resource_type_filter,
            &value_filter,
        ],
        "tag asset list",
    )
    .await?;
    let items = rows.iter().map(tag_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn tag_asset_detail(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_tag_asset_detail(&client, &tag_id).await?))
}

pub(crate) async fn export_tag_metadata(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_tag_asset_detail(&client, &tag_id).await?))
}

pub(crate) async fn load_tag_asset_detail(
    client: &tokio_postgres::Client,
    tag_id: &str,
) -> Result<TagAssetItem, ApiError> {
    parse_uuid(&tag_id)?;
    let row = client
        .query_opt(tag_asset_detail_sql(), &[&tag_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(tag_asset_from_row(&row))
}

pub(crate) async fn tag_asset_resources(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<TagResourceCollection>, ApiError> {
    let tag_id = parse_uuid(&tag_id)?.to_string();
    let params = normalize_collection_query(query, TAG_RESOURCE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TAG_RESOURCE_SORT_FIELDS)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tag_row = client
        .query_opt(tag_resource_lookup_sql(), &[&tag_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag lookup for resource expansion failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let tag_internal_id: i32 = tag_row.get("id");
    let resource_type = normalize_tag_resource_type(tag_row.get("resource_type"));
    let sql = tag_resource_collection_sql(&resource_type, &sort_sql)?;
    let rows = client
        .query(
            &sql,
            &[
                &tag_internal_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, %resource_type, "tag resource query failed");
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
            &tag_internal_id,
            &params.filter,
            &probe_page_size,
            &probe_offset,
        ],
        "tag resource list",
    )
    .await?;
    let items = rows.iter().map(tag_resource_from_row).collect();
    Ok(Json(TagResourceCollection {
        tag_id,
        resource_type,
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn tag_resource_names(
    State(state): State<AppState>,
    Path(resource_type): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TagResourceItem>>, ApiError> {
    let resource_type = normalize_tag_resource_type(resource_type);
    let params = normalize_collection_query(query, TAG_RESOURCE_DEFAULT_SORT)?;
    if params.page_size > TAG_RESOURCE_NAME_MAX_PAGE_SIZE {
        return Err(ApiError::BadRequest(format!(
            "page_size must be between 1 and {TAG_RESOURCE_NAME_MAX_PAGE_SIZE}"
        )));
    }
    let sort_sql = sort_clause(&params.sort, TAG_RESOURCE_SORT_FIELDS)?;
    let (filter, exact_id_filter) = tag_resource_name_filter(&params.filter);
    let sql = tag_resource_name_collection_sql(&resource_type, &sort_sql)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[&filter, &exact_id_filter, &params.page_size, &params.offset],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, %resource_type, "tag resource-name query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&filter, &exact_id_filter, &probe_page_size, &probe_offset],
        "tag resource-name list",
    )
    .await?;
    let items = rows.iter().map(tag_resource_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
