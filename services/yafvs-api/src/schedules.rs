// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Client;

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::schedule_user_tags_sql,
    collections::{SCHEDULE_DEFAULT_SORT, SCHEDULE_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    schedule_payloads::{
        ScheduleAssetDetail, ScheduleAssetItem, schedule_asset_detail_payload,
        schedule_asset_from_row, schedule_task_from_row,
    },
    schedule_query_sql::{schedule_asset_detail_sql, schedule_assets_sql, schedule_tasks_sql},
    user_tags::ReportUserTag,
};

pub(crate) async fn schedule_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScheduleAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCHEDULE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCHEDULE_SORT_FIELDS)?;
    let sql = schedule_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "schedule asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| schedule_asset_from_row(row, Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn schedule_asset_detail(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_schedule_asset_detail(&client, &schedule_id).await?,
    ))
}

pub(crate) async fn export_schedule_metadata(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_schedule_asset_detail(&client, &schedule_id).await?,
    ))
}

pub(crate) async fn load_schedule_asset_detail(
    client: &Client,
    schedule_id: &str,
) -> Result<ScheduleAssetDetail, ApiError> {
    parse_uuid(schedule_id)?;
    let row = client
        .query_opt(schedule_asset_detail_sql(), &[&schedule_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let tasks = client
        .query(schedule_tasks_sql(), &[&internal_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule task backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(schedule_task_from_row)
        .collect();
    let user_tags = schedule_user_tags(&client, &schedule_id).await?;
    Ok(schedule_asset_detail_payload(
        schedule_asset_from_row(&row, tasks),
        user_tags,
    ))
}

async fn schedule_user_tags(
    client: &tokio_postgres::Client,
    schedule_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(schedule_user_tags_sql(), &[&schedule_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule user-tag query failed");
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
