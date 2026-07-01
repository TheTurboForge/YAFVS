// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{TASK_DEFAULT_SORT, TASK_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    task_query_sql::task_sql,
    task_target_payloads::{TaskItem, task_from_row},
};

pub(crate) async fn tasks(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TaskItem>>, ApiError> {
    let params = normalize_collection_query(query, TASK_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TASK_SORT_FIELDS)?;
    let sql = task_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(comment) LIKE '%' || lower($1) || '%'\n\
            OR lower(status) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(target_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(config_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(scanner_name, '')) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(task_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn task_detail(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_task_detail(&client, &task_id).await?))
}

pub(crate) async fn task_export(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_task_detail(&client, &task_id).await?))
}

pub(crate) async fn load_task_detail(
    client: &tokio_postgres::Client,
    task_id: &str,
) -> Result<TaskItem, ApiError> {
    parse_uuid(&task_id)?;
    let sql = task_sql("lower(uuid) = lower($1)", "name ASC", "");
    let row = client
        .query_opt(&sql, &[&task_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(task_from_row(&row))
}
