// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::target_user_tags_sql,
    collections::{TARGET_DEFAULT_SORT, TARGET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    target_query_sql::{target_collection_predicate_sql, target_sql},
    task_target_payloads::{TargetItem, target_from_row, target_from_row_with_user_tags},
    user_tags::ReportUserTag,
};

pub(crate) async fn targets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TargetItem>>, ApiError> {
    let params = normalize_collection_query(query, TARGET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TARGET_SORT_FIELDS)?;
    let sql = target_sql(
        &target_collection_predicate_sql(
            "uuid",
            "name",
            "comment",
            "port_list_name",
            "hosts",
            "$1",
        ),
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "target list")
            .await?;
    let items = rows.iter().map(target_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn target_detail(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> Result<Json<TargetItem>, ApiError> {
    parse_uuid(&target_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_target_detail(&client, &target_id).await?))
}

pub(crate) async fn target_export(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> Result<Json<TargetItem>, ApiError> {
    parse_uuid(&target_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_target_detail(&client, &target_id).await?))
}

pub(crate) async fn load_target_detail(
    client: &tokio_postgres::Client,
    target_id: &str,
) -> Result<TargetItem, ApiError> {
    parse_uuid(target_id)?;
    let sql = target_sql("lower(uuid) = lower($1)", "name ASC", "");
    let row = client
        .query_opt(&sql, &[&target_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let user_tags = target_user_tags(client, target_id).await?;
    Ok(target_from_row_with_user_tags(&row, user_tags))
}

async fn target_user_tags(
    client: &tokio_postgres::Client,
    target_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(target_user_tags_sql(), &[&target_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target user-tag query failed");
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
