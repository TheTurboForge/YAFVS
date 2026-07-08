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
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    task_query_sql::task_sql,
    task_target_payloads::{TaskItem, task_from_row},
};

pub(crate) async fn tasks(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TaskItem>>, ApiError> {
    let schedules_only = parse_schedules_only(query.schedules_only.as_deref())?;
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
            OR lower(coalesce(scanner_name, '')) LIKE '%' || lower($1) || '%')\n\
            AND (NOT $2 OR schedule_id IS NOT NULL)",
        &sort_sql,
        "LIMIT $3 OFFSET $4",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &schedules_only,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task list query failed");
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
            &schedules_only,
            &probe_page_size,
            &probe_offset,
        ],
        "task list",
    )
    .await?;
    let items = rows.iter().map(task_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

fn parse_schedules_only(value: Option<&str>) -> Result<bool, ApiError> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("") | Some("false") | Some("0") | Some("no") => Ok(false),
        Some("true") | Some("1") | Some("yes") => Ok(true),
        Some(_) => Err(ApiError::BadRequest(
            "schedules_only must be a boolean".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_only_query_accepts_boolean_like_values() {
        assert!(!parse_schedules_only(None).unwrap());
        assert!(!parse_schedules_only(Some("false")).unwrap());
        assert!(!parse_schedules_only(Some("0")).unwrap());
        assert!(!parse_schedules_only(Some("no")).unwrap());
        assert!(parse_schedules_only(Some("true")).unwrap());
        assert!(parse_schedules_only(Some("1")).unwrap());
        assert!(parse_schedules_only(Some("yes")).unwrap());
    }

    #[test]
    fn schedules_only_query_rejects_invalid_values() {
        let err = parse_schedules_only(Some("maybe")).unwrap_err();
        assert!(
            matches!(err, ApiError::BadRequest(message) if message == "schedules_only must be a boolean")
        );
    }

    #[test]
    fn task_list_sql_keeps_schedules_only_predicate_explicit() {
        let sql = task_sql(
            "($1 = '' OR lower(name) LIKE '%' || lower($1) || '%')\n\
             AND (NOT $2 OR schedule_id IS NOT NULL)",
            "name ASC",
            "LIMIT $3 OFFSET $4",
        );
        assert!(sql.contains("LEFT JOIN schedules schedule ON schedule.id = task.schedule"));
        assert!(sql.contains("schedule.uuid AS schedule_id"));
        assert!(sql.contains("AND (NOT $2 OR schedule_id IS NOT NULL)"));
        assert!(sql.contains("LIMIT $3 OFFSET $4"));
    }
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
