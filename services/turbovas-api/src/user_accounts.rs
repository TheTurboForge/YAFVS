// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{USER_ACCOUNT_DEFAULT_SORT, USER_ACCOUNT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    user_account_payloads::{UserAccountItem, user_account_from_row},
    user_account_query_sql::{user_account_detail_sql, user_accounts_sql},
};

#[derive(Debug, serde::Deserialize)]
pub(crate) struct UserAccountCollectionQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    sort: Option<String>,
    filter: Option<String>,
    filter_type: Option<String>,
    active: Option<String>,
    predefined: Option<String>,
    resource_type: Option<String>,
    text: Option<String>,
    task_name: Option<String>,
    value: Option<String>,
}

impl UserAccountCollectionQuery {
    fn collection_query(&self) -> CollectionQuery {
        CollectionQuery {
            page: self.page,
            page_size: self.page_size,
            sort: self.sort.clone(),
            filter: self.filter.clone(),
            filter_type: self.filter_type.clone(),
            active: self.active.clone(),
            predefined: self.predefined.clone(),
            resource_type: self.resource_type.clone(),
            schedules_only: None,
            text: self.text.clone(),
            task_name: self.task_name.clone(),
            value: self.value.clone(),
        }
    }
}

pub(crate) async fn user_accounts(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<UserAccountCollectionQuery>,
) -> Result<Json<Collection<UserAccountItem>>, ApiError> {
    let params = normalize_collection_query(query.collection_query(), USER_ACCOUNT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, USER_ACCOUNT_SORT_FIELDS)?;
    let sql = user_accounts_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "user account list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&params.filter, &1_i64, &0_i64],
        "user account list",
    )
    .await?;
    let items = rows.iter().map(user_account_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn user_account_detail(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<UserAccountItem>, ApiError> {
    let user_id = parse_uuid(&user_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(user_account_detail_sql(), &[&user_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "user account detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(user_account_from_row(&row)))
}
