// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::{Client, Row};

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{FILTER_ASSET_DEFAULT_SORT, FILTER_ASSET_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
};

#[derive(Serialize)]
pub(crate) struct FilterAlertReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct FilterAssetItem {
    id: String,
    name: String,
    comment: String,
    filter_type: String,
    term: String,
    alert_count: i64,
    alerts: Vec<FilterAlertReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn filter_alert_from_row(row: &Row) -> FilterAlertReference {
    FilterAlertReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

pub(crate) fn filter_asset_from_row(
    row: &Row,
    alerts: Vec<FilterAlertReference>,
) -> FilterAssetItem {
    FilterAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        filter_type: row.get("filter_type"),
        term: row.get("term"),
        alert_count: row.get("alert_count"),
        alerts,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) async fn filter_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<FilterAssetItem>>, ApiError> {
    let filter_type = query
        .filter_type
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let params = normalize_collection_query(query, FILTER_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, FILTER_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH filter_rows AS (
             SELECT f.uuid AS id,
                    coalesce(f.name, '') AS name,
                    coalesce(f.comment, '') AS comment,
                    coalesce(f.type, '') AS filter_type,
                    coalesce(f.term, '') AS term,
                    coalesce(f.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(f.modification_time, 0)::bigint AS modified_at_unix,
                    (
                      SELECT count(DISTINCT alert_id)::bigint
                        FROM (
                          SELECT a.id AS alert_id
                            FROM alerts a
                           WHERE a.filter = f.id
                          UNION
                          SELECT acd.alert AS alert_id
                            FROM alert_condition_data acd
                           WHERE acd.name = 'filter_id'
                             AND acd.data = f.uuid
                        ) alert_refs
                    ) AS alert_count
               FROM filters f
         ),
         filtered AS (
             SELECT * FROM filter_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(filter_type) LIKE '%' || lower($1) || '%'
                     OR lower(term) LIKE '%' || lower($1) || '%')
                AND ($2 = '' OR lower(filter_type) = lower($2))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $3 OFFSET $4;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &filter_type,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| filter_asset_from_row(row, Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn filter_asset_detail(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_filter_asset_detail(&client, &filter_id).await?))
}

pub(crate) async fn load_filter_asset_detail(
    client: &Client,
    filter_id: &str,
) -> Result<FilterAssetItem, ApiError> {
    parse_uuid(&filter_id)?;
    let row = client
        .query_opt(
            r#"SELECT f.id AS internal_id,
                      f.uuid AS id,
                      coalesce(f.name, '') AS name,
                      coalesce(f.comment, '') AS comment,
                      coalesce(f.type, '') AS filter_type,
                      coalesce(f.term, '') AS term,
                      coalesce(f.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(f.modification_time, 0)::bigint AS modified_at_unix,
                      (
                        SELECT count(DISTINCT alert_id)::bigint
                          FROM (
                            SELECT a.id AS alert_id
                              FROM alerts a
                             WHERE a.filter = f.id
                            UNION
                            SELECT acd.alert AS alert_id
                              FROM alert_condition_data acd
                             WHERE acd.name = 'filter_id'
                               AND acd.data = f.uuid
                          ) alert_refs
                      ) AS alert_count
                 FROM filters f
                WHERE f.uuid = $1
                LIMIT 1;"#,
            &[&filter_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let alerts = client
        .query(
            r#"SELECT DISTINCT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alerts a
                WHERE a.filter = $1
                UNION
               SELECT DISTINCT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alert_condition_data acd
                 JOIN alerts a ON a.id = acd.alert
                WHERE acd.name = 'filter_id'
                  AND acd.data = $2
                ORDER BY name ASC, id ASC;"#,
            &[&row.get::<_, i32>("internal_id"), &filter_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(filter_alert_from_row)
        .collect();
    Ok(filter_asset_from_row(&row, alerts))
}
