// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    alert_payloads::{AlertAssetItem, AlertReference, alert_asset_from_row},
    app_state::AppState,
    collections::{ALERT_DEFAULT_SORT, ALERT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) fn alert_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH alert_rows AS (
             SELECT a.uuid AS id,
                    coalesce(a.name, '') AS name,
                    coalesce(a.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(a.active, 0)::integer AS active_int,
                    CASE coalesce(a.event, 0)::integer
                      WHEN 1 THEN 'Task run status changed'
                      WHEN 2 THEN 'New SecInfo arrived'
                      WHEN 3 THEN 'Updated SecInfo arrived'
                      ELSE 'Internal Error'
                    END AS event_type,
                    CASE coalesce(a.condition, 0)::integer
                      WHEN 1 THEN 'Always'
                      WHEN 2 THEN 'Severity at least'
                      WHEN 3 THEN 'Severity changed'
                      WHEN 4 THEN 'Filter count at least'
                      WHEN 5 THEN 'Filter count changed'
                      ELSE 'Internal Error'
                    END AS condition_type,
                    CASE coalesce(a.method, 0)::integer
                      WHEN 1 THEN 'Email'
                      WHEN 2 THEN 'HTTP Get'
                      WHEN 3 THEN 'Sourcefire Connector'
                      WHEN 4 THEN 'Start Task'
                      WHEN 5 THEN 'Syslog'
                      WHEN 6 THEN 'verinice Connector'
                      WHEN 7 THEN 'Send'
                      WHEN 8 THEN 'SCP'
                      WHEN 9 THEN 'SNMP'
                      WHEN 10 THEN 'SMB'
                      WHEN 11 THEN 'TippingPoint SMS'
                      WHEN 12 THEN 'Alemba vFire'
                      ELSE 'Internal Error'
                    END AS method_type,
                    f.uuid AS filter_id,
                    coalesce(f.name, '') AS filter_name,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM task_alerts ta
                        JOIN tasks t ON t.id = ta.task
                       WHERE ta.alert = a.id
                         AND coalesce(t.hidden, 0) = 0
                    ), 0)::bigint AS task_count,
                    coalesce(a.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(a.modification_time, 0)::bigint AS modified_at_unix
               FROM alerts a
          LEFT JOIN users u ON u.id = a.owner
          LEFT JOIN filters f ON f.id = a.filter
         ),
         filtered AS (
             SELECT * FROM alert_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(event_type) LIKE '%' || lower($1) || '%'
                     OR lower(condition_type) LIKE '%' || lower($1) || '%'
                     OR lower(method_type) LIKE '%' || lower($1) || '%'
                     OR lower(filter_name) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) async fn alert_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<AlertAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, ALERT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, ALERT_SORT_FIELDS)?;
    let sql = alert_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "alert asset list")
            .await?;
    let items = rows.iter().map(alert_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) fn alert_asset_detail_sql() -> &'static str {
    r#"SELECT a.uuid AS id,
              coalesce(a.name, '') AS name,
              coalesce(a.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              coalesce(a.active, 0)::integer AS active_int,
              CASE coalesce(a.event, 0)::integer
                WHEN 1 THEN 'Task run status changed'
                WHEN 2 THEN 'New SecInfo arrived'
                WHEN 3 THEN 'Updated SecInfo arrived'
                ELSE 'Internal Error'
              END AS event_type,
              CASE coalesce(a.condition, 0)::integer
                WHEN 1 THEN 'Always'
                WHEN 2 THEN 'Severity at least'
                WHEN 3 THEN 'Severity changed'
                WHEN 4 THEN 'Filter count at least'
                WHEN 5 THEN 'Filter count changed'
                ELSE 'Internal Error'
              END AS condition_type,
              CASE coalesce(a.method, 0)::integer
                WHEN 1 THEN 'Email'
                WHEN 2 THEN 'HTTP Get'
                WHEN 3 THEN 'Sourcefire Connector'
                WHEN 4 THEN 'Start Task'
                WHEN 5 THEN 'Syslog'
                WHEN 6 THEN 'verinice Connector'
                WHEN 7 THEN 'Send'
                WHEN 8 THEN 'SCP'
                WHEN 9 THEN 'SNMP'
                WHEN 10 THEN 'SMB'
                WHEN 11 THEN 'TippingPoint SMS'
                WHEN 12 THEN 'Alemba vFire'
                ELSE 'Internal Error'
              END AS method_type,
              f.uuid AS filter_id,
              coalesce(f.name, '') AS filter_name,
              coalesce((
                SELECT count(*)::bigint
                  FROM task_alerts ta
                  JOIN tasks t ON t.id = ta.task
                 WHERE ta.alert = a.id
                   AND coalesce(t.hidden, 0) = 0
              ), 0)::bigint AS task_count,
              coalesce(a.creation_time, 0)::bigint AS created_at_unix,
              coalesce(a.modification_time, 0)::bigint AS modified_at_unix
         FROM alerts a
    LEFT JOIN users u ON u.id = a.owner
    LEFT JOIN filters f ON f.id = a.filter
        WHERE a.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn alert_asset_tasks_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name
         FROM alerts a
         JOIN task_alerts ta ON ta.alert = a.id
         JOIN tasks t ON t.id = ta.task
        WHERE a.uuid = $1
          AND coalesce(t.hidden, 0) = 0
        ORDER BY name ASC, id ASC;"#
}

pub(crate) async fn alert_asset_detail(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_alert_asset_detail(&client, &alert_id).await?))
}

pub(crate) async fn export_alert_metadata(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_alert_asset_detail(&client, &alert_id).await?))
}

pub(crate) async fn load_alert_asset_detail(
    client: &tokio_postgres::Client,
    alert_id: &str,
) -> Result<AlertAssetItem, ApiError> {
    let alert_id = parse_uuid(alert_id)?.to_string();
    let row = client
        .query_opt(alert_asset_detail_sql(), &[&alert_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let task_rows = client
        .query(alert_asset_tasks_sql(), &[&alert_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset task reference query failed");
            ApiError::Database
        })?;
    let tasks = task_rows
        .iter()
        .map(|row| AlertReference {
            id: row.get("id"),
            name: row.get("name"),
        })
        .collect();
    let mut item = alert_asset_from_row(&row);
    item.tasks = tasks;
    Ok(item)
}
