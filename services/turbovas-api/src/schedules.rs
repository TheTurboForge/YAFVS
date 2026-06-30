// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Client;

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCHEDULE_DEFAULT_SORT, SCHEDULE_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    schedule_payloads::{
        ScheduleAssetDetail, ScheduleAssetItem, schedule_asset_detail_payload,
        schedule_asset_from_row, schedule_task_from_row,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn schedule_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScheduleAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCHEDULE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCHEDULE_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH schedule_rows AS (
             SELECT s.id AS internal_id,
                    s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.icalendar, '') AS icalendar,
                    coalesce(s.timezone, 'UTC') AS timezone,
                    coalesce(s.first_time, 0)::bigint AS first_run_unix,
                    coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                    coalesce(s.period, 0)::bigint AS period_seconds,
                    coalesce(s.duration, 0)::bigint AS duration_seconds,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM tasks t
                       WHERE t.schedule = s.id
                         AND t.hidden = 0
                    ), 0)::bigint AS task_count
               FROM schedules s
         ),
         filtered AS (
             SELECT * FROM schedule_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(timezone) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
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

pub(crate) async fn load_schedule_asset_detail(
    client: &Client,
    schedule_id: &str,
) -> Result<ScheduleAssetDetail, ApiError> {
    parse_uuid(schedule_id)?;
    let row = client
        .query_opt(
            r#"SELECT s.id AS internal_id,
                      s.uuid AS id,
                      coalesce(s.name, '') AS name,
                      coalesce(s.comment, '') AS comment,
                      coalesce(s.icalendar, '') AS icalendar,
                      coalesce(s.timezone, 'UTC') AS timezone,
                      coalesce(s.first_time, 0)::bigint AS first_run_unix,
                      coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                      coalesce(s.period, 0)::bigint AS period_seconds,
                      coalesce(s.duration, 0)::bigint AS duration_seconds,
                      coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce((
                        SELECT count(*)::bigint
                          FROM tasks t
                         WHERE t.schedule = s.id
                           AND t.hidden = 0
                      ), 0)::bigint AS task_count
                 FROM schedules s
                WHERE s.uuid = $1
                LIMIT 1;"#,
            &[&schedule_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let tasks = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.usage_type, 'scan') AS usage_type
                 FROM tasks t
                WHERE t.schedule = $1
                  AND t.hidden = 0
                ORDER BY name ASC, id ASC;"#,
            &[&internal_id],
        )
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

pub(crate) fn schedule_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN schedules s ON s.id = tr.resource
        WHERE lower(s.uuid) = lower($1)
          AND tr.resource_type = 'schedule'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
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
