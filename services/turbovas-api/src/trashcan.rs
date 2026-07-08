// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{Json, extract::State};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    collections::{TRASHCAN_ITEM_DEFAULT_SORT, TRASHCAN_ITEM_SORT_FIELDS},
    errors::ApiError,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
};

#[derive(Serialize)]
struct TrashcanSummaryItem {
    resource_type: String,
    title: String,
    count: i64,
}

#[derive(Serialize)]
pub(crate) struct TrashcanSummary {
    items: Vec<TrashcanSummaryItem>,
    total: i64,
}

#[derive(Serialize)]
pub(crate) struct TrashcanItem {
    id: String,
    resource_type: String,
    entity_type: String,
    title: String,
    name: String,
    comment: Option<String>,
    creation_time: Option<i64>,
    modification_time: Option<i64>,
}

pub(crate) fn trashcan_summary_from_rows(rows: &[Row]) -> TrashcanSummary {
    let items: Vec<TrashcanSummaryItem> = rows
        .iter()
        .map(|row| TrashcanSummaryItem {
            resource_type: row.get("resource_type"),
            title: row.get("title"),
            count: row.get("item_count"),
        })
        .collect();
    let total = items.iter().map(|item| item.count).sum();
    TrashcanSummary { items, total }
}

pub(crate) async fn trashcan_summary(
    State(state): State<AppState>,
) -> Result<Json<TrashcanSummary>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            r#"SELECT resource_type, title, item_count
                 FROM (
                   SELECT 1 AS sort_order, 'alerts'::text AS resource_type, 'Alerts'::text AS title, count(*)::bigint AS item_count FROM alerts_trash
                   UNION ALL
                   SELECT 2 AS sort_order, 'scan_configs'::text AS resource_type, 'Scan Configs'::text AS title, count(*)::bigint AS item_count FROM configs_trash
                   UNION ALL
                   SELECT 3 AS sort_order, 'credentials'::text AS resource_type, 'Credentials'::text AS title, count(*)::bigint AS item_count FROM credentials_trash
                   UNION ALL
                   SELECT 4 AS sort_order, 'filters'::text AS resource_type, 'Filters'::text AS title, count(*)::bigint AS item_count FROM filters_trash
                   UNION ALL
                   SELECT 5 AS sort_order, 'overrides'::text AS resource_type, 'Overrides'::text AS title, count(*)::bigint AS item_count FROM overrides_trash
                   UNION ALL
                   SELECT 6 AS sort_order, 'port_lists'::text AS resource_type, 'Port Lists'::text AS title, count(*)::bigint AS item_count FROM port_lists_trash
                   UNION ALL
                   SELECT 7 AS sort_order, 'report_configs'::text AS resource_type, 'Report Configs'::text AS title, count(*)::bigint AS item_count FROM report_configs_trash
                   UNION ALL
                   SELECT 8 AS sort_order, 'report_formats'::text AS resource_type, 'Report Formats'::text AS title, count(*)::bigint AS item_count FROM report_formats_trash
                   UNION ALL
                   SELECT 9 AS sort_order, 'scanners'::text AS resource_type, 'Scanners'::text AS title, count(*)::bigint AS item_count FROM scanners_trash
                   UNION ALL
                   SELECT 10 AS sort_order, 'schedules'::text AS resource_type, 'Schedules'::text AS title, count(*)::bigint AS item_count FROM schedules_trash
                   UNION ALL
                   SELECT 11 AS sort_order, 'tags'::text AS resource_type, 'Tags'::text AS title, count(*)::bigint AS item_count FROM tags_trash
                   UNION ALL
                   SELECT 12 AS sort_order, 'targets'::text AS resource_type, 'Targets'::text AS title, count(*)::bigint AS item_count FROM targets_trash
                   UNION ALL
                   SELECT 13 AS sort_order, 'tasks'::text AS resource_type, 'Tasks'::text AS title, count(*)::bigint AS item_count FROM tasks WHERE hidden = 2
                 ) trash_counts
                ORDER BY sort_order ASC;"#,
            &[],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "trashcan summary query failed");
            ApiError::Database
        })?;
    Ok(Json(trashcan_summary_from_rows(&rows)))
}

fn trashcan_item_from_row(row: &Row) -> TrashcanItem {
    TrashcanItem {
        id: row.get("id"),
        resource_type: row.get("resource_type"),
        entity_type: row.get("entity_type"),
        title: row.get("title"),
        name: row.get("name"),
        comment: row.get("comment"),
        creation_time: row.get::<_, Option<i32>>("creation_time").map(i64::from),
        modification_time: row
            .get::<_, Option<i32>>("modification_time")
            .map(i64::from),
    }
}

fn trashcan_items_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH trash_items AS (
             SELECT uuid::text AS id, 'alerts'::text AS resource_type, 'alert'::text AS entity_type, 'Alerts'::text AS title,
                    name::text AS name, comment::text AS comment, creation_time, modification_time, 1 AS sort_order
               FROM alerts_trash
             UNION ALL
             SELECT uuid::text, 'scan_configs'::text, 'scanconfig'::text, 'Scan Configs'::text,
                    name::text, comment::text, creation_time, modification_time, 2
               FROM configs_trash
              WHERE coalesce(usage_type, 'scan') = 'scan'
             UNION ALL
             SELECT uuid::text, 'credentials'::text, 'credential'::text, 'Credentials'::text,
                    name::text, comment::text, creation_time, modification_time, 3
               FROM credentials_trash
             UNION ALL
             SELECT uuid::text, 'filters'::text, 'filter'::text, 'Filters'::text,
                    name::text, comment::text, creation_time, modification_time, 4
               FROM filters_trash
             UNION ALL
             SELECT uuid::text, 'overrides'::text, 'override'::text, 'Overrides'::text,
                    coalesce(nullif(nvt, ''), 'Override')::text, NULL::text, creation_time, modification_time, 5
               FROM overrides_trash
             UNION ALL
             SELECT uuid::text, 'port_lists'::text, 'portlist'::text, 'Port Lists'::text,
                    name::text, comment::text, creation_time, modification_time, 6
               FROM port_lists_trash
             UNION ALL
             SELECT uuid::text, 'report_configs'::text, 'reportconfig'::text, 'Report Configs'::text,
                    name::text, comment::text, creation_time, modification_time, 7
               FROM report_configs_trash
             UNION ALL
             SELECT uuid::text, 'report_formats'::text, 'reportformat'::text, 'Report Formats'::text,
                    name::text, description::text, creation_time, modification_time, 8
               FROM report_formats_trash
             UNION ALL
             SELECT uuid::text, 'scanners'::text, 'scanner'::text, 'Scanners'::text,
                    coalesce(nullif(name, ''), 'Scanner')::text, comment::text, creation_time, modification_time, 9
               FROM scanners_trash
             UNION ALL
             SELECT uuid::text, 'schedules'::text, 'schedule'::text, 'Schedules'::text,
                    name::text, comment::text, creation_time, modification_time, 10
               FROM schedules_trash
             UNION ALL
             SELECT uuid::text, 'tags'::text, 'tag'::text, 'Tags'::text,
                    name::text, comment::text, creation_time, modification_time, 11
               FROM tags_trash
             UNION ALL
             SELECT uuid::text, 'targets'::text, 'target'::text, 'Targets'::text,
                    name::text, comment::text, creation_time, modification_time, 12
               FROM targets_trash
             UNION ALL
             SELECT uuid::text, 'tasks'::text, 'task'::text, 'Tasks'::text,
                    coalesce(nullif(name, ''), 'Task')::text, comment::text, creation_time, modification_time, 13
               FROM tasks
              WHERE hidden = 2
                AND coalesce(usage_type, 'scan') = 'scan'
           ), filtered AS (
             SELECT *
               FROM trash_items
              WHERE $1 = ''
                 OR lower(resource_type || ' ' || title || ' ' || name || ' ' || coalesce(comment, '')) LIKE '%' || lower($1) || '%'
           )
           SELECT count(*) OVER() AS total,
                  id, resource_type, entity_type, title, name, comment, creation_time, modification_time
             FROM filtered
            ORDER BY {sort_sql}, sort_order ASC, lower(name) ASC, id ASC
            LIMIT $2 OFFSET $3;"#
    )
}

pub(crate) async fn trashcan_items(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TrashcanItem>>, ApiError> {
    let params = normalize_collection_query(query, TRASHCAN_ITEM_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TRASHCAN_ITEM_SORT_FIELDS)?;
    let sql = trashcan_items_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "trashcan item list query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&params.filter, &probe_page_size, &probe_offset],
        "trashcan item list",
    )
    .await?;
    let items = rows.iter().map(trashcan_item_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trashcan_items_sql_redacts_secret_adjacent_fields() {
        let sql = trashcan_items_sql("resource_type ASC");
        for forbidden in [
            "password",
            "scanner_credential",
            "credential_location",
            "ca_pub",
            "relay_host",
            "hosts::text",
            "exclude_hosts",
            "nvt_selector",
            "method_data",
            "condition_data",
            "event_data",
            "icalendar",
        ] {
            assert!(
                !sql.contains(forbidden),
                "trashcan item row list must not expose {forbidden}"
            );
        }
        assert!(sql.contains("FROM credentials_trash"));
        assert!(sql.contains("FROM scanners_trash"));
        assert!(sql.contains("FROM targets_trash"));
        assert!(sql.contains("FROM tasks"));
        assert!(sql.contains("WHERE hidden = 2"));
    }
}
