// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{Json, extract::State};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{app_state::AppState, errors::ApiError};

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
