// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{OVERRIDE_ASSET_DEFAULT_SORT, OVERRIDE_ASSET_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
};

#[derive(Serialize)]
struct OverrideOwner {
    name: String,
}

#[derive(Serialize)]
struct OverrideNvtReference {
    id: String,
    name: String,
    #[serde(rename = "type")]
    nvt_type: String,
}

#[derive(Serialize)]
struct OverrideTaskReference {
    id: String,
    name: String,
    trash: bool,
}

#[derive(Serialize)]
struct OverrideReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct OverrideAssetItem {
    id: String,
    owner: OverrideOwner,
    nvt: OverrideNvtReference,
    text: String,
    text_excerpt: bool,
    hosts: String,
    port: String,
    severity: Option<f64>,
    new_severity: Option<f64>,
    writable: bool,
    in_use: bool,
    orphan: bool,
    active: bool,
    end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<OverrideTaskReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<OverrideReference>,
    permissions: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn override_asset_from_row(row: &Row) -> OverrideAssetItem {
    let task_id: Option<String> = row.get("task_id");
    let task = task_id.map(|id| OverrideTaskReference {
        name: row
            .get::<_, Option<String>>("task_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        trash: false,
        id,
    });
    let result_id: Option<String> = row.get("result_id");
    let result = result_id.map(|id| OverrideReference {
        name: row
            .get::<_, Option<String>>("result_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        id,
    });

    OverrideAssetItem {
        id: row.get("id"),
        owner: OverrideOwner {
            name: row.get("owner_name"),
        },
        nvt: OverrideNvtReference {
            id: row.get("nvt_id"),
            name: row.get("nvt_name"),
            nvt_type: row.get("nvt_type"),
        },
        text: row.get("text"),
        text_excerpt: false,
        hosts: row.get("hosts"),
        port: row.get("port"),
        severity: row.get("severity"),
        new_severity: row.get("new_severity"),
        writable: true,
        in_use: false,
        orphan: row.get::<_, i32>("orphan_int") != 0,
        active: row.get::<_, i32>("active_int") != 0,
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        task,
        result,
        permissions: vec![
            "get_overrides".to_string(),
            "modify_override".to_string(),
            "delete_override".to_string(),
            "create_override".to_string(),
        ],
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) async fn override_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OverrideAssetItem>>, ApiError> {
    let active_filter = query.active.clone().unwrap_or_default();
    let text_filter = query.text.clone().unwrap_or_default();
    let task_name_filter = query.task_name.clone().unwrap_or_default();
    let params = normalize_collection_query(query, OVERRIDE_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, OVERRIDE_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH override_rows AS (
             SELECT o.uuid AS id,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(o.nvt, '') AS nvt_id,
                    CASE
                      WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                      ELSE coalesce(n.name, o.nvt, '')
                    END AS nvt_name,
                    CASE
                      WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                      ELSE 'nvt'
                    END AS nvt_type,
                    coalesce(o.text, '') AS text,
                    coalesce(o.hosts, '') AS hosts,
                    coalesce(o.port, '') AS port,
                    o.severity::double precision AS severity,
                    coalesce(o.severity, -9999)::double precision AS severity_sort,
                    o.new_severity::double precision AS new_severity,
                    coalesce(o.new_severity, -9999)::double precision AS new_severity_sort,
                    coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(o.end_time, 0)::bigint AS end_time_unix,
                    CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int,
                    t.uuid AS task_id,
                    coalesce(t.name, '') AS task_name,
                    r.uuid AS result_id,
                    coalesce(r.uuid, '') AS result_name,
                    CASE
                      WHEN ((coalesce(o.task, 0) <> 0 AND t.uuid IS NULL)
                            OR (coalesce(o.result, 0) <> 0 AND r.uuid IS NULL))
                      THEN 1 ELSE 0
                    END AS orphan_int
               FROM overrides o
          LEFT JOIN users u ON u.id = o.owner
          LEFT JOIN nvts n ON n.oid = o.nvt
          LEFT JOIN tasks t ON t.id = o.task
          LEFT JOIN results r ON r.id = o.result
         ),
         filtered AS (
             SELECT * FROM override_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_id) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_name) LIKE '%' || lower($1) || '%'
                     OR lower(text) LIKE '%' || lower($1) || '%'
                     OR lower(hosts) LIKE '%' || lower($1) || '%'
                     OR lower(port) LIKE '%' || lower($1) || '%'
                     OR lower(task_name) LIKE '%' || lower($1) || '%')
                AND ($4 = '' OR lower(text) LIKE '%' || lower($4) || '%')
                AND ($5 = '' OR lower(task_name) LIKE '%' || lower($5) || '%')
                AND ($6 = ''
                     OR ($6 = '1' AND active_int = 1)
                     OR ($6 = '0' AND active_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, text ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &text_filter,
                &task_name_filter,
                &active_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "override asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(override_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn override_asset_detail(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    parse_uuid(&override_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT o.uuid AS id,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(o.nvt, '') AS nvt_id,
                      CASE
                        WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                        ELSE coalesce(n.name, o.nvt, '')
                      END AS nvt_name,
                      CASE
                        WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                        ELSE 'nvt'
                      END AS nvt_type,
                      coalesce(o.text, '') AS text,
                      coalesce(o.hosts, '') AS hosts,
                      coalesce(o.port, '') AS port,
                      o.severity::double precision AS severity,
                      o.new_severity::double precision AS new_severity,
                      coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce(o.end_time, 0)::bigint AS end_time_unix,
                      CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int,
                      t.uuid AS task_id,
                      coalesce(t.name, '') AS task_name,
                      r.uuid AS result_id,
                      coalesce(r.uuid, '') AS result_name,
                      CASE
                        WHEN ((coalesce(o.task, 0) <> 0 AND t.uuid IS NULL)
                              OR (coalesce(o.result, 0) <> 0 AND r.uuid IS NULL))
                        THEN 1 ELSE 0
                      END AS orphan_int
                 FROM overrides o
            LEFT JOIN users u ON u.id = o.owner
            LEFT JOIN nvts n ON n.oid = o.nvt
            LEFT JOIN tasks t ON t.id = o.task
            LEFT JOIN results r ON r.id = o.result
                WHERE o.uuid = $1
                LIMIT 1;"#,
            &[&override_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "override asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(override_asset_from_row(&row)))
}
