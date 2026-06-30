// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{OVERRIDE_ASSET_DEFAULT_SORT, OVERRIDE_ASSET_SORT_FIELDS},
    errors::ApiError,
    override_payloads::{OverrideAssetItem, override_asset_from_row},
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
};

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
