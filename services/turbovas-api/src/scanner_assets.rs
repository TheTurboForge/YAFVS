// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCANNER_ASSET_DEFAULT_SORT, SCANNER_ASSET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    scanner_asset_payloads::{
        ScannerAssetDetail, ScannerAssetItem, ScannerTaskReference, scanner_asset_from_row,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn scanner_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScannerAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCANNER_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCANNER_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH scanner_rows AS (
             SELECT s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.host, '') AS host,
                    coalesce(s.port, 0)::bigint AS port,
                    coalesce(s.type, 0)::bigint AS scanner_type,
                    nullif(c.uuid, '') AS credential_id,
                    nullif(c.name, '') AS credential_name,
                    nullif(s.relay_host, '') AS relay_host,
                    coalesce(s.relay_port, 0)::bigint AS relay_port,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix
               FROM scanners s
               LEFT JOIN credentials c ON c.id = s.credential
         ),
         filtered AS (
             SELECT * FROM scanner_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(host) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(credential_name, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(relay_host, '')) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(scanner_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scanner_asset_detail(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let scanner_id = parse_uuid(&scanner_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT s.uuid AS id,
                      coalesce(s.name, '') AS name,
                      coalesce(s.comment, '') AS comment,
                      coalesce(s.host, '') AS host,
                      coalesce(s.port, 0)::bigint AS port,
                      coalesce(s.type, 0)::bigint AS scanner_type,
                      nullif(c.uuid, '') AS credential_id,
                      nullif(c.name, '') AS credential_name,
                      nullif(s.relay_host, '') AS relay_host,
                      coalesce(s.relay_port, 0)::bigint AS relay_port,
                      coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(s.modification_time, 0)::bigint AS modified_at_unix
                 FROM scanners s
            LEFT JOIN credentials c ON c.id = s.credential
                WHERE s.uuid = $1
                LIMIT 1;"#,
            &[&scanner_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let tasks = scanner_task_references(&client, &scanner_id).await?;
    let user_tags = scanner_user_tags(&client, &scanner_id).await?;
    Ok(Json(ScannerAssetDetail {
        asset: scanner_asset_from_row(&row),
        tasks,
        user_tags,
    }))
}

pub(crate) async fn scanner_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    scanner_asset_detail(state, path).await
}

pub(crate) fn scanner_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM scanners s
         JOIN tasks t ON t.scanner = s.id
        WHERE lower(s.uuid) = lower($1)
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scanner_task_references(
    client: &tokio_postgres::Client,
    scanner_id: &str,
) -> Result<Vec<ScannerTaskReference>, ApiError> {
    let rows = client
        .query(scanner_task_references_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ScannerTaskReference {
            id: row.get("id"),
            name: row.get("name"),
            usage_type: row.get("usage_type"),
        })
        .collect())
}

pub(crate) fn scanner_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN scanners ON scanners.id = tr.resource
        WHERE lower(scanners.uuid) = lower($1)
          AND tr.resource_type = 'scanner'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scanner_user_tags(
    client: &tokio_postgres::Client,
    scanner_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scanner_user_tags_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner user-tag query failed");
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
