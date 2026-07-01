// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use tokio_postgres::Client;

use crate::{
    app_state::AppState,
    collections::{CREDENTIAL_ASSET_DEFAULT_SORT, CREDENTIAL_ASSET_SORT_FIELDS},
    credential_payloads::{
        CredentialAssetItem, credential_asset_from_row, credential_usage_reference_from_row,
    },
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) async fn credential_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CredentialAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, CREDENTIAL_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CREDENTIAL_ASSET_SORT_FIELDS)?;
    let sql = credential_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "credential asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| credential_asset_from_row(row, Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn credential_asset_detail(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    let credential_id = parse_uuid(&credential_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_credential_asset_detail(&client, &credential_id).await?,
    ))
}

async fn load_credential_asset_detail(
    client: &Client,
    credential_id: &str,
) -> Result<CredentialAssetItem, ApiError> {
    let row = client
        .query_opt(credential_asset_detail_sql(), &[&credential_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let targets = client
        .query(credential_target_references_sql(), &[&credential_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential target-reference query failed");
            ApiError::Database
        })?
        .iter()
        .map(credential_usage_reference_from_row)
        .collect();
    let scanners = client
        .query(credential_scanner_references_sql(), &[&credential_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "credential scanner-reference query failed");
            ApiError::Database
        })?
        .iter()
        .map(credential_usage_reference_from_row)
        .collect();
    Ok(credential_asset_from_row(&row, targets, scanners))
}

pub(crate) fn credential_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH credential_rows AS (
             SELECT c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.type, '') AS credential_type,
                    coalesce(c.allow_insecure, 0)::integer AS allow_insecure_int,
                    coalesce((SELECT count(DISTINCT tld.target)::bigint
                                FROM targets_login_data tld
                               WHERE tld.credential = c.id), 0)::bigint AS target_count,
                    coalesce((SELECT count(DISTINCT s.id)::bigint
                                FROM scanners s
                               WHERE s.credential = c.id), 0)::bigint AS scanner_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM credentials c
          LEFT JOIN users u ON u.id = c.owner
         ),
         filtered AS (
             SELECT * FROM credential_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(credential_type) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn credential_asset_detail_sql() -> &'static str {
    r#"SELECT c.uuid AS id,
              coalesce(c.name, '') AS name,
              coalesce(c.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              coalesce(c.type, '') AS credential_type,
              coalesce(c.allow_insecure, 0)::integer AS allow_insecure_int,
              coalesce((SELECT count(DISTINCT tld.target)::bigint
                          FROM targets_login_data tld
                         WHERE tld.credential = c.id), 0)::bigint AS target_count,
              coalesce((SELECT count(DISTINCT s.id)::bigint
                          FROM scanners s
                         WHERE s.credential = c.id), 0)::bigint AS scanner_count,
              coalesce(c.creation_time, 0)::bigint AS created_at_unix,
              coalesce(c.modification_time, 0)::bigint AS modified_at_unix
         FROM credentials c
    LEFT JOIN users u ON u.id = c.owner
        WHERE c.uuid = $1
        LIMIT 1;"#
}

pub(crate) fn credential_target_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(tld.type, '') AS use_type,
              NULLIF(tld.port, 0)::bigint AS port
         FROM credentials c
         JOIN targets_login_data tld ON tld.credential = c.id
         JOIN targets t ON t.id = tld.target
        WHERE c.uuid = $1
        ORDER BY name ASC, id ASC, use_type ASC;"#
}

pub(crate) fn credential_scanner_references_sql() -> &'static str {
    r#"SELECT s.uuid AS id,
              coalesce(s.name, '') AS name,
              'scanner'::text AS use_type,
              NULL::bigint AS port
         FROM credentials c
         JOIN scanners s ON s.credential = c.id
        WHERE c.uuid = $1
        ORDER BY name ASC, id ASC;"#
}
