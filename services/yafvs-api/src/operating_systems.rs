// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::operating_system_user_tags_sql,
    collections::{OPERATING_SYSTEM_ASSET_DEFAULT_SORT, OPERATING_SYSTEM_ASSET_SORT_FIELDS},
    errors::ApiError,
    operating_system_payloads::{OperatingSystemAssetItem, operating_system_asset_from_row},
    operating_system_query_sql::{operating_system_asset_detail_sql, operating_system_assets_sql},
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, normalize_optional_exact_query, sort_clause,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn operating_system_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemAssetItem>>, ApiError> {
    let name_filter = normalize_optional_exact_query(query.name.as_deref(), "name")?;
    let params = normalize_collection_query(query, OPERATING_SYSTEM_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, OPERATING_SYSTEM_ASSET_SORT_FIELDS)?;
    let sql = operating_system_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &name_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system asset list query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[
            &params.filter,
            &probe_page_size,
            &probe_offset,
            &name_filter,
        ],
        "operating system asset list",
    )
    .await?;
    let items = rows.iter().map(operating_system_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn operating_system_asset_detail(
    State(state): State<AppState>,
    Path(os_id): Path<String>,
) -> Result<Json<OperatingSystemAssetItem>, ApiError> {
    parse_uuid(&os_id)?;
    let os_id = os_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(operating_system_asset_detail_sql(), &[&os_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = operating_system_asset_from_row(&row);
    item.user_tags = operating_system_user_tags(&client, &os_id).await?;
    Ok(Json(item))
}

pub(crate) async fn operating_system_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<OperatingSystemAssetItem>, ApiError> {
    operating_system_asset_detail(state, path).await
}

async fn operating_system_user_tags(
    client: &tokio_postgres::Client,
    os_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(operating_system_user_tags_sql(), &[&os_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system user-tag query failed");
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
