// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::tls_certificate_user_tags_sql,
    collections::{TLS_CERTIFICATE_ASSET_DEFAULT_SORT, TLS_CERTIFICATE_ASSET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    tls_certificate_payloads::{
        TlsCertificateAssetDetail, TlsCertificateAssetItem, tls_certificate_asset_from_row,
        tls_certificate_source_from_row,
    },
    tls_certificate_query_sql::{
        tls_certificate_asset_detail_sql, tls_certificate_assets_sql, tls_certificate_sources_sql,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn tls_certificate_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, TLS_CERTIFICATE_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TLS_CERTIFICATE_ASSET_SORT_FIELDS)?;
    let sql = tls_certificate_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "TLS certificate asset list",
    )
    .await?;
    let items = rows.iter().map(tls_certificate_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn tls_certificate_asset_detail(
    State(state): State<AppState>,
    Path(certificate_id): Path<String>,
) -> Result<Json<TlsCertificateAssetDetail>, ApiError> {
    parse_uuid(&certificate_id)?;
    let certificate_id = certificate_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(tls_certificate_asset_detail_sql(), &[&certificate_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let source_rows = client
        .query(tls_certificate_sources_sql(), &[&certificate_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset source query failed");
            ApiError::Database
        })?;
    let user_tags = tls_certificate_user_tags(&client, &certificate_id).await?;
    Ok(Json(TlsCertificateAssetDetail {
        asset: tls_certificate_asset_from_row(&row),
        sources: source_rows
            .iter()
            .map(tls_certificate_source_from_row)
            .collect(),
        user_tags,
    }))
}

pub(crate) async fn tls_certificate_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<TlsCertificateAssetDetail>, ApiError> {
    tls_certificate_asset_detail(state, path).await
}

async fn tls_certificate_user_tags(
    client: &tokio_postgres::Client,
    certificate_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(tls_certificate_user_tags_sql(), &[&certificate_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate user-tag query failed");
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
