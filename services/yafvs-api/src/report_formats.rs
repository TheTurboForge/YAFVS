// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use deadpool_postgres::Client;

use crate::{
    app_state::AppState,
    collections::{REPORT_FORMAT_DEFAULT_SORT, REPORT_FORMAT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_format_payloads::{
        ReportFormatAssetItem, report_format_asset_from_row, report_format_param_from_row,
        report_format_param_option_from_row, report_format_reference_from_row,
    },
    report_format_query_sql::{
        report_format_alert_backlinks_sql, report_format_asset_detail_sql,
        report_format_assets_sql, report_format_param_options_sql, report_format_params_sql,
    },
};

pub(crate) async fn report_format_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportFormatAssetItem>>, ApiError> {
    let predefined_filter = query.predefined.clone().unwrap_or_default();
    if !matches!(predefined_filter.as_str(), "" | "0" | "1") {
        return Err(ApiError::BadRequest("invalid predefined filter".into()));
    }
    let params = normalize_collection_query(query, REPORT_FORMAT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_FORMAT_SORT_FIELDS)?;
    let sql = report_format_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &predefined_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset list query failed");
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
            &predefined_filter,
        ],
        "report format asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| report_format_asset_from_row(row, Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_format_asset_detail(
    State(state): State<AppState>,
    Path(report_format_id): Path<String>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_report_format_asset_detail(&client, &report_format_id).await?,
    ))
}

pub(crate) async fn load_report_format_asset_detail(
    client: &Client,
    report_format_id: &str,
) -> Result<ReportFormatAssetItem, ApiError> {
    parse_uuid(&report_format_id)?;
    let row = client
        .query_opt(report_format_asset_detail_sql(), &[&report_format_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let alerts = client
        .query(report_format_alert_backlinks_sql(), &[&report_format_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let mut params = Vec::new();
    for param_row in client
        .query(report_format_params_sql(), &[&internal_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format params query failed");
            ApiError::Database
        })?
    {
        let param_id: i32 = param_row.get("internal_id");
        let options = client
            .query(report_format_param_options_sql(), &[&param_id])
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report format param options query failed");
                ApiError::Database
            })?
            .iter()
            .map(report_format_param_option_from_row)
            .collect();
        params.push(report_format_param_from_row(&param_row, options));
    }

    Ok(report_format_asset_from_row(&row, alerts, params))
}

pub(crate) async fn export_report_format_metadata(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    report_format_asset_detail(state, path).await
}
