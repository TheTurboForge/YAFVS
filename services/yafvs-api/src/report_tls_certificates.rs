// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{REPORT_TLS_CERTIFICATE_DEFAULT_SORT, REPORT_TLS_CERTIFICATE_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{TlsCertificateItem, tls_certificate_from_row},
    report_helpers::raw_report_exists,
    report_tls_certificate_query_sql::report_tls_certificates_sql,
};

pub(crate) async fn report_tls_certificates(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_TLS_CERTIFICATE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_TLS_CERTIFICATE_SORT_FIELDS)?;
    let sql = report_tls_certificates_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report TLS certificate query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&report_id, &params.filter, &probe_page_size, &probe_offset],
        "raw report TLS certificate list",
    )
    .await?;
    let items = rows.iter().map(tls_certificate_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
