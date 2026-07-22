// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    cert_advisory_feed::{cert_bund_rich_detail, dfn_cert_rich_detail},
    cert_advisory_payloads::{
        CertBundAdvisoryDetail, CertBundAdvisoryItem, DfnCertAdvisoryDetail, DfnCertAdvisoryItem,
        cert_bund_advisory_from_row, dfn_cert_advisory_from_row,
    },
    collections::{CERT_ADVISORY_DEFAULT_SORT, CERT_ADVISORY_SORT_FIELDS},
    errors::ApiError,
    path_ids::validate_advisory_id,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    user_tags::catalog_user_tags,
};

pub(crate) async fn dfn_cert_advisories(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<DfnCertAdvisoryItem>>, ApiError> {
    let params = normalize_collection_query(query, CERT_ADVISORY_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CERT_ADVISORY_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH advisory_rows AS (
             SELECT d.uuid AS id,
                    d.name AS name,
                    coalesce(d.comment, '') AS comment,
                    coalesce(d.title, '') AS title,
                    coalesce(d.summary, '') AS summary,
                    coalesce(d.severity, 0)::double precision AS severity,
                    coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                    coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(array_agg(dc.cve_name ORDER BY dc.cve_name)
                      FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
               FROM cert.dfn_cert_advs d
               LEFT JOIN cert.dfn_cert_cves dc ON dc.adv_id = d.id
              GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                       d.severity, d.cve_refs, d.creation_time,
                       d.modification_time
         ),
         filtered AS (
             SELECT * FROM advisory_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR EXISTS (
                         SELECT 1 FROM unnest(cves) AS cve_name
                          WHERE lower(cve_name) LIKE '%' || lower($1) || '%'))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "DFN-CERT advisory list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "DFN-CERT advisory list",
    )
    .await?;
    let items = rows.iter().map(dfn_cert_advisory_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn dfn_cert_advisory_detail(
    State(state): State<AppState>,
    Path(advisory_id): Path<String>,
) -> Result<Json<DfnCertAdvisoryDetail>, ApiError> {
    validate_advisory_id(&advisory_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT d.uuid AS id,
                      d.name AS name,
                      coalesce(d.comment, '') AS comment,
                      coalesce(d.title, '') AS title,
                      coalesce(d.summary, '') AS summary,
                      coalesce(d.severity, 0)::double precision AS severity,
                      coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                      coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce(array_agg(dc.cve_name ORDER BY dc.cve_name)
                        FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
                 FROM cert.dfn_cert_advs d
                 LEFT JOIN cert.dfn_cert_cves dc ON dc.adv_id = d.id
                WHERE d.uuid = $1 OR d.name = $1
                GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                         d.severity, d.cve_refs, d.creation_time,
                         d.modification_time;"#,
            &[&advisory_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "DFN-CERT advisory detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let id: String = row.get("id");
    let name: String = row.get("name");
    let user_tags = catalog_user_tags(&client, "dfn_cert_adv", &id).await?;
    Ok(Json(DfnCertAdvisoryDetail {
        item: dfn_cert_advisory_from_row(&row),
        rich_detail: dfn_cert_rich_detail(&name),
        user_tags,
    }))
}

pub(crate) async fn dfn_cert_advisory_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<DfnCertAdvisoryDetail>, ApiError> {
    dfn_cert_advisory_detail(state, path).await
}

pub(crate) async fn cert_bund_advisories(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CertBundAdvisoryItem>>, ApiError> {
    let params = normalize_collection_query(query, CERT_ADVISORY_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CERT_ADVISORY_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH advisory_rows AS (
             SELECT d.uuid AS id,
                    d.name AS name,
                    coalesce(d.comment, '') AS comment,
                    coalesce(d.title, '') AS title,
                    coalesce(d.summary, '') AS summary,
                    coalesce(d.severity, 0)::double precision AS severity,
                    coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                    coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(array_agg(dc.cve_name::text ORDER BY dc.cve_name)
                      FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
               FROM cert.cert_bund_advs d
               LEFT JOIN cert.cert_bund_cves dc ON dc.adv_id = d.id
              GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                       d.severity, d.cve_refs, d.creation_time,
                       d.modification_time
         ),
         filtered AS (
             SELECT * FROM advisory_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR EXISTS (
                         SELECT 1 FROM unnest(cves) AS cve_name
                          WHERE lower(cve_name) LIKE '%' || lower($1) || '%'))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CERT-Bund advisory list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "CERT-Bund advisory list",
    )
    .await?;
    let items = rows.iter().map(cert_bund_advisory_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn cert_bund_advisory_detail(
    State(state): State<AppState>,
    Path(advisory_id): Path<String>,
) -> Result<Json<CertBundAdvisoryDetail>, ApiError> {
    validate_advisory_id(&advisory_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT d.uuid AS id,
                      d.name AS name,
                      coalesce(d.comment, '') AS comment,
                      coalesce(d.title, '') AS title,
                      coalesce(d.summary, '') AS summary,
                      coalesce(d.severity, 0)::double precision AS severity,
                      coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                      coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce(array_agg(dc.cve_name::text ORDER BY dc.cve_name)
                        FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
                 FROM cert.cert_bund_advs d
                 LEFT JOIN cert.cert_bund_cves dc ON dc.adv_id = d.id
                WHERE d.uuid = $1 OR d.name = $1
                GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                         d.severity, d.cve_refs, d.creation_time,
                         d.modification_time;"#,
            &[&advisory_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CERT-Bund advisory detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let id: String = row.get("id");
    let name: String = row.get("name");
    let user_tags = catalog_user_tags(&client, "cert_bund_adv", &id).await?;
    Ok(Json(CertBundAdvisoryDetail {
        item: cert_bund_advisory_from_row(&row),
        rich_detail: cert_bund_rich_detail(&name),
        user_tags,
    }))
}

pub(crate) async fn cert_bund_advisory_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<CertBundAdvisoryDetail>, ApiError> {
    cert_bund_advisory_detail(state, path).await
}
