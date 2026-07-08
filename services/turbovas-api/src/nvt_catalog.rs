// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{NVT_CATALOG_DEFAULT_SORT, NVT_CATALOG_SORT_FIELDS},
    errors::ApiError,
    nvt_catalog_payloads::{
        NvtCatalogDetail, NvtCatalogItem, nvt_catalog_detail_from_row, nvt_catalog_from_row,
        nvt_catalog_preference_from_row,
    },
    path_ids::validate_nvt_oid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    user_tags::catalog_user_tags,
};

pub(crate) async fn nvt_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<NvtCatalogItem>>, ApiError> {
    let params = normalize_collection_query(query, NVT_CATALOG_DEFAULT_SORT)?;
    let (filter_mode, filter_value) = nvt_filter_parts(&params.filter);
    let sort_sql = sort_clause(&params.sort, NVT_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH filtered AS (
             SELECT n.oid AS id,
                    n.oid AS oid,
                    coalesce(n.name, '') AS name,
                    coalesce(n.family, '') AS family,
                    coalesce(n.category, '') AS category,
                    coalesce(n.discovery, 0)::bigint AS discovery,
                    coalesce(n.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(n.modification_time, 0)::bigint AS modified_at_unix,
                    CASE
                      WHEN coalesce(n.cvss_base, '') ~ '^-?[0-9]+(\.[0-9]+)?$'
                      THEN n.cvss_base::double precision
                      ELSE 0::double precision
                    END AS severity,
                    coalesce(n.qod, 0)::bigint AS qod,
                    coalesce(n.qod_type, '') AS qod_type,
                    coalesce(n.solution_type, '') AS solution_type,
                    coalesce(n.solution_method, '') AS solution_method,
                    coalesce(n.solution, '') AS solution,
                    coalesce(n.tag, '') AS tags,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    coalesce(n.epss_cve, '') AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    coalesce(n.max_epss_cve, '') AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity
               FROM nvts n
              WHERE ($2 = ''
                     OR ($1 = 'family' AND lower(n.family) = lower($2))
                     OR ($1 = 'category' AND lower(coalesce(n.category, '')) = lower($2))
                     OR ($1 = 'discovery' AND coalesce(n.discovery, 0)::text = $2)
                     OR ($1 = 'name' AND lower(n.name) LIKE '%' || lower($2) || '%')
                     OR ($1 = 'cve' AND lower(coalesce(n.cve, '')) LIKE '%' || lower($2) || '%')
                     OR ($1 = 'qod_type' AND lower(coalesce(n.qod_type, '')) = lower($2))
                     OR ($1 = 'solution_type' AND lower(coalesce(n.solution_type, '')) = lower($2))
                     OR ($1 = 'search'
                         AND (lower(n.oid) LIKE '%' || lower($2) || '%'
                              OR lower(n.name) LIKE '%' || lower($2) || '%'
                              OR lower(n.family) LIKE '%' || lower($2) || '%'
                              OR lower(coalesce(n.cve, '')) LIKE '%' || lower($2) || '%')))
         ),
         page_rows AS (
             SELECT count(*) OVER()::bigint AS total, * FROM filtered
              ORDER BY {sort_sql}, name ASC, oid ASC LIMIT $3 OFFSET $4
         ),
         page_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs
               FROM page_rows p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.oid
               ) refs ON true
         )
         SELECT *, cardinality(cves)::bigint AS cve_refs FROM page_with_refs;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &filter_mode,
                &filter_value,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "NVT catalog list query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&filter_mode, &filter_value, &probe_page_size, &probe_offset],
        "NVT catalog list",
    )
    .await?;
    let items = rows.iter().map(nvt_catalog_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

fn nvt_filter_parts(raw: &str) -> (&'static str, String) {
    for key in [
        "family",
        "category",
        "discovery",
        "name",
        "cve",
        "qod_type",
        "solution_type",
    ] {
        if let Some(value) = raw.strip_prefix(&format!("{key}=")) {
            return (key, value.trim_matches('"').to_string());
        }
    }
    ("search", raw.to_string())
}

pub(crate) async fn nvt_catalog_detail(
    State(state): State<AppState>,
    Path(nvt_id): Path<String>,
) -> Result<Json<NvtCatalogDetail>, ApiError> {
    validate_nvt_oid(&nvt_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"WITH nvt_row AS (
             SELECT n.oid AS id,
                    n.oid AS oid,
                    coalesce(n.name, '') AS name,
                    coalesce(n.comment, '') AS comment,
                    coalesce(n.summary, '') AS summary,
                    coalesce(n.insight, '') AS insight,
                    coalesce(n.affected, '') AS affected,
                    coalesce(n.impact, '') AS impact,
                    coalesce(n.detection, '') AS detection,
                    coalesce(n.family, '') AS family,
                    coalesce(n.category, '') AS category,
                    coalesce(n.discovery, 0)::bigint AS discovery,
                    coalesce(n.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(n.modification_time, 0)::bigint AS modified_at_unix,
                    CASE
                      WHEN coalesce(n.cvss_base, '') ~ '^-?[0-9]+(\.[0-9]+)?$'
                      THEN n.cvss_base::double precision
                      ELSE 0::double precision
                    END AS severity,
                    coalesce(n.qod, 0)::bigint AS qod,
                    coalesce(n.qod_type, '') AS qod_type,
                    coalesce(n.solution_type, '') AS solution_type,
                    coalesce(n.solution_method, '') AS solution_method,
                    coalesce(n.solution, '') AS solution,
                    coalesce(n.tag, '') AS tags,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    coalesce(n.epss_cve, '') AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    coalesce(n.max_epss_cve, '') AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity
               FROM nvts n
              WHERE n.oid = $1
         ),
         row_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs
               FROM nvt_row p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.oid
               ) refs ON true
         )
         SELECT *, cardinality(cves)::bigint AS cve_refs FROM row_with_refs;"#,
            &[&nvt_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "NVT catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let default_timeout = nvt_catalog_default_timeout(&client, &nvt_id).await?;
    let preferences = nvt_catalog_preferences(&client, &nvt_id).await?;
    let user_tags = catalog_user_tags(&client, "nvt", &nvt_id).await?;
    Ok(Json(nvt_catalog_detail_from_row(
        &row,
        default_timeout,
        preferences,
        user_tags,
    )))
}

async fn nvt_catalog_default_timeout(
    client: &tokio_postgres::Client,
    nvt_id: &str,
) -> Result<Option<String>, ApiError> {
    let row = client
        .query_opt(
            r#"SELECT value
                 FROM nvt_preferences
                WHERE pref_nvt = $1
                  AND pref_type = 'entry'
                  AND pref_name = 'timeout'
                ORDER BY pref_id ASC
                LIMIT 1;"#,
            &[&nvt_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "NVT default timeout query failed");
            ApiError::Database
        })?;
    Ok(row.and_then(|row| row.get::<_, Option<String>>("value")))
}

async fn nvt_catalog_preferences(
    client: &tokio_postgres::Client,
    nvt_id: &str,
) -> Result<Vec<crate::nvt_catalog_payloads::NvtCatalogPreference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT coalesce(pref_id, 0)::bigint AS id,
                      coalesce(pref_name, '') AS name,
                      CASE
                        WHEN coalesce(pref_name, '') = 'timeout' THEN 'Timeout'
                        ELSE coalesce(pref_name, '')
                      END AS hr_name,
                      coalesce(pref_type, '') AS type,
                      CASE
                        WHEN pref_type = 'password' THEN ''
                        ELSE coalesce(value, '')
                      END AS value,
                      CASE
                        WHEN pref_type = 'password' THEN ''
                        ELSE coalesce(value, '')
                      END AS default
                 FROM nvt_preferences
                WHERE pref_nvt = $1
                  AND name != 'cache_folder'
                  AND name != 'include_folders'
                  AND name != 'nasl_no_signature_check'
                  AND name != 'network_targets'
                  AND name != 'ntp_save_sessions'
                  AND name NOT ILIKE 'server_info_%'
                  AND name != 'max_checks'
                  AND name != 'max_hosts'
                  AND NOT (pref_type = 'entry' AND pref_name = 'timeout')
                ORDER BY name ASC;"#,
            &[&nvt_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "NVT preferences query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(nvt_catalog_preference_from_row).collect())
}

pub(crate) async fn nvt_catalog_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<NvtCatalogDetail>, ApiError> {
    nvt_catalog_detail(state, path).await
}
