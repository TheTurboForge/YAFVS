// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    collections::{
        CPE_CATALOG_DEFAULT_SORT, CPE_CATALOG_SORT_FIELDS, CVE_CATALOG_DEFAULT_SORT,
        CVE_CATALOG_SORT_FIELDS, NVT_CATALOG_DEFAULT_SORT, NVT_CATALOG_SORT_FIELDS,
    },
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    nvt_payloads::{NvtEpssItem, nvt_epss_from_row, nvt_max_severity_from_row},
    path_ids::{validate_cpe_id, validate_cve_id, validate_nvt_oid},
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    user_tags::{ReportUserTag, catalog_user_tags, catalog_user_tags_for_aliases},
};

#[derive(Debug, Serialize)]
struct CatalogEpssItem {
    score: f64,
    percentile: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveCertReference {
    pub(crate) name: String,
    pub(crate) title: String,
    #[serde(rename = "type")]
    pub(crate) cert_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveNvtReference {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveItem {
    id: String,
    name: String,
    comment: String,
    description: String,
    cvss_base_vector: String,
    severity: f64,
    products: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) cert_refs: Vec<CatalogCveCertReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) nvt_refs: Vec<CatalogCveNvtReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss: Option<CatalogEpssItem>,
    published_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCveDetail {
    #[serde(flatten)]
    pub(crate) item: CatalogCveItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeCveItem {
    id: String,
    severity: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    cpe_name_id: String,
    deprecated: bool,
    deprecated_by: Option<String>,
    severity: f64,
    cve_refs: i64,
    cves: Vec<CatalogCpeCveItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatalogCpeDetail {
    #[serde(flatten)]
    pub(crate) item: CatalogCpeItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) async fn cpe_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CatalogCpeItem>>, ApiError> {
    let params = normalize_collection_query(query, CPE_CATALOG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CPE_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH cpe_rows AS (
             SELECT c.uuid AS id,
                    c.name AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.title, '') AS title,
                    coalesce(c.cpe_name_id, '') AS cpe_name_id,
                    coalesce(c.deprecated, 0)::integer AS deprecated_int,
                    coalesce(c.severity, 0)::double precision AS severity,
                    coalesce(c.cve_refs, 0)::bigint AS cve_refs,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM scap.cpes c
         ),
         filtered AS (
             SELECT * FROM cpe_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%'
                     OR lower(cpe_name_id) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| catalog_cpe_from_row(row, Vec::new(), None))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn cpe_catalog_detail(
    State(state): State<AppState>,
    Path(cpe_id): Path<String>,
) -> Result<Json<CatalogCpeDetail>, ApiError> {
    let cpe_id = cpe_id.strip_prefix('/').unwrap_or(&cpe_id).to_string();
    validate_cpe_id(&cpe_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.uuid AS id,
                      c.name AS name,
                      coalesce(c.comment, '') AS comment,
                      coalesce(c.title, '') AS title,
                      coalesce(c.cpe_name_id, '') AS cpe_name_id,
                      coalesce(c.deprecated, 0)::integer AS deprecated_int,
                      coalesce(c.severity, 0)::double precision AS severity,
                      coalesce(c.cve_refs, 0)::bigint AS cve_refs,
                      coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                 FROM scap.cpes c
                WHERE c.uuid = $1 OR c.name = $1
                LIMIT 1;"#,
            &[&cpe_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let cpe_uuid: String = row.get("id");
    let cpe_name: String = row.get("name");
    let cves = client
        .query(
            r#"SELECT cv.name AS id,
                      coalesce(cv.severity, 0)::double precision AS severity
                 FROM scap.cves cv
                 JOIN scap.affected_products ap ON ap.cve = cv.id
                 JOIN scap.cpes c ON c.id = ap.cpe
                WHERE c.uuid = $1 OR c.name = $1
                ORDER BY severity DESC, cv.name ASC;"#,
            &[&cpe_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog CVE reference query failed");
            ApiError::Database
        })?
        .iter()
        .map(catalog_cpe_cve_from_row)
        .collect();
    let deprecated_by = client
        .query_opt(
            r#"SELECT deprecated_by
                 FROM scap.cpes_deprecated_by
                WHERE cpe = $1
                ORDER BY deprecated_by
                LIMIT 1;"#,
            &[&cpe_name],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog deprecated-by query failed");
            ApiError::Database
        })?
        .map(|row| row.get("deprecated_by"));

    let cpe_tag_ids = vec![cpe_uuid, cpe_name.clone()];
    let user_tags = catalog_user_tags_for_aliases(&client, "cpe", &cpe_tag_ids).await?;
    Ok(Json(CatalogCpeDetail {
        item: catalog_cpe_from_row(&row, cves, deprecated_by),
        user_tags,
    }))
}

pub(crate) async fn cve_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CatalogCveItem>>, ApiError> {
    let params = normalize_collection_query(query, CVE_CATALOG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CVE_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH cve_rows AS (
             SELECT c.name AS id,
                    c.name AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.description, '') AS description,
                    coalesce(c.cvss_vector, '') AS cvss_base_vector,
                    coalesce(c.severity, 0)::double precision AS severity,
                    coalesce(c.products, '') AS products,
                    e.epss::double precision AS epss_score,
                    e.percentile::double precision AS epss_percentile,
                    coalesce(c.creation_time, 0)::bigint AS published_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM scap.cves c
               LEFT JOIN scap.epss_scores e ON e.cve = c.name
         ),
         filtered AS (
             SELECT * FROM cve_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(description) LIKE '%' || lower($1) || '%'
                     OR lower(cvss_base_vector) LIKE '%' || lower($1) || '%'
                     OR lower(products) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(catalog_cve_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn cve_catalog_detail(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
) -> Result<Json<CatalogCveDetail>, ApiError> {
    validate_cve_id(&cve_id)?;
    let sql = r#"SELECT c.name AS id,
                        c.name AS name,
                        coalesce(c.comment, '') AS comment,
                        coalesce(c.description, '') AS description,
                        coalesce(c.cvss_vector, '') AS cvss_base_vector,
                        coalesce(c.severity, 0)::double precision AS severity,
                        coalesce(c.products, '') AS products,
                        e.epss::double precision AS epss_score,
                        e.percentile::double precision AS epss_percentile,
                        coalesce(c.creation_time, 0)::bigint AS published_at_unix,
                        coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                   FROM scap.cves c
                   LEFT JOIN scap.epss_scores e ON e.cve = c.name
                  WHERE lower(c.name) = lower($1)
                  LIMIT 1;"#;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(sql, &[&cve_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = catalog_cve_from_row(&row);
    item.cert_refs = cve_cert_refs(&client, &cve_id).await?;
    item.nvt_refs = cve_nvt_refs(&client, &cve_id).await?;
    let user_tags = catalog_user_tags(&client, "cve", &cve_id).await?;
    Ok(Json(CatalogCveDetail { item, user_tags }))
}

async fn cve_cert_refs(
    client: &tokio_postgres::Client,
    cve_id: &str,
) -> Result<Vec<CatalogCveCertReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT *
                 FROM (
                       SELECT 'CERT-Bund'::text AS cert_type,
                              d.name AS name,
                              coalesce(d.title, '') AS title
                         FROM cert.cert_bund_cves dc
                         JOIN cert.cert_bund_advs d ON d.id = dc.adv_id
                        WHERE lower(dc.cve_name) = lower($1)
                        UNION ALL
                       SELECT 'DFN-CERT'::text AS cert_type,
                              d.name AS name,
                              coalesce(d.title, '') AS title
                         FROM cert.dfn_cert_cves dc
                         JOIN cert.dfn_cert_advs d ON d.id = dc.adv_id
                        WHERE lower(dc.cve_name) = lower($1)
                      ) refs
                ORDER BY cert_type ASC, name ASC;"#,
            &[&cve_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog CERT reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveCertReference {
            cert_type: row.get("cert_type"),
            name: row.get("name"),
            title: row.get("title"),
        })
        .collect())
}

async fn cve_nvt_refs(
    client: &tokio_postgres::Client,
    cve_id: &str,
) -> Result<Vec<CatalogCveNvtReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT DISTINCT n.oid AS id,
                              coalesce(nullif(n.name, ''), n.oid) AS name
                 FROM vt_refs vr
                 JOIN nvts n ON n.oid = vr.vt_oid
                WHERE lower(vr.ref_id) = lower($1)
                  AND lower(vr.type) IN ('cve', 'cve_id')
                ORDER BY name ASC, id ASC;"#,
            &[&cve_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog NVT reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveNvtReference {
            id: row.get("id"),
            name: row.get("name"),
        })
        .collect())
}

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
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(nvt_catalog_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

fn nvt_filter_parts(raw: &str) -> (&'static str, String) {
    for key in ["family", "name", "cve", "qod_type", "solution_type"] {
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
    let user_tags = catalog_user_tags(&client, "nvt", &nvt_id).await?;
    Ok(Json(nvt_catalog_detail_from_row(&row, user_tags)))
}

#[derive(Debug, Serialize)]
pub(crate) struct NvtCatalogItem {
    id: String,
    oid: String,
    name: String,
    family: String,
    severity: f64,
    qod: i64,
    qod_type: String,
    solution_type: String,
    solution_method: String,
    solution: String,
    tags: String,
    cve_refs: i64,
    cves: Vec<String>,
    cert_refs: Vec<String>,
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct NvtCatalogDetail {
    #[serde(flatten)]
    catalog: NvtCatalogItem,
    comment: String,
    summary: String,
    insight: String,
    affected: String,
    impact: String,
    detection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

fn split_catalog_products(value: String) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|product| !product.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn catalog_cve_from_row(row: &Row) -> CatalogCveItem {
    let epss_score: Option<f64> = row.get("epss_score");
    let epss_percentile: Option<f64> = row.get("epss_percentile");
    CatalogCveItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        description: row.get("description"),
        cvss_base_vector: row.get("cvss_base_vector"),
        severity: row.get("severity"),
        products: split_catalog_products(row.get("products")),
        cert_refs: Vec::new(),
        nvt_refs: Vec::new(),
        epss: epss_score
            .zip(epss_percentile)
            .map(|(score, percentile)| CatalogEpssItem { score, percentile }),
        published_at: unix_ts_to_rfc3339(row.get("published_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn catalog_cpe_cve_from_row(row: &Row) -> CatalogCpeCveItem {
    CatalogCpeCveItem {
        id: row.get("id"),
        severity: row.get("severity"),
    }
}

pub(crate) fn catalog_cpe_from_row(
    row: &Row,
    cves: Vec<CatalogCpeCveItem>,
    deprecated_by: Option<String>,
) -> CatalogCpeItem {
    let deprecated_int: i32 = row.get("deprecated_int");
    CatalogCpeItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        cpe_name_id: row.get("cpe_name_id"),
        deprecated: deprecated_int != 0,
        deprecated_by,
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn nvt_catalog_from_row(row: &Row) -> NvtCatalogItem {
    NvtCatalogItem {
        id: row.get("id"),
        oid: row.get("oid"),
        name: row.get("name"),
        family: row.get("family"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        qod_type: row.get("qod_type"),
        solution_type: row.get("solution_type"),
        solution_method: row.get("solution_method"),
        solution: row.get("solution"),
        tags: row.get("tags"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        cert_refs: row.get("cert_refs"),
        xrefs: row.get("xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn nvt_catalog_detail_from_row(
    row: &Row,
    user_tags: Vec<ReportUserTag>,
) -> NvtCatalogDetail {
    NvtCatalogDetail {
        catalog: nvt_catalog_from_row(row),
        comment: row.get("comment"),
        summary: row.get("summary"),
        insight: row.get("insight"),
        affected: row.get("affected"),
        impact: row.get("impact"),
        detection: row.get("detection"),
        user_tags,
    }
}
