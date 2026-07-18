// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{
        REPORT_RESULT_DEFAULT_SORT, REPORT_RESULT_SORT_FIELDS, RESULT_DEFAULT_SORT,
        RESULT_SORT_FIELDS,
    },
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        collection_total_with_empty_page_probe_params, normalize_collection_query, sort_clause,
    },
    report_helpers::raw_report_exists,
    result_payload_rows::{
        ResultItem, ResultOverrideItem, result_from_row, result_override_from_row,
    },
    result_query_sql::{result_detail_sql, result_effective_overrides_sql, result_user_tags_sql},
    user_tags::ReportUserTag,
};

pub(crate) async fn results(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    let params = normalize_collection_query(query, RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, RESULT_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH result_rows AS (
             SELECT r.uuid AS id,
                    r.id AS result_internal_id,
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
                    h.uuid AS host_asset_id,
                    nullif(r.hostname, '') AS hostname,
                    coalesce(r.port, '') AS port,
                    coalesce(r.nvt, '') AS nvt_oid,
                    coalesce(n.name, r.nvt, '') AS name,
                    nullif(n.family, '') AS nvt_family,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    n.epss_cve AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    n.max_epss_cve AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity,
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,
                    nullif(n.solution_type, '') AS solution_type,
                    nullif(n.solution, '') AS solution,
                    coalesce(r.severity, 0)::double precision AS severity,
                    coalesce(r.qod, 0)::bigint AS qod,
                    nullif(r.nvt_version, '') AS scan_nvt_version,
                    coalesce(r.date, 0)::bigint AS created_at_unix,
                    rep.uuid AS source_report_id,
                    coalesce(nullif(t.name, ''), rep.uuid) AS source_report_name,
                    t.uuid AS task_id,
                    t.name AS task_name
               FROM results r
               JOIN reports rep ON rep.id = r.report
               LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
               LEFT JOIN hosts h ON lower(h.name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))
               LEFT JOIN nvts n ON n.oid = r.nvt
              WHERE coalesce(r.severity, 0) != -3.0
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
                AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
         ),
         filtered AS (
             SELECT * FROM result_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(host) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($1) || '%'
                     OR lower(port) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_oid) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(task_name, '')) LIKE '%' || lower($1) || '%'
                     OR lower(source_report_name) LIKE '%' || lower($1) || '%')
         ),
         page_rows AS (
             SELECT count(*) OVER()::bigint AS total, * FROM filtered
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $2 OFFSET $3
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
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs,
                    coalesce(active_overrides.override_ids, ARRAY[]::text[]) AS override_ids,
                    coalesce(active_overrides.override_nvt_ids, ARRAY[]::text[]) AS override_nvt_ids,
                    coalesce(active_overrides.override_nvt_names, ARRAY[]::text[]) AS override_nvt_names,
                    coalesce(active_overrides.override_nvt_types, ARRAY[]::text[]) AS override_nvt_types,
                    coalesce(active_overrides.override_texts, ARRAY[]::text[]) AS override_texts,
                    coalesce(active_overrides.override_hosts, ARRAY[]::text[]) AS override_hosts,
                    coalesce(active_overrides.override_ports, ARRAY[]::text[]) AS override_ports,
                    coalesce(active_overrides.override_severities, ARRAY[]::double precision[]) AS override_severities,
                    coalesce(active_overrides.override_new_severities, ARRAY[]::double precision[]) AS override_new_severities,
                    coalesce(active_overrides.override_created_at_unix, ARRAY[]::bigint[]) AS override_created_at_unix,
                    coalesce(active_overrides.override_modified_at_unix, ARRAY[]::bigint[]) AS override_modified_at_unix,
                    coalesce(active_overrides.override_end_time_unix, ARRAY[]::bigint[]) AS override_end_time_unix,
                    coalesce(active_overrides.override_active_ints, ARRAY[]::integer[]) AS override_active_ints
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
                    WHERE vr.vt_oid = p.nvt_oid
               ) refs ON true
               LEFT JOIN LATERAL (
                   SELECT array_agg(m.id ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_ids,
                          array_agg(m.nvt_id ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_ids,
                          array_agg(m.nvt_name ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_names,
                          array_agg(m.nvt_type ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_types,
                          array_agg(m.text ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_texts,
                          array_agg(m.hosts ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_hosts,
                          array_agg(m.port ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_ports,
                          array_agg(m.severity ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_severities,
                          array_agg(m.new_severity ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_new_severities,
                          array_agg(m.created_at_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_created_at_unix,
                          array_agg(m.modified_at_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_modified_at_unix,
                          array_agg(m.end_time_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_end_time_unix,
                          array_agg(m.active_int ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_active_ints
                     FROM (
                         SELECT DISTINCT ON (o.id)
                                o.uuid AS id,
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
                                CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int
                           FROM result_overrides ro
                           JOIN overrides o ON o.id = ro.override
                      LEFT JOIN nvts n ON n.oid = o.nvt
                          WHERE ro.result = p.result_internal_id
                          ORDER BY o.id, coalesce(o.modification_time, o.creation_time, 0) DESC, o.uuid ASC
                     ) m
               ) active_overrides ON true
         )
         SELECT * FROM page_with_refs;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "result list")
            .await?;
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn result_detail(
    State(state): State<AppState>,
    Path(result_id): Path<String>,
) -> Result<Json<ResultItem>, ApiError> {
    parse_uuid(&result_id)?;
    let sql = result_detail_sql();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(sql, &[&result_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = result_from_row(&row);
    item.user_tags = result_user_tags(&client, &result_id).await?;
    item.overrides = result_effective_overrides(&client, &result_id).await?;
    Ok(Json(item))
}

pub(crate) async fn result_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<ResultItem>, ApiError> {
    result_detail(state, path).await
}

async fn result_user_tags(
    client: &tokio_postgres::Client,
    result_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(result_user_tags_sql(), &[&result_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result user-tag query failed");
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

async fn result_effective_overrides(
    client: &tokio_postgres::Client,
    result_id: &str,
) -> Result<Vec<ResultOverrideItem>, ApiError> {
    let rows = client
        .query(result_effective_overrides_sql(), &[&result_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result effective-override query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(result_override_from_row).collect())
}

pub(crate) async fn report_results(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_RESULT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         result_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    nullif(r.hostname, '') AS hostname,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
                    nullif(n.family, '') AS nvt_family,\n\
                    n.cve AS cve_text,\n\
                    n.epss_score::double precision AS epss_score,\n\
                    n.epss_percentile::double precision AS epss_percentile,\n\
                    n.epss_cve AS epss_cve,\n\
                    n.epss_severity::double precision AS epss_severity,\n\
                    n.max_epss_score::double precision AS max_epss_score,\n\
                    n.max_epss_percentile::double precision AS max_epss_percentile,\n\
                    n.max_epss_cve AS max_epss_cve,\n\
                    n.max_epss_severity::double precision AS max_epss_severity,\n\
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(r.qod, 0)::bigint AS qod,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix,\n\
                    sr.uuid AS source_report_id\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               LEFT JOIN nvts n ON n.oid = r.nvt\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM result_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(host) LIKE '%' || lower($2) || '%'\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($2) || '%'\n\
                     OR lower(name) LIKE '%' || lower($2) || '%')\n\
         ),\n\
         page_rows AS (\n\
             SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $3 OFFSET $4\n\
         ),\n\
         page_with_refs AS (\n\
             SELECT p.*,\n\
                    CASE\n\
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0\n\
                      THEN refs.cves\n\
                      WHEN coalesce(p.cve_text, '') <> ''\n\
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')\n\
                      ELSE ARRAY[]::text[]\n\
                    END AS cves,\n\
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,\n\
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs\n\
               FROM page_rows p\n\
               LEFT JOIN LATERAL (\n\
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs\n\
                     FROM vt_refs vr\n\
                    WHERE vr.vt_oid = p.nvt_oid\n\
               ) refs ON true\n\
         )\n\
         SELECT * FROM page_with_refs;"
    );
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
            tracing::warn!(%error, "raw report result query failed");
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
        "raw report result list",
    )
    .await?;
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
