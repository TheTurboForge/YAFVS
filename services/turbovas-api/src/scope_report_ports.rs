// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCOPE_REPORT_PORT_DEFAULT_SORT, SCOPE_REPORT_PORT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{PortItem, port_from_row},
    scope_report_lookup::scope_report_exists,
};

pub(crate) async fn scope_report_ports(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_PORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_PORT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         port_rows AS (\n\
             SELECT coalesce(r.port, '') AS port,\n\
                    CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                         THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                         ELSE '' END AS protocol,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                AND coalesce(r.port, '') <> ''\n\
              GROUP BY coalesce(r.port, ''),\n\
                       CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                            THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                            ELSE '' END\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM port_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(protocol) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, port ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report port query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[
            &scope_report_id,
            &scope_id,
            &params.filter,
            &probe_page_size,
            &probe_offset,
        ],
        "scope report port list",
    )
    .await?;
    let items = rows.iter().map(port_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
