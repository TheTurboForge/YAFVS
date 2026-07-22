// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCOPE_REPORT_HOST_DEFAULT_SORT, SCOPE_REPORT_HOST_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{HostItem, host_from_row},
    scope_report_lookup::scope_report_exists,
};

pub(crate) async fn scope_report_hosts(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<HostItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_HOST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_HOST_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         member_hosts AS (\n\
             SELECT lower(h.name) AS host_key, min(h.name) AS host\n\
               FROM selected_scope_report sr\n\
               JOIN hosts h ON sr.is_global = 1\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
             UNION\n\
             SELECT lower(srh.host_name) AS host_key, min(srh.host_name) AS host\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_hosts srh ON srh.scope_report = sr.id AND sr.is_global = 0\n\
              WHERE coalesce(srh.host_name, '') <> ''\n\
              GROUP BY lower(srh.host_name)\n\
         ),\n\
         evidence_hosts AS (\n\
             SELECT lower(rh.host) AS host_key, min(rh.host) AS host,\n\
                    count(DISTINCT srs.source_report)::bigint AS source_report_count,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
         ),\n\
         result_counts AS (\n\
             SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    count(DISTINCT (coalesce(r.nvt, ''), coalesce(r.port, '')))::bigint AS result_count\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
         ),\n\
         host_rows AS (\n\
             SELECT coalesce(m.host_key, e.host_key) AS host_key,\n\
                    coalesce(m.host, e.host) AS host,\n\
                    m.host_key IS NOT NULL AS is_member,\n\
                    e.host_key IS NOT NULL AS has_evidence,\n\
                    coalesce(e.source_report_count, 0)::bigint AS source_report_count,\n\
                    coalesce(e.source_report_ids, ARRAY[]::text[]) AS source_report_ids\n\
               FROM member_hosts m\n\
               FULL OUTER JOIN evidence_hosts e ON e.host_key = m.host_key\n\
         ),\n\
         rows AS (\n\
             SELECT hr.host,\n\
                    CASE\n\
                      WHEN sr.is_global = 1 THEN 'organization'\n\
                      WHEN hr.is_member THEN 'member'\n\
                      ELSE 'candidate'\n\
                    END AS scope_membership,\n\
                    hr.source_report_count,\n\
                    coalesce(rc.result_count, 0)::bigint AS result_count,\n\
                    coalesce(srm.vulnerability_count, 0)::bigint AS vulnerability_count,\n\
                    coalesce(nullif(srm.authentication_state, ''), 'unknown') AS authenticated_scan_state,\n\
                    hr.source_report_ids\n\
               FROM selected_scope_report sr\n\
               CROSS JOIN host_rows hr\n\
               LEFT JOIN result_counts rc ON rc.host_key = hr.host_key\n\
               LEFT JOIN scope_report_system_metrics srm\n\
                 ON srm.scope_report = sr.id AND lower(srm.host) = hr.host_key\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM rows\n\
              WHERE ($3 = '' OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(scope_membership) LIKE '%' || lower($3) || '%'\n\
                     OR lower(authenticated_scan_state) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, host ASC LIMIT $4 OFFSET $5;"
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
            tracing::warn!(%error, "scope report host query failed");
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
        "scope report host list",
    )
    .await?;
    let items = rows.iter().map(host_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
