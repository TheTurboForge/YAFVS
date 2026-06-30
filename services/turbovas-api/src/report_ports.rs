// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{REPORT_PORT_DEFAULT_SORT, REPORT_PORT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    report_evidence_payloads::{PortItem, port_from_row},
    report_helpers::raw_report_exists,
};

pub(crate) async fn report_ports(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_PORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_PORT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
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
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
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
              WHERE ($2 = ''\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(protocol) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, port ASC LIMIT $3 OFFSET $4;"
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
            tracing::warn!(%error, "raw report port query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(port_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
