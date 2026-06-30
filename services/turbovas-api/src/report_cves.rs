// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{REPORT_CVE_DEFAULT_SORT, REPORT_CVE_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    report_evidence_payloads::{CveItem, cve_from_row},
    report_helpers::raw_report_exists,
};

pub(crate) async fn report_cves(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CveItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_CVE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_CVE_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         cve_rows AS (\n\
             SELECT vr.ref_id AS id,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS affected_system_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               JOIN vt_refs vr ON vr.vt_oid = r.nvt AND vr.type = 'cve'\n\
              WHERE coalesce(r.severity, 0) > 0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY vr.ref_id\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM cve_rows\n\
              WHERE ($2 = '' OR lower(id) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
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
            tracing::warn!(%error, "raw report CVE query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(cve_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
