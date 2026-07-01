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
        SCOPE_REPORT_TLS_CERTIFICATE_DEFAULT_SORT, SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS,
    },
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::{TlsCertificateItem, tls_certificate_from_row},
    scope_report_lookup::scope_report_exists,
};

pub(crate) async fn scope_report_tls_certificates(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_TLS_CERTIFICATE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS)?;
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
         tls_rows AS (\n\
             SELECT c.uuid AS id,\n\
                    coalesce(c.sha256_fingerprint, '') AS fingerprint_sha256,\n\
                    coalesce(c.subject_dn, '') AS subject,\n\
                    coalesce(c.issuer_dn, '') AS issuer,\n\
                    coalesce(c.serial, '') AS serial,\n\
                    coalesce(c.activation_time, 0)::bigint AS not_before_unix,\n\
                    coalesce(c.expiration_time, 0)::bigint AS not_after_unix,\n\
                    count(DISTINCT lower(loc.host_ip))::bigint AS host_count,\n\
                    count(DISTINCT loc.port)::bigint AS port_count,\n\
                    count(DISTINCT src.uuid)::bigint AS result_count,\n\
                    array_remove(array_agg(DISTINCT origin.origin_id), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN tls_certificate_origins origin\n\
                 ON origin.origin_type = 'Report'\n\
                AND origin.origin_id = srs.source_report_uuid\n\
               JOIN tls_certificate_sources src ON src.origin = origin.id\n\
               JOIN tls_certificates c ON c.id = src.tls_certificate\n\
               JOIN tls_certificate_locations loc ON loc.id = src.location\n\
               JOIN selected_hosts sh ON sh.host_key = lower(loc.host_ip)\n\
              GROUP BY c.uuid, c.sha256_fingerprint, c.subject_dn, c.issuer_dn,\n\
                       c.serial, c.activation_time, c.expiration_time\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM tls_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(fingerprint_sha256) LIKE '%' || lower($3) || '%'\n\
                     OR lower(subject) LIKE '%' || lower($3) || '%'\n\
                     OR lower(issuer) LIKE '%' || lower($3) || '%'\n\
                     OR lower(serial) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $4 OFFSET $5;"
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
            tracing::warn!(%error, "scope report TLS certificate query failed");
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
        "scope report TLS certificate list",
    )
    .await?;
    let items = rows.iter().map(tls_certificate_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
