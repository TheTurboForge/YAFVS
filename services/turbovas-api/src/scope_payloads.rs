// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use tokio_postgres::Client;

use crate::{
    app_state::AppState,
    collections::{SCOPE_DEFAULT_SORT, SCOPE_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    scope_payload_rows::{
        ScopeCandidateHost, ScopeEntity, ScopeItem, ScopeReportReference,
        scope_candidate_host_from_row, scope_entity_from_row, scope_from_row,
        scope_report_reference_from_row,
    },
};

pub(crate) async fn scopes(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScopeItem>>, ApiError> {
    let params = normalize_collection_query(query, SCOPE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_SORT_FIELDS)?;
    let sql = scope_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(comment, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(protection_requirement) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope list query failed");
            ApiError::Database
        })?;
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| scope_from_row(row, Vec::new(), Vec::new(), Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scope_detail(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
) -> Result<Json<ScopeItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_scope_detail(&client, &scope_id).await?))
}

pub(crate) async fn load_scope_detail(
    client: &Client,
    scope_id: &str,
) -> Result<ScopeItem, ApiError> {
    parse_uuid(&scope_id)?;
    let sql = scope_sql("lower(uuid) = lower($1)", "is_global DESC, name ASC", "");
    let row = client
        .query_opt(&sql, &[&scope_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let scope_pk: i32 = row.get(1);
    let is_global: i32 = row.get(7);
    let global = is_global != 0;
    let targets = scope_targets(&client, scope_pk, global).await?;
    let hosts = scope_hosts(&client, scope_pk, global).await?;
    let candidate_hosts = scope_candidate_hosts(&client, scope_pk, global).await?;
    let scope_reports = scope_report_references(&client, scope_pk).await?;
    Ok(scope_from_row(
        &row,
        targets,
        hosts,
        candidate_hosts,
        scope_reports,
    ))
}

pub(crate) fn scope_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH base AS (
             SELECT s.id AS scope_pk,
                    s.uuid,
                    s.name,
                    coalesce(s.comment, '') AS comment,
                    s.protection_requirement,
                    coalesce(s.predefined, 0)::int AS predefined,
                    coalesce(s.is_global, 0)::int AS is_global,
                    coalesce(s.creation_time, 0)::bigint AS creation_time,
                    coalesce(s.modification_time, 0)::bigint AS modification_time,
                    CASE WHEN coalesce(s.is_global, 0) = 1
                         THEN (SELECT count(*) FROM targets)::bigint
                         ELSE (SELECT count(*) FROM scope_targets st WHERE st.scope = s.id)::bigint END AS target_count,
                    CASE WHEN coalesce(s.is_global, 0) = 1
                         THEN (SELECT count(*) FROM hosts)::bigint
                         ELSE (SELECT count(*) FROM scope_hosts sh WHERE sh.scope = s.id)::bigint END AS host_count,
                    (SELECT count(*) FROM scope_reports sr WHERE sr.scope = s.id)::bigint AS scope_report_count
               FROM scopes s
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total,
                scope_pk, uuid, name, comment, protection_requirement,
                predefined, is_global, creation_time, modification_time,
                target_count, host_count, scope_report_count
           FROM filtered
          ORDER BY {sort_sql}, uuid ASC {limit_clause};"#,
    )
}

async fn scope_targets(
    client: &Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeEntity>, ApiError> {
    let sql = if global {
        "SELECT uuid, coalesce(name, uuid) FROM targets ORDER BY name, uuid;"
    } else {
        "SELECT target_uuid, coalesce(target_name, target_uuid) FROM scope_targets WHERE scope = $1 ORDER BY target_name, target_uuid;"
    };
    let rows = if global {
        client.query(sql, &[]).await
    } else {
        client.query(sql, &[&scope_pk]).await
    }
    .map_err(|error| {
        tracing::warn!(%error, "scope targets query failed");
        ApiError::Database
    })?;
    Ok(rows.iter().map(scope_entity_from_row).collect())
}

async fn scope_hosts(
    client: &Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeEntity>, ApiError> {
    let sql = if global {
        "SELECT uuid, coalesce(name, uuid) FROM hosts ORDER BY name, uuid;"
    } else {
        "SELECT host_uuid, coalesce(host_name, host_uuid) FROM scope_hosts WHERE scope = $1 ORDER BY host_name, host_uuid;"
    };
    let rows = if global {
        client.query(sql, &[]).await
    } else {
        client.query(sql, &[&scope_pk]).await
    }
    .map_err(|error| {
        tracing::warn!(%error, "scope hosts query failed");
        ApiError::Database
    })?;
    Ok(rows.iter().map(scope_entity_from_row).collect())
}

pub(crate) fn scope_candidate_hosts_sql() -> &'static str {
    "WITH newest_reports AS (\n\
         SELECT DISTINCT ON (t.id) t.id AS target, r.id AS report, r.uuid AS report_uuid\n\
           FROM targets t\n\
           JOIN scope_targets st ON st.target = t.id\n\
           JOIN tasks task ON task.target = t.id\n\
           JOIN reports r ON r.task = task.id\n\
          WHERE st.scope = $1\n\
            AND coalesce(task.usage_type, 'scan') = 'scan'\n\
            AND run_status_name(coalesce(r.scan_run_status, 0)) = 'Done'\n\
          ORDER BY t.id, coalesce(r.end_time, r.creation_time) DESC, r.id DESC\n\
     )\n\
     SELECT DISTINCT rh.host::text, st.target_uuid::text, coalesce(st.target_name, st.target_uuid)::text, nr.report_uuid::text\n\
       FROM scope_targets st\n\
       JOIN newest_reports nr ON nr.target = st.target\n\
       JOIN report_hosts rh ON rh.report = nr.report\n\
      WHERE st.scope = $1\n\
        AND coalesce(rh.host, '') <> ''\n\
        AND NOT EXISTS (\n\
            SELECT 1 FROM scope_hosts sh\n\
            JOIN hosts h ON h.id = sh.host\n\
            WHERE sh.scope = $1 AND lower(h.name) = lower(rh.host)\n\
        )\n\
      ORDER BY rh.host, st.target_uuid;"
}

async fn scope_candidate_hosts(
    client: &Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeCandidateHost>, ApiError> {
    if global {
        return Ok(Vec::new());
    }
    let rows = client
        .query(scope_candidate_hosts_sql(), &[&scope_pk])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope candidate hosts query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(scope_candidate_host_from_row).collect())
}

async fn scope_report_references(
    client: &Client,
    scope_pk: i32,
) -> Result<Vec<ScopeReportReference>, ApiError> {
    let rows = client
        .query(
            "SELECT uuid, scope_name, creation_time::bigint, latest_evidence_time::bigint,\n\
                    source_report_count::bigint, member_host_count::bigint,\n\
                    evidence_host_count::bigint, missing_host_count::bigint,\n\
                    result_count::bigint, vulnerability_count::bigint,\n\
                    max_severity::double precision\n\
               FROM scope_reports\n\
              WHERE scope = $1\n\
              ORDER BY creation_time DESC, id DESC;",
            &[&scope_pk],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report references query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(scope_report_reference_from_row).collect())
}
