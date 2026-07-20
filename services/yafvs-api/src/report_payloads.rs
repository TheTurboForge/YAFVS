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
    collections::{REPORT_DEFAULT_SORT, REPORT_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
    report_evidence_payloads::ReportSeverityCounts,
    user_tags::ReportUserTag,
};

pub(crate) fn normalize_report_task_id(task_id: Option<&str>) -> Result<String, ApiError> {
    let Some(task_id) = task_id else {
        return Ok(String::new());
    };
    let task_id = task_id.trim();
    if task_id.is_empty() {
        return Err(ApiError::BadRequest("task_id must be a UUID".to_string()));
    }
    parse_uuid(task_id)
        .map(|task_id| task_id.to_string())
        .map_err(|_| ApiError::BadRequest("task_id must be a UUID".to_string()))
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct ReportOwner {
    name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportItem {
    id: String,
    name: String,
    owner: ReportOwner,
    status: String,
    progress: i64,
    task: Option<ReportReference>,
    target: Option<ReportReference>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    creation_time: Option<String>,
    modification_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    host_count: i64,
    cve_count: i64,
    severity: ReportSeverityCounts,
    max_severity: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) fn report_reference(
    id: Option<String>,
    name: Option<String>,
) -> Option<ReportReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(ReportReference { id, name })
}

pub(crate) fn report_from_row(row: &Row) -> ReportItem {
    ReportItem {
        id: row.get(1),
        name: row.get(2),
        owner: ReportOwner { name: row.get(3) },
        task: report_reference(row.get(4), row.get(5)),
        target: report_reference(row.get(6), row.get(7)),
        status: row.get(8),
        creation_time: unix_ts_to_rfc3339(row.get(9)),
        scan_start: unix_ts_to_rfc3339(row.get(10)),
        scan_end: unix_ts_to_rfc3339(row.get(11)),
        modification_time: unix_ts_to_rfc3339(row.get(12)),
        result_count: row.get(13),
        vulnerability_count: row.get(14),
        host_count: row.get(15),
        cve_count: row.get(16),
        max_severity: row.get(17),
        severity: ReportSeverityCounts {
            critical: row.get(18),
            high: row.get(19),
            medium: row.get(20),
            low: row.get(21),
            log: row.get(22),
            false_positive: row.get(23),
        },
        progress: row.get(24),
        user_tags: Vec::new(),
    }
}

pub(crate) fn raw_report_sql(
    filtered_predicate: &str,
    sort_sql: &str,
    limit_clause: &str,
) -> String {
    format!(
        r#"WITH base AS (
             SELECT r.id AS report_pk,
                    r.uuid,
                    coalesce(nullif(t.name, ''), r.uuid) AS name,
                    coalesce(u.name, '') AS owner_name,
                    t.uuid AS task_uuid,
                    t.name AS task_name,
                    tg.uuid AS target_uuid,
                    tg.name AS target_name,
                    run_status_name(coalesce(r.scan_run_status, 0)) AS status,
                    coalesce(r.creation_time, 0)::bigint AS creation_time,
                    coalesce(r.start_time, 0)::bigint AS scan_start,
                    coalesce(r.end_time, 0)::bigint AS scan_end,
                    coalesce(r.modification_time, 0)::bigint AS modification_time
               FROM reports r
               LEFT JOIN tasks t ON t.id = r.task
               LEFT JOIN users u ON u.id = r.owner
               LEFT JOIN targets tg ON tg.id = t.target
              WHERE (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
         ),
         result_agg AS (
             SELECT b.report_pk,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) != -3.0)::bigint AS result_count,
                    count(DISTINCT nullif(res.nvt, '')) FILTER (WHERE coalesce(res.severity, 0) != -3.0)::bigint AS vulnerability_count,
                    coalesce(max(coalesce(res.severity, 0)) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) >= 9.0)::bigint AS severity_critical,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) >= 7.0 AND coalesce(res.severity, 0) < 9.0)::bigint AS severity_high,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) >= 4.0 AND coalesce(res.severity, 0) < 7.0)::bigint AS severity_medium,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) > 0.0 AND coalesce(res.severity, 0) < 4.0)::bigint AS severity_low,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) = 0.0)::bigint AS severity_log,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) = -1.0)::bigint AS severity_false_positive
               FROM base b
               LEFT JOIN results res ON res.report = b.report_pk
              GROUP BY b.report_pk
         ),
         host_agg AS (
             SELECT b.report_pk,
                    count(DISTINCT lower(rh.host)) FILTER (WHERE coalesce(rh.host, '') <> '')::bigint AS host_count
               FROM base b
               LEFT JOIN report_hosts rh ON rh.report = b.report_pk
              GROUP BY b.report_pk
         ),
         cve_agg AS (
             SELECT b.report_pk,
                    count(DISTINCT lower(vr.ref_id)) FILTER (WHERE coalesce(vr.ref_id, '') <> '')::bigint AS cve_count
               FROM base b
               LEFT JOIN results res ON res.report = b.report_pk AND coalesce(res.severity, 0) > 0
               LEFT JOIN vt_refs vr ON vr.vt_oid = res.nvt AND lower(vr.type) = 'cve'
              GROUP BY b.report_pk
         ),
         joined AS (
             SELECT b.report_pk, b.uuid, b.name, b.owner_name, b.task_uuid, b.task_name, b.target_uuid, b.target_name,
                    b.status, b.creation_time, b.scan_start, b.scan_end, b.modification_time,
                    coalesce(ra.result_count, 0)::bigint AS result_count,
                    coalesce(ra.vulnerability_count, 0)::bigint AS vulnerability_count,
                    coalesce(ha.host_count, 0)::bigint AS host_count,
                    coalesce(ca.cve_count, 0)::bigint AS cve_count,
                    coalesce(ra.max_severity, 0)::double precision AS max_severity,
                    coalesce(ra.severity_critical, 0)::bigint AS severity_critical,
                    coalesce(ra.severity_high, 0)::bigint AS severity_high,
                    coalesce(ra.severity_medium, 0)::bigint AS severity_medium,
                    coalesce(ra.severity_low, 0)::bigint AS severity_low,
                    coalesce(ra.severity_log, 0)::bigint AS severity_log,
                    coalesce(ra.severity_false_positive, 0)::bigint AS severity_false_positive
               FROM base b
               LEFT JOIN result_agg ra ON ra.report_pk = b.report_pk
               LEFT JOIN host_agg ha ON ha.report_pk = b.report_pk
               LEFT JOIN cve_agg ca ON ca.report_pk = b.report_pk
         ),
         filtered AS (
             SELECT * FROM joined WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total,
                uuid, name, owner_name, task_uuid, task_name, target_uuid, target_name, status,
                creation_time, scan_start, scan_end, modification_time,
                result_count, vulnerability_count, host_count, cve_count, max_severity,
                severity_critical, severity_high, severity_medium, severity_low,
                severity_log, severity_false_positive,
                CASE WHEN status = 'Done' THEN 100::bigint
                     ELSE least(greatest(coalesce(report_progress(report_pk), 0), 0), 100)::bigint END AS progress
           FROM filtered
          ORDER BY {sort_sql}, creation_time DESC, uuid DESC {limit_clause};"#,
    )
}

async fn report_user_tags(
    client: &tokio_postgres::Client,
    report_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.value, '') AS value,
                      coalesce(t.comment, '') AS comment
                 FROM tags t
                 JOIN tag_resources tr ON tr.tag = t.id
                 JOIN reports r ON r.id = tr.resource
                WHERE lower(r.uuid) = lower($1)
                  AND tr.resource_type = 'report'
                  AND tr.resource_location = 0
                  AND coalesce(t.active, 0) = 1
                ORDER BY t.name ASC, t.uuid ASC;"#,
            &[&report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report user-tag query failed");
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

pub(crate) async fn reports(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportItem>>, ApiError> {
    let task_id = normalize_report_task_id(query.task_id.as_deref())?;
    let params = normalize_collection_query(query, REPORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_SORT_FIELDS)?;
    let sql = raw_report_sql(
        "($1 = '' OR lower(coalesce(task_uuid, '')) = lower($1))\n\
         AND ($2 = ''\n\
            OR lower(uuid) = lower($2)\n\
            OR lower(name) LIKE '%' || lower($2) || '%'\n\
            OR lower(status) LIKE '%' || lower($2) || '%'\n\
            OR lower(coalesce(task_name, '')) LIKE '%' || lower($2) || '%'\n\
            OR lower(coalesce(target_name, '')) LIKE '%' || lower($2) || '%')",
        &sort_sql,
        "LIMIT $3 OFFSET $4",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[&task_id, &params.filter, &params.page_size, &params.offset],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report list query failed");
            ApiError::Database
        })?;
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&task_id, &params.filter, &probe_page_size, &probe_offset],
        "raw report list",
    )
    .await?;
    let items = rows.iter().map(report_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_detail(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<ReportItem>, ApiError> {
    parse_uuid(&report_id)?;
    let sql = raw_report_sql("lower(uuid) = lower($1)", "creation_time DESC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&report_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut report = report_from_row(&row);
    report.user_tags = report_user_tags(&client, &report_id).await?;
    Ok(Json(report))
}
