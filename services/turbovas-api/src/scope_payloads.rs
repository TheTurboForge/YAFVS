// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::{Client, Row};

use crate::{
    app_state::AppState,
    collections::{SCOPE_DEFAULT_SORT, SCOPE_SORT_FIELDS},
    errors::ApiError,
    formatters::{normalize_protection_requirement, unix_ts_to_rfc3339},
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
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
    parse_uuid(&scope_id)?;
    let sql = scope_sql("lower(uuid) = lower($1)", "is_global DESC, name ASC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
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
    Ok(Json(scope_from_row(
        &row,
        targets,
        hosts,
        candidate_hosts,
        scope_reports,
    )))
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

#[derive(Debug, Serialize)]
pub(crate) struct ScopeSummary {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportItem {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) status: String,
    pub(crate) scope: ScopeSummary,
    pub(crate) protection_requirement: String,
    pub(crate) source_report_count: i64,
    pub(crate) source_target_count: i64,
    pub(crate) member_host_count: i64,
    pub(crate) evidence_host_count: i64,
    pub(crate) missing_host_count: i64,
    pub(crate) result_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) severity: SeverityCounts,
    pub(crate) max_severity: f64,
    pub(crate) latest_evidence_time: Option<String>,
    pub(crate) excluded_candidate_host_count: i64,
    pub(crate) creation_time: Option<String>,
    pub(crate) modification_time: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportDetail {
    #[serde(flatten)]
    pub(crate) report: ScopeReportItem,
    pub(crate) sources: Vec<ScopeReportSourceItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportSourceItem {
    pub(crate) id: String,
    pub(crate) source_report_id: String,
    pub(crate) target_id: String,
    pub(crate) target_name: String,
    pub(crate) task_id: String,
    pub(crate) task_name: String,
    pub(crate) scan_end: Option<String>,
    pub(crate) selected: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionPolicyPreview {
    pub(crate) mode: String,
    pub(crate) destructive_actions: bool,
    pub(crate) latest_completed_raw_report_retains_full_detail: bool,
    pub(crate) detail_compacted_field: String,
    pub(crate) aggregate_only_field: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionSummary {
    pub(crate) source_report_count: i64,
    pub(crate) current_full_fidelity_count: i64,
    pub(crate) future_tiered_retention_candidate_count: i64,
    pub(crate) detail_compacted_count: i64,
    pub(crate) aggregate_only_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionSource {
    pub(crate) source_report_id: String,
    pub(crate) target_id: String,
    pub(crate) target_name: String,
    pub(crate) task_id: String,
    pub(crate) task_name: String,
    pub(crate) scan_start: Option<String>,
    pub(crate) scan_end: Option<String>,
    pub(crate) selected_time: Option<String>,
    pub(crate) result_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) max_severity: f64,
    pub(crate) retention_state: String,
    pub(crate) detail_compacted: bool,
    pub(crate) aggregate_only: bool,
    pub(crate) kept_as_latest: bool,
    pub(crate) pinned_by_scope_report: bool,
    pub(crate) future_tiered_retention_candidate: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportRetentionPlan {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) scope: ScopeSummary,
    pub(crate) generated_at: Option<String>,
    pub(crate) policy: ScopeReportRetentionPolicyPreview,
    pub(crate) summary: ScopeReportRetentionSummary,
    pub(crate) sources: Vec<ScopeReportRetentionSource>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeEntity {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeCandidateHost {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) target_id: Option<String>,
    pub(crate) target_name: Option<String>,
    pub(crate) source_report_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeReportReference {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) creation_time: Option<String>,
    pub(crate) latest_evidence_time: Option<String>,
    pub(crate) source_report_count: i64,
    pub(crate) member_host_count: i64,
    pub(crate) evidence_host_count: i64,
    pub(crate) missing_host_count: i64,
    pub(crate) result_count: i64,
    pub(crate) vulnerability_count: i64,
    pub(crate) max_severity: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeItem {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) protection_requirement: String,
    pub(crate) protection_requirement_label: String,
    pub(crate) predefined: bool,
    pub(crate) global: bool,
    pub(crate) creation_time: Option<String>,
    pub(crate) modification_time: Option<String>,
    pub(crate) target_count: i64,
    pub(crate) host_count: i64,
    pub(crate) scope_report_count: i64,
    pub(crate) targets: Vec<ScopeEntity>,
    pub(crate) hosts: Vec<ScopeEntity>,
    pub(crate) candidate_hosts: Vec<ScopeCandidateHost>,
    pub(crate) scope_reports: Vec<ScopeReportReference>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SeverityCounts {
    pub(crate) high: i64,
    pub(crate) medium: i64,
    pub(crate) low: i64,
    pub(crate) log: i64,
    pub(crate) false_positive: i64,
}

pub(crate) fn scope_from_row(
    row: &Row,
    targets: Vec<ScopeEntity>,
    hosts: Vec<ScopeEntity>,
    candidate_hosts: Vec<ScopeCandidateHost>,
    scope_reports: Vec<ScopeReportReference>,
) -> ScopeItem {
    let protection = row.get::<_, String>(5);
    let predefined: i32 = row.get(6);
    let global: i32 = row.get(7);
    ScopeItem {
        id: row.get(2),
        name: row.get(3),
        comment: row.get(4),
        protection_requirement: protection.clone(),
        protection_requirement_label: normalize_protection_requirement(&protection),
        predefined: predefined != 0,
        global: global != 0,
        creation_time: unix_ts_to_rfc3339(row.get(8)),
        modification_time: unix_ts_to_rfc3339(row.get(9)),
        target_count: row.get(10),
        host_count: row.get(11),
        scope_report_count: row.get(12),
        targets,
        hosts,
        candidate_hosts,
        scope_reports,
    }
}

pub(crate) fn scope_entity_from_row(row: &Row) -> ScopeEntity {
    ScopeEntity {
        id: row.get(0),
        name: row.get(1),
    }
}

pub(crate) fn scope_candidate_host_from_row(row: &Row) -> ScopeCandidateHost {
    let name: String = row.get(0);
    ScopeCandidateHost {
        id: name.clone(),
        name,
        target_id: row.get(1),
        target_name: row.get(2),
        source_report_id: row.get(3),
    }
}

pub(crate) fn scope_report_reference_from_row(row: &Row) -> ScopeReportReference {
    let scope_name: String = row.get(1);
    ScopeReportReference {
        id: row.get(0),
        name: format!("{scope_name} scope report"),
        creation_time: unix_ts_to_rfc3339(row.get(2)),
        latest_evidence_time: unix_ts_to_rfc3339(row.get(3)),
        source_report_count: row.get(4),
        member_host_count: row.get(5),
        evidence_host_count: row.get(6),
        missing_host_count: row.get(7),
        result_count: row.get(8),
        vulnerability_count: row.get(9),
        max_severity: row.get(10),
    }
}

pub(crate) fn scope_report_from_row(row: &Row) -> ScopeReportItem {
    let scope_name: String = row.get(3);
    ScopeReportItem {
        id: row.get(1),
        name: format!("{scope_name} scope report"),
        status: "Done".to_string(),
        scope: ScopeSummary {
            id: row.get(2),
            name: scope_name,
        },
        protection_requirement: normalize_protection_requirement(&row.get::<_, String>(4)),
        source_report_count: row.get(5),
        source_target_count: row.get(6),
        member_host_count: row.get(7),
        evidence_host_count: row.get(8),
        missing_host_count: row.get(9),
        result_count: row.get(10),
        vulnerability_count: row.get(11),
        max_severity: row.get(12),
        severity: SeverityCounts {
            high: row.get(17),
            medium: row.get(18),
            low: row.get(19),
            log: row.get(20),
            false_positive: row.get(21),
        },
        latest_evidence_time: unix_ts_to_rfc3339(row.get(13)),
        excluded_candidate_host_count: row.get(14),
        creation_time: unix_ts_to_rfc3339(row.get(15)),
        modification_time: unix_ts_to_rfc3339(row.get(16)),
    }
}

pub(crate) fn scope_report_source_from_row(row: &Row) -> ScopeReportSourceItem {
    let id: i64 = row.get("id");
    ScopeReportSourceItem {
        id: id.to_string(),
        source_report_id: row.get("source_report_id"),
        target_id: row.get("target_id"),
        target_name: row.get("target_name"),
        task_id: row.get("task_id"),
        task_name: row.get("task_name"),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        selected: true,
    }
}

pub(crate) fn scope_report_retention_source_from_row(row: &Row) -> ScopeReportRetentionSource {
    let kept_as_latest: bool = row.get("kept_as_latest");
    ScopeReportRetentionSource {
        source_report_id: row.get("source_report_uuid"),
        target_id: row.get("target_uuid"),
        target_name: row.get("target_name"),
        task_id: row.get("task_uuid"),
        task_name: row.get("task_name"),
        scan_start: unix_ts_to_rfc3339(row.get("scan_start")),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        selected_time: unix_ts_to_rfc3339(row.get("selected_time")),
        result_count: row.get("result_count"),
        vulnerability_count: row.get("vulnerability_count"),
        max_severity: row.get("max_severity"),
        retention_state: if kept_as_latest {
            "current_full_fidelity".to_string()
        } else {
            "future_tiered_retention_candidate".to_string()
        },
        detail_compacted: false,
        aggregate_only: false,
        kept_as_latest,
        pinned_by_scope_report: true,
        future_tiered_retention_candidate: !kept_as_latest,
    }
}
