// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    scope_payload_rows::{
        ScopeReportRetentionPlan, ScopeReportRetentionPolicyPreview, ScopeReportRetentionSummary,
        ScopeSummary, scope_report_retention_source_from_row,
    },
};

pub(crate) async fn scope_report_retention_plan(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
) -> Result<Json<ScopeReportRetentionPlan>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let report_row = client
        .query_opt(
            "SELECT id, uuid, scope_uuid, scope_name, creation_time::bigint\n\
               FROM scope_reports\n\
              WHERE uuid = $1 AND scope_uuid = $2;",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report retention plan header query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = report_row.get(0);
    let source_rows = client
        .query(scope_report_retention_sources_sql(), &[&internal_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report retention plan source query failed");
            ApiError::Database
        })?;
    let sources: Vec<_> = source_rows
        .iter()
        .map(scope_report_retention_source_from_row)
        .collect();
    let source_report_count = sources.len() as i64;
    let current_full_fidelity_count = sources
        .iter()
        .filter(|source| source.kept_as_latest)
        .count() as i64;
    let future_tiered_retention_candidate_count = sources
        .iter()
        .filter(|source| source.future_tiered_retention_candidate)
        .count() as i64;
    let scope_name: String = report_row.get(3);
    Ok(Json(ScopeReportRetentionPlan {
        id: report_row.get(1),
        name: format!("{scope_name} scope report retention plan"),
        scope: ScopeSummary {
            id: report_row.get(2),
            name: scope_name,
        },
        generated_at: unix_ts_to_rfc3339(report_row.get(4)),
        policy: ScopeReportRetentionPolicyPreview {
            mode: "dry_run_preview".to_string(),
            destructive_actions: false,
            latest_completed_raw_report_retains_full_detail: true,
            detail_compacted_field: "detail_compacted".to_string(),
            aggregate_only_field: "aggregate_only".to_string(),
        },
        summary: ScopeReportRetentionSummary {
            source_report_count,
            current_full_fidelity_count,
            future_tiered_retention_candidate_count,
            detail_compacted_count: 0,
            aggregate_only_count: 0,
        },
        sources,
    }))
}

pub(crate) fn scope_report_retention_sources_sql() -> &'static str {
    "WITH latest_completed AS (\n\
         SELECT DISTINCT ON (task.target)\n\
                task.target AS target, reports.id AS source_report\n\
           FROM reports\n\
           JOIN tasks task ON task.id = reports.task\n\
          WHERE coalesce(task.usage_type, 'scan') = 'scan'\n\
            AND run_status_name(reports.scan_run_status) = 'Done'\n\
          ORDER BY task.target, coalesce(reports.end_time, reports.creation_time) DESC, reports.id DESC\n\
     ),\n\
     source_rows AS (\n\
         SELECT srs.source_report, srs.source_report_uuid, srs.target,\n\
                srs.target_uuid, srs.target_name, srs.task_uuid, srs.task_name,\n\
                srs.scan_start::bigint, srs.scan_end::bigint, srs.selected_time::bigint,\n\
                (lc.source_report = srs.source_report) AS kept_as_latest\n\
           FROM scope_report_sources srs\n\
           LEFT JOIN latest_completed lc ON lc.target = srs.target\n\
          WHERE srs.scope_report = $1\n\
     )\n\
     SELECT sr.source_report_uuid::text, sr.target_uuid::text,\n\
            coalesce(nullif(sr.target_name, ''), sr.target_uuid)::text AS target_name,\n\
            sr.task_uuid::text, coalesce(sr.task_name, '')::text AS task_name,\n\
            coalesce(sr.scan_start, 0)::bigint AS scan_start,\n\
            coalesce(sr.scan_end, 0)::bigint AS scan_end,\n\
            coalesce(sr.selected_time, 0)::bigint AS selected_time,\n\
            count(res.id) FILTER (WHERE coalesce(res.severity, 0) != -3.0)::bigint AS result_count,\n\
            count(DISTINCT nullif(res.nvt, '')) FILTER (WHERE coalesce(res.severity, 0) > 0)::bigint AS vulnerability_count,\n\
            coalesce(max(coalesce(res.severity, 0)) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity,\n\
            coalesce(sr.kept_as_latest, false) AS kept_as_latest\n\
       FROM source_rows sr\n\
       LEFT JOIN results res ON res.report = sr.source_report\n\
      GROUP BY sr.source_report_uuid, sr.target_uuid, sr.target_name, sr.task_uuid,\n\
               sr.task_name, sr.scan_start, sr.scan_end, sr.selected_time, sr.kept_as_latest\n\
      ORDER BY target_name ASC, sr.target_uuid ASC, scan_end DESC, sr.source_report_uuid ASC;"
}
