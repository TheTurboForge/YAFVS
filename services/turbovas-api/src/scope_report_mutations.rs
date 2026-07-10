// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::LOCATION},
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    scope_report_generation_sql::*,
    scope_reports::scope_report_detail,
    scope_write_db::{
        ensure_scope_owner_matches_operator, map_scope_write_db_error,
        require_scope_write_operator, resolve_scope_write_operator_owner,
    },
};

#[derive(Debug)]
struct ScopeReportGenerationState {
    internal_id: i32,
    owner_id: i32,
    is_global: bool,
    uuid: String,
    name: String,
    protection_requirement: String,
}

pub(crate) async fn generate_scope_report(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<crate::scope_payload_rows::ScopeReportDetail>,
    ),
    ApiError,
> {
    let operator = require_scope_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scope_write_db_error(error, "begin generate scope-report transaction")
    })?;
    let operator_owner_id = resolve_scope_write_operator_owner(&tx, &operator).await?;
    let scope = load_scope_report_generation_state(&tx, &scope_id).await?;
    ensure_scope_owner_matches_operator(scope.owner_id, operator_owner_id)?;
    let scope_report_id =
        execute_scope_report_generation_transaction(&tx, &scope, operator_owner_id).await?;
    tx.commit().await.map_err(|error| {
        map_scope_write_db_error(error, "commit generate scope-report transaction")
    })?;
    drop(client);

    let Json(detail) = scope_report_detail(State(state), Path(scope_report_id.clone())).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        LOCATION,
        HeaderValue::from_str(&format!("/api/v1/scope-reports/{scope_report_id}"))
            .map_err(|_| ApiError::Database)?,
    );
    Ok((StatusCode::CREATED, headers, Json(detail)))
}

async fn load_scope_report_generation_state(
    tx: &Transaction<'_>,
    scope_id: &str,
) -> Result<ScopeReportGenerationState, ApiError> {
    let scope_id = parse_uuid(scope_id)?.to_string();
    let row = tx
        .query_opt(scope_report_generation_state_sql(), &[&scope_id])
        .await
        .map_err(|error| map_scope_write_db_error(error, "load scope-report generation state"))?
        .ok_or(ApiError::NotFound)?;
    Ok(ScopeReportGenerationState {
        internal_id: row.get(0),
        owner_id: row.get(1),
        is_global: row.get::<_, i32>(2) != 0,
        uuid: row.get(3),
        name: row.get(4),
        protection_requirement: row.get(5),
    })
}

async fn execute_scope_report_generation_transaction(
    tx: &Transaction<'_>,
    scope: &ScopeReportGenerationState,
    operator_owner_id: i32,
) -> Result<String, ApiError> {
    let row = tx
        .query_one(
            scope_report_generation_insert_sql(),
            &[
                &scope.internal_id,
                &scope.uuid,
                &scope.name,
                &scope.protection_requirement,
                &operator_owner_id,
            ],
        )
        .await
        .map_err(|error| map_scope_write_db_error(error, "insert scope-report snapshot"))?;
    let scope_report_internal_id: i32 = row.get(0);
    let scope_report_id: String = row.get(1);
    let generation_params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &scope.internal_id,
        &scope.is_global,
        &scope_report_internal_id,
    ];
    execute_scope_report_generation_sql(
        tx,
        scope_report_generation_sources_sql(),
        generation_params,
        "insert scope-report source provenance",
    )
    .await?;
    execute_scope_report_generation_sql(
        tx,
        scope_report_generation_counts_sql(),
        &[
            &scope_report_internal_id,
            &scope.internal_id,
            &scope.is_global,
        ],
        "rebuild scope-report counts",
    )
    .await?;
    for (sql, action) in [
        (
            "DELETE FROM scope_report_system_metrics WHERE scope_report = $1;",
            "clear scope-report system metrics",
        ),
        (
            "DELETE FROM scope_report_vulnerability_metrics WHERE scope_report = $1;",
            "clear scope-report vulnerability metrics",
        ),
    ] {
        execute_scope_report_generation_sql(tx, sql, &[&scope_report_internal_id], action).await?;
    }
    for (sql, action) in [
        (
            scope_report_generation_system_metrics_sql(),
            "rebuild scope-report system metrics",
        ),
        (
            scope_report_generation_vulnerability_metrics_sql(),
            "rebuild scope-report vulnerability metrics",
        ),
    ] {
        execute_scope_report_generation_sql(
            tx,
            sql,
            &[
                &scope_report_internal_id,
                &scope.internal_id,
                &scope.is_global,
            ],
            action,
        )
        .await?;
    }
    execute_scope_report_generation_sql(
        tx,
        scope_report_generation_metric_summary_sql(),
        &[&scope_report_internal_id],
        "update scope-report metric summary",
    )
    .await?;
    Ok(scope_report_id)
}

async fn execute_scope_report_generation_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeReportDeleteState {
    internal_id: i32,
    scope_owner_id: i32,
}

pub(crate) async fn delete_scope_report(
    State(state): State<AppState>,
    Path(scope_report_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scope_write_db_error(error, "begin delete scope-report transaction")
    })?;
    let operator_owner_id = resolve_scope_write_operator_owner(&tx, &operator).await?;
    let delete_state = load_scope_report_delete_state(&tx, &scope_report_id).await?;
    ensure_scope_owner_matches_operator(delete_state.scope_owner_id, operator_owner_id)?;
    execute_scope_report_delete_transaction(&tx, delete_state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scope_write_db_error(error, "commit delete scope-report transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn load_scope_report_delete_state(
    tx: &Transaction<'_>,
    scope_report_id: &str,
) -> Result<ScopeReportDeleteState, ApiError> {
    let scope_report_id = parse_uuid(scope_report_id)?.to_string();
    let row = tx
        .query_opt(scope_report_delete_state_sql(), &[&scope_report_id])
        .await
        .map_err(|error| map_scope_write_db_error(error, "load scope-report delete state"))?
        .ok_or(ApiError::NotFound)?;

    Ok(ScopeReportDeleteState {
        internal_id: row.get(0),
        scope_owner_id: row.get(1),
    })
}

async fn execute_scope_report_delete_transaction(
    tx: &Transaction<'_>,
    scope_report_internal_id: i32,
) -> Result<(), ApiError> {
    execute_scope_report_delete_sql(
        tx,
        scope_report_delete_sources_sql(),
        &[&scope_report_internal_id],
        "delete scope-report source links",
    )
    .await?;
    let deleted = execute_scope_report_delete_sql(
        tx,
        scope_report_delete_snapshot_sql(),
        &[&scope_report_internal_id],
        "delete scope-report snapshot",
    )
    .await?;
    if deleted == 1 {
        Ok(())
    } else {
        Err(ApiError::Database)
    }
}

async fn execute_scope_report_delete_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))
}

pub(crate) fn scope_report_delete_state_sql() -> &'static str {
    "SELECT sr.id::integer, s.owner::integer
       FROM scope_reports sr
       JOIN scopes s ON s.id = sr.scope
      WHERE sr.uuid = $1;"
}

pub(crate) fn scope_report_delete_sources_sql() -> &'static str {
    "DELETE FROM scope_report_sources WHERE scope_report = $1;"
}

pub(crate) fn scope_report_delete_snapshot_sql() -> &'static str {
    "DELETE FROM scope_reports WHERE id = $1;"
}

#[cfg(test)]
#[path = "scope_report_mutations_tests.rs"]
mod scope_report_mutations_tests;
