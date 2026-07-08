// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    scope_write_db::{
        ensure_scope_owner_matches_operator, map_scope_write_db_error,
        require_scope_write_operator, resolve_scope_write_operator_owner,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeReportDeleteState {
    internal_id: i64,
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
    scope_report_internal_id: i64,
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
    "SELECT sr.id::bigint, s.owner::integer
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
