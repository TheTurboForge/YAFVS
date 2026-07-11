// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, override_write_sql::*, path_ids::parse_uuid,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
    pub(crate) nvt: String,
    pub(crate) task_id: i32,
    pub(crate) result_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideTrashRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

pub(crate) fn require_override_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("override write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_override_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        override_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_override_write_db_error(error, "resolve override write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!(
                "direct API override write operator does not resolve to a database user"
            );
            ApiError::Forbidden
        })
}

pub(crate) async fn load_override_write_state(
    tx: &Transaction<'_>,
    override_id: &str,
) -> Result<OverrideWriteState, ApiError> {
    let override_id = parse_uuid(override_id)?.to_string();
    tx.query_opt(override_write_state_sql(), &[&override_id])
        .await
        .map_err(|error| map_override_write_db_error(error, "load override write state"))?
        .map(|row| OverrideWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
            nvt: row.get(2),
            task_id: row.get(3),
            result_id: row.get(4),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_override_owner_matches_operator(
    override_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if override_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!(
            override_owner_id,
            operator_owner_id,
            "direct API override write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn load_override_affected_reports(
    tx: &Transaction<'_>,
    state: &OverrideWriteState,
) -> Result<Vec<i32>, ApiError> {
    tx.query(
        override_affected_reports_sql(),
        &[&state.nvt, &state.task_id, &state.result_id],
    )
    .await
    .map_err(|error| map_override_write_db_error(error, "load override affected reports"))
    .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
}

pub(crate) async fn query_override_trash_record(
    tx: &Transaction<'_>,
    live_internal_id: i32,
) -> Result<OverrideTrashRecord, ApiError> {
    tx.query_opt(override_trash_insert_sql(), &[&live_internal_id])
        .await
        .map_err(|error| map_override_write_db_error(error, "move override metadata to trash"))?
        .map(|row| OverrideTrashRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn execute_override_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_override_write_db_error(error, action))
}

pub(crate) fn map_override_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "override write database operation failed");
    ApiError::Database
}
