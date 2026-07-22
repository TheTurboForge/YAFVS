// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, override_write_sql::*, path_ids::parse_uuid,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
    pub(crate) nvt: String,
    pub(crate) task_id: i32,
    pub(crate) result_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideTrashState {
    pub(crate) write_state: OverrideWriteState,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

pub(crate) async fn load_override_trash_state(
    tx: &Transaction<'_>,
    override_id: &str,
) -> Result<OverrideTrashState, ApiError> {
    let override_id = parse_uuid(override_id)?.to_string();
    tx.query_opt(override_trash_state_sql(), &[&override_id])
        .await
        .map_err(|error| map_override_write_db_error(error, "load override trash state"))?
        .map(|row| OverrideTrashState {
            write_state: OverrideWriteState {
                internal_id: row.get(0),
                owner_id: row.get(1),
                nvt: row.get(2),
                task_id: row.get(3),
                result_id: row.get(4),
            },
            uuid: row.get(5),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_override_live_uuid_available(
    tx: &Transaction<'_>,
    override_id: &str,
) -> Result<(), ApiError> {
    let exists: bool = tx
        .query_one(override_live_uuid_conflict_sql(), &[&override_id])
        .await
        .map_err(|error| map_override_write_db_error(error, "check override live UUID"))?
        .get(0);
    if exists {
        Err(ApiError::Conflict(
            "a live override already uses this id".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideResultScope {
    pub(crate) internal_id: i32,
    pub(crate) task_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideTrashRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

pub(crate) async fn ensure_override_nvt_exists(
    tx: &Transaction<'_>,
    nvt_id: &str,
) -> Result<(), ApiError> {
    let exists: bool = tx
        .query_one(override_nvt_exists_sql(), &[&nvt_id])
        .await
        .map_err(|error| map_override_write_db_error(error, "validate override NVT"))?
        .get(0);
    if exists {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "nvt_id does not identify an available NVT or CVE".to_string(),
        ))
    }
}

pub(crate) async fn resolve_override_task_scope(
    tx: &Transaction<'_>,
    task_uuid: &str,
) -> Result<i32, ApiError> {
    let row = tx
        .query_opt(override_task_scope_sql(), &[&task_uuid])
        .await
        .map_err(|error| map_override_write_db_error(error, "resolve override task scope"))?
        .ok_or_else(|| ApiError::BadRequest("task_id was not found".to_string()))?;
    let task_id: i32 = row.get(0);
    let owner_id: Option<i32> = row.get(1);
    ensure_override_is_human_owned(owner_id)?;
    Ok(task_id)
}

pub(crate) async fn resolve_override_result_scope(
    tx: &Transaction<'_>,
    result_uuid: &str,
) -> Result<OverrideResultScope, ApiError> {
    let row = tx
        .query_opt(override_result_scope_sql(), &[&result_uuid])
        .await
        .map_err(|error| map_override_write_db_error(error, "resolve override result scope"))?
        .ok_or_else(|| ApiError::BadRequest("result_id was not found".to_string()))?;
    let owner_id: Option<i32> = row.get(2);
    ensure_override_is_human_owned(owner_id)?;
    Ok(OverrideResultScope {
        internal_id: row.get(0),
        task_id: row.get(1),
    })
}

pub(crate) async fn load_override_result_scope(
    tx: &Transaction<'_>,
    result_id: i32,
) -> Result<OverrideResultScope, ApiError> {
    let row = tx
        .query_opt(override_result_scope_by_internal_id_sql(), &[&result_id])
        .await
        .map_err(|error| map_override_write_db_error(error, "load override result scope"))?
        .ok_or_else(|| ApiError::Conflict("the override result no longer exists".to_string()))?;
    let owner_id: Option<i32> = row.get(2);
    ensure_override_is_human_owned(owner_id)?;
    Ok(OverrideResultScope {
        internal_id: row.get(0),
        task_id: row.get(1),
    })
}

pub(crate) fn ensure_override_task_result_match(
    task_id: i32,
    result: Option<&OverrideResultScope>,
) -> Result<(), ApiError> {
    if let Some(result) = result {
        if task_id != 0 && result.task_id != 0 && task_id != result.task_id {
            return Err(ApiError::BadRequest(
                "task_id and result_id must refer to the same task".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn query_override_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<OverrideWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_override_write_db_error(error, action))?
        .map(|row| OverrideWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
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

pub(crate) fn ensure_override_is_human_owned(
    override_owner_id: Option<i32>,
) -> Result<i32, ApiError> {
    override_owner_id.ok_or_else(|| {
        tracing::warn!("direct API override write rejected an ownerless override or scope");
        ApiError::Forbidden
    })
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
