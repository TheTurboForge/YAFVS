// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, task_write_sql::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskWriteRecordWithInternalId {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
    pub(crate) run_status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssignableTaskResource {
    pub(crate) internal_id: i32,
}

pub(crate) fn require_task_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("task write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn load_assignable_task_target(
    tx: &Transaction<'_>,
    target_id: &str,
    operator_owner_id: i32,
) -> Result<AssignableTaskResource, ApiError> {
    let row =
        load_task_resource_row(tx, task_assignable_target_state_sql(), target_id, "target").await?;
    let internal_id: i32 = row.get(0);
    let owner_id: i32 = row.get(1);
    if owner_id == operator_owner_id {
        Ok(AssignableTaskResource { internal_id })
    } else {
        tracing::warn!(
            target_owner_id = owner_id,
            operator_owner_id,
            "direct API task create operator cannot assign target"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn load_assignable_task_config(
    tx: &Transaction<'_>,
    config_id: &str,
    operator_owner_id: i32,
) -> Result<AssignableTaskResource, ApiError> {
    let row =
        load_task_resource_row(tx, task_assignable_config_state_sql(), config_id, "config").await?;
    let internal_id: i32 = row.get(0);
    let owner_id: i32 = row.get(1);
    let predefined: i32 = row.get(2);
    if predefined != 0 || owner_id == operator_owner_id {
        Ok(AssignableTaskResource { internal_id })
    } else {
        tracing::warn!(
            config_owner_id = owner_id,
            operator_owner_id,
            "direct API task create operator cannot assign scan config"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn load_assignable_task_scanner(
    tx: &Transaction<'_>,
    scanner_id: &str,
    operator_owner_id: i32,
) -> Result<AssignableTaskResource, ApiError> {
    const SCANNER_TYPE_OPENVAS: i32 = 2;
    const SCANNER_TYPE_OSP_SENSOR: i32 = 5;
    const SCANNER_TYPE_OPENVASD: i32 = 6;
    const SCANNER_TYPE_OPENVASD_SENSOR: i32 = 8;

    let row = load_task_resource_row(
        tx,
        task_assignable_scanner_state_sql(),
        scanner_id,
        "scanner",
    )
    .await?;
    let internal_id: i32 = row.get(0);
    let owner_id: Option<i32> = row.get(1);
    let scanner_type: i32 = row.get(2);
    if !matches!(
        scanner_type,
        SCANNER_TYPE_OPENVAS
            | SCANNER_TYPE_OSP_SENSOR
            | SCANNER_TYPE_OPENVASD
            | SCANNER_TYPE_OPENVASD_SENSOR
    ) {
        return Err(ApiError::BadRequest(
            "scanner_id must reference a scanner type that can run scan tasks".to_string(),
        ));
    }
    if owner_id.is_none() || owner_id == Some(operator_owner_id) {
        Ok(AssignableTaskResource { internal_id })
    } else {
        tracing::warn!(
            scanner_owner_id = ?owner_id,
            operator_owner_id,
            "direct API task create operator cannot assign scanner"
        );
        Err(ApiError::Forbidden)
    }
}

async fn load_task_resource_row(
    tx: &Transaction<'_>,
    sql: &str,
    resource_id: &str,
    resource_name: &'static str,
) -> Result<tokio_postgres::Row, ApiError> {
    let resource_id = parse_uuid(resource_id)?.to_string();
    tx.query_opt(sql, &[&resource_id])
        .await
        .map_err(|error| map_task_write_db_error(error, resource_name))?
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn resolve_task_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(task_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_task_write_db_error(error, "resolve task write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API task write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn query_task_write_record_with_internal_id(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TaskWriteRecordWithInternalId, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_task_write_db_error(error, action))?
        .map(|row| TaskWriteRecordWithInternalId {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_task_write_state(
    tx: &Transaction<'_>,
    task_id: &str,
) -> Result<TaskWriteState, ApiError> {
    let task_id = parse_uuid(task_id)?.to_string();
    tx.query_opt(task_write_state_sql(), &[&task_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "load task write state"))?
        .map(|row| TaskWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
            run_status: row.get(2),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_task_not_in_use_for_native_trash(run_status: i32) -> Result<(), ApiError> {
    const TASK_STATUS_DELETE_REQUESTED: i32 = 0;
    const TASK_STATUS_REQUESTED: i32 = 3;
    const TASK_STATUS_RUNNING: i32 = 4;
    const TASK_STATUS_STOP_REQUESTED: i32 = 10;
    const TASK_STATUS_STOP_WAITING: i32 = 11;
    const TASK_STATUS_DELETE_ULTIMATE_REQUESTED: i32 = 14;
    const TASK_STATUS_DELETE_WAITING: i32 = 16;
    const TASK_STATUS_DELETE_ULTIMATE_WAITING: i32 = 17;
    const TASK_STATUS_QUEUED: i32 = 18;
    const TASK_STATUS_PROCESSING: i32 = 19;

    match run_status {
        TASK_STATUS_DELETE_REQUESTED
        | TASK_STATUS_REQUESTED
        | TASK_STATUS_RUNNING
        | TASK_STATUS_STOP_REQUESTED
        | TASK_STATUS_STOP_WAITING
        | TASK_STATUS_DELETE_ULTIMATE_REQUESTED
        | TASK_STATUS_DELETE_WAITING
        | TASK_STATUS_DELETE_ULTIMATE_WAITING
        | TASK_STATUS_QUEUED
        | TASK_STATUS_PROCESSING => Err(ApiError::Conflict(
            "native task trash move is only available for non-running tasks".to_string(),
        )),
        _ => Ok(()),
    }
}

pub(crate) async fn ensure_unique_task_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            task_unique_name_sql(),
            &[&name, &except_internal_id, &owner_id],
        )
        .await
        .map_err(|error| map_task_write_db_error(error, "check task name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "task with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn execute_task_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_task_write_db_error(error, action))
}

pub(crate) fn ensure_task_owner_matches_operator(
    task_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if task_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!("direct API task write operator does not own task");
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn query_task_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TaskWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_task_write_db_error(error, action))?
        .map(|row| TaskWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_task_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "task write database operation failed");
    ApiError::Database
}
