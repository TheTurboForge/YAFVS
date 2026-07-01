// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, schedule_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleTrashWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleTrashWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_schedule_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("schedule write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_schedule_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        schedule_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "resolve schedule write operator"))?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!("direct API schedule write operator does not resolve to a database user");
        ApiError::Forbidden
    })
}

pub(crate) async fn load_schedule_write_state(
    tx: &Transaction<'_>,
    schedule_id: &str,
) -> Result<ScheduleWriteState, ApiError> {
    let schedule_id = parse_uuid(schedule_id)?.to_string();
    tx.query_opt(schedule_write_state_sql(), &[&schedule_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "load schedule write state"))?
        .map(|row| ScheduleWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_schedule_owner_matches_operator(
    schedule_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if schedule_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!(
            schedule_owner_id,
            operator_owner_id,
            "direct API schedule write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn load_schedule_trash_state(
    tx: &Transaction<'_>,
    schedule_id: &str,
) -> Result<ScheduleTrashWriteState, ApiError> {
    let schedule_id = parse_uuid(schedule_id)?.to_string();
    tx.query_opt(schedule_trash_state_sql(), &[&schedule_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "load schedule trash state"))?
        .map(|row| ScheduleTrashWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_schedule_not_in_use_by_live_tasks(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_live_task_count_sql(), &[&schedule_internal_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check schedule task usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule is still referenced by a live task".to_string(),
        ))
    }
}

pub(crate) async fn ensure_schedule_not_in_use_by_trash_tasks(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_trash_task_count_sql(), &[&schedule_internal_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check schedule trash task usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule is still referenced by a trash task".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_schedule_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_unique_live_owner_name_sql(), &[&name, &owner_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check live schedule name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_schedule_uuid_not_live(
    tx: &Transaction<'_>,
    schedule_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_live_uuid_conflict_sql(), &[&schedule_uuid])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check live schedule uuid conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_schedule_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check schedule name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn execute_schedule_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_schedule_write_db_error(error, action))
}

pub(crate) async fn query_schedule_trash_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScheduleTrashWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_schedule_write_db_error(error, action))?
        .map(|row| ScheduleTrashWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn query_schedule_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScheduleWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_schedule_write_db_error(error, action))?
        .map(schedule_write_record_from_row)
        .ok_or(ApiError::NotFound)
}

fn schedule_write_record_from_row(row: Row) -> ScheduleWriteRecord {
    ScheduleWriteRecord { uuid: row.get(0) }
}

pub(crate) fn map_schedule_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "schedule write database operation failed");
    ApiError::Database
}
