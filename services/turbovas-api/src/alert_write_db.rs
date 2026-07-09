// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{alert_write_sql::*, auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlertWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlertWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_alert_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("alert write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_alert_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(alert_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_alert_write_db_error(error, "resolve alert write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API alert write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_alert_write_state(
    tx: &Transaction<'_>,
    alert_id: &str,
) -> Result<AlertWriteState, ApiError> {
    let alert_id = parse_uuid(alert_id)?.to_string();
    tx.query_opt(alert_write_state_sql(), &[&alert_id])
        .await
        .map_err(|error| map_alert_write_db_error(error, "load alert write state"))?
        .map(|row| AlertWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_alert_owner_matches_operator(
    alert_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if alert_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!(
            alert_owner_id,
            operator_owner_id,
            "direct API alert write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn ensure_unique_alert_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(alert_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_alert_write_db_error(error, "check alert name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "alert with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn query_alert_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<AlertWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_alert_write_db_error(error, action))?
        .map(|row| AlertWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn execute_alert_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_alert_write_db_error(error, action))
}

pub(crate) async fn ensure_alert_not_in_use_by_live_tasks(
    tx: &Transaction<'_>,
    alert_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(alert_live_task_count_sql(), &[&alert_internal_id])
        .await
        .map_err(|error| map_alert_write_db_error(error, "check alert live task usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "alert is still referenced by a visible task".to_string(),
        ))
    }
}

pub(crate) fn map_alert_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "alert write database operation failed");
    ApiError::Database
}
