// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{auth::DirectApiOperator, errors::ApiError, filter_write_sql::*, path_ids::parse_uuid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterCloneWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterTrashWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterTrashWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) owner_id: Option<i32>,
}

pub(crate) fn require_filter_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("filter write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_filter_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        filter_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_filter_write_db_error(error, "resolve filter write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API filter write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_filter_write_state(
    tx: &Transaction<'_>,
    filter_id: &str,
) -> Result<FilterWriteState, ApiError> {
    let filter_id = parse_uuid(filter_id)?.to_string();
    tx.query_opt(filter_write_state_sql(), &[&filter_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "load filter write state"))?
        .map(|row| FilterWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_filter_is_user_owned(owner_id: Option<i32>) -> Result<i32, ApiError> {
    owner_id
        .ok_or_else(|| ApiError::Conflict("global saved filters cannot be modified".to_string()))
}

pub(crate) async fn load_filter_trash_state(
    tx: &Transaction<'_>,
    filter_id: &str,
) -> Result<FilterTrashWriteState, ApiError> {
    let filter_id = parse_uuid(filter_id)?.to_string();
    tx.query_opt(filter_trash_state_sql(), &[&filter_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "load filter trash state"))?
        .map(|row| FilterTrashWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_filter_not_in_use_by_alerts(
    tx: &Transaction<'_>,
    filter_internal_id: i32,
) -> Result<(), ApiError> {
    let direct_count: i64 = tx
        .query_one(filter_live_alert_count_sql(), &[&filter_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check direct alert filter usage"))?
        .get(0);
    let condition_count: i64 = tx
        .query_one(filter_alert_condition_count_sql(), &[&filter_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check alert condition filter usage"))?
        .get(0);
    if direct_count == 0 && condition_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter is still referenced by an alert".to_string(),
        ))
    }
}

pub(crate) async fn ensure_filter_not_in_use_by_trash_alerts(
    tx: &Transaction<'_>,
    filter_internal_id: i32,
) -> Result<(), ApiError> {
    let direct_count: i64 = tx
        .query_one(filter_trash_alert_count_sql(), &[&filter_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check trash alert filter usage"))?
        .get(0);
    let condition_count: i64 = tx
        .query_one(
            filter_trash_alert_condition_count_sql(),
            &[&filter_internal_id],
        )
        .await
        .map_err(|error| {
            map_filter_write_db_error(error, "check trash alert condition filter usage")
        })?
        .get(0);
    if direct_count == 0 && condition_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter is still referenced by a trash alert".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_filter_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(filter_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check filter name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_filter_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(filter_unique_live_owner_name_sql(), &[&name, &owner_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check live filter name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_filter_uuid_not_live(
    tx: &Transaction<'_>,
    filter_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(filter_live_uuid_conflict_sql(), &[&filter_uuid])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check live filter uuid conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn execute_filter_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))
}

pub(crate) async fn query_filter_clone_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<FilterCloneWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))?
        .map(|row| FilterCloneWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn query_filter_trash_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<FilterTrashWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))?
        .map(|row| FilterTrashWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn query_filter_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<FilterWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))?
        .map(|row| FilterWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_filter_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "filter write database operation failed");
    ApiError::Database
}
