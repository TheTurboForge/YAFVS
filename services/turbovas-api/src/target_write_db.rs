// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, target_write_sql::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_target_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("target write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_target_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(target_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_target_write_db_error(error, "resolve target write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API target write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_target_write_state(
    tx: &Transaction<'_>,
    target_id: &str,
) -> Result<TargetWriteState, ApiError> {
    let target_id = parse_uuid(target_id)?.to_string();
    tx.query_opt(target_write_state_sql(), &[&target_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "load target write state"))?
        .map(|row| TargetWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_unique_target_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            target_unique_name_sql(),
            &[&name, &except_internal_id, &owner_id],
        )
        .await
        .map_err(|error| map_target_write_db_error(error, "check target name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target with the same name already exists".to_string(),
        ))
    }
}

pub(crate) fn ensure_target_owner_matches_operator(
    target_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if target_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!("direct API target write operator does not own target");
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn query_target_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TargetWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_target_write_db_error(error, action))?
        .map(|row| TargetWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_target_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "target write database operation failed");
    ApiError::Database
}
