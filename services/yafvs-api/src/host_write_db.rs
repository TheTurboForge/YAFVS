// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{auth::DirectApiOperator, errors::ApiError, host_write_sql::*, path_ids::parse_uuid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostCreateRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
}

pub(crate) fn require_host_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("host write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_host_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        host_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_host_write_db_error(error, "resolve host write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API host write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_host_write_state(
    tx: &Transaction<'_>,
    host_id: &str,
) -> Result<HostWriteState, ApiError> {
    let host_id = parse_uuid(host_id)?.to_string();
    tx.query_opt(host_write_state_sql(), &[&host_id])
        .await
        .map_err(|error| map_host_write_db_error(error, "load host write state"))?
        .map(|row| HostWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_host_identifier_write_state(
    tx: &Transaction<'_>,
    identifier_id: &str,
) -> Result<HostWriteState, ApiError> {
    let identifier_id = parse_uuid(identifier_id)?.to_string();
    tx.query_opt(host_identifier_write_state_sql(), &[&identifier_id])
        .await
        .map_err(|error| map_host_write_db_error(error, "load host identifier write state"))?
        .map(|row| HostWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_host_operating_system_write_state(
    tx: &Transaction<'_>,
    host_operating_system_id: &str,
) -> Result<HostWriteState, ApiError> {
    let host_operating_system_id = parse_uuid(host_operating_system_id)?.to_string();
    tx.query_opt(
        host_operating_system_write_state_sql(),
        &[&host_operating_system_id],
    )
    .await
    .map_err(|error| map_host_write_db_error(error, "load host operating system write state"))?
    .map(|row| HostWriteState {
        internal_id: row.get(0),
        owner_id: row.get(1),
    })
    .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_host_is_human_owned(host_owner_id: Option<i32>) -> Result<(), ApiError> {
    if host_owner_id.is_some() {
        return Ok(());
    }
    tracing::warn!("direct API host write rejected an ownerless host");
    Err(ApiError::Forbidden)
}

pub(crate) async fn query_host_create_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<HostCreateRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_host_write_db_error(error, action))?
        .map(|row| HostCreateRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::Database)
}

pub(crate) async fn query_host_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<HostWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_host_write_db_error(error, action))?
        .map(|row| HostWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn execute_host_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_host_write_db_error(error, action))
}

pub(crate) fn map_host_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "host write database operation failed");
    ApiError::Database
}
