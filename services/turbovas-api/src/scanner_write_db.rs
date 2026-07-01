// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, scanner_write_sql::*,
};

const SCANNER_UUID_DEFAULT: &str = "08b69003-5fc2-4037-a479-93b440211c73";
const SCANNER_UUID_CVE: &str = "6acd0832-df90-11e4-b9d5-28d24461215b";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannerWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannerWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
}

pub(crate) fn require_scanner_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("scanner write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_scanner_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(scanner_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "resolve scanner write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API scanner write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_scanner_write_state(
    tx: &Transaction<'_>,
    scanner_id: &str,
) -> Result<ScannerWriteState, ApiError> {
    let scanner_id = parse_uuid(scanner_id)?.to_string();
    tx.query_opt(scanner_write_state_sql(), &[&scanner_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "load scanner write state"))?
        .map(|row| ScannerWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            owner_id: row.get(2),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_scanner_metadata_patch_allowed(
    state: &ScannerWriteState,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if scanner_is_builtin(&state.uuid) {
        return Err(ApiError::Forbidden);
    }
    if state.owner_id == Some(operator_owner_id) {
        Ok(())
    } else {
        tracing::warn!(
            scanner_owner_id = ?state.owner_id,
            operator_owner_id,
            "direct API scanner write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn ensure_unique_scanner_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scanner_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "check scanner name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scanner with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn query_scanner_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScannerWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scanner_write_db_error(error, action))?
        .map(|row| ScannerWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_scanner_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "scanner write database operation failed");
    ApiError::Database
}

fn scanner_is_builtin(scanner_uuid: &str) -> bool {
    scanner_uuid.eq_ignore_ascii_case(SCANNER_UUID_DEFAULT)
        || scanner_uuid.eq_ignore_ascii_case(SCANNER_UUID_CVE)
}
