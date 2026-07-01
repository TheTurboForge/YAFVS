// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, scan_config_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanConfigWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanConfigWriteState {
    pub(crate) internal_id: i32,
    pub(crate) predefined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanConfigTrashState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) scanner_location: i32,
}

pub(crate) fn require_scan_config_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("scan-config write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_scan_config_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        scan_config_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "resolve scan-config write operator"))?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!("direct API scan-config write operator does not resolve to a database user");
        ApiError::Forbidden
    })
}

pub(crate) async fn load_scan_config_write_state(
    tx: &Transaction<'_>,
    scan_config_id: &str,
) -> Result<ScanConfigWriteState, ApiError> {
    let scan_config_id = parse_uuid(scan_config_id)?.to_string();
    tx.query_opt(scan_config_write_state_sql(), &[&scan_config_id])
        .await
        .map_err(|error| map_scan_config_write_db_error(error, "load scan-config write state"))?
        .map(|row| ScanConfigWriteState {
            internal_id: row.get(0),
            predefined: row.get::<_, i32>(1) != 0,
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_scan_config_trash_state(
    tx: &Transaction<'_>,
    scan_config_id: &str,
) -> Result<ScanConfigTrashState, ApiError> {
    let scan_config_id = parse_uuid(scan_config_id)?.to_string();
    tx.query_opt(scan_config_trash_state_sql(), &[&scan_config_id])
        .await
        .map_err(|error| map_scan_config_write_db_error(error, "load scan-config trash state"))?
        .map(|row| ScanConfigTrashState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            scanner_location: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_unique_scan_config_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scan_config_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "check scan-config name uniqueness")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scan config with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_scan_config_name(
    tx: &Transaction<'_>,
    name: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scan_config_unique_live_name_sql(), &[&name])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "check scan-config restore name conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scan config with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_scan_config_uuid_not_live(
    tx: &Transaction<'_>,
    scan_config_id: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scan_config_live_uuid_conflict_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "check scan-config restore UUID conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "live scan config with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_scan_config_not_in_use_by_live_tasks(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            scan_config_live_task_count_sql(),
            &[&scan_config_internal_id],
        )
        .await
        .map_err(|error| map_scan_config_write_db_error(error, "check scan-config task usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scan config is still referenced by a live task".to_string(),
        ))
    }
}

pub(crate) fn ensure_scan_config_trash_scanner_is_live(
    trash: &ScanConfigTrashState,
) -> Result<(), ApiError> {
    if trash.scanner_location == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scan config cannot be restored while its scanner is in the trash".to_string(),
        ))
    }
}

pub(crate) async fn query_scan_config_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScanConfigWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scan_config_write_db_error(error, action))?
        .map(|row| ScanConfigWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn execute_scan_config_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<(), ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scan_config_write_db_error(error, action))?;
    Ok(())
}

pub(crate) fn map_scan_config_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "scan-config write database operation failed");
    ApiError::Database
}
