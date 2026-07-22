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
pub(crate) struct ScannerWriteRecordWithInternalId {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannerWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannerTrashState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
    pub(crate) name: Option<String>,
    pub(crate) credential_id: Option<i32>,
    pub(crate) credential_location: i32,
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

pub(crate) async fn load_scanner_trash_state(
    tx: &Transaction<'_>,
    scanner_id: &str,
) -> Result<ScannerTrashState, ApiError> {
    let scanner_id = parse_uuid(scanner_id)?.to_string();
    tx.query_opt(scanner_trash_state_sql(), &[&scanner_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "load scanner trash state"))?
        .map(|row| ScannerTrashState {
            internal_id: row.get(0),
            uuid: row.get(1),
            owner_id: row.get(2),
            name: row.get(3),
            credential_id: row.get(4),
            credential_location: row.get(5),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn resolve_scanner_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        scanner_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "resolve scanner write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API scanner write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) fn ensure_scanner_clone_source_allowed(
    state: &ScannerWriteState,
) -> Result<(), ApiError> {
    if state.uuid.eq_ignore_ascii_case(SCANNER_UUID_CVE) {
        return Err(ApiError::Forbidden);
    }
    if state.owner_id.is_some() || state.uuid.eq_ignore_ascii_case(SCANNER_UUID_DEFAULT) {
        Ok(())
    } else {
        tracing::warn!(
            scanner_uuid = %state.uuid,
            "direct API scanner clone rejected an ownerless custom scanner"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) fn ensure_scanner_is_human_owned(owner_id: Option<i32>) -> Result<i32, ApiError> {
    owner_id.ok_or_else(|| {
        tracing::warn!("direct API scanner lifecycle rejected an ownerless scanner");
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

pub(crate) async fn ensure_scanner_not_in_use_for_delete(
    tx: &Transaction<'_>,
    scanner_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scanner_live_task_count_sql(), &[&scanner_internal_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "check scanner live task references"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scanner cannot be deleted while it is used by a live task".to_string(),
        ))
    }
}

pub(crate) async fn ensure_trash_scanner_not_in_use(
    tx: &Transaction<'_>,
    scanner_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scanner_trash_task_count_sql(), &[&scanner_internal_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "check scanner trash task references"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scanner cannot be hard-deleted while trash tasks reference it".to_string(),
        ))
    }
}

pub(crate) async fn ensure_scanner_uuid_not_live(
    tx: &Transaction<'_>,
    scanner_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scanner_live_uuid_conflict_sql(), &[&scanner_uuid])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "check live scanner id conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scanner with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_trash_scanner_credential_is_live(
    tx: &Transaction<'_>,
    trash: &ScannerTrashState,
) -> Result<(), ApiError> {
    if trash.credential_location != 0 {
        return Err(ApiError::Conflict(
            "scanner cannot be restored while its credential is in trash".to_string(),
        ));
    }
    let Some(credential_id) = trash.credential_id else {
        return Ok(());
    };
    let count: i64 = tx
        .query_one(scanner_live_credential_count_sql(), &[&credential_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "check scanner restore credential"))?
        .get(0);
    if count == 1 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scanner cannot be restored because its credential is unavailable".to_string(),
        ))
    }
}

pub(crate) fn ensure_scanner_metadata_patch_allowed(
    state: &ScannerWriteState,
) -> Result<(), ApiError> {
    if scanner_is_builtin(&state.uuid) {
        return Err(ApiError::Forbidden);
    }
    if state.owner_id.is_some() {
        Ok(())
    } else {
        tracing::warn!("direct API scanner write rejected an ownerless scanner");
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn query_scanner_write_record_with_internal_id(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScannerWriteRecordWithInternalId, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scanner_write_db_error(error, action))?
        .map(|row| ScannerWriteRecordWithInternalId {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
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

pub(crate) async fn load_human_owned_scanner_credential(
    tx: &Transaction<'_>,
    credential_id: &str,
) -> Result<i32, ApiError> {
    let credential_id = parse_uuid(credential_id)?.to_string();
    let Some(row) = tx
        .query_opt(scanner_credential_state_sql(), &[&credential_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "load scanner credential"))?
    else {
        return Err(ApiError::NotFound);
    };
    let owner_id: Option<i32> = row.get(1);
    if owner_id.is_none() {
        tracing::warn!("direct API scanner write rejected an ownerless credential");
        return Err(ApiError::Forbidden);
    }
    let credential_type: String = row.get(2);
    if credential_type != "cc" {
        return Err(ApiError::BadRequest(
            "credential_id must reference a certificate credential of type cc".to_string(),
        ));
    }
    Ok(row.get(0))
}

pub(crate) async fn ensure_scanner_not_in_use_for_configuration_replace(
    tx: &Transaction<'_>,
    scanner_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scanner_live_task_count_sql(), &[&scanner_internal_id])
        .await
        .map_err(|error| map_scanner_write_db_error(error, "check scanner task references"))?
        .get(0);
    ensure_scanner_live_task_count_allows_replace(count)
}

pub(crate) fn ensure_scanner_live_task_count_allows_replace(
    live_task_count: i64,
) -> Result<(), ApiError> {
    if live_task_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scanner configuration cannot be replaced while the scanner is used by a task"
                .to_string(),
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
