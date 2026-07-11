// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, port_list_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

pub(crate) async fn unique_port_list_name_with_suffix(
    tx: &Transaction<'_>,
    name: &str,
) -> Result<String, ApiError> {
    let mut candidate = name.to_string();
    let mut suffix = 1;
    loop {
        let count: i64 = tx
            .query_one(port_list_unique_name_sql(), &[&candidate, &-1])
            .await
            .map_err(|error| {
                map_port_list_write_db_error(error, "check imported port list name uniqueness")
            })?
            .get(0);
        if count == 0 {
            return Ok(candidate);
        }
        candidate = format!("{name} {suffix}");
        suffix += 1;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListTrashWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListTrashWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) owner_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
    pub(crate) predefined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListRangeWriteState {
    pub(crate) internal_id: i32,
    pub(crate) port_list_internal_id: i32,
    pub(crate) owner_id: i32,
    pub(crate) predefined: bool,
}

pub(crate) fn require_port_list_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("port list write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_port_list_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        port_list_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "resolve port list write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!(
                "direct API port list write operator does not resolve to a database user"
            );
            ApiError::Forbidden
        })
}

pub(crate) async fn load_port_list_write_state(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<PortListWriteState, ApiError> {
    let port_list_id = parse_uuid(port_list_id)?.to_string();
    tx.query_opt(port_list_write_state_sql(), &[&port_list_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "load port list write state"))?
        .map(|row| PortListWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
            predefined: row.get::<_, i32>(2) != 0,
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_port_list_range_write_state(
    tx: &Transaction<'_>,
    port_list_id: &str,
    port_range_id: &str,
) -> Result<PortListRangeWriteState, ApiError> {
    let port_list_id = parse_uuid(port_list_id)?.to_string();
    let port_range_id = parse_uuid(port_range_id)?.to_string();
    tx.query_opt(
        port_list_range_write_state_sql(),
        &[&port_list_id, &port_range_id],
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "load port list range write state"))?
    .map(|row| PortListRangeWriteState {
        internal_id: row.get(0),
        port_list_internal_id: row.get(1),
        owner_id: row.get(2),
        predefined: row.get::<_, i32>(3) != 0,
    })
    .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_port_list_owner_matches_operator(
    port_list_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if port_list_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!(
            port_list_owner_id,
            operator_owner_id,
            "direct API port list write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn load_port_list_trash_state(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<PortListTrashWriteState, ApiError> {
    let port_list_id = parse_uuid(port_list_id)?.to_string();
    tx.query_opt(port_list_trash_state_sql(), &[&port_list_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "load port list trash state"))?
        .map(|row| PortListTrashWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_unique_port_list_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "check port list name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_port_list_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_unique_live_owner_name_sql(), &[&name, &owner_id])
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check port list restore name conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list with the same owner and name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_port_list_uuid_not_live(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_live_uuid_conflict_sql(), &[&port_list_id])
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check port list restore UUID conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "live port list with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_port_list_uuid_not_live_or_trash(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            port_list_live_or_trash_uuid_conflict_sql(),
            &[&port_list_id],
        )
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check port list import UUID conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "live or trash port list with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_port_list_not_in_use_by_live_targets(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_live_target_count_sql(), &[&port_list_internal_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "check port list target usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list is still referenced by a live target".to_string(),
        ))
    }
}

pub(crate) async fn ensure_port_list_not_in_use_by_live_location_trash_targets(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            port_list_live_location_trash_target_count_sql(),
            &[&port_list_internal_id],
        )
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check live port list trash target usage")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list is still referenced by a trash target".to_string(),
        ))
    }
}

pub(crate) async fn ensure_port_list_not_in_use_by_trash_targets(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            port_list_trash_target_count_sql(),
            &[&port_list_internal_id],
        )
        .await
        .map_err(|error| map_port_list_write_db_error(error, "check port list trash target usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list is still referenced by a trash target".to_string(),
        ))
    }
}

pub(crate) async fn query_port_list_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<PortListWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_port_list_write_db_error(error, action))?
        .map(|row| PortListWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn query_port_list_trash_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<PortListTrashWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_port_list_write_db_error(error, action))?
        .map(|row| PortListTrashWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn execute_port_list_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_port_list_write_db_error(error, action))
}

pub(crate) fn map_port_list_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "port list write database operation failed");
    ApiError::Database
}
