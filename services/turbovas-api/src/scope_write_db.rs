// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use axum::extract::Extension;
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    scope_write_sql::*,
    scope_write_validation::{ValidatedScopeCreate, ValidatedScopePatch},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

pub(crate) fn require_scope_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("scope write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) fn ensure_scope_is_mutable(is_global: bool, predefined: bool) -> Result<(), ApiError> {
    if is_global || predefined {
        Err(ApiError::Conflict("scope is immutable".to_string()))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_scope_write_references_visible(
    field_name: &str,
    requested_ids: &[String],
    visible_ids: &[String],
) -> Result<(), ApiError> {
    let visible = visible_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if requested_ids.iter().all(|id| visible.contains(id.as_str())) {
        return Ok(());
    }
    tracing::warn!(
        field = field_name,
        "scope write references are not visible to operator"
    );
    Err(ApiError::Forbidden)
}

pub(crate) async fn resolve_scope_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(scope_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_scope_write_db_error(error, "resolve scope write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API scope write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_mutable_scope_write_state(
    tx: &Transaction<'_>,
    scope_id: &str,
) -> Result<ScopeWriteState, ApiError> {
    let scope_id = parse_uuid(scope_id)?.to_string();
    let row = tx
        .query_opt(scope_write_mutability_sql(), &[&scope_id])
        .await
        .map_err(|error| map_scope_write_db_error(error, "load scope write state"))?
        .ok_or(ApiError::NotFound)?;
    let state = ScopeWriteState {
        internal_id: row.get(0),
        uuid: scope_id,
    };
    let predefined: i32 = row.get(1);
    let global: i32 = row.get(2);
    ensure_scope_is_mutable(global != 0, predefined != 0)?;
    Ok(state)
}

pub(crate) async fn ensure_scope_has_no_report_history(
    tx: &Transaction<'_>,
    scope_id: &str,
) -> Result<(), ApiError> {
    let row = tx
        .query_one(scope_write_report_history_sql(), &[&scope_id])
        .await
        .map_err(|error| map_scope_write_db_error(error, "check scope report history"))?;
    let report_count: i64 = row.get(0);
    if report_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scope with report history cannot be deleted".to_string(),
        ))
    }
}

pub(crate) async fn verify_scope_write_references_visible(
    tx: &Transaction<'_>,
    target_ids: &[String],
    host_ids: &[String],
) -> Result<(), ApiError> {
    let visible_target_ids = visible_scope_reference_ids(
        tx,
        scope_write_visible_targets_sql(),
        target_ids,
        "load visible scope targets",
    )
    .await?;
    ensure_scope_write_references_visible("target_ids", target_ids, &visible_target_ids)?;

    let visible_host_ids = visible_scope_reference_ids(
        tx,
        scope_write_visible_hosts_sql(),
        host_ids,
        "load visible scope hosts",
    )
    .await?;
    ensure_scope_write_references_visible("host_ids", host_ids, &visible_host_ids)
}

pub(crate) async fn execute_scope_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedScopeCreate,
) -> Result<ScopeWriteRecord, ApiError> {
    let record = query_scope_write_record(
        tx,
        scope_insert_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.protection_requirement,
        ],
        "insert scope",
    )
    .await?;
    replace_scope_membership(
        tx,
        record.internal_id,
        &request.target_ids,
        scope_delete_targets_sql(),
        scope_insert_target_sql(),
        "target_ids",
    )
    .await?;
    replace_scope_membership(
        tx,
        record.internal_id,
        &request.host_ids,
        scope_delete_hosts_sql(),
        scope_insert_host_sql(),
        "host_ids",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scope_patch_transaction(
    tx: &Transaction<'_>,
    scope_internal_id: i32,
    request: &ValidatedScopePatch,
) -> Result<ScopeWriteRecord, ApiError> {
    let record = if request.name.is_some()
        || request.comment.is_some()
        || request.protection_requirement.is_some()
    {
        query_scope_write_record(
            tx,
            scope_update_metadata_sql(),
            &[
                &scope_internal_id,
                &request.name,
                &request.comment,
                &request.protection_requirement,
            ],
            "update scope metadata",
        )
        .await?
    } else {
        query_scope_write_record(
            tx,
            scope_by_internal_id_sql(),
            &[&scope_internal_id],
            "load scope after membership-only patch",
        )
        .await?
    };

    if let Some(target_ids) = request.target_ids.as_ref() {
        replace_scope_membership(
            tx,
            record.internal_id,
            target_ids,
            scope_delete_targets_sql(),
            scope_insert_target_sql(),
            "target_ids",
        )
        .await?;
    }
    if let Some(host_ids) = request.host_ids.as_ref() {
        replace_scope_membership(
            tx,
            record.internal_id,
            host_ids,
            scope_delete_hosts_sql(),
            scope_insert_host_sql(),
            "host_ids",
        )
        .await?;
    }
    Ok(record)
}

pub(crate) async fn execute_scope_delete_transaction(
    tx: &Transaction<'_>,
    scope_internal_id: i32,
) -> Result<(), ApiError> {
    execute_scope_write_sql(
        tx,
        scope_delete_targets_sql(),
        &[&scope_internal_id],
        "delete scope target membership",
    )
    .await?;
    execute_scope_write_sql(
        tx,
        scope_delete_hosts_sql(),
        &[&scope_internal_id],
        "delete scope host membership",
    )
    .await?;
    let deleted = execute_scope_write_sql(
        tx,
        scope_delete_sql(),
        &[&scope_internal_id],
        "delete scope",
    )
    .await?;
    if deleted == 0 {
        Err(ApiError::NotFound)
    } else {
        Ok(())
    }
}

async fn visible_scope_reference_ids(
    tx: &Transaction<'_>,
    sql: &str,
    requested_ids: &[String],
    action: &'static str,
) -> Result<Vec<String>, ApiError> {
    if requested_ids.is_empty() {
        return Ok(Vec::new());
    }
    let requested_ids = requested_ids.to_vec();
    let rows = tx
        .query(sql, &[&requested_ids])
        .await
        .map_err(|error| map_scope_write_db_error(error, action))?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

async fn query_scope_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScopeWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))?
        .map(|row| scope_write_record_from_row(&row))
        .ok_or(ApiError::NotFound)
}

async fn execute_scope_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))
}

async fn replace_scope_membership(
    tx: &Transaction<'_>,
    scope_internal_id: i32,
    requested_ids: &[String],
    delete_sql: &str,
    insert_sql: &str,
    field_name: &'static str,
) -> Result<(), ApiError> {
    execute_scope_write_sql(
        tx,
        delete_sql,
        &[&scope_internal_id],
        "delete scope membership",
    )
    .await?;
    for requested_id in requested_ids {
        let inserted = execute_scope_write_sql(
            tx,
            insert_sql,
            &[&scope_internal_id, requested_id],
            "insert scope membership",
        )
        .await?;
        if inserted == 0 {
            tracing::warn!(
                field = field_name,
                "scope write reference disappeared before insert"
            );
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

fn scope_write_record_from_row(row: &Row) -> ScopeWriteRecord {
    ScopeWriteRecord {
        internal_id: row.get(0),
        uuid: row.get(1),
    }
}

pub(crate) fn map_scope_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "scope write database operation failed");
    ApiError::Database
}
