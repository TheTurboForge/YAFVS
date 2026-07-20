// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use axum::extract::Extension;
use tokio_postgres::Transaction;

use crate::{auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, scope_write_sql::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
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

pub(crate) fn ensure_scope_is_human_owned(scope_owner_id: Option<i32>) -> Result<(), ApiError> {
    if scope_owner_id.is_some() {
        return Ok(());
    }
    tracing::warn!("direct API scope write rejected an ownerless scope");
    Err(ApiError::Forbidden)
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
    let sql = format!(
        "{} FOR KEY SHARE;",
        scope_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
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
        owner_id: row.get(1),
    };
    let predefined: i32 = row.get(2);
    let global: i32 = row.get(3);
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

pub(crate) fn map_scope_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "scope write database operation failed");
    ApiError::Database
}
