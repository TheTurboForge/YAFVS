// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, report_format_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportFormatWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportFormatWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
    pub(crate) predefined: bool,
}

pub(crate) fn require_report_format_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("report format write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_report_format_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        report_format_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| {
        map_report_format_write_db_error(error, "resolve report format write operator")
    })?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!(
            "direct API report format write operator does not resolve to a database user"
        );
        ApiError::Forbidden
    })
}

pub(crate) async fn load_report_format_write_state(
    tx: &Transaction<'_>,
    report_format_id: &str,
) -> Result<ReportFormatWriteState, ApiError> {
    let report_format_id = parse_uuid(report_format_id)?.to_string();
    tx.query_opt(report_format_write_state_sql(), &[&report_format_id])
        .await
        .map_err(|error| map_report_format_write_db_error(error, "load report format write state"))?
        .map(|row| ReportFormatWriteState {
            internal_id: row.get(0),
            owner_id: row.get(2),
            predefined: row.get::<_, i32>(3) != 0,
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_report_format_metadata_patch_allowed(
    state: &ReportFormatWriteState,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if state.predefined {
        return Err(ApiError::Forbidden);
    }
    if state.owner_id == Some(operator_owner_id) {
        Ok(())
    } else {
        tracing::warn!(
            report_format_owner_id = ?state.owner_id,
            operator_owner_id,
            "direct API report format write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn query_report_format_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ReportFormatWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_report_format_write_db_error(error, action))?
        .map(|row| ReportFormatWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_report_format_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "report format write database operation failed");
    ApiError::Database
}
