// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, tls_certificate_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsCertificateWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_tls_certificate_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("TLS certificate write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_tls_certificate_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        tls_certificate_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| {
            map_tls_certificate_write_db_error(error, "resolve TLS certificate write operator")
        })?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!(
                "direct API TLS certificate write operator does not resolve to a database user"
            );
            ApiError::Forbidden
        })
}

pub(crate) async fn load_tls_certificate_write_state(
    tx: &Transaction<'_>,
    certificate_id: &str,
) -> Result<TlsCertificateWriteState, ApiError> {
    let certificate_id = parse_uuid(certificate_id)?.to_string();
    tx.query_opt(tls_certificate_write_state_sql(), &[&certificate_id])
        .await
        .map_err(|error| {
            map_tls_certificate_write_db_error(error, "load TLS certificate write state")
        })?
        .map(|row| TlsCertificateWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_tls_certificate_owner_matches_operator(
    certificate_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if certificate_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!("direct API TLS certificate write operator does not own certificate");
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn execute_tls_certificate_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<(), ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_tls_certificate_write_db_error(error, action))?;
    Ok(())
}

pub(crate) fn map_tls_certificate_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "TLS certificate write database operation failed");
    ApiError::Database
}
