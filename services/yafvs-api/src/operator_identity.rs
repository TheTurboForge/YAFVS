// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::{Client, Row};

use crate::{auth::DirectApiAuth, errors::ApiError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorIdentity {
    pub(crate) user_id: i64,
    pub(crate) user_uuid: String,
    pub(crate) user_name: String,
}

pub(crate) async fn resolve_configured_direct_api_operator(
    client: &Client,
    auth: &DirectApiAuth,
) -> Result<Option<OperatorIdentity>, ApiError> {
    let Some(operator_uuid) = auth.operator_uuid() else {
        return Ok(None);
    };
    let row = client
        .query_opt(direct_operator_lookup_sql(), &[&operator_uuid])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "direct API operator lookup failed");
            ApiError::Database
        })?
        .ok_or(ApiError::Config)?;
    Ok(Some(operator_identity_from_row(&row)))
}

pub(crate) async fn resolve_browser_proxy_operator(
    client: &Client,
    user_uuid: &str,
    user_name: &str,
) -> Result<OperatorIdentity, ApiError> {
    let row = client
        .query_opt(browser_proxy_operator_lookup_sql(), &[&user_uuid])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "browser proxy operator lookup failed");
            ApiError::Database
        })?
        .ok_or(ApiError::Forbidden)?;
    let identity = operator_identity_from_row(&row);
    if identity.user_name != user_name {
        return Err(ApiError::Forbidden);
    }
    Ok(identity)
}

pub(crate) fn direct_operator_lookup_sql() -> &'static str {
    "SELECT id::bigint, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn browser_proxy_operator_lookup_sql() -> &'static str {
    "SELECT id::bigint, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

fn operator_identity_from_row(row: &Row) -> OperatorIdentity {
    OperatorIdentity {
        user_id: row.get(0),
        user_uuid: row.get(1),
        user_name: row.get(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_operator_lookup_is_single_user_uuid_only() {
        let sql = direct_operator_lookup_sql();
        let upper_sql = sql.to_ascii_uppercase();

        assert!(sql.contains("FROM users"));
        assert!(sql.contains("WHERE uuid = $1"));
        assert!(!upper_sql.contains("ORDER BY"));
        assert!(!upper_sql.contains("LIMIT"));
        assert!(!upper_sql.contains("INSERT"));
        assert!(!upper_sql.contains("UPDATE"));
        assert!(!upper_sql.contains("DELETE"));
    }

    #[test]
    fn browser_proxy_operator_lookup_is_single_user_uuid_only() {
        let sql = browser_proxy_operator_lookup_sql();
        let upper_sql = sql.to_ascii_uppercase();

        assert!(sql.contains("FROM users"));
        assert!(sql.contains("WHERE uuid = $1"));
        assert!(!upper_sql.contains("ORDER BY"));
        assert!(!upper_sql.contains("LIMIT"));
        assert!(!upper_sql.contains("INSERT"));
        assert!(!upper_sql.contains("UPDATE"));
        assert!(!upper_sql.contains("DELETE"));
    }

    #[test]
    fn direct_operator_resolver_checks_optional_configured_operator() {
        let source = include_str!("operator_identity.rs");
        let body = source
            .split_once("pub(crate) async fn resolve_configured_direct_api_operator")
            .expect("operator resolver must exist")
            .1
            .split_once("pub(crate) fn direct_operator_lookup_sql")
            .expect("resolver must precede SQL helper")
            .0;

        assert!(body.contains("let Some(operator_uuid) = auth.operator_uuid() else"));
        assert!(body.contains("return Ok(None);"));
        assert!(body.contains(".query_opt(direct_operator_lookup_sql(), &[&operator_uuid])"));
        assert!(body.contains(".ok_or(ApiError::Config)?"));
    }
}
