// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};
use deadpool_postgres::Pool;
use serde::Serialize;
use yafvs_domain::{
    DATABASE_VERSION, DATABASE_VERSION_SQL, SCHEMA_FINGERPRINT, public_schema_fingerprint_sql,
};

use crate::{app_state::AppState, errors::ApiError};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DatabaseCompatibility {
    read_compatibility: &'static str,
    write_compatibility: &'static str,
    reason: &'static str,
    database_version: Option<String>,
    schema_fingerprint: Option<String>,
    expected_database_version: &'static str,
    expected_schema_fingerprint: &'static str,
}

impl DatabaseCompatibility {
    fn inspected(database_version: Option<String>, schema_fingerprint: Option<String>) -> Self {
        let reason = if database_version.as_deref() != Some(DATABASE_VERSION) {
            "database-version-mismatch"
        } else if schema_fingerprint.as_deref() != Some(SCHEMA_FINGERPRINT) {
            "schema-fingerprint-mismatch"
        } else {
            "matched"
        };
        Self {
            read_compatibility: "best-effort",
            write_compatibility: if reason == "matched" {
                "compatible"
            } else {
                "blocked"
            },
            reason,
            database_version,
            schema_fingerprint,
            expected_database_version: DATABASE_VERSION,
            expected_schema_fingerprint: SCHEMA_FINGERPRINT,
        }
    }

    fn inspection_failed() -> Self {
        Self {
            read_compatibility: "best-effort",
            write_compatibility: "blocked",
            reason: "inspection-failed",
            database_version: None,
            schema_fingerprint: None,
            expected_database_version: DATABASE_VERSION,
            expected_schema_fingerprint: SCHEMA_FINGERPRINT,
        }
    }

    pub(crate) fn writes_compatible(&self) -> bool {
        self.write_compatibility == "compatible"
    }

    pub(crate) fn reason(&self) -> &'static str {
        self.reason
    }

    pub(crate) fn database_version(&self) -> Option<&str> {
        self.database_version.as_deref()
    }

    pub(crate) fn schema_fingerprint(&self) -> Option<&str> {
        self.schema_fingerprint.as_deref()
    }
}

pub(crate) async fn inspect_database_compatibility(pool: &Pool) -> DatabaseCompatibility {
    let Ok(client) = pool.get().await else {
        return DatabaseCompatibility::inspection_failed();
    };
    let database_version = match client.query_opt(DATABASE_VERSION_SQL, &[]).await {
        Ok(Some(row)) => Some(row.get::<_, String>(0)),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "database version compatibility inspection failed");
            return DatabaseCompatibility::inspection_failed();
        }
    };
    let schema_fingerprint = match client
        .query_one(&public_schema_fingerprint_sql(), &[])
        .await
    {
        Ok(row) => Some(row.get::<_, String>(0)),
        Err(error) => {
            tracing::warn!(%error, "database schema compatibility inspection failed");
            return DatabaseCompatibility::inspection_failed();
        }
    };
    DatabaseCompatibility::inspected(database_version, schema_fingerprint)
}

fn method_may_mutate(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub(crate) async fn require_native_write_schema_compatibility(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if method_may_mutate(request.method()) && !state.database_compatibility.writes_compatible() {
        return ApiError::DatabaseWriteIncompatible.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_database_version_and_schema_are_required_for_writes() {
        let matched = DatabaseCompatibility::inspected(
            Some(DATABASE_VERSION.to_string()),
            Some(SCHEMA_FINGERPRINT.to_string()),
        );
        assert!(matched.writes_compatible());
        assert_eq!(matched.reason(), "matched");

        let wrong_version = DatabaseCompatibility::inspected(
            Some("286".to_string()),
            Some(SCHEMA_FINGERPRINT.to_string()),
        );
        assert!(!wrong_version.writes_compatible());
        assert_eq!(wrong_version.reason(), "database-version-mismatch");

        let wrong_schema = DatabaseCompatibility::inspected(
            Some(DATABASE_VERSION.to_string()),
            Some("unknown".to_string()),
        );
        assert!(!wrong_schema.writes_compatible());
        assert_eq!(wrong_schema.reason(), "schema-fingerprint-mismatch");

        let unavailable = DatabaseCompatibility::inspection_failed();
        assert!(!unavailable.writes_compatible());
        assert_eq!(unavailable.reason(), "inspection-failed");
    }

    #[test]
    fn only_non_read_methods_require_write_compatibility() {
        assert!(!method_may_mutate(&Method::GET));
        assert!(!method_may_mutate(&Method::HEAD));
        assert!(!method_may_mutate(&Method::OPTIONS));
        assert!(method_may_mutate(&Method::POST));
        assert!(method_may_mutate(&Method::PUT));
        assert!(method_may_mutate(&Method::PATCH));
        assert!(method_may_mutate(&Method::DELETE));
    }
}
