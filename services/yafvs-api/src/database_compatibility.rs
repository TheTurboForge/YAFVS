// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
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
use sha2::{Digest, Sha256};

use crate::{app_state::AppState, errors::ApiError};

const EXPECTED_DATABASE_VERSION: &str = "287";
const EXPECTED_SCHEMA_FINGERPRINT: &str =
    "b87c31288bbdaa9a98d4061f6edd3b01c8e488a422f46fa6fc03a2697f81fb02";

const DATABASE_VERSION_SQL: &str =
    "SELECT value FROM meta WHERE name = 'database_version' LIMIT 1;";
const SCHEMA_FINGERPRINT_SQL: &str = r#"
SELECT item
FROM (
    SELECT format(
        'column|%I|%I|%s|%s|%s|%s',
        table_name,
        column_name,
        ordinal_position,
        udt_name,
        is_nullable,
        coalesce(column_default, '')
    ) AS item
    FROM information_schema.columns
    WHERE table_schema = 'public'

    UNION ALL

    SELECT format(
        'constraint|%s|%s|%s',
        conrelid::regclass::text,
        contype,
        pg_get_constraintdef(oid, true)
    )
    FROM pg_constraint
    WHERE connamespace = 'public'::regnamespace

    UNION ALL

    SELECT format('index|%s|%s|%s', tablename, indexname, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
) AS fingerprint
ORDER BY item;
"#;

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
        let reason = if database_version.as_deref() != Some(EXPECTED_DATABASE_VERSION) {
            "database-version-mismatch"
        } else if schema_fingerprint.as_deref() != Some(EXPECTED_SCHEMA_FINGERPRINT) {
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
            expected_database_version: EXPECTED_DATABASE_VERSION,
            expected_schema_fingerprint: EXPECTED_SCHEMA_FINGERPRINT,
        }
    }

    fn inspection_failed() -> Self {
        Self {
            read_compatibility: "best-effort",
            write_compatibility: "blocked",
            reason: "inspection-failed",
            database_version: None,
            schema_fingerprint: None,
            expected_database_version: EXPECTED_DATABASE_VERSION,
            expected_schema_fingerprint: EXPECTED_SCHEMA_FINGERPRINT,
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
    let rows = match client.query(SCHEMA_FINGERPRINT_SQL, &[]).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "database schema compatibility inspection failed");
            return DatabaseCompatibility::inspection_failed();
        }
    };
    let items = rows
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    DatabaseCompatibility::inspected(database_version, Some(schema_fingerprint(&items)))
}

fn schema_fingerprint(items: &[String]) -> String {
    let mut hasher = Sha256::new();
    for item in items {
        hasher.update(item.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
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
            Some(EXPECTED_DATABASE_VERSION.to_string()),
            Some(EXPECTED_SCHEMA_FINGERPRINT.to_string()),
        );
        assert!(matched.writes_compatible());
        assert_eq!(matched.reason(), "matched");

        let wrong_version = DatabaseCompatibility::inspected(
            Some("286".to_string()),
            Some(EXPECTED_SCHEMA_FINGERPRINT.to_string()),
        );
        assert!(!wrong_version.writes_compatible());
        assert_eq!(wrong_version.reason(), "database-version-mismatch");

        let wrong_schema = DatabaseCompatibility::inspected(
            Some(EXPECTED_DATABASE_VERSION.to_string()),
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

    #[test]
    fn schema_fingerprint_is_stable_and_line_delimited() {
        let items = vec!["a".to_string(), "b".to_string()];
        assert_eq!(
            schema_fingerprint(&items),
            "911169ddaaf146aff539f58c26c489af3b892dff0fe283c1c264c65ae5aa59a2"
        );
    }
}
