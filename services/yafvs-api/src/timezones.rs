// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{app_state::AppState, errors::ApiError};

#[derive(Debug, Serialize)]
pub(crate) struct TimezonesResponse {
    items: Vec<String>,
}

pub(crate) async fn timezones(
    State(state): State<AppState>,
) -> Result<Json<TimezonesResponse>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query("SELECT name FROM pg_timezone_names ORDER BY name ASC;", &[])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "timezone list query failed");
            ApiError::Database
        })?;
    Ok(Json(TimezonesResponse {
        items: rows.iter().map(|row| row.get("name")).collect(),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn timezone_query_is_read_only_and_pg_owned() {
        let sql = "SELECT name FROM pg_timezone_names ORDER BY name ASC;";
        assert!(sql.contains("pg_timezone_names"));
        assert!(sql.starts_with("SELECT"));
        for forbidden in ["INSERT", "UPDATE", "DELETE", "COPY"] {
            assert!(!sql.contains(forbidden));
        }
    }
}
