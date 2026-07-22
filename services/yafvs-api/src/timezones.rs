// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
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
    const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
    const GSAD_GMP_HEADER: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
    const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
    const GVMD_GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
    const GVMD_MANAGE: &str = include_str!("../../../components/gvmd/src/manage.c");
    const GVMD_MANAGE_HEADER: &str = include_str!("../../../components/gvmd/src/manage.h");
    const GSA_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/timezones.ts");

    #[test]
    fn timezone_query_is_read_only_and_pg_owned() {
        let sql = "SELECT name FROM pg_timezone_names ORDER BY name ASC;";
        assert!(sql.contains("pg_timezone_names"));
        assert!(sql.starts_with("SELECT"));
        for forbidden in ["INSERT", "UPDATE", "DELETE", "COPY"] {
            assert!(!sql.contains(forbidden));
        }
    }

    #[test]
    fn timezone_browser_read_has_no_gmp_compatibility_tail() {
        for (source, retired) in [
            (GSAD_GMP, "get_timezones_gmp"),
            (GSAD_GMP, "ELSE (get_timezones)"),
            (GSAD_GMP_HEADER, "get_timezones_gmp"),
            (GSAD_VALIDATOR, "|(get_timezones)"),
            (GVMD_GMP, "CLIENT_GET_TIMEZONES"),
            (GVMD_GMP, "handle_get_timezones"),
            (GVMD_MANAGE, "manage_get_timezones"),
            (GVMD_MANAGE_HEADER, "manage_get_timezones"),
            (GSA_COMMAND, "cmd: 'get_timezones'"),
        ] {
            assert!(
                !source.contains(retired),
                "retired timezone GMP compatibility surface remains: {retired}"
            );
        }
    }
}
