// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: greenbone/gvmd commit 39a51f6ca6ad3d9383765436d2695d87e7dd8933, src/manage_sql_configs.c and src/manage_sql_nvts.c, AGPL-3.0-or-later

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{app_state::AppState, errors::ApiError};

const NVT_FAMILIES_SQL: &str = concat!(
    "SELECT family AS name, COUNT(*)::bigint AS max_nvt_count ",
    "FROM nvts ",
    "WHERE family != 'Credentials' ",
    "GROUP BY family ",
    "ORDER BY family ASC;"
);

#[derive(Debug, Serialize)]
pub(crate) struct NvtFamily {
    name: String,
    max_nvt_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct NvtFamiliesResponse {
    items: Vec<NvtFamily>,
}

pub(crate) async fn nvt_families(
    State(state): State<AppState>,
) -> Result<Json<NvtFamiliesResponse>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client.query(NVT_FAMILIES_SQL, &[]).await.map_err(|error| {
        tracing::warn!(%error, "NVT family list query failed");
        ApiError::Database
    })?;

    Ok(Json(NvtFamiliesResponse {
        items: rows
            .iter()
            .map(|row| NvtFamily {
                name: row.get("name"),
                max_nvt_count: row.get("max_nvt_count"),
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::NVT_FAMILIES_SQL;

    const INHERITED_FAMILY_SQL: &str =
        include_str!("../../../components/gvmd/src/manage_sql_configs.c");
    const INHERITED_NVT_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql_nvts.c");
    const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
    const GSAD_GMP_HEADER: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
    const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
    const GVMD_GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
    const GVMD_COMMANDS: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
    const GVMD_SCHEMA: &str =
        include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
    const GSA_COMMAND: &str =
        include_str!("../../../components/gsa/src/gmp/commands/nvt-families.ts");
    const GSA_CAPABILITIES: &str =
        include_str!("../../../components/gsa/src/gmp/capabilities/capabilities.ts");

    #[test]
    fn native_query_preserves_inherited_family_universe_and_order() {
        assert!(INHERITED_FAMILY_SQL.contains("WHERE family != 'Credentials'"));
        assert!(INHERITED_FAMILY_SQL.contains("ascending ? \"ASC\" : \"DESC\""));
        assert!(INHERITED_NVT_SQL.contains("SELECT COUNT(*) FROM nvts WHERE family = '%s';"));
        assert!(NVT_FAMILIES_SQL.contains("WHERE family != 'Credentials'"));
        assert!(NVT_FAMILIES_SQL.contains("COUNT(*)::bigint AS max_nvt_count"));
        assert!(NVT_FAMILIES_SQL.contains("ORDER BY family ASC"));
        assert!(NVT_FAMILIES_SQL.trim_start().starts_with("SELECT"));
        for forbidden in ["INSERT", "UPDATE", "DELETE", "COPY"] {
            assert!(!NVT_FAMILIES_SQL.contains(forbidden));
        }
    }

    #[test]
    fn nvt_family_browser_read_has_no_gmp_compatibility_tail() {
        for (source, retired) in [
            (GSAD_GMP, "get_nvt_families_gmp"),
            (GSAD_GMP, "ELSE (get_nvt_families)"),
            (GSAD_GMP_HEADER, "get_nvt_families_gmp"),
            (GSAD_VALIDATOR, "|(get_nvt_families)"),
            (GVMD_GMP, "CLIENT_GET_NVT_FAMILIES"),
            (GVMD_GMP, "handle_get_nvt_families"),
            (GVMD_COMMANDS, "GET_NVT_FAMILIES"),
            (GVMD_SCHEMA, "<name>get_nvt_families</name>"),
            (GSA_COMMAND, "cmd: 'get_nvt_families'"),
            (GSA_CAPABILITIES, "'get_nvt_families'"),
        ] {
            assert!(
                !source.contains(retired),
                "retired NVT-family GMP compatibility surface remains: {retired}"
            );
        }
    }
}
