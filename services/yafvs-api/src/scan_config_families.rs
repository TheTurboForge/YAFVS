// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    errors::ApiError,
    path_ids::{parse_uuid, validate_scan_config_family},
    scan_config_payloads::{
        ScanConfigFamiliesPayload, ScanConfigFamilyNvtsPayload,
        scan_config_families_payload_from_rows, scan_config_family_nvts_payload_from_rows,
    },
    scan_config_query_sql::{
        scan_config_families_exists_sql, scan_config_families_sql,
        scan_config_family_nvts_exists_sql, scan_config_family_nvts_sql,
    },
};

pub(crate) async fn scan_config_asset_families(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigFamiliesPayload>, ApiError> {
    parse_uuid(&scan_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(scan_config_families_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config family query failed");
            ApiError::Database
        })?;

    if rows.is_empty() {
        let exists = client
            .query_one(scan_config_families_exists_sql(), &[&scan_config_id])
            .await
            .map_err(|error| {
                tracing::warn!(%error, "scan config family existence query failed");
                ApiError::Database
            })?
            .get::<_, bool>(0);
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    Ok(Json(scan_config_families_payload_from_rows(
        scan_config_id,
        &rows,
    )))
}

pub(crate) async fn scan_config_asset_family_nvts(
    State(state): State<AppState>,
    Path((scan_config_id, family)): Path<(String, String)>,
) -> Result<Json<ScanConfigFamilyNvtsPayload>, ApiError> {
    parse_uuid(&scan_config_id)?;
    validate_scan_config_family(&family)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(scan_config_family_nvts_sql(), &[&scan_config_id, &family])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config family NVT query failed");
            ApiError::Database
        })?;

    if rows.is_empty() {
        let existence = client
            .query_one(
                scan_config_family_nvts_exists_sql(),
                &[&scan_config_id, &family],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "scan config family NVT existence query failed");
                ApiError::Database
            })?;
        ensure_scan_config_family_nvts_exist(
            existence.get("config_exists"),
            existence.get("family_exists"),
        )?;
    }

    Ok(Json(scan_config_family_nvts_payload_from_rows(
        scan_config_id,
        family,
        &rows,
    )))
}

pub(crate) fn ensure_scan_config_family_nvts_exist(
    config_exists: bool,
    family_exists: bool,
) -> Result<(), ApiError> {
    if config_exists && family_exists {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}
