// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
    scan_config_payloads::ScanConfigAssetDetail,
    scan_config_write_validation::{
        ScanConfigCloneRequest, ScanConfigCreateRequest, ScanConfigPatchRequest,
    },
    scan_config_writes::{
        clone_scan_config, create_scan_config, delete_scan_config, hard_delete_scan_config,
        patch_scan_config, restore_scan_config,
    },
};

pub(crate) async fn browser_proxy_restore_scan_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scan_config_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_scan_config(
        State(state),
        Path(scan_config_id),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_scan_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scan_config_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_scan_config(
        State(state),
        Path(scan_config_id),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_hard_delete_scan_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scan_config_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_scan_config(
        State(state),
        Path(scan_config_id),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_create_scan_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<ScanConfigCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScanConfigAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_scan_config(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_scan_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scan_config_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ScanConfigPatchRequest>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_scan_config(
        State(state),
        Path(scan_config_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_clone_scan_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scan_config_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ScanConfigCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScanConfigAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_scan_config(
        State(state),
        Path(scan_config_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
