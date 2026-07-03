// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};

use crate::{
    alert_payloads::AlertAssetItem,
    alert_write_validation::AlertPatchRequest,
    alert_writes::patch_alert,
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    credential_payloads::CredentialAssetItem,
    credential_write_validation::CredentialPatchRequest,
    credential_writes::patch_credential,
    errors::ApiError,
    scanner_asset_payloads::ScannerAssetDetail,
    scanner_write_validation::ScannerPatchRequest,
    scanner_writes::patch_scanner,
    task_target_payloads::TaskItem,
    task_write_validation::TaskPatchRequest,
    task_writes::patch_task,
};

pub(crate) async fn browser_proxy_patch_scanner(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scanner_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ScannerPatchRequest>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_scanner(
        State(state),
        Path(scanner_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_patch_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialPatchRequest>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_credential(
        State(state),
        Path(credential_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_patch_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AlertPatchRequest>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_alert(
        State(state),
        Path(alert_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_patch_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TaskPatchRequest>,
) -> Result<Json<TaskItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_task(
        State(state),
        Path(task_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
