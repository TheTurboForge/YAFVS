// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
    host_asset_payloads::HostAssetDetail,
    host_write_validation::{HostCreateRequest, HostPatchRequest},
    host_writes::{
        create_host, delete_host, delete_host_identifier, delete_host_operating_system, patch_host,
    },
};

pub(crate) async fn browser_proxy_create_host(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<HostCreateRequest>,
) -> Result<(StatusCode, Json<HostAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_host(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_host(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(host_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<HostPatchRequest>,
) -> Result<Json<HostAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_host(
        State(state),
        Path(host_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_host(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(host_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_host(State(state), Path(host_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_host_identifier(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(identifier_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_host_identifier(State(state), Path(identifier_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_host_operating_system(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(host_operating_system_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_host_operating_system(
        State(state),
        Path(host_operating_system_id),
        Some(Extension(operator)),
    )
    .await
}
