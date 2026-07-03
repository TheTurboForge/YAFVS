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
    filter_payloads::FilterAssetItem,
    filter_write_validation::{FilterCloneRequest, FilterCreateRequest, FilterPatchRequest},
    filter_writes::{
        clone_filter, create_filter, delete_filter, hard_delete_filter, patch_filter,
        restore_filter,
    },
};

pub(crate) async fn browser_proxy_delete_filter(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(filter_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_filter(State(state), Path(filter_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_hard_delete_filter(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(filter_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_filter(State(state), Path(filter_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_create_filter(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<FilterCreateRequest>,
) -> Result<(StatusCode, Json<FilterAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_filter(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_filter(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(filter_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FilterPatchRequest>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_filter(
        State(state),
        Path(filter_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_restore_filter(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(filter_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_filter(State(state), Path(filter_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_clone_filter(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(filter_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FilterCloneRequest>,
) -> Result<(StatusCode, Json<FilterAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_filter(
        State(state),
        Path(filter_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
