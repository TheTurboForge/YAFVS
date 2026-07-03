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
    target_write_validation::{TargetCloneRequest, TargetCreateRequest, TargetPatchRequest},
    target_writes::{
        clone_target, create_target, delete_target, hard_delete_target, patch_target,
        restore_target,
    },
    task_target_payloads::TargetItem,
};

pub(crate) async fn browser_proxy_restore_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_target(State(state), Path(target_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_create_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<TargetCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_target(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TargetPatchRequest>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_target(
        State(state),
        Path(target_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_clone_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TargetCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_target(
        State(state),
        Path(target_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_target(State(state), Path(target_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_hard_delete_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(target_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_target(State(state), Path(target_id), Some(Extension(operator))).await
}
