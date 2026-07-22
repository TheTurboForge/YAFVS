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
    tag_payloads::TagAssetItem,
    tag_write_validation::{
        TagCloneRequest, TagCreateRequest, TagPatchRequest, TagResourceUpdateRequest,
    },
    tag_writes::{
        clone_tag, create_tag, delete_tag, hard_delete_tag, patch_tag, restore_tag,
        update_tag_resources,
    },
};

pub(crate) async fn browser_proxy_restore_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_tag(State(state), Path(tag_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_tag(State(state), Path(tag_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_hard_delete_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_tag(State(state), Path(tag_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_clone_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TagCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_tag(
        State(state),
        Path(tag_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_create_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<TagCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_tag(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TagPatchRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_tag(
        State(state),
        Path(tag_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_update_tag_resources(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TagResourceUpdateRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    update_tag_resources(
        State(state),
        Path(tag_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
