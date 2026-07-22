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
    port_list_payloads::PortListAssetDetail,
    port_list_write_validation::{
        PortListCloneRequest, PortListCreateRangeRequest, PortListCreateRequest,
        PortListImportRequest, PortListPatchRequest,
    },
    port_list_writes::{
        clone_port_list, create_port_list, create_port_list_range, delete_port_list,
        delete_port_list_range, hard_delete_port_list, import_port_list, patch_port_list,
        restore_port_list,
    },
};

pub(crate) async fn browser_proxy_create_port_list_range(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(port_list_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PortListCreateRangeRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_port_list_range(
        State(state),
        Path(port_list_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_restore_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(port_list_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_port_list(State(state), Path(port_list_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(port_list_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_port_list(State(state), Path(port_list_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_port_list_range(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path((port_list_id, port_range_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_port_list_range(
        State(state),
        Path((port_list_id, port_range_id)),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_hard_delete_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(port_list_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_port_list(State(state), Path(port_list_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_create_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<PortListCreateRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_port_list(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_import_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<PortListImportRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    import_port_list(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_clone_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(port_list_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PortListCloneRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_port_list(
        State(state),
        Path(port_list_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_patch_port_list(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(port_list_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PortListPatchRequest>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_port_list(
        State(state),
        Path(port_list_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
