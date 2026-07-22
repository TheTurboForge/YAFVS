// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
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
    scope_payload_rows::ScopeItem,
    scope_write_validation::{ScopeCreateRequest, ScopePatchRequest},
    scope_writes::{create_scope, delete_scope, patch_scope},
};

pub(crate) async fn browser_proxy_create_scope(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<ScopeCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScopeItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_scope(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_scope(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scope_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ScopePatchRequest>,
) -> Result<Json<ScopeItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_scope(
        State(state),
        Path(scope_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_scope(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scope_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_scope(State(state), Path(scope_id), Some(Extension(operator))).await
}
