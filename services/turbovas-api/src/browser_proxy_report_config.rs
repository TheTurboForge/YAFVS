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
    report_config_payloads::ReportConfigAssetItem,
    report_config_write_validation::{
        ReportConfigCloneRequest, ReportConfigCreateRequest, ReportConfigPatchRequest,
    },
    report_config_writes::{
        clone_report_config, create_report_config, delete_report_config, hard_delete_report_config,
        patch_report_config, restore_report_config,
    },
};

pub(crate) async fn browser_proxy_restore_report_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(report_config_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_report_config(
        State(state),
        Path(report_config_id),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_report_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(report_config_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_report_config(
        State(state),
        Path(report_config_id),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_hard_delete_report_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(report_config_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_report_config(
        State(state),
        Path(report_config_id),
        Some(Extension(operator)),
    )
    .await
}

pub(crate) async fn browser_proxy_create_report_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<ReportConfigCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ReportConfigAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_report_config(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_report_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(report_config_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ReportConfigPatchRequest>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_report_config(
        State(state),
        Path(report_config_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_clone_report_config(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(report_config_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ReportConfigCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ReportConfigAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_report_config(
        State(state),
        Path(report_config_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
