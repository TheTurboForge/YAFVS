// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    alert_payloads::AlertAssetItem,
    alert_write_validation::{AlertCloneRequest, AlertPatchRequest},
    alert_writes::{clone_alert, delete_alert, patch_alert},
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    credential_payloads::CredentialAssetItem,
    credential_write_validation::CredentialPatchRequest,
    credential_writes::patch_credential,
    errors::ApiError,
    report_format_payloads::ReportFormatAssetItem,
    report_format_write_validation::ReportFormatPatchRequest,
    report_format_writes::patch_report_format,
    scanner_asset_payloads::ScannerAssetDetail,
    scanner_write_validation::ScannerPatchRequest,
    scanner_writes::patch_scanner,
    task_target_payloads::TaskItem,
    task_write_validation::TaskPatchRequest,
    task_writes::{delete_task, patch_task},
    tls_certificate_writes::delete_tls_certificate,
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

pub(crate) async fn browser_proxy_clone_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AlertCloneRequest>,
) -> Result<(StatusCode, Json<AlertAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_alert(
        State(state),
        Path(alert_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_alert(State(state), Path(alert_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_task(State(state), Path(task_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_delete_tls_certificate(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(certificate_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_tls_certificate(
        State(state),
        Path(certificate_id),
        Some(Extension(operator)),
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

pub(crate) async fn browser_proxy_patch_report_format(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(report_format_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ReportFormatPatchRequest>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_report_format(
        State(state),
        Path(report_format_id),
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
