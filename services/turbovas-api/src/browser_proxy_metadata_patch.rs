// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};

use crate::{
    alert_deliver_report::{AlertDeliverReportRequest, deliver_alert_report},
    alert_payloads::AlertAssetItem,
    alert_test::test_alert,
    alert_write_validation::{AlertCloneRequest, AlertCreateRequest, AlertPatchRequest},
    alert_writes::{
        clone_alert, create_alert, delete_alert, parse_alert_create_payload, patch_alert,
    },
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    credential_payloads::CredentialAssetItem,
    credential_write_validation::{CredentialCreateRequest, CredentialPatchRequest},
    credential_writes::{create_credential, patch_credential},
    errors::ApiError,
    override_payloads::OverrideAssetItem,
    override_write_validation::{
        OverrideCloneRequest, OverrideCreateRequest, OverridePatchRequest,
    },
    override_writes::{
        clone_override, create_override, delete_override, hard_delete_override, patch_override,
        restore_override,
    },
    scanner_asset_payloads::ScannerAssetDetail,
    scanner_verify::{ScannerVerifyResult, verify_scanner},
    scanner_write_validation::{ScannerConfigurationRequest, ScannerPatchRequest},
    scanner_writes::{create_scanner, patch_scanner, replace_scanner_configuration},
    task_control::{TaskStartResult, start_task},
    task_stop::{TaskStopResult, stop_task},
    task_target_payloads::TaskItem,
    task_target_replace::{TaskTargetReplaceResponse, replace_task_target},
    task_target_replace_validation::TaskTargetReplaceRequest,
    task_write_validation::{TaskCreateRequest, TaskPatchRequest, TaskReplaceRequest},
    task_writes::{clone_task, create_task, delete_task, patch_task, replace_task},
    tls_certificate_writes::delete_tls_certificate,
};

pub(crate) async fn browser_proxy_create_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<AlertCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<AlertAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    let request = parse_alert_create_payload(payload)?;
    create_alert(State(state), Some(Extension(operator)), Ok(Json(request))).await
}

pub(crate) async fn browser_proxy_test_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    test_alert(State(state), Path(alert_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_deliver_alert_report(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<AlertDeliverReportRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    deliver_alert_report(
        State(state),
        Path(alert_id),
        Some(Extension(operator)),
        payload,
    )
    .await
}

pub(crate) async fn browser_proxy_restore_override(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(override_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_override(State(state), Path(override_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_hard_delete_override(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(override_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_override(State(state), Path(override_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_create_override(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<OverrideCreateRequest>,
) -> Result<(StatusCode, Json<OverrideAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_override(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_override(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(override_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<OverridePatchRequest>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_override(
        State(state),
        Path(override_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_clone_override(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(override_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<OverrideCloneRequest>,
) -> Result<(StatusCode, Json<OverrideAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_override(
        State(state),
        Path(override_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

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

pub(crate) async fn browser_proxy_create_scanner(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<ScannerConfigurationRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScannerAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_scanner(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_replace_scanner_configuration(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scanner_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ScannerConfigurationRequest>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    replace_scanner_configuration(
        State(state),
        Path(scanner_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_verify_scanner(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scanner_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ScannerVerifyResult>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    verify_scanner(State(state), Path(scanner_id), Some(Extension(operator))).await
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

pub(crate) async fn browser_proxy_delete_override(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(override_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_override(State(state), Path(override_id), Some(Extension(operator))).await
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

pub(crate) async fn browser_proxy_clone_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, Json<TaskItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_task(State(state), Path(task_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_create_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<TaskCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TaskItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_task(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_start_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<TaskStartResult>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    start_task(State(state), Path(task_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_stop_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<TaskStopResult>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    stop_task(Path(task_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_replace_task_target(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TaskTargetReplaceRequest>,
) -> Result<Json<TaskTargetReplaceResponse>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    replace_task_target(
        State(state),
        Path(task_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
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

pub(crate) async fn browser_proxy_create_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<CredentialCreateRequest>,
) -> Result<(StatusCode, Json<CredentialAssetItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_credential(State(state), Some(Extension(operator)), Json(request)).await
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

pub(crate) async fn browser_proxy_replace_task(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TaskReplaceRequest>,
) -> Result<Json<TaskItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    replace_task(
        State(state),
        Path(task_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}
