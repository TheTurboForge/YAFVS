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
    schedule_payloads::ScheduleAssetDetail,
    schedule_write_validation::{
        ScheduleCloneRequest, ScheduleCreateRequest, SchedulePatchRequest,
    },
    schedule_writes::{
        SchedulePatchError, clone_schedule, create_schedule, delete_schedule, hard_delete_schedule,
        patch_schedule, restore_schedule,
    },
};

pub(crate) async fn browser_proxy_create_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    Json(request): Json<ScheduleCreateRequest>,
) -> Result<(StatusCode, Json<ScheduleAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_schedule(State(state), Some(Extension(operator)), Json(request)).await
}

pub(crate) async fn browser_proxy_patch_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SchedulePatchRequest>,
) -> Result<Json<ScheduleAssetDetail>, SchedulePatchError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    patch_schedule(
        State(state),
        Path(schedule_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_restore_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_schedule(State(state), Path(schedule_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_clone_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ScheduleCloneRequest>,
) -> Result<(StatusCode, Json<ScheduleAssetDetail>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    clone_schedule(
        State(state),
        Path(schedule_id),
        Some(Extension(operator)),
        Json(request),
    )
    .await
}

pub(crate) async fn browser_proxy_delete_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_schedule(State(state), Path(schedule_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_hard_delete_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    hard_delete_schedule(State(state), Path(schedule_id), Some(Extension(operator))).await
}
