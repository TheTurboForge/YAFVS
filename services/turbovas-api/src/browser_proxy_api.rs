// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    alert_payloads::AlertAssetItem,
    alert_write_validation::AlertPatchRequest,
    alert_writes::patch_alert,
    app_state::AppState,
    auth::{DirectApiOperator, constant_time_str_eq, direct_api_bearer_token_is_acceptable},
    credential_payloads::CredentialAssetItem,
    credential_write_validation::CredentialPatchRequest,
    credential_writes::patch_credential,
    errors::ApiError,
    filter_payloads::FilterAssetItem,
    filter_write_validation::{FilterCloneRequest, FilterCreateRequest, FilterPatchRequest},
    filter_writes::{
        clone_filter, create_filter, delete_filter, hard_delete_filter, patch_filter,
        restore_filter,
    },
    operator_identity::resolve_browser_proxy_operator_by_name,
    scanner_asset_payloads::ScannerAssetDetail,
    scanner_write_validation::ScannerPatchRequest,
    scanner_writes::patch_scanner,
    scope_payload_rows::ScopeItem,
    scope_write_validation::{ScopeCreateRequest, ScopePatchRequest},
    scope_writes::{create_scope, delete_scope, patch_scope},
    tag_payloads::TagAssetItem,
    tag_write_validation::{
        TagCloneRequest, TagCreateRequest, TagPatchRequest, TagResourceUpdateRequest,
    },
    tag_writes::{
        clone_tag, create_tag, delete_tag, hard_delete_tag, patch_tag, restore_tag,
        update_tag_resources,
    },
    target_write_validation::{TargetCloneRequest, TargetCreateRequest, TargetPatchRequest},
    target_writes::{
        clone_target, create_target, delete_target, hard_delete_target, patch_target,
        restore_target,
    },
    task_target_payloads::{TargetItem, TaskItem},
    task_write_validation::TaskPatchRequest,
    task_writes::patch_task,
};

const BROWSER_PROXY_SECRET_ENV: &str = "TURBOVAS_API_BROWSER_PROXY_SECRET";
const BROWSER_PROXY_SECRET_HEADER: &str = "x-turbovas-browser-proxy-secret";
const BROWSER_PROXY_OPERATOR_NAME_HEADER: &str = "x-turbovas-operator-name";

#[derive(Clone)]
pub(crate) struct BrowserProxyAuth {
    secret: String,
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

impl BrowserProxyAuth {
    pub(crate) fn new(secret: String) -> Self {
        Self { secret }
    }
}

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

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn browser_proxy_api_config() -> Result<Option<BrowserProxyAuth>, ApiError> {
    browser_proxy_api_config_from_source(env_string(BROWSER_PROXY_SECRET_ENV))
}

pub(crate) async fn browser_proxy_restore_tag(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(tag_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    restore_tag(State(state), Path(tag_id), Some(Extension(operator))).await
}

fn browser_proxy_api_config_from_source(
    secret: Option<String>,
) -> Result<Option<BrowserProxyAuth>, ApiError> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    if !direct_api_bearer_token_is_acceptable(&secret) {
        return Err(ApiError::Config);
    }
    Ok(Some(BrowserProxyAuth::new(secret)))
}

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

pub(crate) async fn browser_proxy_delete_scope(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scope_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_scope(State(state), Path(scope_id), Some(Extension(operator))).await
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

pub(crate) async fn browser_proxy_operator_from_headers(
    state: &AppState,
    auth: &BrowserProxyAuth,
    headers: &HeaderMap,
) -> Result<DirectApiOperator, ApiError> {
    let secret = header_value(headers, BROWSER_PROXY_SECRET_HEADER)?;
    if !constant_time_str_eq(secret, &auth.secret) {
        return Err(ApiError::Unauthorized);
    }
    let user_name = browser_proxy_operator_name_from_headers(headers)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let identity = resolve_browser_proxy_operator_by_name(&client, user_name).await?;
    DirectApiOperator::new(&identity.user_uuid, Some(identity.user_name))
}

fn browser_proxy_operator_name_from_headers(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = header_value(headers, BROWSER_PROXY_OPERATOR_NAME_HEADER)?.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ApiError::Unauthorized);
    }
    Ok(value)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn browser_proxy_config_requires_bounded_printable_secret() {
        assert!(
            browser_proxy_api_config_from_source(None)
                .unwrap()
                .is_none()
        );
        assert!(
            browser_proxy_api_config_from_source(Some(
                "0123456789abcdef0123456789abcdef".to_string()
            ))
            .unwrap()
            .is_some()
        );
        assert!(browser_proxy_api_config_from_source(Some("short".to_string())).is_err());
        assert!(
            browser_proxy_api_config_from_source(Some(
                "0123456789abcdef0123456789abcde\n".to_string()
            ))
            .is_err()
        );
    }

    #[test]
    fn browser_proxy_operator_name_header_is_strict() {
        let mut headers = HeaderMap::new();
        headers.insert(
            BROWSER_PROXY_OPERATOR_NAME_HEADER,
            HeaderValue::from_static(" admin "),
        );
        assert_eq!(
            browser_proxy_operator_name_from_headers(&headers).unwrap(),
            "admin"
        );

        headers.remove(BROWSER_PROXY_OPERATOR_NAME_HEADER);
        assert!(browser_proxy_operator_name_from_headers(&headers).is_err());

        headers.insert(
            BROWSER_PROXY_OPERATOR_NAME_HEADER,
            HeaderValue::from_str(&"a".repeat(257)).unwrap(),
        );
        assert!(browser_proxy_operator_name_from_headers(&headers).is_err());
    }

    #[test]
    fn browser_proxy_secret_header_uses_constant_time_match() {
        let auth = BrowserProxyAuth::new("0123456789abcdef0123456789abcdef".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            BROWSER_PROXY_SECRET_HEADER,
            HeaderValue::from_static("0123456789abcdef0123456789abcdef"),
        );
        assert!(constant_time_str_eq(
            header_value(&headers, BROWSER_PROXY_SECRET_HEADER).unwrap(),
            &auth.secret
        ));
        headers.insert(
            BROWSER_PROXY_SECRET_HEADER,
            HeaderValue::from_static("wrong"),
        );
        assert!(!constant_time_str_eq(
            header_value(&headers, BROWSER_PROXY_SECRET_HEADER).unwrap(),
            &auth.secret
        ));
    }
}
