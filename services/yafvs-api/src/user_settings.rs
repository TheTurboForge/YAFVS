// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
    gvmd_control::{
        ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response_bytes,
    },
    path_ids::parse_uuid,
};

pub(crate) const MAX_USER_SETTING_BODY_BYTES: usize = 48 * 1024;
const MAX_USER_SETTING_VALUE_BYTES: usize = 32 * 1024;

const USER_SETTINGS_SQL: &str = r#"
WITH operator AS (
  SELECT id
  FROM users
  WHERE uuid = $1
),
resolved AS (
  SELECT DISTINCT ON (settings.uuid)
    settings.uuid::text AS id,
    settings.name,
    settings.comment,
    settings.value
  FROM settings
  CROSS JOIN operator
  WHERE (settings.owner IS NULL OR settings.owner = operator.id)
    AND ($2::text IS NULL OR settings.uuid = $2)
  ORDER BY settings.uuid, (settings.owner IS NOT NULL) DESC
)
SELECT id, name, comment, value
FROM resolved
ORDER BY lower(name), id
"#;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct UserSettingItem {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserSettingsPayload {
    items: Vec<UserSettingItem>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum UserSettingValue {
    String(String),
    Number(serde_json::Number),
}

impl UserSettingValue {
    fn into_string(self) -> String {
        match self {
            Self::String(value) => value,
            Self::Number(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserSettingUpdateRequest {
    value: UserSettingValue,
}

struct ValidatedUserSettingUpdate {
    value: String,
}

fn user_setting_from_row(row: &Row) -> UserSettingItem {
    UserSettingItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row
            .get::<_, Option<String>>("comment")
            .filter(|value| value != "(null)"),
        value: row.get("value"),
    }
}

async fn load_user_settings(
    state: &AppState,
    operator: &DirectApiOperator,
    setting_id: Option<&str>,
) -> Result<Vec<UserSettingItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(USER_SETTINGS_SQL, &[&operator.user_uuid(), &setting_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "current user settings query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(user_setting_from_row).collect())
}

fn require_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    operator
        .map(|Extension(operator)| operator)
        .ok_or(ApiError::Forbidden)
}

pub(crate) async fn current_user_settings(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<UserSettingsPayload>, ApiError> {
    let operator = require_operator(operator)?;
    let items = load_user_settings(&state, &operator, None).await?;
    Ok(Json(UserSettingsPayload { items }))
}

pub(crate) async fn current_user_setting(
    State(state): State<AppState>,
    Path(setting_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<UserSettingItem>, ApiError> {
    let operator = require_operator(operator)?;
    let setting_id = parse_uuid(&setting_id)?.to_string();
    let item = load_user_settings(&state, &operator, Some(&setting_id))
        .await?
        .into_iter()
        .next()
        .ok_or(ApiError::NotFound)?;
    Ok(Json(item))
}

pub(crate) async fn browser_proxy_current_user_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
) -> Result<Json<UserSettingsPayload>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    current_user_settings(State(state), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_current_user_setting(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(setting_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<UserSettingItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    current_user_setting(State(state), Path(setting_id), Some(Extension(operator))).await
}

pub(crate) async fn update_current_user_setting(
    State(_state): State<AppState>,
    Path(setting_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<UserSettingUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = require_operator(operator)?;
    let setting_id = parse_uuid(&setting_id)?.to_string();
    let request = validate_user_setting_update(parse_user_setting_payload(payload)?)?;
    request_user_setting_update(&operator, Some(&setting_id), &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn update_current_user_timezone(
    State(_state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<UserSettingUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = require_operator(operator)?;
    let request = validate_user_setting_update(parse_user_setting_payload(payload)?)?;
    request_user_setting_update(&operator, None, &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn browser_proxy_update_current_user_setting(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(setting_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UserSettingUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    update_current_user_setting(
        State(state),
        Path(setting_id),
        Some(Extension(operator)),
        payload,
    )
    .await
}

pub(crate) async fn browser_proxy_update_current_user_timezone(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<UserSettingUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    update_current_user_timezone(State(state), Some(Extension(operator)), payload).await
}

fn parse_user_setting_payload(
    payload: Result<Json<UserSettingUpdateRequest>, JsonRejection>,
) -> Result<UserSettingUpdateRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::RequestTooLarge
        } else {
            ApiError::BadRequest(
                "request body must be application/json matching UserSettingUpdateRequest"
                    .to_string(),
            )
        }
    })
}

fn validate_user_setting_update(
    request: UserSettingUpdateRequest,
) -> Result<ValidatedUserSettingUpdate, ApiError> {
    let value = request.value.into_string();
    if value.len() > MAX_USER_SETTING_VALUE_BYTES || value.as_bytes().contains(&0) {
        return Err(ApiError::BadRequest(format!(
            "value must be at most {MAX_USER_SETTING_VALUE_BYTES} UTF-8 bytes without NUL characters"
        )));
    }
    Ok(ValidatedUserSettingUpdate { value })
}

async fn request_user_setting_update(
    operator: &DirectApiOperator,
    setting_id: Option<&str>,
    request: &ValidatedUserSettingUpdate,
) -> Result<(), ApiError> {
    let control_secret = gvmd_control_secret()?;
    let command = user_setting_update_command(&control_secret, operator, setting_id, request);
    let response = request_gvmd_control_response_bytes(
        &gvmd_control_socket_path(),
        &control_secret,
        command.as_bytes(),
    )
    .await
    .map_err(map_control_socket_error)?;
    parse_user_setting_update_response(&response)
}

fn user_setting_update_command(
    control_secret: &str,
    operator: &DirectApiOperator,
    setting_id: Option<&str>,
    request: &ValidatedUserSettingUpdate,
) -> ScrubbedControlFrame {
    let encoded = STANDARD.encode(request.value.as_bytes());
    let (kind, identifier) = setting_id.map_or(("timezone", "-"), |id| ("id", id));
    ScrubbedControlFrame::new(
        format!(
            "user-setting-modify {control_secret} {} {kind} {identifier} {encoded}\n",
            operator.user_uuid()
        )
        .into_bytes(),
    )
}

fn parse_user_setting_update_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 modified" => Ok(()),
        b"1 not_found" => Err(ApiError::NotFound),
        b"2 invalid_value" => Err(ApiError::BadRequest(
            "The setting value is invalid.".to_string(),
        )),
        b"3 feature_disabled" => Err(ApiError::Conflict(
            "The setting belongs to a disabled feature.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The setting control request was rejected.".to_string(),
        )),
        b"-1 internal" | _ => Err(ApiError::ControlFailure),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OPERATOR_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const SETTING_UUID: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn request(value: serde_json::Value) -> UserSettingUpdateRequest {
        serde_json::from_value(json!({"value": value})).unwrap()
    }

    #[test]
    fn setting_payload_is_strict_and_bounded() {
        assert!(validate_user_setting_update(request(json!(""))).is_ok());
        assert!(validate_user_setting_update(request(json!(25))).is_ok());
        assert!(
            validate_user_setting_update(request(json!(
                "x".repeat(MAX_USER_SETTING_VALUE_BYTES + 1)
            )))
            .is_err()
        );
        assert!(validate_user_setting_update(request(json!("bad\u{0000}value"))).is_err());
        assert!(
            serde_json::from_value::<UserSettingUpdateRequest>(
                json!({"value": "ok", "unexpected": true})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<UserSettingUpdateRequest>(json!({"value": true})).is_err()
        );
    }

    #[test]
    fn settings_query_resolves_operator_override_over_global_default() {
        assert!(USER_SETTINGS_SQL.contains("SELECT DISTINCT ON (settings.uuid)"));
        assert!(USER_SETTINGS_SQL.contains("(settings.owner IS NOT NULL) DESC"));
        assert!(USER_SETTINGS_SQL.contains("WHERE uuid = $1"));
        assert!(USER_SETTINGS_SQL.contains("$2::text IS NULL"));
        assert!(!USER_SETTINGS_SQL.contains("format!("));
    }

    #[test]
    fn setting_control_frames_are_canonical_and_scrubbed() {
        let operator = DirectApiOperator::new(OPERATOR_UUID, None).unwrap();
        let request = validate_user_setting_update(request(json!("Europe/Berlin"))).unwrap();

        let setting =
            user_setting_update_command(CONTROL_SECRET, &operator, Some(SETTING_UUID), &request);
        assert_eq!(
            setting.as_bytes(),
            format!(
                "user-setting-modify {CONTROL_SECRET} {OPERATOR_UUID} id {SETTING_UUID} RXVyb3BlL0Jlcmxpbg==\n"
            )
            .as_bytes()
        );

        let timezone = user_setting_update_command(CONTROL_SECRET, &operator, None, &request);
        assert_eq!(
            timezone.as_bytes(),
            format!(
                "user-setting-modify {CONTROL_SECRET} {OPERATOR_UUID} timezone - RXVyb3BlL0Jlcmxpbg==\n"
            )
            .as_bytes()
        );
    }

    #[test]
    fn setting_control_responses_have_stable_api_mappings() {
        assert!(parse_user_setting_update_response(b"0 modified").is_ok());
        for (response, status) in [
            (b"1 not_found".as_slice(), StatusCode::NOT_FOUND),
            (b"2 invalid_value".as_slice(), StatusCode::BAD_REQUEST),
            (b"3 feature_disabled".as_slice(), StatusCode::CONFLICT),
            (b"99 forbidden".as_slice(), StatusCode::FORBIDDEN),
            (b"-2 malformed".as_slice(), StatusCode::BAD_REQUEST),
            (b"-1 internal".as_slice(), StatusCode::BAD_GATEWAY),
            (b"unexpected".as_slice(), StatusCode::BAD_GATEWAY),
        ] {
            assert_eq!(
                parse_user_setting_update_response(response)
                    .unwrap_err()
                    .status_code(),
                status
            );
        }
    }
}
