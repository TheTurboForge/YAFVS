// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::env;

use axum::http::HeaderMap;

use crate::{
    app_state::AppState,
    auth::{DirectApiOperator, constant_time_str_eq, direct_api_bearer_token_is_acceptable},
    errors::ApiError,
    operator_identity::resolve_browser_proxy_operator,
};
use uuid::Uuid;

const BROWSER_PROXY_SECRET_ENV: &str = "YAFVS_API_BROWSER_PROXY_SECRET";
const BROWSER_PROXY_SECRET_HEADER: &str = "x-yafvs-browser-proxy-secret";
const BROWSER_PROXY_OPERATOR_NAME_HEADER: &str = "x-yafvs-operator-name";
const BROWSER_PROXY_OPERATOR_UUID_HEADER: &str = "x-yafvs-operator-uuid";

#[derive(Clone)]
pub(crate) struct BrowserProxyAuth {
    secret: String,
}

impl BrowserProxyAuth {
    pub(crate) fn new(secret: String) -> Self {
        Self { secret }
    }
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

pub(crate) async fn browser_proxy_operator_from_headers(
    state: &AppState,
    auth: &BrowserProxyAuth,
    headers: &HeaderMap,
) -> Result<DirectApiOperator, ApiError> {
    let secret = header_value(headers, BROWSER_PROXY_SECRET_HEADER)?;
    if !constant_time_str_eq(secret, &auth.secret) {
        return Err(ApiError::Unauthorized);
    }
    let user_uuid = browser_proxy_operator_uuid_from_headers(headers)?;
    let user_name = browser_proxy_operator_name_from_headers(headers)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let identity = resolve_browser_proxy_operator(&client, &user_uuid, user_name).await?;
    DirectApiOperator::new(&identity.user_uuid, Some(identity.user_name))
}

fn browser_proxy_operator_uuid_from_headers(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = header_value(headers, BROWSER_PROXY_OPERATOR_UUID_HEADER)?.trim();
    Uuid::parse_str(value)
        .map(|uuid| uuid.to_string())
        .map_err(|_| ApiError::Unauthorized)
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
    fn browser_proxy_operator_uuid_header_is_strict_and_canonical() {
        let mut headers = HeaderMap::new();
        headers.insert(
            BROWSER_PROXY_OPERATOR_UUID_HEADER,
            HeaderValue::from_static("123E4567-E89B-12D3-A456-426614174000"),
        );
        assert_eq!(
            browser_proxy_operator_uuid_from_headers(&headers).unwrap(),
            "123e4567-e89b-12d3-a456-426614174000"
        );
        headers.insert(
            BROWSER_PROXY_OPERATOR_UUID_HEADER,
            HeaderValue::from_static("not-a-uuid"),
        );
        assert!(browser_proxy_operator_uuid_from_headers(&headers).is_err());
        headers.remove(BROWSER_PROXY_OPERATOR_UUID_HEADER);
        assert!(browser_proxy_operator_uuid_from_headers(&headers).is_err());
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
