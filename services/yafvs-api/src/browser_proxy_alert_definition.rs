// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{Path, State, rejection::JsonRejection},
    http::HeaderMap,
};

use crate::{
    alert_definition::{
        get_alert_definition, parse_alert_definition_replace_payload, put_alert_definition,
    },
    alert_definition_payloads::{AlertDefinition, AlertDefinitionReplaceRequest},
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
};

pub(crate) async fn browser_proxy_get_alert_definition(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AlertDefinition>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    get_alert_definition(State(state), Path(alert_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_put_alert_definition(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(alert_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<AlertDefinitionReplaceRequest>, JsonRejection>,
) -> Result<Json<AlertDefinition>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    let request = parse_alert_definition_replace_payload(payload)?;
    put_alert_definition(
        State(state),
        Path(alert_id),
        Some(Extension(operator)),
        Ok(Json(request)),
    )
    .await
}
