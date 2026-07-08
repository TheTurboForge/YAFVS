// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    app_state::AppState,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
    scope_report_mutations::delete_scope_report,
};

pub(crate) async fn browser_proxy_delete_scope_report(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(scope_report_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_scope_report(
        State(state),
        Path(scope_report_id),
        Some(Extension(operator)),
    )
    .await
}
