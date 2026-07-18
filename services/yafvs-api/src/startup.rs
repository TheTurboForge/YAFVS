// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    app_state::{AppState, create_pool},
    browser_proxy_api::browser_proxy_api_config,
    direct_api::direct_api_config,
    errors::ApiError,
    operator_identity::resolve_configured_direct_api_operator,
    routes::{browser_proxy_native_api_router, direct_native_api_router, native_api_router},
    runtime::{DirectApiListener, serve_api},
};

pub(crate) async fn run() -> Result<(), ApiError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState {
        pool: create_pool()?,
    };
    let browser_proxy_auth = browser_proxy_api_config()?;
    let direct_api = direct_api_config()?;
    if let Some((_, auth)) = direct_api.as_ref() {
        let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
        if let Some(operator) = resolve_configured_direct_api_operator(&client, auth).await? {
            tracing::info!(operator_uuid = %operator.user_uuid, "direct native API operator identity verified");
        }
    }
    let base_router = native_api_router();
    let internal_app = browser_proxy_native_api_router(base_router.clone(), browser_proxy_auth)
        .with_state(state.clone());
    let direct_api = direct_api.map(|(bind, auth)| {
        let direct_app =
            direct_native_api_router(base_router, auth.write_control_enabled()).with_state(state);
        DirectApiListener {
            bind,
            auth,
            app: direct_app,
        }
    });

    serve_api(internal_app, direct_api).await
}
