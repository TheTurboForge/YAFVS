// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::middleware;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    app_state::{AppState, create_pool},
    browser_proxy_api::browser_proxy_api_config,
    database_compatibility::{
        inspect_database_compatibility, require_native_write_schema_compatibility,
    },
    direct_api::direct_api_config,
    errors::ApiError,
    operator_identity::resolve_configured_direct_api_operator,
    request_deadline::enforce_native_request_deadline,
    routes::{browser_proxy_native_api_router, direct_native_api_router, native_api_router},
    runtime::{DirectApiListener, serve_api},
};

pub(crate) async fn run() -> Result<(), ApiError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = create_pool()?;
    let database_compatibility = inspect_database_compatibility(&pool).await;
    if !database_compatibility.writes_compatible() {
        tracing::warn!(
            reason = database_compatibility.reason(),
            database_version = ?database_compatibility.database_version(),
            schema_fingerprint = ?database_compatibility.schema_fingerprint(),
            "native database writes are disabled for an unrecognized schema"
        );
    }
    let state = AppState {
        pool,
        database_compatibility,
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_native_write_schema_compatibility,
        ))
        .layer(middleware::from_fn(enforce_native_request_deadline))
        .with_state(state.clone());
    let direct_api = direct_api.map(|(bind, auth)| {
        let direct_app = direct_native_api_router(base_router, auth.write_control_enabled())
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_native_write_schema_compatibility,
            ))
            .layer(middleware::from_fn(enforce_native_request_deadline))
            .with_state(state.clone());
        DirectApiListener {
            bind,
            auth,
            app: direct_app,
        }
    });

    serve_api(internal_app, direct_api).await
}
