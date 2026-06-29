// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, net::SocketAddr};

use axum::{Router, middleware};

use crate::{auth::DirectApiAuth, direct_api::require_direct_api_auth, errors::ApiError};

pub(crate) async fn serve_api(
    app: Router,
    direct_api: Option<(String, DirectApiAuth)>,
) -> Result<(), ApiError> {
    let bind = env_string("TURBOVAS_API_BIND").unwrap_or_else(|| "0.0.0.0:9080".to_string());
    let internal_listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|_| ApiError::Config)?;
    let internal_addr: SocketAddr = internal_listener
        .local_addr()
        .map_err(|_| ApiError::Config)?;
    tracing::info!(addr = %internal_addr, "starting turbovas-api internal listener");

    if let Some((direct_bind, auth)) = direct_api {
        let direct_listener = tokio::net::TcpListener::bind(&direct_bind)
            .await
            .map_err(|_| ApiError::Config)?;
        let direct_addr: SocketAddr = direct_listener.local_addr().map_err(|_| ApiError::Config)?;
        tracing::info!(addr = %direct_addr, "starting turbovas-api direct authenticated listener");
        let direct_app = app.clone().layer(middleware::from_fn_with_state(
            auth,
            require_direct_api_auth,
        ));
        tokio::try_join!(
            axum::serve(internal_listener, app).with_graceful_shutdown(shutdown_signal()),
            axum::serve(direct_listener, direct_app).with_graceful_shutdown(shutdown_signal()),
        )
        .map(|_| ())
        .map_err(|_| ApiError::Config)
    } else {
        axum::serve(internal_listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|_| ApiError::Config)
    }
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
