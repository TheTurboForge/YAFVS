// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, future::Future, net::SocketAddr, time::Duration};

use axum::{Router, middleware};
use tokio::{sync::watch, time::timeout};

use crate::{auth::DirectApiAuth, direct_api::require_direct_api_auth, errors::ApiError};

const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct DirectApiListener {
    pub(crate) bind: String,
    pub(crate) auth: DirectApiAuth,
    pub(crate) app: Router,
}

pub(crate) async fn serve_api(
    internal_app: Router,
    direct_api: Option<DirectApiListener>,
) -> Result<(), ApiError> {
    let bind = env_string("YAFVS_API_BIND").unwrap_or_else(|| "0.0.0.0:9080".to_string());
    let internal_listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|_| ApiError::Config)?;
    let internal_addr: SocketAddr = internal_listener
        .local_addr()
        .map_err(|_| ApiError::Config)?;
    tracing::info!(addr = %internal_addr, "starting yafvs-api internal listener");

    if let Some(DirectApiListener { bind, auth, app }) = direct_api {
        let direct_listener = tokio::net::TcpListener::bind(&bind)
            .await
            .map_err(|_| ApiError::Config)?;
        let direct_addr: SocketAddr = direct_listener.local_addr().map_err(|_| ApiError::Config)?;
        tracing::info!(addr = %direct_addr, "starting yafvs-api direct authenticated listener");
        let direct_app = app.layer(middleware::from_fn_with_state(
            auth,
            require_direct_api_auth,
        ));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let direct_shutdown_rx = shutdown_rx.clone();
        let servers = async move {
            tokio::try_join!(
                async {
                    axum::serve(internal_listener, internal_app)
                        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
                        .await
                        .map_err(|_| ApiError::Config)
                },
                async {
                    axum::serve(direct_listener, direct_app)
                        .with_graceful_shutdown(wait_for_shutdown(direct_shutdown_rx))
                        .await
                        .map_err(|_| ApiError::Config)
                },
            )
            .map(|_| ())
        };
        drive_servers_until_shutdown(servers, shutdown_tx).await
    } else {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = async move {
            axum::serve(internal_listener, internal_app)
                .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
                .await
                .map_err(|_| ApiError::Config)
        };
        drive_servers_until_shutdown(server, shutdown_tx).await
    }
}

async fn drive_servers_until_shutdown<F>(
    servers: F,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), ApiError>
where
    F: Future<Output = Result<(), ApiError>>,
{
    tokio::pin!(servers);
    tokio::select! {
        result = &mut servers => result,
        () = shutdown_signal() => {
            let _ = shutdown_tx.send(true);
            match timeout(GRACEFUL_DRAIN_TIMEOUT, &mut servers).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::error!(
                        timeout_seconds = GRACEFUL_DRAIN_TIMEOUT.as_secs(),
                        "native API graceful shutdown drain timed out"
                    );
                    Err(ApiError::Config)
                }
            }
        }
    }
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    while !*shutdown_rx.borrow_and_update() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn shutdown_signal() {
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            if let Some(signal) = terminate.as_mut() {
                signal.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graceful_shutdown_drain_is_bounded() {
        assert_eq!(GRACEFUL_DRAIN_TIMEOUT, Duration::from_secs(30));
    }
}
