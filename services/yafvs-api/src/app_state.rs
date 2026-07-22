// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{env, time::Duration};

use axum::{Json, extract::State};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime, Timeouts};
use serde::Serialize;
use tokio_postgres::{Config as PgConfig, NoTls};

use crate::{database_compatibility::DatabaseCompatibility, errors::ApiError};

const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DATABASE_POOL_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const DATABASE_POOL_CREATE_TIMEOUT: Duration = Duration::from_secs(10);
const DATABASE_POOL_RECYCLE_TIMEOUT: Duration = Duration::from_secs(5);
const DATABASE_STATEMENT_TIMEOUT_MS: u64 = 120_000;
const DATABASE_LOCK_TIMEOUT_MS: u64 = 5_000;
const DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: u64 = 60_000;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pool: Pool,
    pub(crate) database_compatibility: DatabaseCompatibility,
}

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    status: &'static str,
    database: &'static str,
    database_compatibility: DatabaseCompatibility,
}

pub(crate) fn create_pool() -> Result<Pool, ApiError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| ApiError::Config)?;
    let mut pg_config: PgConfig = database_url.parse().map_err(|_| ApiError::Config)?;
    pg_config.connect_timeout(DATABASE_CONNECT_TIMEOUT);
    let inherited_options = pg_config.get_options().unwrap_or_default().trim();
    let bounded_options = format!(
        "{inherited_options} -c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MS} -c lock_timeout={DATABASE_LOCK_TIMEOUT_MS} -c idle_in_transaction_session_timeout={DATABASE_IDLE_TRANSACTION_TIMEOUT_MS}"
    );
    pg_config.options(bounded_options.trim());
    let manager = Manager::from_config(
        pg_config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(8)
        .runtime(Runtime::Tokio1)
        .timeouts(Timeouts {
            wait: Some(DATABASE_POOL_WAIT_TIMEOUT),
            create: Some(DATABASE_POOL_CREATE_TIMEOUT),
            recycle: Some(DATABASE_POOL_RECYCLE_TIMEOUT),
        })
        .build()
        .map_err(|_| ApiError::Config)
}

pub(crate) async fn healthz(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    client
        .query_one("SELECT 1;", &[])
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(Json(HealthResponse {
        status: "ok",
        database: "ok",
        database_compatibility: state.database_compatibility,
    }))
}
