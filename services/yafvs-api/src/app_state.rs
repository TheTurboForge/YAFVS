// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::env;

use axum::{Json, extract::State};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use serde::Serialize;
use tokio_postgres::{Config as PgConfig, NoTls};

use crate::errors::ApiError;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) pool: Pool,
}

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    status: &'static str,
    database: &'static str,
}

pub(crate) fn create_pool() -> Result<Pool, ApiError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| ApiError::Config)?;
    let pg_config: PgConfig = database_url.parse().map_err(|_| ApiError::Config)?;
    let manager = Manager::from_config(
        pg_config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(8)
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
    }))
}
