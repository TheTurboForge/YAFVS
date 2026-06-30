// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod alerts;
mod app_state;
mod auth;
mod catalog_payloads;
mod cert_advisories;
mod collections;
mod direct_api;
mod errors;
mod feeds;
mod filters;
mod formatters;
mod host_assets;
mod metrics_payloads;
mod nvt_payloads;
mod operating_systems;
mod operator_identity;
mod overrides;
mod path_ids;
mod port_lists;
mod query;
mod report_configs;
mod report_evidence_handlers;
mod report_evidence_payloads;
mod report_formats;
mod report_helpers;
mod report_payloads;
mod request_ids;
mod request_shapes;
mod result_payloads;
mod routes;
mod row_helpers;
mod runtime;
mod scan_configs;
mod scanner_assets;
mod schedules;
mod scope_payloads;
mod scope_report_handlers;
mod scope_writes;
mod tag_resource_helpers;
mod tag_writes;
mod tags;
mod task_targets;
mod tls_certificates;
mod trashcan;
mod user_tags;
mod vulnerability_payloads;

use app_state::{AppState, create_pool};
use direct_api::direct_api_config;
use errors::ApiError;
use operator_identity::resolve_configured_direct_api_operator;
use routes::{direct_native_api_router, native_api_router};
use runtime::{DirectApiListener, serve_api};

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState {
        pool: create_pool()?,
    };
    let direct_api = direct_api_config()?;
    if let Some((_, auth)) = direct_api.as_ref() {
        let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
        if let Some(operator) = resolve_configured_direct_api_operator(&client, auth).await? {
            tracing::info!(operator_uuid = %operator.user_uuid, "direct native API operator identity verified");
        }
    }
    let base_router = native_api_router();
    let internal_app = base_router.clone().with_state(state.clone());
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

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod filter_characterization_tests;
#[cfg(test)]
mod port_list_characterization_tests;
#[cfg(test)]
mod schedule_characterization_tests;
