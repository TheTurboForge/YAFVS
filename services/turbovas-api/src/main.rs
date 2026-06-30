// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

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
#[cfg(test)]
mod override_characterization_tests;
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
mod startup;
mod tag_resource_helpers;
mod tag_writes;
mod tags;
mod task_targets;
mod tls_certificates;
mod trashcan;
mod user_tags;
mod vulnerability_payloads;

use errors::ApiError;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    startup::run().await
}

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod filter_characterization_tests;
#[cfg(test)]
mod port_list_characterization_tests;
#[cfg(test)]
mod report_config_characterization_tests;
#[cfg(test)]
mod schedule_characterization_tests;
