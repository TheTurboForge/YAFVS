// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod alert_payloads;
mod alert_query_sql;
mod alert_write_db;
mod alert_write_sql;
mod alert_write_transactions;
mod alert_write_validation;
mod alert_writes;
mod alerts;
mod app_state;
mod asset_user_tag_query_sql;
mod auth;
mod browser_proxy_api;
mod cert_advisories;
mod cert_advisory_payloads;
mod collections;
mod cpe_catalog;
mod cpe_catalog_payloads;
mod credential_payloads;
mod credential_query_sql;
mod credential_write_db;
mod credential_write_sql;
mod credential_write_transactions;
mod credential_write_validation;
mod credential_writes;
mod credentials;
mod cve_catalog;
mod cve_catalog_payloads;
mod direct_api;
mod direct_api_contract;
mod errors;
mod feeds;
mod filter_payloads;
mod filter_query_sql;
mod filter_write_db;
#[cfg(test)]
mod filter_write_plans;
mod filter_write_sql;
mod filter_write_transactions;
mod filter_write_validation;
mod filter_writes;
mod filters;
mod formatters;
mod host_asset_payloads;
mod host_asset_query_sql;
mod host_assets;
mod metrics;
mod metrics_payloads;
#[cfg(test)]
mod monthly_report_characterization_tests;
mod nvt_catalog;
mod nvt_catalog_payloads;
mod nvt_payloads;
mod operating_system_payloads;
mod operating_system_query_sql;
mod operating_systems;
mod operator_identity;
#[cfg(test)]
mod override_characterization_tests;
mod override_payloads;
mod override_query_sql;
mod override_writes;
mod overrides;
mod path_ids;
mod port_list_payloads;
mod port_list_query_sql;
mod port_list_write_db;
#[cfg(test)]
mod port_list_write_plans;
mod port_list_write_sql;
mod port_list_write_transactions;
mod port_list_write_validation;
mod port_list_writes;
mod port_lists;
mod query;
mod report_applications;
mod report_config_payloads;
mod report_config_query_sql;
mod report_config_write_db;
#[cfg(test)]
mod report_config_write_plans;
mod report_config_write_sql;
mod report_config_write_validation;
mod report_config_writes;
mod report_configs;
mod report_cve_query_sql;
mod report_cves;
mod report_error_query_sql;
mod report_errors;
mod report_evidence_payloads;
#[cfg(test)]
mod report_export_characterization_tests;
mod report_format_payloads;
mod report_format_query_sql;
mod report_formats;
mod report_helpers;
mod report_host_query_sql;
mod report_hosts;
mod report_operating_system_query_sql;
mod report_operating_systems;
mod report_payloads;
#[cfg(test)]
mod report_payloads_tests;
mod report_port_query_sql;
mod report_ports;
mod report_tls_certificate_query_sql;
mod report_tls_certificates;
mod request_ids;
mod request_shapes;
mod result_payload_rows;
mod result_payloads;
mod result_query_sql;
mod routes;
mod row_helpers;
mod runtime;
mod scan_config_families;
mod scan_config_payloads;
mod scan_config_query_sql;
mod scan_config_write_db;
mod scan_config_write_sql;
mod scan_config_write_transactions;
mod scan_config_write_validation;
mod scan_config_writes;
mod scan_configs;
mod scanner_asset_payloads;
mod scanner_asset_query_sql;
mod scanner_assets;
mod scanner_write_db;
mod scanner_write_sql;
mod scanner_write_transactions;
mod scanner_write_validation;
mod scanner_writes;
mod schedule_payloads;
mod schedule_query_sql;
mod schedule_write_db;
#[cfg(test)]
mod schedule_write_plans;
mod schedule_write_sql;
mod schedule_write_transactions;
mod schedule_write_validation;
mod schedule_writes;
mod schedules;
mod scope_payload_rows;
mod scope_payloads;
mod scope_report_applications;
mod scope_report_cves;
mod scope_report_errors;
mod scope_report_hosts;
mod scope_report_lookup;
#[cfg(test)]
mod scope_report_mutation_plans;
mod scope_report_operating_systems;
mod scope_report_ports;
mod scope_report_results;
mod scope_report_retention;
mod scope_report_tls_certificates;
mod scope_reports;
mod scope_write_db;
#[cfg(test)]
mod scope_write_plans;
mod scope_write_sql;
mod scope_write_transactions;
mod scope_write_validation;
mod scope_writes;
mod startup;
#[cfg(test)]
mod tag_characterization_tests;
mod tag_payloads;
mod tag_query_sql;
mod tag_resource_helpers;
mod tag_write_db;
#[cfg(test)]
mod tag_write_plans;
mod tag_write_sql;
mod tag_write_transactions;
mod tag_write_validation;
mod tag_writes;
mod tags;
mod target_handlers;
mod target_query_sql;
#[cfg(test)]
mod target_write_characterization_tests;
mod target_write_db;
mod target_write_sql;
mod target_write_transactions;
mod target_write_validation;
mod target_writes;
#[cfg(test)]
mod target_writes_tests;
mod task_handlers;
mod task_query_sql;
mod task_target_payloads;
mod task_targets;
mod task_write_db;
mod task_write_sql;
mod task_write_transactions;
mod task_write_validation;
mod task_writes;
#[cfg(test)]
mod task_writes_tests;
mod timezones;
mod tls_certificate_payloads;
mod tls_certificate_query_sql;
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
mod alert_write_characterization_tests;
#[cfg(test)]
mod alert_writes_tests;
#[cfg(test)]
mod asset_detail_contract_tests;
#[cfg(test)]
mod collection_contract_tests;
#[cfg(test)]
mod collection_query_contract_tests;
#[cfg(test)]
mod credential_contract_tests;
#[cfg(test)]
mod credential_write_characterization_tests;
#[cfg(test)]
mod credential_writes_tests;
#[cfg(test)]
mod direct_api_contract_tests;
#[cfg(test)]
mod filter_characterization_tests;
#[cfg(test)]
mod gsa_sort_contract_tests;
#[cfg(test)]
mod metadata_export_characterization_tests;
#[cfg(test)]
mod port_list_characterization_tests;
#[cfg(test)]
mod report_config_characterization_tests;
#[cfg(test)]
mod report_format_characterization_tests;
#[cfg(test)]
mod result_contract_tests;
#[cfg(test)]
mod scan_config_characterization_tests;
#[cfg(test)]
mod scan_config_writes_tests;
#[cfg(test)]
mod scanner_control_characterization_tests;
#[cfg(test)]
mod scanner_writes_tests;
#[cfg(test)]
mod schedule_characterization_tests;
#[cfg(test)]
mod scope_contract_tests;
#[cfg(test)]
mod scope_report_contract_tests;
#[cfg(test)]
mod scope_report_mutation_characterization_tests;
#[cfg(test)]
mod task_control_characterization_tests;
#[cfg(test)]
mod tooling_account_characterization_tests;
#[cfg(test)]
mod tooling_alert_write_characterization_tests;
#[cfg(test)]
mod tooling_bulk_write_characterization_tests;
#[cfg(test)]
mod tooling_credential_write_characterization_tests;
#[cfg(test)]
mod tooling_override_write_characterization_tests;
#[cfg(test)]
mod tooling_schedule_write_characterization_tests;
#[cfg(test)]
mod tooling_tag_write_characterization_tests;
#[cfg(test)]
mod tooling_target_import_characterization_tests;
#[cfg(test)]
mod tooling_task_control_characterization_tests;
#[cfg(test)]
mod tooling_trash_write_characterization_tests;
