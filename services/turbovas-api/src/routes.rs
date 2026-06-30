// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post},
};

use crate::{
    alerts::*,
    app_state::{AppState, healthz},
    cert_advisories::*,
    cpe_catalog::*,
    cve_catalog::*,
    feeds::feeds,
    filters::*,
    host_assets::*,
    metrics_payloads::*,
    nvt_catalog::*,
    operating_systems::*,
    overrides::*,
    port_lists::*,
    report_applications::report_applications,
    report_configs::*,
    report_cves::report_cves,
    report_errors::report_errors,
    report_evidence_handlers::*,
    report_formats::*,
    report_operating_systems::report_operating_systems,
    report_payloads::*,
    report_ports::report_ports,
    report_tls_certificates::report_tls_certificates,
    request_shapes::MAX_DIRECT_API_WRITE_BODY_BYTES,
    result_payloads::*,
    scan_configs::*,
    scanner_assets::*,
    schedules::*,
    scope_payloads::*,
    scope_report_applications::scope_report_applications,
    scope_report_cves::scope_report_cves,
    scope_report_errors::scope_report_errors,
    scope_report_hosts::scope_report_hosts,
    scope_report_operating_systems::scope_report_operating_systems,
    scope_report_ports::scope_report_ports,
    scope_report_results::scope_report_results,
    scope_report_retention::scope_report_retention_plan,
    scope_report_tls_certificates::scope_report_tls_certificates,
    scope_reports::*,
    scope_writes::{create_scope, delete_scope, patch_scope},
    tag_writes::{create_tag, delete_tag, patch_tag, update_tag_resources},
    tags::*,
    task_targets::*,
    tls_certificates::*,
    trashcan::trashcan_summary,
    vulnerability_payloads::*,
};

pub(crate) fn native_api_router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/results", get(results))
        .route("/api/v1/results/:result_id", get(result_detail))
        .route("/api/v1/vulnerabilities", get(vulnerabilities))
        .route("/api/v1/cpes", get(cpe_catalog))
        .route("/api/v1/cpes/*cpe_id", get(cpe_catalog_detail))
        .route("/api/v1/cves", get(cve_catalog))
        .route("/api/v1/cves/:cve_id", get(cve_catalog_detail))
        .route("/api/v1/cert-bund-advisories", get(cert_bund_advisories))
        .route(
            "/api/v1/cert-bund-advisories/*advisory_id",
            get(cert_bund_advisory_detail),
        )
        .route("/api/v1/dfn-cert-advisories", get(dfn_cert_advisories))
        .route(
            "/api/v1/dfn-cert-advisories/*advisory_id",
            get(dfn_cert_advisory_detail),
        )
        .route("/api/v1/nvts", get(nvt_catalog))
        .route("/api/v1/nvts/:nvt_id", get(nvt_catalog_detail))
        .route("/api/v1/operating-systems", get(operating_system_assets))
        .route(
            "/api/v1/operating-systems/:os_id",
            get(operating_system_asset_detail),
        )
        .route("/api/v1/hosts", get(host_assets))
        .route("/api/v1/hosts/:host_id", get(host_asset_detail))
        .route("/api/v1/tls-certificates", get(tls_certificate_assets))
        .route(
            "/api/v1/tls-certificates/:certificate_id",
            get(tls_certificate_asset_detail),
        )
        .route("/api/v1/scanners", get(scanner_assets))
        .route("/api/v1/scanners/:scanner_id", get(scanner_asset_detail))
        .route("/api/v1/scan-configs", get(scan_config_assets))
        .route(
            "/api/v1/scan-configs/:scan_config_id",
            get(scan_config_asset_detail),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/families",
            get(scan_config_asset_families),
        )
        .route("/api/v1/filters", get(filter_assets))
        .route("/api/v1/filters/:filter_id", get(filter_asset_detail))
        .route("/api/v1/feeds", get(feeds))
        .route("/api/v1/alerts", get(alert_assets))
        .route("/api/v1/alerts/:alert_id", get(alert_asset_detail))
        .route("/api/v1/tags", get(tag_assets))
        .route(
            "/api/v1/tags/resource-names/:resource_type",
            get(tag_resource_names),
        )
        .route("/api/v1/tags/:tag_id/resources", get(tag_asset_resources))
        .route("/api/v1/tags/:tag_id", get(tag_asset_detail))
        .route("/api/v1/overrides", get(override_assets))
        .route("/api/v1/overrides/:override_id", get(override_asset_detail))
        .route("/api/v1/port-lists", get(port_list_assets))
        .route(
            "/api/v1/port-lists/:port_list_id",
            get(port_list_asset_detail),
        )
        .route("/api/v1/schedules", get(schedule_assets))
        .route("/api/v1/schedules/:schedule_id", get(schedule_asset_detail))
        .route("/api/v1/report-configs", get(report_config_assets))
        .route(
            "/api/v1/report-configs/:report_config_id",
            get(report_config_asset_detail),
        )
        .route("/api/v1/report-formats", get(report_format_assets))
        .route(
            "/api/v1/report-formats/:report_format_id",
            get(report_format_asset_detail),
        )
        .route("/api/v1/trashcan/summary", get(trashcan_summary))
        .route("/api/v1/reports", get(reports))
        .route("/api/v1/reports/:report_id", get(report_detail))
        .route("/api/v1/reports/:report_id/results", get(report_results))
        .route("/api/v1/reports/:report_id/hosts", get(report_hosts))
        .route("/api/v1/reports/:report_id/ports", get(report_ports))
        .route(
            "/api/v1/reports/:report_id/applications",
            get(report_applications),
        )
        .route(
            "/api/v1/reports/:report_id/operating-systems",
            get(report_operating_systems),
        )
        .route("/api/v1/reports/:report_id/cves", get(report_cves))
        .route(
            "/api/v1/reports/:report_id/tls-certificates",
            get(report_tls_certificates),
        )
        .route("/api/v1/reports/:report_id/errors", get(report_errors))
        .route("/api/v1/scopes", get(scopes))
        .route("/api/v1/scopes/:scope_id", get(scope_detail))
        .route("/api/v1/targets", get(targets))
        .route("/api/v1/targets/:target_id", get(target_detail))
        .route("/api/v1/tasks", get(tasks))
        .route("/api/v1/tasks/:task_id", get(task_detail))
        .route("/api/v1/scope-reports", get(scope_reports))
        .route(
            "/api/v1/scope-reports/:scope_report_id",
            get(scope_report_detail),
        )
        .route("/api/v1/reports/:report_id/metrics", get(report_metrics))
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/results",
            get(scope_report_results),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/hosts",
            get(scope_report_hosts),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/ports",
            get(scope_report_ports),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/applications",
            get(scope_report_applications),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/operating-systems",
            get(scope_report_operating_systems),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/cves",
            get(scope_report_cves),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/tls-certificates",
            get(scope_report_tls_certificates),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/errors",
            get(scope_report_errors),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/metrics",
            get(scope_report_metrics),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan",
            get(scope_report_retention_plan),
        )
}

pub(crate) fn direct_native_api_router(
    router: Router<AppState>,
    write_control_enabled: bool,
) -> Router<AppState> {
    let router = if write_control_enabled {
        router
            .route("/api/v1/scopes", post(create_scope))
            .route("/api/v1/scopes/:scope_id", patch(patch_scope))
            .route("/api/v1/scopes/:scope_id", delete(delete_scope))
            .route("/api/v1/tags", post(create_tag))
            .route("/api/v1/tags/:tag_id", patch(patch_tag))
            .route("/api/v1/tags/:tag_id", delete(delete_tag))
            .route("/api/v1/tags/:tag_id/resources", post(update_tag_resources))
    } else {
        router
    };

    router.layer(DefaultBodyLimit::max(
        MAX_DIRECT_API_WRITE_BODY_BYTES as usize,
    ))
}
