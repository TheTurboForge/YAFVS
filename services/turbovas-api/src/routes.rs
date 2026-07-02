// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post},
};

use crate::{
    alert_writes::patch_alert,
    alerts::*,
    app_state::{AppState, healthz},
    browser_proxy_api::{
        BrowserProxyAuth, browser_proxy_clone_filter, browser_proxy_clone_port_list,
        browser_proxy_clone_report_config, browser_proxy_clone_scan_config,
        browser_proxy_clone_schedule, browser_proxy_clone_tag, browser_proxy_clone_target,
        browser_proxy_create_filter, browser_proxy_create_tag, browser_proxy_restore_filter,
        browser_proxy_restore_port_list, browser_proxy_restore_report_config,
        browser_proxy_restore_scan_config, browser_proxy_restore_schedule,
        browser_proxy_restore_tag, browser_proxy_restore_target,
        browser_proxy_update_tag_resources,
    },
    cert_advisories::*,
    cpe_catalog::*,
    credential_writes::patch_credential,
    credentials::{credential_asset_detail, credential_asset_export, credential_assets},
    cve_catalog::*,
    feeds::feeds,
    filter_writes::{
        clone_filter, create_filter, delete_filter, hard_delete_filter, patch_filter,
        restore_filter,
    },
    filters::*,
    host_assets::*,
    metrics::*,
    nvt_catalog::*,
    operating_systems::*,
    overrides::*,
    port_list_writes::{
        clone_port_list, create_port_list, delete_port_list, hard_delete_port_list,
        patch_port_list, restore_port_list,
    },
    port_lists::*,
    report_applications::report_applications,
    report_config_writes::{
        clone_report_config, create_report_config, delete_report_config, hard_delete_report_config,
        patch_report_config, restore_report_config,
    },
    report_configs::*,
    report_cves::report_cves,
    report_errors::report_errors,
    report_formats::*,
    report_hosts::report_hosts,
    report_operating_systems::report_operating_systems,
    report_payloads::*,
    report_ports::report_ports,
    report_tls_certificates::report_tls_certificates,
    request_shapes::MAX_DIRECT_API_WRITE_BODY_BYTES,
    result_payloads::*,
    scan_config_families::scan_config_asset_families,
    scan_config_writes::{
        clone_scan_config, delete_scan_config, hard_delete_scan_config, patch_scan_config,
        restore_scan_config,
    },
    scan_configs::*,
    scanner_assets::*,
    scanner_writes::patch_scanner,
    schedule_writes::{
        clone_schedule, delete_schedule, hard_delete_schedule, patch_schedule, restore_schedule,
    },
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
    tag_writes::{
        clone_tag, create_tag, delete_tag, hard_delete_tag, patch_tag, restore_tag,
        update_tag_resources,
    },
    tags::*,
    target_writes::{
        clone_target, create_target, delete_target, hard_delete_target, patch_target,
        restore_target,
    },
    task_targets::*,
    task_writes::patch_task,
    timezones::timezones,
    tls_certificates::*,
    trashcan::trashcan_summary,
    vulnerability_payloads::*,
};

pub(crate) fn native_api_router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/results", get(results))
        .route("/api/v1/results/:result_id", get(result_detail))
        .route("/api/v1/results/:result_id/export", get(result_export))
        .route("/api/v1/vulnerabilities", get(vulnerabilities))
        .route("/api/v1/cpes", get(cpe_catalog))
        .route("/api/v1/cpes/*cpe_id", get(cpe_catalog_detail))
        .route("/api/v1/cves", get(cve_catalog))
        .route("/api/v1/cves/:cve_id", get(cve_catalog_detail))
        .route("/api/v1/cves/:cve_id/export", get(cve_catalog_export))
        .route("/api/v1/cert-bund-advisories", get(cert_bund_advisories))
        .route(
            "/api/v1/cert-bund-advisories/:advisory_id/export",
            get(cert_bund_advisory_export),
        )
        .route(
            "/api/v1/cert-bund-advisories/:advisory_id",
            get(cert_bund_advisory_detail),
        )
        .route("/api/v1/dfn-cert-advisories", get(dfn_cert_advisories))
        .route(
            "/api/v1/dfn-cert-advisories/:advisory_id/export",
            get(dfn_cert_advisory_export),
        )
        .route(
            "/api/v1/dfn-cert-advisories/:advisory_id",
            get(dfn_cert_advisory_detail),
        )
        .route("/api/v1/nvts", get(nvt_catalog))
        .route("/api/v1/nvts/:nvt_id", get(nvt_catalog_detail))
        .route("/api/v1/nvts/:nvt_id/export", get(nvt_catalog_export))
        .route("/api/v1/operating-systems", get(operating_system_assets))
        .route(
            "/api/v1/operating-systems/:os_id",
            get(operating_system_asset_detail),
        )
        .route(
            "/api/v1/operating-systems/:os_id/export",
            get(operating_system_asset_export),
        )
        .route("/api/v1/hosts", get(host_assets))
        .route("/api/v1/hosts/:host_id", get(host_asset_detail))
        .route("/api/v1/hosts/:host_id/export", get(host_asset_export))
        .route("/api/v1/tls-certificates", get(tls_certificate_assets))
        .route(
            "/api/v1/tls-certificates/:certificate_id",
            get(tls_certificate_asset_detail),
        )
        .route(
            "/api/v1/tls-certificates/:certificate_id/export",
            get(tls_certificate_asset_export),
        )
        .route("/api/v1/scanners", get(scanner_assets))
        .route("/api/v1/scanners/:scanner_id", get(scanner_asset_detail))
        .route(
            "/api/v1/scanners/:scanner_id/export",
            get(scanner_asset_export),
        )
        .route("/api/v1/credentials", get(credential_assets))
        .route(
            "/api/v1/credentials/:credential_id",
            get(credential_asset_detail),
        )
        .route(
            "/api/v1/credentials/:credential_id/export",
            get(credential_asset_export),
        )
        .route("/api/v1/scan-configs", get(scan_config_assets))
        .route(
            "/api/v1/scan-configs/:scan_config_id",
            get(scan_config_asset_detail),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/export",
            get(export_scan_config_metadata),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/families",
            get(scan_config_asset_families),
        )
        .route("/api/v1/filters", get(filter_assets))
        .route("/api/v1/filters/:filter_id", get(filter_asset_detail))
        .route(
            "/api/v1/filters/:filter_id/export",
            get(export_filter_metadata),
        )
        .route("/api/v1/feeds", get(feeds))
        .route("/api/v1/alerts", get(alert_assets))
        .route("/api/v1/alerts/:alert_id", get(alert_asset_detail))
        .route(
            "/api/v1/alerts/:alert_id/export",
            get(export_alert_metadata),
        )
        .route("/api/v1/tags", get(tag_assets))
        .route(
            "/api/v1/tags/resource-names/:resource_type",
            get(tag_resource_names),
        )
        .route("/api/v1/tags/:tag_id/resources", get(tag_asset_resources))
        .route("/api/v1/tags/:tag_id/export", get(export_tag_metadata))
        .route("/api/v1/tags/:tag_id", get(tag_asset_detail))
        .route("/api/v1/overrides", get(override_assets))
        .route("/api/v1/overrides/:override_id", get(override_asset_detail))
        .route(
            "/api/v1/overrides/:override_id/export",
            get(override_asset_export),
        )
        .route("/api/v1/port-lists", get(port_list_assets))
        .route(
            "/api/v1/port-lists/:port_list_id",
            get(port_list_asset_detail),
        )
        .route(
            "/api/v1/port-lists/:port_list_id/export",
            get(export_port_list_metadata),
        )
        .route("/api/v1/schedules", get(schedule_assets))
        .route("/api/v1/schedules/:schedule_id", get(schedule_asset_detail))
        .route(
            "/api/v1/schedules/:schedule_id/export",
            get(export_schedule_metadata),
        )
        .route("/api/v1/timezones", get(timezones))
        .route("/api/v1/report-configs", get(report_config_assets))
        .route(
            "/api/v1/report-configs/:report_config_id",
            get(report_config_asset_detail),
        )
        .route(
            "/api/v1/report-configs/:report_config_id/export",
            get(export_report_config_metadata),
        )
        .route("/api/v1/report-formats", get(report_format_assets))
        .route(
            "/api/v1/report-formats/:report_format_id",
            get(report_format_asset_detail),
        )
        .route(
            "/api/v1/report-formats/:report_format_id/export",
            get(export_report_format_metadata),
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
        .route("/api/v1/targets/:target_id/export", get(target_export))
        .route("/api/v1/tasks", get(tasks))
        .route("/api/v1/tasks/:task_id", get(task_detail))
        .route("/api/v1/tasks/:task_id/export", get(task_export))
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
            .route("/api/v1/report-configs", post(create_report_config))
            .route(
                "/api/v1/report-configs/:report_config_id",
                patch(patch_report_config),
            )
            .route(
                "/api/v1/report-configs/:report_config_id",
                delete(delete_report_config),
            )
            .route(
                "/api/v1/report-configs/:report_config_id/clone",
                post(clone_report_config),
            )
            .route(
                "/api/v1/report-configs/:report_config_id/restore",
                post(restore_report_config),
            )
            .route(
                "/api/v1/report-configs/:report_config_id/trash",
                delete(hard_delete_report_config),
            )
            .route(
                "/api/v1/scan-configs/:scan_config_id",
                patch(patch_scan_config),
            )
            .route(
                "/api/v1/scan-configs/:scan_config_id",
                delete(delete_scan_config),
            )
            .route(
                "/api/v1/scan-configs/:scan_config_id/clone",
                post(clone_scan_config),
            )
            .route(
                "/api/v1/scan-configs/:scan_config_id/restore",
                post(restore_scan_config),
            )
            .route(
                "/api/v1/scan-configs/:scan_config_id/trash",
                delete(hard_delete_scan_config),
            )
            .route("/api/v1/filters", post(create_filter))
            .route("/api/v1/filters/:filter_id", patch(patch_filter))
            .route("/api/v1/filters/:filter_id", delete(delete_filter))
            .route("/api/v1/filters/:filter_id/clone", post(clone_filter))
            .route("/api/v1/filters/:filter_id/restore", post(restore_filter))
            .route(
                "/api/v1/filters/:filter_id/trash",
                delete(hard_delete_filter),
            )
            .route("/api/v1/alerts/:alert_id", patch(patch_alert))
            .route(
                "/api/v1/credentials/:credential_id",
                patch(patch_credential),
            )
            .route("/api/v1/scanners/:scanner_id", patch(patch_scanner))
            .route("/api/v1/targets/:target_id", patch(patch_target))
            .route("/api/v1/targets", post(create_target))
            .route("/api/v1/targets/:target_id", delete(delete_target))
            .route("/api/v1/targets/:target_id/clone", post(clone_target))
            .route("/api/v1/targets/:target_id/restore", post(restore_target))
            .route(
                "/api/v1/targets/:target_id/trash",
                delete(hard_delete_target),
            )
            .route("/api/v1/tasks/:task_id", patch(patch_task))
            .route("/api/v1/port-lists/:port_list_id", patch(patch_port_list))
            .route("/api/v1/port-lists/:port_list_id", delete(delete_port_list))
            .route(
                "/api/v1/port-lists/:port_list_id/clone",
                post(clone_port_list),
            )
            .route(
                "/api/v1/port-lists/:port_list_id/restore",
                post(restore_port_list),
            )
            .route(
                "/api/v1/port-lists/:port_list_id/trash",
                delete(hard_delete_port_list),
            )
            .route("/api/v1/port-lists", post(create_port_list))
            .route("/api/v1/schedules/:schedule_id", patch(patch_schedule))
            .route("/api/v1/schedules/:schedule_id", delete(delete_schedule))
            .route("/api/v1/schedules/:schedule_id/clone", post(clone_schedule))
            .route(
                "/api/v1/schedules/:schedule_id/restore",
                post(restore_schedule),
            )
            .route(
                "/api/v1/schedules/:schedule_id/trash",
                delete(hard_delete_schedule),
            )
            .route("/api/v1/tags", post(create_tag))
            .route("/api/v1/tags/:tag_id", patch(patch_tag))
            .route("/api/v1/tags/:tag_id", delete(delete_tag))
            .route("/api/v1/tags/:tag_id/clone", post(clone_tag))
            .route("/api/v1/tags/:tag_id/restore", post(restore_tag))
            .route("/api/v1/tags/:tag_id/trash", delete(hard_delete_tag))
            .route("/api/v1/tags/:tag_id/resources", post(update_tag_resources))
    } else {
        router
    };

    router.layer(DefaultBodyLimit::max(
        MAX_DIRECT_API_WRITE_BODY_BYTES as usize,
    ))
}

pub(crate) fn browser_proxy_native_api_router(
    router: Router<AppState>,
    auth: Option<BrowserProxyAuth>,
) -> Router<AppState> {
    let Some(auth) = auth else {
        return router;
    };
    let write_router = Router::new()
        .route("/api/v1/filters", post(browser_proxy_create_filter))
        .route("/api/v1/tags", post(browser_proxy_create_tag))
        .route(
            "/api/v1/tags/:tag_id/resources",
            post(browser_proxy_update_tag_resources),
        )
        .route(
            "/api/v1/filters/:filter_id/clone",
            post(browser_proxy_clone_filter),
        )
        .route(
            "/api/v1/filters/:filter_id/restore",
            post(browser_proxy_restore_filter),
        )
        .route(
            "/api/v1/port-lists/:port_list_id/clone",
            post(browser_proxy_clone_port_list),
        )
        .route(
            "/api/v1/port-lists/:port_list_id/restore",
            post(browser_proxy_restore_port_list),
        )
        .route(
            "/api/v1/report-configs/:report_config_id/clone",
            post(browser_proxy_clone_report_config),
        )
        .route(
            "/api/v1/report-configs/:report_config_id/restore",
            post(browser_proxy_restore_report_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/clone",
            post(browser_proxy_clone_scan_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/restore",
            post(browser_proxy_restore_scan_config),
        )
        .route(
            "/api/v1/schedules/:schedule_id/clone",
            post(browser_proxy_clone_schedule),
        )
        .route(
            "/api/v1/schedules/:schedule_id/restore",
            post(browser_proxy_restore_schedule),
        )
        .route("/api/v1/tags/:tag_id/clone", post(browser_proxy_clone_tag))
        .route(
            "/api/v1/tags/:tag_id/restore",
            post(browser_proxy_restore_tag),
        )
        .route(
            "/api/v1/targets/:target_id/clone",
            post(browser_proxy_clone_target),
        )
        .route(
            "/api/v1/targets/:target_id/restore",
            post(browser_proxy_restore_target),
        )
        .layer(DefaultBodyLimit::max(
            MAX_DIRECT_API_WRITE_BODY_BYTES as usize,
        ))
        .layer(Extension(auth));

    router.merge(write_router)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_tables_build_without_conflicts() {
        let base_router = native_api_router();
        let _direct_read_router = direct_native_api_router(base_router, false);
        let _direct_write_router = direct_native_api_router(native_api_router(), true);
        let _browser_proxy_router = browser_proxy_native_api_router(native_api_router(), None);
        let _browser_write_router = browser_proxy_native_api_router(
            native_api_router(),
            Some(BrowserProxyAuth::new(
                "0123456789abcdef0123456789abcdef".to_string(),
            )),
        );
    }
}
