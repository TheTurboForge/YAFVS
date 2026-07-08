// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    routing::{delete, patch, post},
};

use crate::{
    app_state::AppState,
    browser_proxy_api::BrowserProxyAuth,
    browser_proxy_filter::{
        browser_proxy_clone_filter, browser_proxy_create_filter, browser_proxy_delete_filter,
        browser_proxy_hard_delete_filter, browser_proxy_patch_filter, browser_proxy_restore_filter,
    },
    browser_proxy_host::{
        browser_proxy_create_host, browser_proxy_delete_host, browser_proxy_delete_host_identifier,
        browser_proxy_patch_host,
    },
    browser_proxy_metadata_patch::{
        browser_proxy_delete_task, browser_proxy_patch_alert, browser_proxy_patch_credential,
        browser_proxy_patch_report_format, browser_proxy_patch_scanner, browser_proxy_patch_task,
    },
    browser_proxy_port_list::{
        browser_proxy_clone_port_list, browser_proxy_create_port_list,
        browser_proxy_delete_port_list, browser_proxy_hard_delete_port_list,
        browser_proxy_import_port_list, browser_proxy_patch_port_list,
        browser_proxy_restore_port_list,
    },
    browser_proxy_report_config::{
        browser_proxy_clone_report_config, browser_proxy_create_report_config,
        browser_proxy_delete_report_config, browser_proxy_hard_delete_report_config,
        browser_proxy_patch_report_config, browser_proxy_restore_report_config,
    },
    browser_proxy_scan_config::{
        browser_proxy_clone_scan_config, browser_proxy_create_scan_config,
        browser_proxy_delete_scan_config, browser_proxy_hard_delete_scan_config,
        browser_proxy_patch_scan_config, browser_proxy_restore_scan_config,
    },
    browser_proxy_schedule::{
        browser_proxy_clone_schedule, browser_proxy_delete_schedule,
        browser_proxy_hard_delete_schedule, browser_proxy_patch_schedule,
        browser_proxy_restore_schedule,
    },
    browser_proxy_scope::{
        browser_proxy_create_scope, browser_proxy_delete_scope, browser_proxy_patch_scope,
    },
    browser_proxy_scope_report::browser_proxy_delete_scope_report,
    browser_proxy_tag::{
        browser_proxy_clone_tag, browser_proxy_create_tag, browser_proxy_delete_tag,
        browser_proxy_hard_delete_tag, browser_proxy_patch_tag, browser_proxy_restore_tag,
        browser_proxy_update_tag_resources,
    },
    browser_proxy_target::{
        browser_proxy_clone_target, browser_proxy_create_target, browser_proxy_delete_target,
        browser_proxy_hard_delete_target, browser_proxy_patch_target, browser_proxy_restore_target,
    },
    request_shapes::MAX_DIRECT_API_WRITE_BODY_BYTES,
};

pub(crate) fn browser_proxy_native_api_router(
    router: Router<AppState>,
    auth: Option<BrowserProxyAuth>,
) -> Router<AppState> {
    let Some(auth) = auth else {
        return router;
    };
    let router = router
        .route("/api/v1/alerts/:alert_id", patch(browser_proxy_patch_alert))
        .route(
            "/api/v1/credentials/:credential_id",
            patch(browser_proxy_patch_credential),
        )
        .route(
            "/api/v1/scanners/:scanner_id",
            patch(browser_proxy_patch_scanner),
        )
        .route("/api/v1/filters", post(browser_proxy_create_filter))
        .route("/api/v1/hosts", post(browser_proxy_create_host))
        .route("/api/v1/hosts/:host_id", patch(browser_proxy_patch_host))
        .route("/api/v1/hosts/:host_id", delete(browser_proxy_delete_host))
        .route(
            "/api/v1/host-identifiers/:identifier_id",
            delete(browser_proxy_delete_host_identifier),
        )
        .route(
            "/api/v1/filters/:filter_id",
            patch(browser_proxy_patch_filter),
        )
        .route(
            "/api/v1/filters/:filter_id",
            delete(browser_proxy_delete_filter),
        )
        .route(
            "/api/v1/filters/:filter_id/trash",
            delete(browser_proxy_hard_delete_filter),
        )
        .route(
            "/api/v1/report-configs/:report_config_id",
            patch(browser_proxy_patch_report_config),
        )
        .route(
            "/api/v1/report-configs/:report_config_id",
            delete(browser_proxy_delete_report_config),
        )
        .route(
            "/api/v1/report-configs/:report_config_id/trash",
            delete(browser_proxy_hard_delete_report_config),
        )
        .route(
            "/api/v1/report-formats/:report_format_id",
            patch(browser_proxy_patch_report_format),
        )
        .route("/api/v1/tags/:tag_id", patch(browser_proxy_patch_tag))
        .route("/api/v1/tags/:tag_id", delete(browser_proxy_delete_tag))
        .route(
            "/api/v1/tags/:tag_id/trash",
            delete(browser_proxy_hard_delete_tag),
        )
        .route("/api/v1/port-lists", post(browser_proxy_create_port_list))
        .route(
            "/api/v1/port-list-imports",
            post(browser_proxy_import_port_list),
        )
        .route(
            "/api/v1/port-lists/:port_list_id",
            patch(browser_proxy_patch_port_list),
        )
        .route(
            "/api/v1/port-lists/:port_list_id",
            delete(browser_proxy_delete_port_list),
        )
        .route(
            "/api/v1/port-lists/:port_list_id/trash",
            delete(browser_proxy_hard_delete_port_list),
        )
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
            "/api/v1/report-configs",
            post(browser_proxy_create_report_config),
        )
        .route(
            "/api/v1/report-configs/:report_config_id/restore",
            post(browser_proxy_restore_report_config),
        )
        .route(
            "/api/v1/scan-configs",
            post(browser_proxy_create_scan_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/clone",
            post(browser_proxy_clone_scan_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id",
            patch(browser_proxy_patch_scan_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/restore",
            post(browser_proxy_restore_scan_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id",
            delete(browser_proxy_delete_scan_config),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/trash",
            delete(browser_proxy_hard_delete_scan_config),
        )
        .route(
            "/api/v1/schedules/:schedule_id/clone",
            post(browser_proxy_clone_schedule),
        )
        .route(
            "/api/v1/schedules/:schedule_id",
            patch(browser_proxy_patch_schedule),
        )
        .route(
            "/api/v1/schedules/:schedule_id/restore",
            post(browser_proxy_restore_schedule),
        )
        .route(
            "/api/v1/schedules/:schedule_id",
            delete(browser_proxy_delete_schedule),
        )
        .route(
            "/api/v1/schedules/:schedule_id/trash",
            delete(browser_proxy_hard_delete_schedule),
        )
        .route("/api/v1/scopes", post(browser_proxy_create_scope))
        .route("/api/v1/scopes/:scope_id", patch(browser_proxy_patch_scope))
        .route(
            "/api/v1/scopes/:scope_id",
            delete(browser_proxy_delete_scope),
        )
        .route(
            "/api/v1/scope-reports/:scope_report_id",
            delete(browser_proxy_delete_scope_report),
        )
        .route("/api/v1/tags/:tag_id/clone", post(browser_proxy_clone_tag))
        .route(
            "/api/v1/tags/:tag_id/restore",
            post(browser_proxy_restore_tag),
        )
        .route("/api/v1/tasks/:task_id", patch(browser_proxy_patch_task))
        .route("/api/v1/tasks/:task_id", delete(browser_proxy_delete_task))
        .route("/api/v1/targets", post(browser_proxy_create_target))
        .route(
            "/api/v1/targets/:target_id/clone",
            post(browser_proxy_clone_target),
        )
        .route(
            "/api/v1/targets/:target_id/restore",
            post(browser_proxy_restore_target),
        )
        .route(
            "/api/v1/targets/:target_id",
            patch(browser_proxy_patch_target),
        )
        .route(
            "/api/v1/targets/:target_id",
            delete(browser_proxy_delete_target),
        )
        .route(
            "/api/v1/targets/:target_id/trash",
            delete(browser_proxy_hard_delete_target),
        )
        .layer(DefaultBodyLimit::max(
            MAX_DIRECT_API_WRITE_BODY_BYTES as usize,
        ))
        .layer(Extension(auth));

    router
}
