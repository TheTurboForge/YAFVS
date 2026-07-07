// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, patch, post},
};

use crate::{
    alert_writes::patch_alert,
    app_state::AppState,
    credential_writes::patch_credential,
    filter_writes::{
        clone_filter, create_filter, delete_filter, hard_delete_filter, patch_filter,
        restore_filter,
    },
    port_list_writes::{
        clone_port_list, create_port_list, delete_port_list, hard_delete_port_list,
        import_port_list, patch_port_list, restore_port_list,
    },
    report_config_writes::{
        clone_report_config, create_report_config, delete_report_config, hard_delete_report_config,
        patch_report_config, restore_report_config,
    },
    request_shapes::MAX_DIRECT_API_WRITE_BODY_BYTES,
    scan_config_writes::{
        clone_scan_config, create_scan_config, delete_scan_config, hard_delete_scan_config,
        patch_scan_config, restore_scan_config,
    },
    scanner_writes::patch_scanner,
    schedule_writes::{
        clone_schedule, delete_schedule, hard_delete_schedule, patch_schedule, restore_schedule,
    },
    scope_writes::{create_scope, delete_scope, patch_scope},
    tag_writes::{
        clone_tag, create_tag, delete_tag, hard_delete_tag, patch_tag, restore_tag,
        update_tag_resources,
    },
    target_writes::{
        clone_target, create_target, delete_target, hard_delete_target, patch_target,
        restore_target,
    },
    task_writes::patch_task,
};

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
            .route("/api/v1/scan-configs", post(create_scan_config))
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
            .route("/api/v1/port-list-imports", post(import_port_list))
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
