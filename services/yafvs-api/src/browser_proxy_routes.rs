// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post, put},
};

use crate::{
    app_state::AppState,
    authentication_settings::{
        MAX_AUTHENTICATION_SETTINGS_BODY_BYTES, browser_proxy_authentication_settings,
        browser_proxy_update_ldap_authentication_settings,
        browser_proxy_update_radius_authentication_settings,
    },
    browser_proxy_alert_definition::{
        browser_proxy_get_alert_definition, browser_proxy_put_alert_definition,
    },
    browser_proxy_api::BrowserProxyAuth,
    browser_proxy_filter::{
        browser_proxy_clone_filter, browser_proxy_create_filter, browser_proxy_delete_filter,
        browser_proxy_hard_delete_filter, browser_proxy_patch_filter, browser_proxy_restore_filter,
    },
    browser_proxy_host::{
        browser_proxy_create_host, browser_proxy_delete_host, browser_proxy_delete_host_identifier,
        browser_proxy_delete_host_operating_system, browser_proxy_patch_host,
    },
    browser_proxy_metadata_patch::{
        browser_proxy_clone_alert, browser_proxy_clone_override, browser_proxy_clone_scanner,
        browser_proxy_clone_task, browser_proxy_create_alert, browser_proxy_create_credential,
        browser_proxy_create_override, browser_proxy_create_scanner, browser_proxy_create_task,
        browser_proxy_delete_alert, browser_proxy_delete_override, browser_proxy_delete_scanner,
        browser_proxy_delete_task, browser_proxy_delete_tls_certificate,
        browser_proxy_deliver_alert_report, browser_proxy_hard_delete_alert,
        browser_proxy_hard_delete_credential, browser_proxy_hard_delete_override,
        browser_proxy_hard_delete_scanner, browser_proxy_hard_delete_task,
        browser_proxy_patch_alert, browser_proxy_patch_credential, browser_proxy_patch_override,
        browser_proxy_patch_scanner, browser_proxy_patch_task,
        browser_proxy_replace_scanner_configuration, browser_proxy_replace_task,
        browser_proxy_replace_task_target, browser_proxy_restore_alert,
        browser_proxy_restore_credential, browser_proxy_restore_override,
        browser_proxy_restore_scanner, browser_proxy_restore_task, browser_proxy_start_task,
        browser_proxy_stop_task, browser_proxy_test_alert, browser_proxy_verify_scanner,
    },
    browser_proxy_port_list::{
        browser_proxy_clone_port_list, browser_proxy_create_port_list,
        browser_proxy_create_port_list_range, browser_proxy_delete_port_list,
        browser_proxy_delete_port_list_range, browser_proxy_hard_delete_port_list,
        browser_proxy_import_port_list, browser_proxy_patch_port_list,
        browser_proxy_restore_port_list,
    },
    browser_proxy_scan_config::{
        browser_proxy_clone_scan_config, browser_proxy_create_scan_config,
        browser_proxy_delete_scan_config, browser_proxy_hard_delete_scan_config,
        browser_proxy_import_scan_config, browser_proxy_patch_scan_config,
        browser_proxy_patch_scan_config_family_nvts, browser_proxy_restore_scan_config,
    },
    browser_proxy_schedule::{
        browser_proxy_clone_schedule, browser_proxy_create_schedule, browser_proxy_delete_schedule,
        browser_proxy_hard_delete_schedule, browser_proxy_patch_schedule,
        browser_proxy_restore_schedule,
    },
    browser_proxy_scope::{
        browser_proxy_create_scope, browser_proxy_delete_scope, browser_proxy_patch_scope,
    },
    browser_proxy_scope_report::{
        browser_proxy_delete_scope_report, browser_proxy_generate_scope_report,
    },
    browser_proxy_tag::{
        browser_proxy_clone_tag, browser_proxy_create_tag, browser_proxy_delete_tag,
        browser_proxy_hard_delete_tag, browser_proxy_patch_tag, browser_proxy_restore_tag,
        browser_proxy_update_tag_resources,
    },
    browser_proxy_target::{
        browser_proxy_clone_target, browser_proxy_create_target, browser_proxy_delete_target,
        browser_proxy_hard_delete_target, browser_proxy_patch_target, browser_proxy_restore_target,
    },
    current_user_password::{
        MAX_CURRENT_USER_PASSWORD_CHANGE_BODY_BYTES, browser_proxy_change_current_user_password,
    },
    request_shapes::MAX_DIRECT_API_WRITE_BODY_BYTES,
    scan_config_backup::MAX_SCAN_CONFIG_BACKUP_BODY_BYTES,
    trash_empty::{
        MAX_TRASH_EMPTY_BODY_BYTES, browser_proxy_empty_trashcan, browser_proxy_trash_empty_preview,
    },
    user_management::{
        MAX_USER_MANAGEMENT_BODY_BYTES, browser_proxy_clone_user, browser_proxy_create_user,
        browser_proxy_delete_user, browser_proxy_modify_user, browser_proxy_user_management_detail,
        browser_proxy_user_management_users,
    },
    user_settings::{
        MAX_USER_SETTING_BODY_BYTES, browser_proxy_current_user_setting,
        browser_proxy_current_user_settings, browser_proxy_update_current_user_setting,
        browser_proxy_update_current_user_timezone,
    },
};

pub(crate) fn browser_proxy_native_api_router(
    router: Router<AppState>,
    auth: Option<BrowserProxyAuth>,
) -> Router<AppState> {
    let Some(auth) = auth else {
        return router;
    };
    let router = router
        .route(
            "/api/v1/authentication-settings",
            get(browser_proxy_authentication_settings),
        )
        .route(
            "/api/v1/authentication-settings/ldap",
            put(browser_proxy_update_ldap_authentication_settings).layer(DefaultBodyLimit::max(
                MAX_AUTHENTICATION_SETTINGS_BODY_BYTES,
            )),
        )
        .route(
            "/api/v1/authentication-settings/radius",
            put(browser_proxy_update_radius_authentication_settings).layer(DefaultBodyLimit::max(
                MAX_AUTHENTICATION_SETTINGS_BODY_BYTES,
            )),
        )
        .route(
            "/api/v1/alerts/:alert_id/definition",
            get(browser_proxy_get_alert_definition).put(browser_proxy_put_alert_definition),
        )
        .route("/api/v1/alerts", post(browser_proxy_create_alert))
        .route("/api/v1/alerts/:alert_id", patch(browser_proxy_patch_alert))
        .route(
            "/api/v1/alerts/:alert_id",
            delete(browser_proxy_delete_alert),
        )
        .route(
            "/api/v1/alerts/:alert_id/clone",
            post(browser_proxy_clone_alert),
        )
        .route(
            "/api/v1/alerts/:alert_id/restore",
            post(browser_proxy_restore_alert),
        )
        .route(
            "/api/v1/alerts/:alert_id/trash",
            delete(browser_proxy_hard_delete_alert),
        )
        .route(
            "/api/v1/alerts/:alert_id/test",
            post(browser_proxy_test_alert),
        )
        .route(
            "/api/v1/alerts/:alert_id/deliver-report",
            post(browser_proxy_deliver_alert_report),
        )
        .route(
            "/api/v1/overrides/:override_id",
            delete(browser_proxy_delete_override),
        )
        .route("/api/v1/overrides", post(browser_proxy_create_override))
        .route(
            "/api/v1/overrides/:override_id",
            patch(browser_proxy_patch_override),
        )
        .route(
            "/api/v1/overrides/:override_id/clone",
            post(browser_proxy_clone_override),
        )
        .route(
            "/api/v1/overrides/:override_id/restore",
            post(browser_proxy_restore_override),
        )
        .route(
            "/api/v1/overrides/:override_id/trash",
            delete(browser_proxy_hard_delete_override),
        )
        .route(
            "/api/v1/credentials/:credential_id",
            patch(browser_proxy_patch_credential),
        )
        .route(
            "/api/v1/credentials/:credential_id/restore",
            post(browser_proxy_restore_credential),
        )
        .route(
            "/api/v1/credentials/:credential_id/trash",
            delete(browser_proxy_hard_delete_credential),
        )
        .route("/api/v1/credentials", post(browser_proxy_create_credential))
        .route("/api/v1/scanners", post(browser_proxy_create_scanner))
        .route(
            "/api/v1/scanners/:scanner_id",
            patch(browser_proxy_patch_scanner),
        )
        .route(
            "/api/v1/scanners/:scanner_id",
            delete(browser_proxy_delete_scanner),
        )
        .route(
            "/api/v1/scanners/:scanner_id/clone",
            post(browser_proxy_clone_scanner),
        )
        .route(
            "/api/v1/scanners/:scanner_id/restore",
            post(browser_proxy_restore_scanner),
        )
        .route(
            "/api/v1/scanners/:scanner_id/trash",
            delete(browser_proxy_hard_delete_scanner),
        )
        .route(
            "/api/v1/scanners/:scanner_id/replace-configuration",
            post(browser_proxy_replace_scanner_configuration),
        )
        .route(
            "/api/v1/scanners/:scanner_id/verify",
            post(browser_proxy_verify_scanner),
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
            "/api/v1/host-operating-systems/:host_operating_system_id",
            delete(browser_proxy_delete_host_operating_system),
        )
        .route(
            "/api/v1/tls-certificates/:certificate_id",
            delete(browser_proxy_delete_tls_certificate),
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
            "/api/v1/port-lists/:port_list_id/ranges",
            post(browser_proxy_create_port_list_range),
        )
        .route(
            "/api/v1/port-lists/:port_list_id/ranges/:port_range_id",
            delete(browser_proxy_delete_port_list_range),
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
            "/api/v1/scan-configs",
            post(browser_proxy_create_scan_config),
        )
        .route(
            "/api/v1/scan-configs/import",
            post(browser_proxy_import_scan_config)
                .layer(DefaultBodyLimit::max(MAX_SCAN_CONFIG_BACKUP_BODY_BYTES)),
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
            "/api/v1/scan-configs/:scan_config_id/families/:family/nvts",
            patch(browser_proxy_patch_scan_config_family_nvts),
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
        .route("/api/v1/schedules", post(browser_proxy_create_schedule))
        .route("/api/v1/scopes", post(browser_proxy_create_scope))
        .route("/api/v1/scopes/:scope_id", patch(browser_proxy_patch_scope))
        .route(
            "/api/v1/scopes/:scope_id",
            delete(browser_proxy_delete_scope),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports",
            post(browser_proxy_generate_scope_report),
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
        .route("/api/v1/tasks", post(browser_proxy_create_task))
        .route(
            "/api/v1/tasks/:task_id/clone",
            post(browser_proxy_clone_task),
        )
        .route(
            "/api/v1/tasks/:task_id/start",
            post(browser_proxy_start_task),
        )
        .route("/api/v1/tasks/:task_id/stop", post(browser_proxy_stop_task))
        .route(
            "/api/v1/tasks/:task_id/restore",
            post(browser_proxy_restore_task),
        )
        .route(
            "/api/v1/tasks/:task_id/trash",
            delete(browser_proxy_hard_delete_task),
        )
        .route(
            "/api/v1/tasks/:task_id/replace-target",
            post(browser_proxy_replace_task_target),
        )
        .route(
            "/api/v1/tasks/:task_id/replace-configuration",
            post(browser_proxy_replace_task),
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
        .route(
            "/api/v1/trashcan/empty-preview",
            get(browser_proxy_trash_empty_preview),
        )
        .route(
            "/api/v1/trashcan/empty",
            post(browser_proxy_empty_trashcan)
                .layer(DefaultBodyLimit::max(MAX_TRASH_EMPTY_BODY_BYTES)),
        )
        .route(
            "/api/v1/users/current/password",
            post(browser_proxy_change_current_user_password).layer(DefaultBodyLimit::max(
                MAX_CURRENT_USER_PASSWORD_CHANGE_BODY_BYTES,
            )),
        )
        .route(
            "/api/v1/users/current/settings",
            get(browser_proxy_current_user_settings),
        )
        .route(
            "/api/v1/users/current/settings/:setting_id",
            get(browser_proxy_current_user_setting)
                .put(browser_proxy_update_current_user_setting)
                .layer(DefaultBodyLimit::max(MAX_USER_SETTING_BODY_BYTES)),
        )
        .route(
            "/api/v1/users/current/timezone",
            put(browser_proxy_update_current_user_timezone)
                .layer(DefaultBodyLimit::max(MAX_USER_SETTING_BODY_BYTES)),
        )
        .route(
            "/api/v1/user-management/users",
            get(browser_proxy_user_management_users)
                .post(browser_proxy_create_user)
                .layer(DefaultBodyLimit::max(MAX_USER_MANAGEMENT_BODY_BYTES)),
        )
        .route(
            "/api/v1/user-management/users/:user_id",
            get(browser_proxy_user_management_detail)
                .patch(browser_proxy_modify_user)
                .layer(DefaultBodyLimit::max(MAX_USER_MANAGEMENT_BODY_BYTES)),
        )
        .route(
            "/api/v1/user-management/users/:user_id",
            delete(browser_proxy_delete_user)
                .layer(DefaultBodyLimit::max(MAX_USER_MANAGEMENT_BODY_BYTES)),
        )
        .route(
            "/api/v1/user-management/users/:user_id/clone",
            post(browser_proxy_clone_user),
        )
        .layer(DefaultBodyLimit::max(
            MAX_DIRECT_API_WRITE_BODY_BYTES as usize,
        ))
        .layer(Extension(auth));

    router
}
