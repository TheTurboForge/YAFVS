// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, patch, post, put},
};

use crate::{
    alert_definition::{get_alert_definition, put_alert_definition},
    alert_deliver_report::deliver_alert_report,
    alert_test::test_alert,
    alert_writes::{
        clone_alert, create_alert, delete_alert, hard_delete_alert, patch_alert, restore_alert,
    },
    app_state::AppState,
    authentication_settings::{
        MAX_AUTHENTICATION_SETTINGS_BODY_BYTES, authentication_settings,
        update_ldap_authentication_settings, update_radius_authentication_settings,
    },
    credential_public_key::credential_public_key,
    credential_writes::{
        clone_credential, create_credential, delete_credential, hard_delete_credential,
        patch_credential, restore_credential,
    },
    filter_writes::{
        clone_filter, create_filter, delete_filter, hard_delete_filter, patch_filter,
        restore_filter,
    },
    host_writes::{
        create_host, delete_host, delete_host_identifier, delete_host_operating_system, patch_host,
    },
    override_writes::{
        clone_override, create_override, delete_override, hard_delete_override, patch_override,
        restore_override,
    },
    port_list_writes::{
        clone_port_list, create_port_list, create_port_list_range, delete_port_list,
        delete_port_list_range, hard_delete_port_list, import_port_list, patch_port_list,
        restore_port_list,
    },
    request_shapes::MAX_DIRECT_API_WRITE_BODY_BYTES,
    scan_config_backup::{MAX_SCAN_CONFIG_BACKUP_BODY_BYTES, import_scan_config},
    scan_config_writes::{
        clone_scan_config, create_scan_config, delete_scan_config, hard_delete_scan_config,
        patch_scan_config, patch_scan_config_family_nvts, restore_scan_config,
        select_diagnostic_nvt,
    },
    scanner_verify::verify_scanner,
    scanner_writes::{
        clone_scanner, create_scanner, delete_scanner, hard_delete_scanner, patch_scanner,
        replace_scanner_configuration, restore_scanner,
    },
    schedule_writes::{
        clone_schedule, create_schedule, delete_schedule, hard_delete_schedule, patch_schedule,
        restore_schedule,
    },
    scope_report_mutations::{delete_scope_report, generate_scope_report},
    scope_writes::{create_scope, delete_scope, patch_scope},
    tag_writes::{
        clone_tag, create_tag, delete_tag, hard_delete_tag, patch_tag, restore_tag,
        update_tag_resources,
    },
    target_writes::{
        clone_target, create_target, delete_target, hard_delete_target, patch_target,
        restore_target,
    },
    task_control::start_task,
    task_stop::stop_task,
    task_target_replace::replace_task_target,
    task_writes::{
        clone_task, create_task, delete_task, hard_delete_task, patch_task, replace_task,
        restore_task,
    },
    tls_certificate_writes::delete_tls_certificate,
    trash_empty::{MAX_TRASH_EMPTY_BODY_BYTES, empty_trashcan, trash_empty_preview},
    user_management::{
        MAX_USER_MANAGEMENT_BODY_BYTES, clone_user, create_user, user_management_detail,
        user_management_users,
    },
    user_settings::{
        MAX_USER_SETTING_BODY_BYTES, current_user_setting, current_user_settings,
        update_current_user_setting, update_current_user_timezone,
    },
};

pub(crate) fn direct_native_api_router(
    router: Router<AppState>,
    write_control_enabled: bool,
) -> Router<AppState> {
    let router = router
        .route(
            "/api/v1/authentication-settings",
            get(authentication_settings),
        )
        .route(
            "/api/v1/alerts/:alert_id/definition",
            get(get_alert_definition),
        )
        .route("/api/v1/users/current/settings", get(current_user_settings))
        .route("/api/v1/user-management/users", get(user_management_users))
        .route(
            "/api/v1/user-management/users/:user_id",
            get(user_management_detail),
        )
        .route(
            "/api/v1/users/current/settings/:setting_id",
            get(current_user_setting),
        )
        .route(
            "/api/v1/credentials/:credential_id/public-key",
            get(credential_public_key),
        );
    let router = if write_control_enabled {
        router
            .route(
                "/api/v1/authentication-settings/ldap",
                put(update_ldap_authentication_settings).layer(DefaultBodyLimit::max(
                    MAX_AUTHENTICATION_SETTINGS_BODY_BYTES,
                )),
            )
            .route(
                "/api/v1/authentication-settings/radius",
                put(update_radius_authentication_settings).layer(DefaultBodyLimit::max(
                    MAX_AUTHENTICATION_SETTINGS_BODY_BYTES,
                )),
            )
            .route("/api/v1/scopes", post(create_scope))
            .route("/api/v1/scopes/:scope_id", patch(patch_scope))
            .route("/api/v1/scopes/:scope_id", delete(delete_scope))
            .route(
                "/api/v1/scope-reports/:scope_report_id",
                delete(delete_scope_report),
            )
            .route(
                "/api/v1/scopes/:scope_id/reports",
                post(generate_scope_report),
            )
            .route("/api/v1/scan-configs", post(create_scan_config))
            .route(
                "/api/v1/scan-configs/import",
                post(import_scan_config)
                    .layer(DefaultBodyLimit::max(MAX_SCAN_CONFIG_BACKUP_BODY_BYTES)),
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
            .route(
                "/api/v1/scan-configs/:scan_config_id/diagnostic-nvt-selection",
                post(select_diagnostic_nvt),
            )
            .route(
                "/api/v1/scan-configs/:scan_config_id/families/:family/nvts",
                patch(patch_scan_config_family_nvts),
            )
            .route("/api/v1/filters", post(create_filter))
            .route("/api/v1/hosts", post(create_host))
            .route("/api/v1/hosts/:host_id", patch(patch_host))
            .route("/api/v1/hosts/:host_id", delete(delete_host))
            .route(
                "/api/v1/host-identifiers/:identifier_id",
                delete(delete_host_identifier),
            )
            .route(
                "/api/v1/host-operating-systems/:host_operating_system_id",
                delete(delete_host_operating_system),
            )
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
                "/api/v1/alerts/:alert_id/definition",
                put(put_alert_definition),
            )
            .route("/api/v1/alerts/:alert_id", delete(delete_alert))
            .route("/api/v1/alerts/:alert_id/restore", post(restore_alert))
            .route("/api/v1/alerts/:alert_id/trash", delete(hard_delete_alert))
            .route("/api/v1/alerts", post(create_alert))
            .route("/api/v1/alerts/:alert_id/test", post(test_alert))
            .route(
                "/api/v1/alerts/:alert_id/deliver-report",
                post(deliver_alert_report),
            )
            .route("/api/v1/overrides", post(create_override))
            .route("/api/v1/overrides/:override_id", patch(patch_override))
            .route("/api/v1/overrides/:override_id", delete(delete_override))
            .route("/api/v1/overrides/:override_id/clone", post(clone_override))
            .route(
                "/api/v1/overrides/:override_id/restore",
                post(restore_override),
            )
            .route(
                "/api/v1/overrides/:override_id/trash",
                delete(hard_delete_override),
            )
            .route("/api/v1/alerts/:alert_id/clone", post(clone_alert))
            .route(
                "/api/v1/credentials/:credential_id",
                patch(patch_credential),
            )
            .route(
                "/api/v1/credentials/:credential_id",
                delete(delete_credential),
            )
            .route(
                "/api/v1/credentials/:credential_id/clone",
                post(clone_credential),
            )
            .route(
                "/api/v1/credentials/:credential_id/restore",
                post(restore_credential),
            )
            .route(
                "/api/v1/credentials/:credential_id/trash",
                delete(hard_delete_credential),
            )
            .route("/api/v1/credentials", post(create_credential))
            .route("/api/v1/scanners", post(create_scanner))
            .route("/api/v1/scanners/:scanner_id", patch(patch_scanner))
            .route("/api/v1/scanners/:scanner_id", delete(delete_scanner))
            .route("/api/v1/scanners/:scanner_id/clone", post(clone_scanner))
            .route(
                "/api/v1/scanners/:scanner_id/restore",
                post(restore_scanner),
            )
            .route(
                "/api/v1/scanners/:scanner_id/trash",
                delete(hard_delete_scanner),
            )
            .route(
                "/api/v1/scanners/:scanner_id/replace-configuration",
                post(replace_scanner_configuration),
            )
            .route("/api/v1/scanners/:scanner_id/verify", post(verify_scanner))
            .route("/api/v1/targets/:target_id", patch(patch_target))
            .route("/api/v1/targets", post(create_target))
            .route("/api/v1/targets/:target_id", delete(delete_target))
            .route("/api/v1/targets/:target_id/clone", post(clone_target))
            .route("/api/v1/targets/:target_id/restore", post(restore_target))
            .route(
                "/api/v1/targets/:target_id/trash",
                delete(hard_delete_target),
            )
            .route("/api/v1/tasks", post(create_task))
            .route("/api/v1/tasks/:task_id/clone", post(clone_task))
            .route(
                "/api/v1/tasks/:task_id/replace-target",
                post(replace_task_target),
            )
            .route(
                "/api/v1/tasks/:task_id/replace-configuration",
                post(replace_task),
            )
            .route("/api/v1/tasks/:task_id/start", post(start_task))
            .route("/api/v1/tasks/:task_id/stop", post(stop_task))
            .route("/api/v1/tasks/:task_id/restore", post(restore_task))
            .route("/api/v1/tasks/:task_id/trash", delete(hard_delete_task))
            .route("/api/v1/tasks/:task_id", patch(patch_task))
            .route("/api/v1/tasks/:task_id", delete(delete_task))
            .route(
                "/api/v1/tls-certificates/:certificate_id",
                delete(delete_tls_certificate),
            )
            .route("/api/v1/port-lists/:port_list_id", patch(patch_port_list))
            .route("/api/v1/port-lists/:port_list_id", delete(delete_port_list))
            .route(
                "/api/v1/port-lists/:port_list_id/ranges",
                post(create_port_list_range),
            )
            .route(
                "/api/v1/port-lists/:port_list_id/ranges/:port_range_id",
                delete(delete_port_list_range),
            )
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
            .route("/api/v1/schedules", post(create_schedule))
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
            .route(
                "/api/v1/users/current/settings/:setting_id",
                put(update_current_user_setting)
                    .layer(DefaultBodyLimit::max(MAX_USER_SETTING_BODY_BYTES)),
            )
            .route(
                "/api/v1/users/current/timezone",
                put(update_current_user_timezone)
                    .layer(DefaultBodyLimit::max(MAX_USER_SETTING_BODY_BYTES)),
            )
            .route(
                "/api/v1/user-management/users",
                post(create_user).layer(DefaultBodyLimit::max(MAX_USER_MANAGEMENT_BODY_BYTES)),
            )
            .route(
                "/api/v1/user-management/users/:user_id/clone",
                post(clone_user),
            )
            .route("/api/v1/trashcan/empty-preview", get(trash_empty_preview))
            .route(
                "/api/v1/trashcan/empty",
                post(empty_trashcan).layer(DefaultBodyLimit::max(MAX_TRASH_EMPTY_BODY_BYTES)),
            )
    } else {
        router
    };

    router.layer(DefaultBodyLimit::max(
        MAX_DIRECT_API_WRITE_BODY_BYTES as usize,
    ))
}
