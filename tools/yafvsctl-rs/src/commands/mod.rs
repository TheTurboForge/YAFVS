// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

mod artifact;
mod audit;
mod branding;
mod build;
mod build_hardening;
mod c_hardening;
mod common;
mod compose;
mod config_schedule_schema;
mod db_introspect;
mod deps;
mod direct_api;
mod direct_bootstrap;
mod direct_posture;
mod direct_token;
mod doctor;
mod feed;
mod feed_cache_sync;
mod feed_generation;
mod filter_schema;
mod foundational_schema;
mod gvmd_retirement;
mod gvmd_smoke;
mod license;
mod license_policy;
mod native_api_request;
mod native_bulk_modify_schedules;
mod native_delete_overrides;
mod native_empty_trash;
mod native_export_report_bundle;
mod native_export_report_csv;
mod native_export_report_pdf;
mod native_runtime;
pub(crate) mod native_scan;
mod native_verify_scanners;
mod path_coupling;
mod production_posture;
mod quality_gate;
mod quality_schedule;
mod redis;
mod report_selection;
mod repository;
mod resource_import;
mod runtime;
mod runtime_app_smoke;
mod runtime_certbund_report;
mod runtime_certs;
mod runtime_data_state;
mod runtime_feed_keyring;
mod runtime_health;
mod runtime_identity_migrate;
mod runtime_init;
mod runtime_lock;
mod runtime_log_review;
mod runtime_manager_init;
mod runtime_native_api_direct_smoke;
mod runtime_native_api_smoke;
mod runtime_performance_snapshot;
mod runtime_probe;
mod runtime_report;
mod runtime_scanner_capability;
mod runtime_scanner_process;
mod runtime_scanner_redis;
mod runtime_scanner_register;
mod runtime_scope_report;
mod runtime_setup;
mod runtime_webui;
mod rust_migration;
mod secret;
mod security_policy;
mod task_batch_control;
mod task_control;
mod task_target;
mod up;

pub(crate) use common::runtime_dir_configuration_error;

pub use audit::{
    command_gsa_npm_audit, command_native_api_cargo_audit, command_native_api_semgrep_audit,
    command_osv_lockfile_audit,
};
pub use branding::command_branding_state;
pub use build::{
    command_build, command_build_baseline, command_build_c_services, command_build_core_c,
    command_build_python, command_build_ui, command_configure,
};
pub use c_hardening::{command_c_hardening_check, command_c_hardening_manifest_write};
pub use db_introspect::command_runtime_db_introspect;
pub use deps::command_deps;
pub use direct_bootstrap::command_runtime_native_api_direct_bootstrap;
pub use direct_token::command_runtime_native_api_direct_token;
pub use doctor::command_doctor;
pub use feed::{
    command_feed_copy_to_runtime, command_feed_state, command_runtime_feed_import_init,
};
pub use feed_cache_sync::command_feed_cache_sync;
pub use feed_generation::{
    command_feed_generation_activate, command_feed_generation_rollback,
    command_feed_generation_runtime_guard, command_feed_generation_stage,
    command_feed_generation_state, command_runtime_app_build, command_runtime_app_up,
    command_runtime_native_api_rebuild,
};
pub use gvmd_retirement::command_gvmd_retirement_state;
pub use gvmd_smoke::command_gvmd_smoke;
pub use license::command_license_report;
pub use native_api_request::command_native_api_request;
pub use native_bulk_modify_schedules::command_native_bulk_modify_schedules;
pub use native_delete_overrides::command_native_delete_overrides_by_filter;
pub use native_empty_trash::command_native_empty_trash;
pub use native_export_report_bundle::command_native_export_report_bundle;
pub(crate) use native_export_report_bundle::{
    DEFAULT_MAX_BYTES as NATIVE_REPORT_BUNDLE_DEFAULT_MAX_BYTES,
    DEFAULT_MAX_ITEMS as NATIVE_REPORT_BUNDLE_DEFAULT_MAX_ITEMS,
};
pub(crate) use native_export_report_csv::DEFAULT_MAX_RESULTS as NATIVE_REPORT_CSV_DEFAULT_MAX_RESULTS;
pub use native_export_report_csv::command_native_export_report_csv;
pub(crate) use native_export_report_pdf::DEFAULT_MAX_BYTES as NATIVE_REPORT_PDF_DEFAULT_MAX_BYTES;
pub use native_export_report_pdf::command_native_export_report_pdf;
pub use native_scan::{
    command_native_nvt_diagnostic_scan, command_native_scan_new_system,
    command_native_scan_with_delivery,
};
pub use native_verify_scanners::command_native_verify_scanners;
pub use path_coupling::command_path_coupling_state;
pub use production_posture::command_production_posture_check;
pub use quality_gate::command_quality_gate_state;
pub use quality_schedule::command_quality_gate_schedule;
pub use redis::command_runtime_redis_state;
pub use repository::{
    command_inventory, command_repository_unavailable, command_runtime_configuration_rejected,
    command_status, find_repo_root,
};
pub use resource_import::{
    command_native_alerts_from_csv, command_native_credentials_from_csv,
    command_native_schedules_from_csv, command_native_schedules_from_xml,
    command_native_tags_from_csv, command_native_targets_from_csv,
    command_native_targets_from_host_list, command_native_targets_from_xml,
    command_native_tasks_from_csv,
};
pub use runtime::{command_down, command_logs, command_runtime_app_down, command_runtime_plan};
pub use runtime_app_smoke::command_runtime_app_smoke;
pub use runtime_certbund_report::command_runtime_certbund_report;
pub use runtime_certs::command_runtime_certs_init;
pub use runtime_data_state::command_runtime_data_state;
pub use runtime_feed_keyring::command_runtime_feed_keyring_init;
pub use runtime_health::{command_runtime_smoke, command_runtime_status};
pub use runtime_identity_migrate::command_runtime_identity_migrate;
pub use runtime_init::command_runtime_init;
pub use runtime_log_review::command_runtime_log_review;
pub use runtime_manager_init::command_runtime_manager_init;
pub use runtime_native_api_direct_smoke::command_runtime_native_api_direct_smoke;
pub use runtime_native_api_smoke::command_runtime_native_api_smoke;
pub use runtime_performance_snapshot::command_runtime_performance_snapshot;
pub use runtime_probe::{
    command_runtime_credential_smoke, command_runtime_full_test_scan_preflight,
    command_runtime_full_test_scan_start, command_runtime_full_test_scan_status,
    command_runtime_gmp_smoke, command_runtime_rbac_smoke, command_runtime_scope_smoke,
};
pub use runtime_report::{
    command_runtime_report_export, command_runtime_report_metrics, command_runtime_report_summary,
};
pub use runtime_scanner_capability::{
    command_runtime_nmap_capability_check, command_runtime_scanner_capability_check,
};
pub use runtime_scanner_process::command_runtime_scanner_process_check;
pub use runtime_scanner_redis::command_runtime_scanner_redis_init;
pub use runtime_scanner_register::command_runtime_scanner_register;
pub use runtime_scope_report::{
    command_runtime_scope_report_metrics, command_runtime_scope_report_summary,
};
pub use runtime_webui::command_runtime_webui_smoke;
pub use rust_migration::command_rust_migration_state;
pub use security_policy::command_security_policy_check;
pub use task_batch_control::{
    command_native_start_tasks_from_csv, command_native_stop_all_tasks,
    command_native_stop_tasks_from_csv,
};
pub use task_control::{command_native_start_task, command_native_stop_task};
pub use task_target::command_native_update_task_target;
pub use up::command_up;
