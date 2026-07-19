// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

mod audit;
mod branding;
mod c_hardening;
mod common;
mod compose;
mod db_introspect;
mod deps;
mod direct_token;
mod doctor;
mod feed;
mod feed_generation;
mod license;
mod path_coupling;
mod quality_gate;
mod quality_schedule;
mod redis;
mod repository;
mod runtime;
mod runtime_data_state;
mod runtime_identity_migrate;
mod runtime_lock;
mod runtime_log_review;
mod runtime_performance_snapshot;
mod runtime_probe;
mod runtime_scanner_capability;
mod runtime_scanner_process;
mod rust_migration;
mod secret;
mod security_policy;

pub use audit::{
    command_gsa_npm_audit, command_native_api_cargo_audit, command_native_api_semgrep_audit,
    command_osv_lockfile_audit,
};
pub use branding::command_branding_state;
pub use c_hardening::{command_c_hardening_check, command_c_hardening_manifest_write};
pub use db_introspect::command_runtime_db_introspect;
pub use deps::command_deps;
pub use direct_token::command_runtime_native_api_direct_token;
pub use doctor::command_doctor;
pub use feed::{
    command_feed_copy_to_runtime, command_feed_state, command_runtime_feed_import_init,
};
pub use feed_generation::{
    command_feed_generation_activate, command_feed_generation_rollback,
    command_feed_generation_runtime_guard, command_feed_generation_stage,
    command_feed_generation_state,
};
pub use license::command_license_report;
pub use path_coupling::command_path_coupling_state;
pub use quality_gate::command_quality_gate_state;
pub use quality_schedule::command_quality_gate_schedule;
pub use redis::command_runtime_redis_state;
pub use repository::{
    command_inventory, command_repository_unavailable, command_status, find_repo_root,
};
pub use runtime::{command_down, command_logs, command_runtime_app_down, command_runtime_plan};
pub use runtime_data_state::command_runtime_data_state;
pub use runtime_identity_migrate::command_runtime_identity_migrate;
pub use runtime_log_review::command_runtime_log_review;
pub use runtime_performance_snapshot::command_runtime_performance_snapshot;
pub use runtime_probe::{
    command_runtime_credential_smoke, command_runtime_full_test_scan_preflight,
    command_runtime_full_test_scan_start, command_runtime_full_test_scan_status,
    command_runtime_gmp_smoke, command_runtime_rbac_smoke,
};
pub use runtime_scanner_capability::{
    command_runtime_nmap_capability_check, command_runtime_scanner_capability_check,
};
pub use runtime_scanner_process::command_runtime_scanner_process_check;
pub use rust_migration::command_rust_migration_state;
pub use security_policy::command_security_policy_check;
