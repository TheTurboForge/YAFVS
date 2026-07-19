// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod cli;
mod commands;
mod process;
mod render;
mod result;

use std::env;
use std::path::{Path, PathBuf};

pub use cli::{Cli, CliCommand, parse_cli};
pub use commands::{
    command_branding_state, command_c_hardening_check, command_c_hardening_manifest_write,
    command_deps, command_doctor, command_feed_copy_to_runtime, command_feed_generation_activate,
    command_feed_generation_rollback, command_feed_generation_runtime_guard,
    command_feed_generation_stage, command_feed_generation_state, command_feed_state,
    command_gsa_npm_audit, command_inventory, command_license_report, command_logs,
    command_native_api_cargo_audit, command_native_api_semgrep_audit, command_osv_lockfile_audit,
    command_path_coupling_state, command_quality_gate_schedule, command_quality_gate_state,
    command_repository_unavailable, command_runtime_data_state, command_runtime_db_introspect,
    command_runtime_feed_import_init, command_runtime_gmp_smoke, command_runtime_identity_migrate,
    command_runtime_log_review, command_runtime_native_api_direct_token,
    command_runtime_nmap_capability_check, command_runtime_performance_snapshot,
    command_runtime_plan, command_runtime_rbac_smoke, command_runtime_redis_state,
    command_runtime_scanner_capability_check, command_runtime_scanner_process_check,
    command_rust_migration_state, command_security_policy_check, command_status, find_repo_root,
};
pub use render::{render_human, render_json};
pub use result::{ResultEnvelope, exit_code};

pub fn run(cli: &Cli, cwd: &Path) -> ResultEnvelope {
    let repo_root = match find_repo_root(cwd) {
        Some(repo_root) => repo_root,
        None if matches!(cli.command, CliCommand::Status) => return command_status(cwd),
        None => return command_repository_unavailable(cwd, cli.command.name()),
    };
    match &cli.command {
        CliCommand::Status => command_status(&repo_root),
        CliCommand::Inventory { scope } => command_inventory(&repo_root, scope.as_deref()),
        CliCommand::BrandingState => command_branding_state(&repo_root),
        CliCommand::PathCouplingState => command_path_coupling_state(&repo_root, cli.status_only),
        CliCommand::RuntimeRedisState => command_runtime_redis_state(&repo_root),
        CliCommand::RuntimeIdentityMigrate { apply } => {
            command_runtime_identity_migrate(&repo_root, *apply)
        }
        CliCommand::RuntimeDbIntrospect { columns_for } => {
            command_runtime_db_introspect(&repo_root, cli.status_only, columns_for)
        }
        CliCommand::CHardeningCheck { profile } => {
            command_c_hardening_check(&repo_root, cli.status_only, profile.as_deref())
        }
        CliCommand::CHardeningManifestWrite => command_c_hardening_manifest_write(&repo_root),
        CliCommand::QualityGateState => command_quality_gate_state(&repo_root, cli.status_only),
        CliCommand::FeedState => command_feed_state(&repo_root),
        CliCommand::FeedGenerationState => {
            command_feed_generation_state(&repo_root, cli.status_only)
        }
        CliCommand::FeedGenerationRuntimeGuard { selector_only } => {
            command_feed_generation_runtime_guard(&repo_root, *selector_only)
        }
        CliCommand::FeedGenerationStage => command_feed_generation_stage(&repo_root),
        CliCommand::FeedGenerationActivate {
            generation_id,
            allow_first_activation,
            repair_attestation,
        } => command_feed_generation_activate(
            &repo_root,
            generation_id,
            *allow_first_activation,
            *repair_attestation,
        ),
        CliCommand::FeedGenerationRollback { generation_id } => {
            command_feed_generation_rollback(&repo_root, generation_id)
        }
        CliCommand::RustMigrationState => command_rust_migration_state(&repo_root),
        CliCommand::NativeApiCargoAudit => {
            command_native_api_cargo_audit(&repo_root, cli.status_only)
        }
        CliCommand::GsaNpmAudit => command_gsa_npm_audit(&repo_root, cli.status_only),
        CliCommand::NativeApiSemgrepAudit => {
            command_native_api_semgrep_audit(&repo_root, cli.status_only)
        }
        CliCommand::OsvLockfileAudit => command_osv_lockfile_audit(&repo_root, cli.status_only),
        CliCommand::SecurityPolicyCheck => {
            command_security_policy_check(&repo_root, cli.status_only)
        }
        CliCommand::RuntimePlan => command_runtime_plan(&repo_root),
        CliCommand::FeedCopyToRuntime => command_feed_copy_to_runtime(&repo_root),
        CliCommand::Deps { component } => command_deps(&repo_root, component.as_deref()),
        CliCommand::RuntimeFeedImportInit => command_runtime_feed_import_init(&repo_root),
        CliCommand::RuntimePerformanceSnapshot => command_runtime_performance_snapshot(&repo_root),
        CliCommand::RuntimeLogReview => command_runtime_log_review(&repo_root),
        CliCommand::RuntimeScannerCapabilityCheck => {
            command_runtime_scanner_capability_check(&repo_root)
        }
        CliCommand::RuntimeScannerProcessCheck => command_runtime_scanner_process_check(&repo_root),
        CliCommand::RuntimeNmapCapabilityCheck => command_runtime_nmap_capability_check(&repo_root),
        CliCommand::RuntimeDataState => command_runtime_data_state(&repo_root),
        CliCommand::RuntimeGmpSmoke => command_runtime_gmp_smoke(&repo_root),
        CliCommand::RuntimeRbacSmoke => command_runtime_rbac_smoke(&repo_root),
        CliCommand::Logs {
            service,
            service_option,
            lines,
        } => command_logs(
            &repo_root,
            service_option.as_deref().or(service.as_deref()),
            *lines,
        ),
        CliCommand::LicenseReport {
            public_release,
            mode,
            diff_scope,
            modified_imported_only,
        } => command_license_report(
            &repo_root,
            *public_release,
            mode,
            diff_scope,
            *modified_imported_only,
            cli.status_only,
        ),
        CliCommand::Doctor => command_doctor(&repo_root, cli.status_only),
        CliCommand::QualityGateSchedule {
            install,
            status: _,
            disable,
        } => command_quality_gate_schedule(
            &repo_root,
            if *install {
                "install"
            } else if *disable {
                "disable"
            } else {
                "status"
            },
        ),
        CliCommand::RuntimeNativeApiDirectToken { rotate } => {
            command_runtime_native_api_direct_token(&repo_root, *rotate)
        }
    }
}

pub fn current_dir() -> Result<PathBuf, String> {
    env::current_dir().map_err(|error| format!("could not read current directory: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inventory_is_a_warning_and_success_exit() {
        let root = Path::new("/definitely/not/a/yafvs/repository");
        let result = command_inventory(root, Some("not-a-component"));
        assert_eq!(result.status, "warn");
        assert_eq!(exit_code(&result), 0);
    }
}
