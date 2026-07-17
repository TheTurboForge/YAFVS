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
    command_branding_state, command_deps, command_feed_copy_to_runtime, command_feed_state,
    command_gsa_npm_audit, command_inventory, command_logs, command_native_api_cargo_audit,
    command_native_api_semgrep_audit, command_osv_lockfile_audit, command_path_coupling_state,
    command_quality_gate_state, command_runtime_feed_import_init, command_runtime_plan,
    command_rust_migration_state, command_security_policy_check, command_status, find_repo_root,
};
pub use render::{render_human, render_json};
pub use result::{ResultEnvelope, exit_code};

pub fn run(cli: &Cli, cwd: &Path) -> ResultEnvelope {
    let repo_root = find_repo_root(cwd);
    match &cli.command {
        CliCommand::Status => command_status(&repo_root),
        CliCommand::Inventory { scope } => command_inventory(&repo_root, scope.as_deref()),
        CliCommand::BrandingState => command_branding_state(&repo_root),
        CliCommand::PathCouplingState => command_path_coupling_state(&repo_root, cli.status_only),
        CliCommand::QualityGateState => command_quality_gate_state(&repo_root, cli.status_only),
        CliCommand::FeedState => command_feed_state(&repo_root),
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
        CliCommand::Logs {
            service,
            service_option,
            lines,
        } => command_logs(
            &repo_root,
            service_option.as_deref().or(service.as_deref()),
            *lines,
        ),
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
        let root = Path::new("/definitely/not/a/turbovas/repository");
        let result = command_inventory(root, Some("not-a-component"));
        assert_eq!(result.status, "warn");
        assert_eq!(exit_code(&result), 0);
    }
}
