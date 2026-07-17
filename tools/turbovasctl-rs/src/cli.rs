// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "turbovasctl", disable_help_subcommand = true)]
pub struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub json: bool,

    /// Request a compact status-oriented response where the command supports it.
    #[arg(long, global = true)]
    pub status_only: bool,

    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum CliCommand {
    /// Show repository status.
    Status,
    /// Show expected component inventory.
    Inventory {
        /// Limit inventory to a path under the repository.
        #[arg(long)]
        scope: Option<String>,
    },
    /// Show branding and upstream-identity state.
    BrandingState,
    /// Inspect absolute checkout/runtime path coupling.
    PathCouplingState,
    /// Show retained local quality gate history.
    QualityGateState,
    /// Show Community Feed cache and active-runtime state.
    FeedState,
    /// Inspect Rust migration tooling and the first dry-run candidate.
    RustMigrationState,
    /// Audit native API Rust dependencies against the local advisory database.
    NativeApiCargoAudit,
    /// Audit GSA dependencies from the local npm cache.
    GsaNpmAudit,
    /// Run the native API Semgrep security policy.
    NativeApiSemgrepAudit,
    /// Audit supported lockfiles with the local OSV database.
    OsvLockfileAudit,
    /// Validate security-sensitive path policy scaffolding.
    SecurityPolicyCheck,
    /// Show the persistent Docker runtime plan.
    RuntimePlan,
    /// Refuse unsafe sequential copying into live feed paths.
    FeedCopyToRuntime,
    /// Check dependency readiness, optionally for one component.
    Deps {
        /// Component name to check.
        component: Option<String>,
    },
    /// Refuse standalone feed import outside guarded generation activation.
    RuntimeFeedImportInit,
    /// Show recent runtime logs.
    Logs {
        /// Optional Compose service name.
        service: Option<String>,
        /// Alias for the positional service argument.
        #[arg(long = "service")]
        service_option: Option<String>,
        /// Number of log lines to request and retain.
        #[arg(long, default_value_t = 120)]
        lines: i64,
    },
    /// Check preserved license and provenance files.
    LicenseReport {
        /// Apply the selected publication-mode release gate.
        #[arg(long)]
        public_release: bool,
        /// Publication mode to evaluate.
        #[arg(
            long,
            default_value = "source-public",
            value_parser = ["source-public", "binary", "container", "hosted", "feed-redistribution"]
        )]
        mode: String,
        /// Diff scope for focused modified-imported-file checks.
        #[arg(
            long,
            default_value = "baseline",
            value_parser = ["baseline", "staged", "worktree"]
        )]
        diff_scope: String,
        /// Run only the fast modified-imported-file notice checks.
        #[arg(long)]
        modified_imported_only: bool,
    },
    /// Run structural and environment health checks.
    Doctor,
    /// Install, inspect, or disable the user quality-gate timer.
    QualityGateSchedule {
        /// Install and enable the timer (requires explicit host opt-in).
        #[arg(long, conflicts_with_all = ["status", "disable"])]
        install: bool,
        /// Inspect timer status (the default action).
        #[arg(long, conflicts_with_all = ["install", "disable"])]
        status: bool,
        /// Disable the timer.
        #[arg(long, conflicts_with_all = ["install", "status"])]
        disable: bool,
    },
    /// Inspect or rotate the opt-in direct native API runtime bearer token.
    RuntimeNativeApiDirectToken {
        /// Rotate the ignored runtime token without printing it.
        #[arg(long)]
        rotate: bool,
    },
}

pub fn parse_cli<I, S>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    Cli::try_parse_from(
        std::iter::once(OsString::from("turbovasctl")).chain(args.into_iter().map(Into::into)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_flags_before_or_after_subcommands() {
        assert_eq!(
            parse_cli(["--json", "status"]).unwrap(),
            Cli {
                command: CliCommand::Status,
                json: true,
                status_only: false,
            }
        );
        assert_eq!(
            parse_cli(["inventory", "--scope", "components/gsa", "--json"]).unwrap(),
            Cli {
                command: CliCommand::Inventory {
                    scope: Some("components/gsa".to_string()),
                },
                json: true,
                status_only: false,
            }
        );
    }

    #[test]
    fn rejects_inventory_scope_on_status() {
        assert!(parse_cli(["status", "--scope", "components"]).is_err());
    }

    #[test]
    fn parses_status_only_as_a_global_flag() {
        assert_eq!(
            parse_cli(["inventory", "--status-only"]).unwrap(),
            Cli {
                command: CliCommand::Inventory { scope: None },
                json: false,
                status_only: true,
            }
        );
    }
}
