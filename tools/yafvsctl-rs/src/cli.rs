// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "yafvsctl", disable_help_subcommand = true)]
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
    /// Inspect Redis dependency and runtime boundary state.
    RuntimeRedisState,
    /// Plan or apply the atomic TurboVAS-to-YAFVS runtime identity migration.
    RuntimeIdentityMigrate {
        /// Perform the rename after all safety checks pass.
        #[arg(long)]
        apply: bool,
    },
    /// Inspect fixed read-only database catalog facts.
    RuntimeDbIntrospect {
        /// Include information_schema columns for a safe schema.table identifier.
        #[arg(long = "columns-for", value_name = "SCHEMA.TABLE")]
        columns_for: Vec<String>,
    },
    /// Inspect current final C ELF artifact hardening properties.
    CHardeningCheck {
        /// Build profile to inspect.
        #[arg(long, value_parser = ["hardened"])]
        profile: Option<String>,
    },
    /// Record the exact hardened C build identity after a successful build.
    #[command(hide = true)]
    CHardeningManifestWrite,
    /// Show retained local quality gate history.
    QualityGateState,
    /// Show Community Feed cache and active-runtime state.
    FeedState,
    /// Verify immutable content-addressed feed generations without changing them.
    FeedGenerationState,
    /// Verify that the selected feed generation, activation journal, and database attestation agree.
    #[command(hide = true)]
    FeedGenerationRuntimeGuard {
        /// Verify only the selector and activation journal, without reading PostgreSQL.
        #[arg(long)]
        selector_only: bool,
    },
    /// Stage and verify an immutable content-addressed feed generation.
    FeedGenerationStage,
    /// Activate a verified immutable feed generation.
    FeedGenerationActivate {
        /// Generation identifier to activate.
        generation_id: String,
        /// Allow the first activation when no active generation exists yet.
        #[arg(long)]
        allow_first_activation: bool,
        /// Repair the activation attestation for the currently active generation.
        #[arg(long)]
        repair_attestation: bool,
    },
    /// Roll back to the journaled predecessor of a verified immutable feed generation.
    FeedGenerationRollback {
        /// Generation identifier to roll back from.
        generation_id: String,
    },
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
    /// Stop and remove the development runtime infrastructure and application containers.
    Down,
    /// Stop and remove experimental application runtime containers.
    RuntimeAppDown,
    /// Refuse unsafe sequential copying into live feed paths.
    FeedCopyToRuntime,
    /// Check dependency readiness, optionally for one component.
    Deps {
        /// Component name to check.
        component: Option<String>,
    },
    /// Refuse standalone feed import outside guarded generation activation.
    RuntimeFeedImportInit,
    /// Capture a runtime performance snapshot for diagnostics.
    RuntimePerformanceSnapshot,
    /// Review recent full-stack runtime logs for high-signal failures.
    RuntimeLogReview,
    /// Verify non-root OpenVAS raw-socket capabilities.
    RuntimeScannerCapabilityCheck,
    /// Verify scanner process and MQTT credential hygiene.
    RuntimeScannerProcessCheck,
    /// Verify non-root Nmap raw scan capabilities.
    RuntimeNmapCapabilityCheck,
    /// Classify database and non-database runtime state.
    RuntimeDataState,
    /// Run the retained authenticated GMP smoke.
    RuntimeGmpSmoke,
    /// Run the browser-level temporary credential create/cleanup smoke.
    RuntimeCredentialSmoke,
    /// Characterize the retained shared operator-account compatibility boundary.
    RuntimeRbacSmoke,
    /// Preflight an explicit authorized full test scan without starting it.
    RuntimeFullTestScanPreflight {
        /// Explicit canonical authorized target CIDR; at most 256 addresses.
        #[arg(long)]
        target_cidr: String,
    },
    /// Start an explicit authorized full test scan.
    RuntimeFullTestScanStart {
        /// Explicit canonical authorized target CIDR; at most 256 addresses.
        #[arg(long)]
        target_cidr: String,
        /// Exact target confirmation required before scan start.
        #[arg(long)]
        confirm_authorized_target: Option<String>,
    },
    /// Show an explicit authorized full test scan status.
    RuntimeFullTestScanStatus {
        /// Explicit canonical authorized target CIDR; at most 256 addresses.
        #[arg(long)]
        target_cidr: String,
    },
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

impl CliCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Inventory { .. } => "inventory",
            Self::BrandingState => "branding-state",
            Self::PathCouplingState => "path-coupling-state",
            Self::RuntimeRedisState => "runtime-redis-state",
            Self::RuntimeIdentityMigrate { .. } => "runtime-identity-migrate",
            Self::RuntimeDbIntrospect { .. } => "runtime-db-introspect",
            Self::CHardeningCheck { .. } => "c-hardening-check",
            Self::CHardeningManifestWrite => "c-hardening-manifest-write",
            Self::QualityGateState => "quality-gate-state",
            Self::FeedState => "feed-state",
            Self::FeedGenerationState => "feed-generation-state",
            Self::FeedGenerationRuntimeGuard { .. } => "feed-generation-runtime-guard",
            Self::FeedGenerationStage => "feed-generation-stage",
            Self::FeedGenerationActivate { .. } => "feed-generation-activate",
            Self::FeedGenerationRollback { .. } => "feed-generation-rollback",
            Self::RustMigrationState => "rust-migration-state",
            Self::NativeApiCargoAudit => "native-api-cargo-audit",
            Self::GsaNpmAudit => "gsa-npm-audit",
            Self::NativeApiSemgrepAudit => "native-api-semgrep-audit",
            Self::OsvLockfileAudit => "osv-lockfile-audit",
            Self::SecurityPolicyCheck => "security-policy-check",
            Self::RuntimePlan => "runtime-plan",
            Self::Down => "down",
            Self::RuntimeAppDown => "runtime-app-down",
            Self::FeedCopyToRuntime => "feed-copy-to-runtime",
            Self::Deps { .. } => "deps",
            Self::RuntimeFeedImportInit => "runtime-feed-import-init",
            Self::RuntimePerformanceSnapshot => "runtime-performance-snapshot",
            Self::RuntimeLogReview => "runtime-log-review",
            Self::RuntimeScannerCapabilityCheck => "runtime-scanner-capability-check",
            Self::RuntimeScannerProcessCheck => "runtime-scanner-process-check",
            Self::RuntimeNmapCapabilityCheck => "runtime-nmap-capability-check",
            Self::RuntimeDataState => "runtime-data-state",
            Self::RuntimeGmpSmoke => "runtime-gmp-smoke",
            Self::RuntimeCredentialSmoke => "runtime-credential-smoke",
            Self::RuntimeRbacSmoke => "runtime-rbac-smoke",
            Self::RuntimeFullTestScanPreflight { .. } => "runtime-full-test-scan-preflight",
            Self::RuntimeFullTestScanStart { .. } => "runtime-full-test-scan-start",
            Self::RuntimeFullTestScanStatus { .. } => "runtime-full-test-scan-status",
            Self::Logs { .. } => "logs",
            Self::LicenseReport { .. } => "license-report",
            Self::Doctor => "doctor",
            Self::QualityGateSchedule { .. } => "quality-gate-schedule",
            Self::RuntimeNativeApiDirectToken { .. } => "runtime-native-api-direct-token",
        }
    }
}

pub fn parse_cli<I, S>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    Cli::try_parse_from(
        std::iter::once(OsString::from("yafvsctl")).chain(args.into_iter().map(Into::into)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::fs;
    use std::path::Path;

    #[test]
    fn parses_scanner_capability_commands() {
        for (argument, expected) in [
            (
                "runtime-scanner-capability-check",
                CliCommand::RuntimeScannerCapabilityCheck,
            ),
            (
                "runtime-nmap-capability-check",
                CliCommand::RuntimeNmapCapabilityCheck,
            ),
            (
                "runtime-scanner-process-check",
                CliCommand::RuntimeScannerProcessCheck,
            ),
        ] {
            let cli = parse_cli([argument]).unwrap();
            assert_eq!(cli.command, expected);
            assert_eq!(cli.command.name(), argument);
        }
    }

    #[test]
    fn parses_guarded_full_test_scan_commands() {
        assert_eq!(
            parse_cli([
                "runtime-full-test-scan-preflight",
                "--target-cidr",
                "192.0.2.0/24",
            ])
            .unwrap()
            .command,
            CliCommand::RuntimeFullTestScanPreflight {
                target_cidr: "192.0.2.0/24".into(),
            }
        );
        assert_eq!(
            parse_cli([
                "runtime-full-test-scan-start",
                "--target-cidr",
                "192.0.2.0/24",
                "--confirm-authorized-target",
                "192.0.2.0/24",
            ])
            .unwrap()
            .command,
            CliCommand::RuntimeFullTestScanStart {
                target_cidr: "192.0.2.0/24".into(),
                confirm_authorized_target: Some("192.0.2.0/24".into()),
            }
        );
        assert_eq!(
            parse_cli([
                "runtime-full-test-scan-status",
                "--target-cidr",
                "2001:db8::/120",
            ])
            .unwrap()
            .command,
            CliCommand::RuntimeFullTestScanStatus {
                target_cidr: "2001:db8::/120".into(),
            }
        );
        assert!(
            parse_cli([
                "runtime-full-test-scan-start",
                "--target-cidr",
                "192.0.2.0/24"
            ])
            .is_ok()
        );
        assert!(parse_cli(["runtime-full-test-scan-preflight"]).is_err());
    }

    #[test]
    fn parses_runtime_probe_commands() {
        for (argument, expected) in [
            ("runtime-gmp-smoke", CliCommand::RuntimeGmpSmoke),
            (
                "runtime-credential-smoke",
                CliCommand::RuntimeCredentialSmoke,
            ),
            ("runtime-rbac-smoke", CliCommand::RuntimeRbacSmoke),
        ] {
            let cli = parse_cli([argument]).unwrap();
            assert_eq!(cli.command, expected);
            assert_eq!(cli.command.name(), argument);
        }
    }

    #[test]
    fn parses_quality_gate_schedule_actions_and_rejects_combinations() {
        for (arguments, command) in [
            (
                vec!["quality-gate-schedule"],
                CliCommand::QualityGateSchedule {
                    install: false,
                    status: false,
                    disable: false,
                },
            ),
            (
                vec!["quality-gate-schedule", "--status"],
                CliCommand::QualityGateSchedule {
                    install: false,
                    status: true,
                    disable: false,
                },
            ),
            (
                vec!["quality-gate-schedule", "--install"],
                CliCommand::QualityGateSchedule {
                    install: true,
                    status: false,
                    disable: false,
                },
            ),
            (
                vec!["quality-gate-schedule", "--disable"],
                CliCommand::QualityGateSchedule {
                    install: false,
                    status: false,
                    disable: true,
                },
            ),
        ] {
            assert_eq!(parse_cli(arguments).unwrap().command, command);
        }
        assert!(parse_cli(["quality-gate-schedule", "--install", "--status"]).is_err());
        assert!(parse_cli(["quality-gate-schedule", "--status", "--disable"]).is_err());
        assert!(parse_cli(["quality-gate-schedule", "--install", "--disable"]).is_err());
    }

    #[test]
    fn parses_and_names_direct_token_inspection_and_rotation() {
        assert_eq!(
            parse_cli(["runtime-native-api-direct-token"]).unwrap(),
            Cli {
                command: CliCommand::RuntimeNativeApiDirectToken { rotate: false },
                json: false,
                status_only: false,
            }
        );
        assert_eq!(
            parse_cli(["runtime-native-api-direct-token", "--rotate", "--json"]).unwrap(),
            Cli {
                command: CliCommand::RuntimeNativeApiDirectToken { rotate: true },
                json: true,
                status_only: false,
            }
        );
        assert_eq!(
            CliCommand::RuntimeNativeApiDirectToken { rotate: true }.name(),
            "runtime-native-api-direct-token"
        );
    }

    #[test]
    fn parses_license_report_options_and_rejects_invalid_values() {
        assert_eq!(
            parse_cli([
                "license-report",
                "--public-release",
                "--mode",
                "container",
                "--diff-scope",
                "staged",
                "--modified-imported-only",
                "--status-only",
                "--json",
            ])
            .unwrap(),
            Cli {
                command: CliCommand::LicenseReport {
                    public_release: true,
                    mode: "container".into(),
                    diff_scope: "staged".into(),
                    modified_imported_only: true,
                },
                json: true,
                status_only: true,
            }
        );
        assert!(parse_cli(["license-report", "--mode", "unknown"]).is_err());
        assert!(parse_cli(["license-report", "--diff-scope", "unknown"]).is_err());
    }

    #[test]
    fn parses_feed_generation_runtime_guard() {
        assert_eq!(
            parse_cli(["feed-generation-runtime-guard", "--selector-only"]).unwrap(),
            Cli {
                command: CliCommand::FeedGenerationRuntimeGuard {
                    selector_only: true,
                },
                json: false,
                status_only: false,
            }
        );
        assert_eq!(
            CliCommand::FeedGenerationRuntimeGuard {
                selector_only: false,
            }
            .name(),
            "feed-generation-runtime-guard"
        );
        assert!(
            Cli::command()
                .find_subcommand("feed-generation-runtime-guard")
                .unwrap()
                .is_hide_set()
        );
    }

    #[test]
    fn parses_visible_runtime_data_state() {
        assert_eq!(
            parse_cli(["runtime-data-state", "--json"]).unwrap(),
            Cli {
                command: CliCommand::RuntimeDataState,
                json: true,
                status_only: false,
            }
        );
        assert!(
            !Cli::command()
                .find_subcommand("runtime-data-state")
                .unwrap()
                .is_hide_set()
        );
    }

    #[test]
    fn parses_hidden_c_hardening_manifest_writer() {
        assert_eq!(
            parse_cli(["c-hardening-manifest-write", "--json"]).unwrap(),
            Cli {
                command: CliCommand::CHardeningManifestWrite,
                json: true,
                status_only: false,
            }
        );
        assert!(
            Cli::command()
                .find_subcommand("c-hardening-manifest-write")
                .unwrap()
                .is_hide_set()
        );
    }

    #[test]
    fn parses_repeatable_database_column_requests() {
        assert_eq!(
            parse_cli([
                "runtime-db-introspect",
                "--columns-for",
                "public.targets",
                "--columns-for",
                "cert.cert_bund_advs",
                "--status-only",
            ])
            .unwrap(),
            Cli {
                command: CliCommand::RuntimeDbIntrospect {
                    columns_for: vec!["public.targets".into(), "cert.cert_bund_advs".into(),],
                },
                json: false,
                status_only: true,
            }
        );
    }

    #[test]
    fn parses_c_hardening_profile_and_compact_mode() {
        assert_eq!(
            parse_cli([
                "c-hardening-check",
                "--profile",
                "hardened",
                "--status-only",
                "--json",
            ])
            .unwrap(),
            Cli {
                command: CliCommand::CHardeningCheck {
                    profile: Some("hardened".into()),
                },
                json: true,
                status_only: true,
            }
        );
    }

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

    #[test]
    fn parses_feed_generation_activation_and_rollback_commands() {
        assert_eq!(
            parse_cli([
                "feed-generation-activate",
                "gen-001",
                "--allow-first-activation",
                "--repair-attestation",
            ])
            .unwrap(),
            Cli {
                command: CliCommand::FeedGenerationActivate {
                    generation_id: "gen-001".to_string(),
                    allow_first_activation: true,
                    repair_attestation: true,
                },
                json: false,
                status_only: false,
            }
        );
        assert_eq!(
            parse_cli(["feed-generation-rollback", "gen-002"]).unwrap(),
            Cli {
                command: CliCommand::FeedGenerationRollback {
                    generation_id: "gen-002".to_string(),
                },
                json: false,
                status_only: false,
            }
        );
    }

    #[test]
    fn rollback_rejects_activation_only_flags() {
        assert!(
            parse_cli([
                "feed-generation-rollback",
                "gen-003",
                "--allow-first-activation"
            ])
            .is_err()
        );
        assert!(
            parse_cli([
                "feed-generation-rollback",
                "gen-003",
                "--repair-attestation"
            ])
            .is_err()
        );
    }

    #[test]
    fn public_docs_track_the_complete_rust_command_surface() {
        let command_names = Cli::command()
            .get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(|command| command.get_name().to_string())
            .collect::<Vec<_>>();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let cli_reference = fs::read_to_string(repo_root.join("docs/CLI_REFERENCE.md")).unwrap();
        let documented = cli_reference
            .split_once("<!-- rust-cli-commands:start -->")
            .unwrap()
            .1
            .split_once("<!-- rust-cli-commands:end -->")
            .unwrap()
            .0
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("```"))
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(documented, command_names);

        let readme = fs::read_to_string(repo_root.join("README.md")).unwrap();
        assert!(readme.contains(&format!(
            "{} parity-tested subcommands",
            command_names.len()
        )));
    }

    #[test]
    fn rust_direct_recipes_do_not_route_through_python() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let justfile = fs::read_to_string(repo_root.join("justfile")).unwrap();
        for command in [
            "feed-generation-stage",
            "feed-generation-state",
            "feed-generation-activate",
            "feed-generation-rollback",
            "runtime-db-introspect",
            "runtime-performance-snapshot",
            "runtime-log-review",
            "runtime-redis-state",
            "runtime-gmp-smoke",
            "runtime-credential-smoke",
            "runtime-rbac-smoke",
            "down",
            "runtime-app-down",
            "runtime-full-test-scan-preflight",
            "runtime-full-test-scan-start",
            "runtime-full-test-scan-status",
            "c-hardening-check",
            "quality-gate-schedule",
            "runtime-native-api-direct-token",
        ] {
            let recipe = justfile
                .split_once(&format!("{command} *args:\n"))
                .unwrap()
                .1
                .split_once("\n\n")
                .unwrap()
                .0;
            assert!(recipe.contains("cargo run --quiet --locked"), "{command}");
            assert!(
                recipe.contains(&format!("-- {command} \"$@\"")),
                "{command}"
            );
            assert!(!recipe.contains("tools/yafvsctl "), "{command}");
        }
    }
}
