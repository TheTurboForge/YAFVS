// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

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
    /// Download one bounded PDF report through the guarded direct native API.
    NativeExportReportPdf {
        #[arg(long)]
        report_id: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = crate::commands::NATIVE_REPORT_PDF_DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        #[arg(long)]
        overwrite: bool,
    },
    /// Replace one task target through the guarded direct native API.
    NativeUpdateTaskTarget {
        #[arg(long)]
        task_id: String,
        #[arg(
            long,
            conflicts_with = "hosts_file",
            required_unless_present = "hosts_file"
        )]
        host: Vec<String>,
        #[arg(long, conflicts_with = "host", required_unless_present = "host")]
        hosts_file: Option<PathBuf>,
        #[arg(long)]
        exclude_host: Vec<String>,
        #[arg(long)]
        allow_write_control: bool,
    },
    /// Start one task through the guarded direct native API.
    NativeStartTask {
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        allow_write_control: bool,
    },
    /// Stop one task through the guarded direct native API.
    NativeStopTask {
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        allow_write_control: bool,
    },
    /// Send a bounded native API request.
    NativeApiRequest {
        #[arg(long)]
        path: String,
        #[arg(long)]
        direct: bool,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long)]
        request_id: Option<String>,
        #[arg(long)]
        body_json: Option<String>,
        #[arg(long)]
        allow_write_control: bool,
    },
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
    /// Summarize a completed full-test report through the native API.
    RuntimeReportSummary {
        /// Optional raw report id; defaults to the latest completed full-test report.
        #[arg(long)]
        report_id: Option<String>,
        /// Maximum result rows to fetch.
        #[arg(long, default_value_t = 1000)]
        max_results: usize,
        /// Maximum highest-severity rows to include in the summary.
        #[arg(long, default_value_t = 10)]
        top_results: usize,
    },
    /// Export normalized result rows from a completed full-test report.
    RuntimeReportExport {
        /// Optional raw report id; defaults to the latest completed full-test report.
        #[arg(long)]
        report_id: Option<String>,
        /// Maximum result rows to fetch.
        #[arg(long, default_value_t = 1000)]
        max_results: usize,
        /// Maximum highest-severity rows to include in the summary.
        #[arg(long, default_value_t = 10)]
        top_results: usize,
    },
    /// Emit Prometheus-style metrics for a completed full-test report.
    RuntimeReportMetrics {
        /// Optional raw report id; defaults to the latest completed full-test report.
        #[arg(long)]
        report_id: Option<String>,
    },
    /// Summarize the latest Organization scope report through the native API.
    RuntimeScopeReportSummary,
    /// Emit native metrics for the selected scope report filter.
    RuntimeScopeReportMetrics {
        /// Compatibility selector interpreted as a native scope-report filter.
        #[arg(long)]
        scope_report_id: Option<String>,
    },
    /// Build a native CERT-Bund JSON or CSV report for a raw report or task.
    RuntimeCertbundReport {
        /// Optional raw report id; defaults to the latest completed full-test report.
        #[arg(long)]
        report_id: Option<String>,
        /// Optional task id whose last report should be analysed.
        #[arg(long)]
        task_id: Option<String>,
        /// Maximum result rows to fetch.
        #[arg(long, default_value_t = 1000)]
        max_results: usize,
        /// Maximum host rows to fetch.
        #[arg(long, default_value_t = 5000)]
        max_hosts: usize,
        /// Output artifact format; JSON is always written as the canonical artifact.
        #[arg(long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,
        /// Optional output artifact path for the selected format.
        #[arg(long)]
        output: Option<String>,
    },
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
    /// Verify the staged GSA web UI over gsad.
    RuntimeWebuiSmoke,
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
    /// Prepare and check opt-in direct native API bootstrap guardrails without starting it.
    RuntimeNativeApiDirectBootstrap,
    /// Run the non-destructive production posture checklist.
    ProductionPostureCheck,
}

impl CliCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::NativeExportReportPdf { .. } => "native-export-report-pdf",
            Self::NativeUpdateTaskTarget { .. } => "native-update-task-target",
            Self::NativeStartTask { .. } => "native-start-task",
            Self::NativeStopTask { .. } => "native-stop-task",
            Self::NativeApiRequest { .. } => "native-api-request",
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
            Self::RuntimeReportSummary { .. } => "runtime-report-summary",
            Self::RuntimeReportExport { .. } => "runtime-report-export",
            Self::RuntimeReportMetrics { .. } => "runtime-report-metrics",
            Self::RuntimeScopeReportSummary => "runtime-scope-report-summary",
            Self::RuntimeScopeReportMetrics { .. } => "runtime-scope-report-metrics",
            Self::RuntimeCertbundReport { .. } => "runtime-certbund-report",
            Self::RuntimeLogReview => "runtime-log-review",
            Self::RuntimeScannerCapabilityCheck => "runtime-scanner-capability-check",
            Self::RuntimeScannerProcessCheck => "runtime-scanner-process-check",
            Self::RuntimeNmapCapabilityCheck => "runtime-nmap-capability-check",
            Self::RuntimeDataState => "runtime-data-state",
            Self::RuntimeGmpSmoke => "runtime-gmp-smoke",
            Self::RuntimeCredentialSmoke => "runtime-credential-smoke",
            Self::RuntimeRbacSmoke => "runtime-rbac-smoke",
            Self::RuntimeWebuiSmoke => "runtime-webui-smoke",
            Self::RuntimeFullTestScanPreflight { .. } => "runtime-full-test-scan-preflight",
            Self::RuntimeFullTestScanStart { .. } => "runtime-full-test-scan-start",
            Self::RuntimeFullTestScanStatus { .. } => "runtime-full-test-scan-status",
            Self::Logs { .. } => "logs",
            Self::LicenseReport { .. } => "license-report",
            Self::Doctor => "doctor",
            Self::QualityGateSchedule { .. } => "quality-gate-schedule",
            Self::RuntimeNativeApiDirectToken { .. } => "runtime-native-api-direct-token",
            Self::RuntimeNativeApiDirectBootstrap => "runtime-native-api-direct-bootstrap",
            Self::ProductionPostureCheck => "production-posture-check",
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
    fn parses_native_pdf_export_bounds_and_output_controls() {
        let cli = parse_cli([
            "native-export-report-pdf",
            "--report-id",
            "11111111-1111-4111-8111-111111111111",
            "--output",
            "report.pdf",
            "--max-bytes",
            "4096",
            "--overwrite",
            "--status-only",
        ])
        .unwrap();
        assert!(cli.status_only);
        assert_eq!(
            cli.command,
            CliCommand::NativeExportReportPdf {
                report_id: "11111111-1111-4111-8111-111111111111".into(),
                output: Some(PathBuf::from("report.pdf")),
                max_bytes: 4096,
                overwrite: true,
            }
        );
        assert_eq!(cli.command.name(), "native-export-report-pdf");
        assert!(
            parse_cli([
                "native-export-report-pdf",
                "--report-id",
                "11111111-1111-4111-8111-111111111111",
                "--max-bytes",
                "-1",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_guarded_task_target_replacement_and_requires_one_host_source() {
        let cli = parse_cli([
            "native-update-task-target",
            "--task-id",
            "11111111-1111-4111-8111-111111111111",
            "--host",
            "192.0.2.10",
            "--exclude-host",
            "192.0.2.11",
            "--allow-write-control",
            "--status-only",
        ])
        .unwrap();
        assert!(cli.status_only);
        assert_eq!(cli.command.name(), "native-update-task-target");
        assert!(
            parse_cli([
                "native-update-task-target",
                "--task-id",
                "11111111-1111-4111-8111-111111111111"
            ])
            .is_err()
        );
        assert!(
            parse_cli([
                "native-update-task-target",
                "--task-id",
                "11111111-1111-4111-8111-111111111111",
                "--host",
                "192.0.2.10",
                "--hosts-file",
                "hosts.csv",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_guarded_native_api_request() {
        let cli = parse_cli([
            "native-api-request",
            "--path",
            "/api/v1/items",
            "--direct",
            "--method",
            "POST",
            "--request-id",
            "request-1",
            "--body-json",
            "{\"name\":\"item\"}",
            "--allow-write-control",
            "--status-only",
        ])
        .unwrap();
        assert!(cli.status_only);
        assert_eq!(
            cli.command,
            CliCommand::NativeApiRequest {
                path: "/api/v1/items".into(),
                direct: true,
                method: "POST".into(),
                request_id: Some("request-1".into()),
                body_json: Some("{\"name\":\"item\"}".into()),
                allow_write_control: true,
            }
        );
        assert_eq!(cli.command.name(), "native-api-request");
    }

    #[test]
    fn parses_guarded_task_control() {
        let cli = parse_cli([
            "native-start-task",
            "--task-id",
            "11111111-1111-4111-8111-111111111111",
            "--allow-write-control",
            "--status-only",
        ])
        .unwrap();
        assert!(cli.status_only);
        assert_eq!(cli.command.name(), "native-start-task");
        assert_eq!(
            parse_cli([
                "native-stop-task",
                "--task-id",
                "11111111-1111-4111-8111-111111111111",
                "--allow-write-control"
            ])
            .unwrap()
            .command
            .name(),
            "native-stop-task"
        );
    }

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
    fn parses_and_names_native_report_commands() {
        assert_eq!(
            parse_cli([
                "runtime-report-summary",
                "--report-id",
                "report-1",
                "--max-results",
                "25",
                "--top-results",
                "5",
            ])
            .unwrap()
            .command,
            CliCommand::RuntimeReportSummary {
                report_id: Some("report-1".into()),
                max_results: 25,
                top_results: 5,
            }
        );
        assert_eq!(
            parse_cli(["runtime-report-export"]).unwrap().command,
            CliCommand::RuntimeReportExport {
                report_id: None,
                max_results: 1000,
                top_results: 10,
            }
        );
        assert_eq!(
            parse_cli(["runtime-report-metrics", "--report-id", "report-2"])
                .unwrap()
                .command,
            CliCommand::RuntimeReportMetrics {
                report_id: Some("report-2".into()),
            }
        );
        assert_eq!(
            CliCommand::RuntimeReportSummary {
                report_id: None,
                max_results: 1,
                top_results: 1,
            }
            .name(),
            "runtime-report-summary"
        );
        assert_eq!(
            CliCommand::RuntimeReportExport {
                report_id: None,
                max_results: 1,
                top_results: 1,
            }
            .name(),
            "runtime-report-export"
        );
        assert_eq!(
            CliCommand::RuntimeReportMetrics { report_id: None }.name(),
            "runtime-report-metrics"
        );
        assert_eq!(
            parse_cli(["runtime-scope-report-summary"]).unwrap().command,
            CliCommand::RuntimeScopeReportSummary
        );
        assert_eq!(
            parse_cli([
                "runtime-scope-report-metrics",
                "--scope-report-id",
                "Organization / one"
            ])
            .unwrap()
            .command,
            CliCommand::RuntimeScopeReportMetrics {
                scope_report_id: Some("Organization / one".into())
            }
        );
    }

    #[test]
    fn parses_and_names_runtime_certbund_report_without_parser_level_selector_conflict() {
        assert_eq!(
            parse_cli([
                "runtime-certbund-report",
                "--report-id",
                "report-1",
                "--task-id",
                "task-1",
                "--max-results",
                "25",
                "--max-hosts",
                "50",
                "--format",
                "csv",
                "--output",
                "report.csv",
            ])
            .unwrap()
            .command,
            CliCommand::RuntimeCertbundReport {
                report_id: Some("report-1".into()),
                task_id: Some("task-1".into()),
                max_results: 25,
                max_hosts: 50,
                format: "csv".into(),
                output: Some("report.csv".into()),
            }
        );
        assert_eq!(
            parse_cli(["runtime-certbund-report"]).unwrap().command,
            CliCommand::RuntimeCertbundReport {
                report_id: None,
                task_id: None,
                max_results: 1000,
                max_hosts: 5000,
                format: "json".into(),
                output: None,
            }
        );
        assert_eq!(
            CliCommand::RuntimeCertbundReport {
                report_id: None,
                task_id: None,
                max_results: 1,
                max_hosts: 1,
                format: "json".into(),
                output: None,
            }
            .name(),
            "runtime-certbund-report"
        );
        assert!(parse_cli(["runtime-certbund-report", "--format", "xml"]).is_err());
    }

    #[test]
    fn parses_and_names_direct_bootstrap() {
        assert_eq!(
            parse_cli(["runtime-native-api-direct-bootstrap", "--status-only"]).unwrap(),
            Cli {
                command: CliCommand::RuntimeNativeApiDirectBootstrap,
                json: false,
                status_only: true,
            }
        );
        assert_eq!(
            CliCommand::RuntimeNativeApiDirectBootstrap.name(),
            "runtime-native-api-direct-bootstrap"
        );
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
            ("runtime-webui-smoke", CliCommand::RuntimeWebuiSmoke),
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
            "native-update-task-target",
            "feed-generation-stage",
            "feed-generation-state",
            "feed-generation-activate",
            "feed-generation-rollback",
            "runtime-db-introspect",
            "runtime-performance-snapshot",
            "runtime-report-summary",
            "runtime-report-export",
            "runtime-report-metrics",
            "runtime-scope-report-summary",
            "runtime-scope-report-metrics",
            "runtime-certbund-report",
            "runtime-log-review",
            "runtime-redis-state",
            "runtime-gmp-smoke",
            "runtime-credential-smoke",
            "runtime-rbac-smoke",
            "down",
            "runtime-app-down",
            "runtime-webui-smoke",
            "runtime-full-test-scan-preflight",
            "runtime-full-test-scan-start",
            "runtime-full-test-scan-status",
            "c-hardening-check",
            "quality-gate-schedule",
            "runtime-native-api-direct-token",
            "runtime-native-api-direct-bootstrap",
            "production-posture-check",
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
