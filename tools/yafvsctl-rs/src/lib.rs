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
    command_deps, command_doctor, command_down, command_feed_copy_to_runtime,
    command_feed_generation_activate, command_feed_generation_rollback,
    command_feed_generation_runtime_guard, command_feed_generation_stage,
    command_feed_generation_state, command_feed_state, command_gsa_npm_audit, command_inventory,
    command_license_report, command_logs, command_native_alerts_from_csv,
    command_native_api_cargo_audit, command_native_api_request, command_native_api_semgrep_audit,
    command_native_bulk_modify_schedules, command_native_credentials_from_csv,
    command_native_delete_overrides_by_filter,
    command_native_empty_trash, command_native_export_report_bundle,
    command_native_export_report_csv, command_native_export_report_pdf,
    command_native_schedules_from_csv, command_native_schedules_from_xml,
    command_native_start_task, command_native_start_tasks_from_csv, command_native_stop_all_tasks,
    command_native_stop_task, command_native_stop_tasks_from_csv, command_native_tags_from_csv,
    command_native_targets_from_csv, command_native_targets_from_host_list,
    command_native_targets_from_xml, command_native_tasks_from_csv,
    command_native_update_task_target, command_native_verify_scanners, command_osv_lockfile_audit,
    command_path_coupling_state, command_production_posture_check, command_quality_gate_schedule,
    command_quality_gate_state, command_repository_unavailable, command_runtime_app_down,
    command_runtime_certbund_report, command_runtime_credential_smoke, command_runtime_data_state,
    command_runtime_db_introspect, command_runtime_feed_import_init,
    command_runtime_full_test_scan_preflight, command_runtime_full_test_scan_start,
    command_runtime_full_test_scan_status, command_runtime_gmp_smoke,
    command_runtime_identity_migrate, command_runtime_log_review,
    command_runtime_native_api_direct_bootstrap, command_runtime_native_api_direct_token,
    command_runtime_nmap_capability_check, command_runtime_performance_snapshot,
    command_runtime_plan, command_runtime_rbac_smoke, command_runtime_redis_state,
    command_runtime_scope_smoke,
    command_runtime_report_export, command_runtime_report_metrics, command_runtime_report_summary,
    command_runtime_scanner_capability_check, command_runtime_scanner_process_check,
    command_runtime_scope_report_metrics, command_runtime_scope_report_summary,
    command_runtime_webui_smoke, command_rust_migration_state, command_security_policy_check,
    command_status, find_repo_root,
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
        CliCommand::NativeBulkModifySchedules {
            filter,
            timezone,
            icalendar_file,
            max_schedules,
            dry_run,
            allow_write_control,
            confirm_snapshot,
        } => command_native_bulk_modify_schedules(
            &repo_root,
            filter,
            timezone.as_deref(),
            icalendar_file.as_deref(),
            *max_schedules,
            *dry_run,
            *allow_write_control,
            confirm_snapshot.as_deref(),
            cli.status_only,
        ),
        CliCommand::NativeDeleteOverridesByFilter {
            filter,
            max_overrides,
            dry_run,
            allow_write_control,
            confirm_snapshot,
            delay_seconds,
        } => command_native_delete_overrides_by_filter(
            &repo_root,
            filter,
            *max_overrides,
            *dry_run,
            *allow_write_control,
            confirm_snapshot.as_deref(),
            *delay_seconds,
            cli.status_only,
        ),
        CliCommand::NativeEmptyTrash {
            allow_write_control,
            acknowledge_permanent_deletion,
            expected_total,
        } => command_native_empty_trash(
            &repo_root,
            *allow_write_control,
            *acknowledge_permanent_deletion,
            *expected_total,
            cli.status_only,
        ),
        CliCommand::NativeSchedulesFromCsv {
            csv_file,
            allow_write_control,
            dry_run,
        } => command_native_schedules_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeVerifyScanners {
            scanner_id,
            page_size,
            allow_write_control,
        } => command_native_verify_scanners(
            &repo_root,
            scanner_id,
            *page_size,
            *allow_write_control,
            cli.status_only,
        ),
        CliCommand::NativeAlertsFromCsv {
            csv_file,
            allow_write_control,
            dry_run,
        } => command_native_alerts_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeCredentialsFromCsv {
            csv_file,
            allow_write_control,
            dry_run,
        } => command_native_credentials_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeTasksFromCsv {
            csv_file,
            allow_write_control,
        } => command_native_tasks_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            cli.status_only,
        ),
        CliCommand::NativeSchedulesFromXml {
            xml_file,
            allow_write_control,
            dry_run,
        } => command_native_schedules_from_xml(
            &repo_root,
            xml_file,
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeExportReportBundle {
            report_id,
            output,
            max_items,
            max_bytes,
            overwrite,
        } => command_native_export_report_bundle(
            &repo_root,
            report_id,
            output.as_deref(),
            *max_items,
            *max_bytes,
            *overwrite,
            cli.status_only,
        ),
        CliCommand::NativeTagsFromCsv {
            csv_file,
            allow_write_control,
            dry_run,
        } => command_native_tags_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeTargetsFromCsv {
            csv_file,
            port_list_id,
            allow_write_control,
            dry_run,
        } => command_native_targets_from_csv(
            &repo_root,
            csv_file,
            port_list_id.as_deref(),
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeTargetsFromXml {
            xml_file,
            allow_write_control,
            dry_run,
        } => command_native_targets_from_xml(
            &repo_root,
            xml_file,
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeExportReportCsv {
            report_id,
            output,
            max_results,
            overwrite,
        } => command_native_export_report_csv(
            &repo_root,
            report_id,
            output.as_deref(),
            *max_results,
            *overwrite,
            cli.status_only,
        ),
        CliCommand::NativeExportReportPdf {
            report_id,
            output,
            max_bytes,
            overwrite,
        } => command_native_export_report_pdf(
            &repo_root,
            report_id,
            output.as_deref(),
            *max_bytes,
            *overwrite,
            cli.status_only,
        ),
        CliCommand::NativeUpdateTaskTarget {
            task_id,
            host,
            hosts_file,
            exclude_host,
            allow_write_control,
        } => command_native_update_task_target(
            &repo_root,
            task_id,
            host,
            hosts_file.as_deref(),
            exclude_host,
            *allow_write_control,
            cli.status_only,
        ),
        CliCommand::NativeTargetsFromHostList {
            hosts_file,
            port_list_id,
            port_range,
            port_list_name,
            allow_write_control,
            dry_run,
        } => command_native_targets_from_host_list(
            &repo_root,
            hosts_file,
            port_list_id.as_deref(),
            port_range.as_deref(),
            port_list_name.as_deref(),
            *allow_write_control,
            *dry_run,
            cli.status_only,
        ),
        CliCommand::NativeStartTask {
            task_id,
            allow_write_control,
        } => command_native_start_task(&repo_root, task_id, *allow_write_control, cli.status_only),
        CliCommand::NativeStopTask {
            task_id,
            allow_write_control,
        } => command_native_stop_task(&repo_root, task_id, *allow_write_control, cli.status_only),
        CliCommand::NativeStartTasksFromCsv {
            csv_file,
            allow_write_control,
        } => command_native_start_tasks_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            cli.status_only,
        ),
        CliCommand::NativeStopTasksFromCsv {
            csv_file,
            allow_write_control,
        } => command_native_stop_tasks_from_csv(
            &repo_root,
            csv_file,
            *allow_write_control,
            cli.status_only,
        ),
        CliCommand::NativeStopAllTasks {
            allow_write_control,
        } => command_native_stop_all_tasks(&repo_root, *allow_write_control, cli.status_only),
        CliCommand::NativeApiRequest {
            path,
            direct,
            method,
            request_id,
            body_json,
            allow_write_control,
        } => command_native_api_request(
            &repo_root,
            path,
            *direct,
            method,
            request_id.as_deref(),
            body_json.as_deref(),
            *allow_write_control,
            cli.status_only,
        ),
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
        CliCommand::Down => command_down(&repo_root),
        CliCommand::RuntimeAppDown => command_runtime_app_down(&repo_root),
        CliCommand::FeedCopyToRuntime => command_feed_copy_to_runtime(&repo_root),
        CliCommand::Deps { component } => command_deps(&repo_root, component.as_deref()),
        CliCommand::RuntimeFeedImportInit => command_runtime_feed_import_init(&repo_root),
        CliCommand::RuntimePerformanceSnapshot => command_runtime_performance_snapshot(&repo_root),
        CliCommand::RuntimeReportSummary {
            report_id,
            max_results,
            top_results,
        } => command_runtime_report_summary(
            &repo_root,
            report_id.as_deref(),
            *max_results,
            *top_results,
        ),
        CliCommand::RuntimeReportExport {
            report_id,
            max_results,
            top_results,
        } => command_runtime_report_export(
            &repo_root,
            report_id.as_deref(),
            *max_results,
            *top_results,
        ),
        CliCommand::RuntimeReportMetrics { report_id } => {
            command_runtime_report_metrics(&repo_root, report_id.as_deref())
        }
        CliCommand::RuntimeScopeReportSummary => command_runtime_scope_report_summary(&repo_root),
        CliCommand::RuntimeScopeReportMetrics { scope_report_id } => {
            command_runtime_scope_report_metrics(&repo_root, scope_report_id.as_deref())
        }
        CliCommand::RuntimeCertbundReport {
            report_id,
            task_id,
            max_results,
            max_hosts,
            format,
            output,
        } => command_runtime_certbund_report(
            &repo_root,
            report_id.as_deref(),
            task_id.as_deref(),
            *max_results,
            *max_hosts,
            format,
            output.as_deref(),
        ),
        CliCommand::RuntimeLogReview => command_runtime_log_review(&repo_root),
        CliCommand::RuntimeScannerCapabilityCheck => {
            command_runtime_scanner_capability_check(&repo_root)
        }
        CliCommand::RuntimeScannerProcessCheck => command_runtime_scanner_process_check(&repo_root),
        CliCommand::RuntimeNmapCapabilityCheck => command_runtime_nmap_capability_check(&repo_root),
        CliCommand::RuntimeDataState => command_runtime_data_state(&repo_root),
        CliCommand::RuntimeGmpSmoke => command_runtime_gmp_smoke(&repo_root),
        CliCommand::RuntimeCredentialSmoke => command_runtime_credential_smoke(&repo_root),
        CliCommand::RuntimeRbacSmoke => command_runtime_rbac_smoke(&repo_root),
        CliCommand::RuntimeScopeSmoke => command_runtime_scope_smoke(&repo_root),
        CliCommand::RuntimeWebuiSmoke => command_runtime_webui_smoke(&repo_root, cli.status_only),
        CliCommand::RuntimeFullTestScanPreflight { target_cidr } => {
            command_runtime_full_test_scan_preflight(&repo_root, target_cidr)
        }
        CliCommand::RuntimeFullTestScanStart {
            target_cidr,
            confirm_authorized_target,
        } => command_runtime_full_test_scan_start(
            &repo_root,
            target_cidr,
            confirm_authorized_target.as_deref(),
        ),
        CliCommand::RuntimeFullTestScanStatus { target_cidr } => {
            command_runtime_full_test_scan_status(&repo_root, target_cidr)
        }
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
        CliCommand::RuntimeNativeApiDirectBootstrap => {
            command_runtime_native_api_direct_bootstrap(&repo_root, cli.status_only)
        }
        CliCommand::ProductionPostureCheck => {
            command_production_posture_check(&repo_root, cli.status_only)
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
