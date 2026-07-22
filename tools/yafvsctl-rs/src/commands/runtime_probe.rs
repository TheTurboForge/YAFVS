// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rust ownership for authenticated runtime-probe orchestration.
//!
//! The narrow Python helpers remain purpose-built GMP clients. Rust owns
//! prerequisite validation, bounded execution, redaction, and result envelopes.

use super::common::{build_env, executable_path, metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::runtime_log_review::redact_text;
use super::runtime_scanner_capability::{
    command_runtime_nmap_capability_check, command_runtime_scanner_capability_check,
};
use super::runtime_scanner_process::command_runtime_scanner_process_check;
use super::secret::{
    random_bytes, random_urlsafe_token, read_existing_runtime_secret, runtime_secret_path,
};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const ADMIN_SECRET: &str = "gvmd-admin-password";
const ADMIN_USER: &str = "admin";
const MAX_HELPER_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_FULL_TEST_TARGET_ADDRESSES: u128 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FullTestAction {
    Preflight,
    Start,
    Status,
}

pub fn command_runtime_credential_smoke(repo_root: &Path) -> ResultEnvelope {
    let node_available = executable_path("node").is_some();
    command_runtime_credential_smoke_with(
        repo_root,
        &SystemCommandRunner,
        node_available,
        temporary_credential_material,
    )
}

impl FullTestAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Start => "start",
            Self::Status => "status",
        }
    }

    fn command_name(self) -> String {
        format!("runtime-full-test-scan-{}", self.as_str())
    }

    fn checks_capabilities(self) -> bool {
        matches!(self, Self::Preflight | Self::Start)
    }
}

fn command_runtime_credential_smoke_with<F>(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    node_available: bool,
    generate_material: F,
) -> ResultEnvelope
where
    F: FnOnce() -> io::Result<(String, String)>,
{
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    let probe = repo_root.join("tools/runtime_credential_smoke.py");
    let artifact_dir = runtime_dir(repo_root).join("artifacts/credential-smoke");
    let mut findings = Vec::new();
    let admin_password = append_secret_prerequisite(
        repo_root,
        &secret_path,
        "Development admin secret is missing.",
        &mut findings,
    );
    findings.push(file_prerequisite(
        repo_root,
        &probe,
        "credential-smoke.probe",
        "Credential browser smoke helper exists.",
        "Credential browser smoke helper is missing.",
    ));
    findings.push(Finding::new(
        if node_available { "pass" } else { "fail" },
        "node.available",
        if node_available {
            "node is available for credential browser smoke."
        } else {
            "node is not available on PATH."
        }
        .into(),
    ));
    match prepare_artifact_dir(&artifact_dir) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "credential-smoke.artifact-dir",
                "Credential smoke artifact directory is ready.".into(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "credential-smoke.artifact-dir",
                format!("Credential smoke artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }
    let urls = gsad_urls_from_env(&build_env(repo_root));
    findings.push(
        Finding::new(
            if urls.is_empty() { "fail" } else { "pass" },
            "gsad.urls",
            if urls.is_empty() {
                "No gsad base URLs are configured."
            } else {
                "Configured gsad base URLs are available."
            }
            .into(),
        )
        .with_details(json!({ "base_urls": urls })),
    );
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "runtime-credential-smoke", runner),
            "Runtime credential smoke stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![artifact_dir.display().to_string()]);
    }

    let (credential_name, credential_password) = match generate_material() {
        Ok(material) => material,
        Err(error) => {
            return credential_entropy_failure(repo_root, runner, findings, &artifact_dir, error);
        }
    };
    let mut environment = build_env(repo_root);
    environment.insert(
        OsString::from("YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD"),
        OsString::from(&credential_password),
    );
    let mut arguments = vec![
        "--username".to_string(),
        ADMIN_USER.to_string(),
        "--password-file".to_string(),
        secret_path.display().to_string(),
        "--artifact-dir".to_string(),
        artifact_dir.display().to_string(),
        "--credential-name".to_string(),
        credential_name,
    ];
    for url in &urls {
        arguments.extend(["--base-url".to_string(), url.clone()]);
    }
    let refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_probe_with_env(
        repo_root,
        runner,
        &probe,
        &refs,
        Duration::from_secs(300),
        environment,
    );
    let redactions = admin_password
        .into_iter()
        .chain(std::iter::once(credential_password))
        .collect::<Vec<_>>();
    let mut parsed = parse_bounded_helper_output(&output);
    if let Some(value) = parsed.as_mut() {
        redact_json_value(value, &redactions);
    }
    let helper_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let finding_status = if output.success && matches!(helper_status, Some("pass" | "warn")) {
        helper_status.unwrap_or("fail")
    } else {
        "fail"
    };
    let exit_code = output.exit_code.unwrap_or(1);
    let summary = parsed
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!("Runtime credential smoke completed with exit code {exit_code}.")
        });
    findings.push(
        Finding::new(finding_status, "credential-smoke.run", summary.clone()).with_details(json!({
            "helper": parsed,
            "output_tail": output_tail(&redact_text(&output.stdout, &redactions), 120),
        })),
    );
    let artifacts = parsed_artifacts(parsed.as_ref())
        .unwrap_or_else(|| vec![artifact_dir.display().to_string()]);
    make_result(
        metadata(repo_root, "runtime-credential-smoke", runner),
        summary,
        findings,
    )
    .with_artifacts(artifacts)
}

fn credential_entropy_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    mut findings: Vec<Finding>,
    artifact_dir: &Path,
    error: io::Error,
) -> ResultEnvelope {
    findings.push(Finding::new(
        "fail",
        "credential-smoke.run",
        format!("Temporary credential material could not be generated: {error}"),
    ));
    make_result(
        metadata(repo_root, "runtime-credential-smoke", runner),
        "Runtime credential smoke could not generate temporary credential material.".into(),
        findings,
    )
    .with_artifacts(vec![artifact_dir.display().to_string()])
}

fn temporary_credential_material() -> io::Result<(String, String)> {
    let suffix = random_bytes(4)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((
        format!("yafvs-credential-smoke-{suffix}"),
        random_urlsafe_token(24)?,
    ))
}

pub(crate) fn gsad_urls_from_env(
    environment: &std::collections::BTreeMap<OsString, OsString>,
) -> Vec<String> {
    let hosts = environment
        .get(&OsString::from("YAFVS_GSAD_HOSTS"))
        .filter(|value| !value.is_empty())
        .or_else(|| environment.get(&OsString::from("YAFVS_GSAD_HOST")));
    let mut unique = Vec::new();
    for host in hosts
        .and_then(|value| value.to_str())
        .unwrap_or("127.0.0.1")
        .split(",")
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        if !unique.contains(&host) {
            unique.push(host);
        }
    }
    if unique.is_empty() {
        unique.push("127.0.0.1");
    }
    unique
        .into_iter()
        .map(|host| format!("https://{host}:19392"))
        .collect()
}

pub fn command_runtime_gmp_smoke(repo_root: &Path) -> ResultEnvelope {
    command_runtime_gmp_smoke_with(repo_root, &SystemCommandRunner)
}

pub fn command_runtime_rbac_smoke(repo_root: &Path) -> ResultEnvelope {
    command_runtime_rbac_smoke_with(repo_root, &SystemCommandRunner)
}

pub fn command_runtime_scope_smoke(repo_root: &Path) -> ResultEnvelope {
    command_runtime_scope_smoke_with(repo_root, &SystemCommandRunner)
}

pub fn command_runtime_full_test_scan_preflight(
    repo_root: &Path,
    target_cidr: &str,
) -> ResultEnvelope {
    command_runtime_full_test_scan_with(
        repo_root,
        FullTestAction::Preflight,
        target_cidr,
        None,
        &SystemCommandRunner,
        system_full_test_capability_findings,
    )
}

pub fn command_runtime_full_test_scan_start(
    repo_root: &Path,
    target_cidr: &str,
    confirm_authorized_target: Option<&str>,
) -> ResultEnvelope {
    command_runtime_full_test_scan_with(
        repo_root,
        FullTestAction::Start,
        target_cidr,
        confirm_authorized_target,
        &SystemCommandRunner,
        system_full_test_capability_findings,
    )
}

pub fn command_runtime_full_test_scan_status(
    repo_root: &Path,
    target_cidr: &str,
) -> ResultEnvelope {
    command_runtime_full_test_scan_with(
        repo_root,
        FullTestAction::Status,
        target_cidr,
        None,
        &SystemCommandRunner,
        system_full_test_capability_findings,
    )
}

fn command_runtime_full_test_scan_with<F>(
    repo_root: &Path,
    action: FullTestAction,
    target_cidr: &str,
    confirm_authorized_target: Option<&str>,
    runner: &dyn CommandRunner,
    capability_findings: F,
) -> ResultEnvelope
where
    F: FnOnce(&Path) -> Vec<Finding>,
{
    let command_name = action.command_name();
    let canonical_target = match validated_full_test_target_cidr(target_cidr) {
        Ok(target) => target,
        Err(error) => {
            return make_result(
                metadata(repo_root, &command_name, runner),
                "Full test scan command refused an invalid target.".into(),
                vec![Finding::new("fail", "full-test-scan.target", error)],
            );
        }
    };
    if action == FullTestAction::Start {
        let Some(confirmation) = confirm_authorized_target else {
            return make_result(
                metadata(repo_root, &command_name, runner),
                "Full test scan start refused without an exact target confirmation.".into(),
                vec![Finding::new(
                    "fail",
                    "full-test-scan.confirmation",
                    "Pass --confirm-authorized-target with the exact --target-cidr value.".into(),
                )],
            );
        };
        let canonical_confirmation = match validated_full_test_target_cidr(confirmation) {
            Ok(target) => target,
            Err(error) => {
                return make_result(
                    metadata(repo_root, &command_name, runner),
                    "Full test scan start refused an invalid target confirmation.".into(),
                    vec![Finding::new("fail", "full-test-scan.confirmation", error)],
                );
            }
        };
        if canonical_confirmation != canonical_target {
            return make_result(
                metadata(repo_root, &command_name, runner),
                "Full test scan start refused a mismatched target confirmation.".into(),
                vec![Finding::new(
                    "fail",
                    "full-test-scan.confirmation",
                    "--confirm-authorized-target must exactly match --target-cidr.".into(),
                )],
            );
        }
    }

    let probe = repo_root.join("tools/runtime_full_test_scan.py");
    let artifact_dir = runtime_dir(repo_root).join("artifacts/full-test-scan");
    let mut findings = Vec::new();
    findings.push(file_prerequisite(
        repo_root,
        &probe,
        "full-test-scan.probe",
        "Full test scan helper exists.",
        "Full test scan helper is missing.",
    ));
    match prepare_artifact_dir(&artifact_dir) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "full-test-scan.artifact-dir",
                "Full test scan artifact directory is ready.".into(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "full-test-scan.artifact-dir",
                format!("Full test scan artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }
    if action.checks_capabilities() {
        findings.extend(capability_findings(repo_root));
    }
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, &command_name, runner),
            "Full test scan command stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![artifact_dir.display().to_string()]);
    }

    let ospd_log = runtime_dir(repo_root).join("logs/ospd/ospd-openvas.log");
    let repo_root_text = repo_root.display().to_string();
    let artifact_text = artifact_dir.display().to_string();
    let ospd_log_text = ospd_log.display().to_string();
    let mut arguments = vec![
        action.as_str(),
        "--operator-name",
        ADMIN_USER,
        "--artifact-dir",
        &artifact_text,
        "--target-cidr",
        &canonical_target,
        "--repo-root",
        &repo_root_text,
        "--ospd-log-file",
        &ospd_log_text,
    ];
    if let Some(confirmation) = confirm_authorized_target {
        // Preserve the characterized wrapper contract: the helper receives the
        // original confirmed text and independently canonicalizes it again.
        arguments.extend(["--confirm-authorized-target", confirmation]);
    }
    let output = run_probe_with_env(
        repo_root,
        runner,
        &probe,
        &arguments,
        Duration::from_secs(120),
        runtime_environment(repo_root),
    );
    let parsed = parse_bounded_helper_output(&output);
    let helper_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let finding_status = if output.success && matches!(helper_status, Some("pass" | "warn")) {
        helper_status.unwrap_or("fail")
    } else {
        "fail"
    };
    let exit_code = output.exit_code.unwrap_or(1);
    let fallback_finding_summary = format!("Full test scan helper exit code {exit_code}.");
    let finding_summary = parsed
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .unwrap_or(&fallback_finding_summary)
        .to_string();
    findings.push(
        Finding::new(
            finding_status,
            &format!("full-test-scan.{}", action.as_str()),
            finding_summary,
        )
        .with_details(json!({
            "helper": parsed,
            "output_tail": output_tail(&output.stdout, 120),
        })),
    );
    let artifacts = parsed_artifacts(parsed.as_ref())
        .unwrap_or_else(|| vec![artifact_dir.display().to_string()]);
    let summary = parsed
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "Full test scan {} command completed with exit code {exit_code}.",
                action.as_str()
            )
        });
    make_result(
        metadata(repo_root, &command_name, runner),
        summary,
        findings,
    )
    .with_artifacts(artifacts)
}

fn system_full_test_capability_findings(repo_root: &Path) -> Vec<Finding> {
    [
        (
            "ospd.capability-check",
            command_runtime_scanner_capability_check(repo_root),
        ),
        (
            "ospd.process-check",
            command_runtime_scanner_process_check(repo_root),
        ),
        (
            "nmap.capability-check",
            command_runtime_nmap_capability_check(repo_root),
        ),
    ]
    .into_iter()
    .map(|(check, result)| {
        Finding::new(&result.status, check, result.summary.clone()).with_details(json!({
            "status": result.status,
            "findings": result.findings,
        }))
    })
    .collect()
}

fn validated_full_test_target_cidr(value: &str) -> Result<String, String> {
    let candidate = value.trim();
    let Some((address_text, prefix_text)) = candidate.split_once('/') else {
        return Err("Full-test target must be a canonical CIDR: missing prefix length.".into());
    };
    if prefix_text.contains('/') {
        return Err("Full-test target must be a canonical CIDR: too many '/' separators.".into());
    }
    let address = address_text
        .parse::<IpAddr>()
        .map_err(|error| format!("Full-test target must be a canonical CIDR: {error}"))?;
    let prefix = prefix_text
        .parse::<u8>()
        .map_err(|error| format!("Full-test target must be a canonical CIDR: {error}"))?;
    let (canonical_address, address_count, unspecified, multicast) = match address {
        IpAddr::V4(address) => {
            if prefix > 32 {
                return Err(format!(
                    "Full-test target must be a canonical CIDR: IPv4 prefix {prefix} exceeds 32."
                ));
            }
            let value = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = value & mask;
            if network != value {
                return Err("Full-test target must be a canonical CIDR: host bits are set.".into());
            }
            let count = 1_u128 << (32 - prefix);
            let network_address = Ipv4Addr::from(network);
            (
                IpAddr::V4(network_address),
                count,
                // Match Python ipaddress.IPv4Network.is_unspecified: only a
                // one-address network whose sole address is unspecified.
                network_address.is_unspecified() && count == 1,
                network_address.is_multicast(),
            )
        }
        IpAddr::V6(address) => {
            if prefix > 128 {
                return Err(format!(
                    "Full-test target must be a canonical CIDR: IPv6 prefix {prefix} exceeds 128."
                ));
            }
            let value = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = value & mask;
            if network != value {
                return Err("Full-test target must be a canonical CIDR: host bits are set.".into());
            }
            let count = 1_u128
                .checked_shl((128 - prefix).into())
                .unwrap_or(u128::MAX);
            let network_address = Ipv6Addr::from(network);
            (
                IpAddr::V6(network_address),
                count,
                // Match Python ipaddress.IPv6Network.is_unspecified.
                network_address.is_unspecified() && count == 1,
                network_address.is_multicast(),
            )
        }
    };
    if unspecified || multicast {
        return Err("Full-test target must not be an unspecified or multicast network.".into());
    }
    if address_count > MAX_FULL_TEST_TARGET_ADDRESSES {
        return Err(format!(
            "Full-test target may contain at most {MAX_FULL_TEST_TARGET_ADDRESSES} addresses; got {address_count}."
        ));
    }
    Ok(format!("{canonical_address}/{prefix}"))
}

pub(crate) fn command_runtime_gmp_smoke_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    let socket_path = gvmd_socket_path(repo_root);
    let probe = repo_root.join("tools/runtime_gmp_smoke.py");
    let mut findings = vec![socket_readiness_finding(
        "gvmd.socket",
        "gvmd",
        &socket_path,
        "fail",
    )];
    let password = append_secret_prerequisite(
        repo_root,
        &secret_path,
        "Development admin secret is missing; run just runtime-manager-init.",
        &mut findings,
    );
    findings.push(file_prerequisite(
        repo_root,
        &probe,
        "gmp.probe",
        "GMP smoke probe exists.",
        "GMP smoke probe is missing.",
    ));
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "runtime-gmp-smoke", runner),
            "GMP smoke stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![runtime_dir(repo_root).display().to_string()]);
    }

    let output = run_probe(
        repo_root,
        runner,
        &probe,
        &[
            "--socket",
            &socket_path.display().to_string(),
            "--username",
            ADMIN_USER,
            "--password-file",
            &secret_path.display().to_string(),
        ],
        Duration::from_secs(60),
    );
    let redactions = password.into_iter().collect::<Vec<_>>();
    let mut parsed = parse_bounded_helper_output(&output);
    if let Some(value) = parsed.as_mut() {
        redact_json_value(value, &redactions);
    }
    let probe_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let exit_code = output.exit_code.unwrap_or(1);
    findings.push(
        Finding::new(
            if output.success && probe_status == Some("pass") {
                "pass"
            } else {
                "fail"
            },
            "gvmd.gmp",
            format!("Raw GMP socket authenticated get_version exit code {exit_code}."),
        )
        .with_details(json!({
            "probe": parsed,
            "output_tail": output_tail(&redact_text(&output.stdout, &redactions), 60),
        })),
    );
    make_result(
        metadata(repo_root, "runtime-gmp-smoke", runner),
        "Runtime GMP smoke completed.".into(),
        findings,
    )
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

fn command_runtime_rbac_smoke_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    let socket_path = gvmd_socket_path(repo_root);
    let probe = repo_root.join("tools/runtime_rbac_smoke.py");
    let artifact_dir = runtime_dir(repo_root).join("artifacts/rbac-smoke");
    let environment = build_env(repo_root);
    let base_url = gsad_urls_from_env(&environment)
        .into_iter()
        .next()
        .unwrap_or_else(|| "https://127.0.0.1:19392".to_string());
    let mut findings = vec![simple_socket_prerequisite(&socket_path)];
    let password = append_secret_prerequisite(
        repo_root,
        &secret_path,
        "Development admin secret is missing.",
        &mut findings,
    );
    findings.push(file_prerequisite(
        repo_root,
        &probe,
        "runtime-rbac.probe",
        "Runtime RBAC smoke helper exists.",
        "Runtime RBAC smoke helper is missing.",
    ));
    match prepare_artifact_dir(&artifact_dir) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "runtime-rbac.artifact-dir",
                "Runtime RBAC smoke artifact directory is ready.".into(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-rbac.artifact-dir",
                format!("Runtime RBAC smoke artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "runtime-rbac-smoke", runner),
            "Runtime RBAC smoke stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![artifact_dir.display().to_string()]);
    }

    let output = run_probe(
        repo_root,
        runner,
        &probe,
        &[
            "--socket",
            &socket_path.display().to_string(),
            "--username",
            ADMIN_USER,
            "--password-file",
            &secret_path.display().to_string(),
            "--base-url",
            &base_url,
            "--artifact-dir",
            &artifact_dir.display().to_string(),
        ],
        Duration::from_secs(180),
    );
    let redactions = password.into_iter().collect::<Vec<_>>();
    let mut parsed = parse_bounded_helper_output(&output);
    if let Some(value) = parsed.as_mut() {
        redact_json_value(value, &redactions);
    }
    let helper_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let finding_status = if output.success && matches!(helper_status, Some("pass" | "warn")) {
        helper_status.unwrap_or("fail")
    } else {
        "fail"
    };
    let exit_code = output.exit_code.unwrap_or(1);
    let summary = parsed
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("Runtime RBAC smoke completed with exit code {exit_code}."));
    findings.push(
        Finding::new(
            finding_status,
            "runtime-rbac.operator-account",
            summary.clone(),
        )
        .with_details(json!({
            "helper": parsed,
            "output_tail": output_tail(&redact_text(&output.stdout, &redactions), 120),
        })),
    );
    let artifacts = parsed_artifacts(parsed.as_ref())
        .unwrap_or_else(|| vec![artifact_dir.display().to_string()]);
    make_result(
        metadata(repo_root, "runtime-rbac-smoke", runner),
        summary,
        findings,
    )
    .with_artifacts(artifacts)
}

fn command_runtime_scope_smoke_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    const COMMAND: &str = "runtime-scope-smoke";
    const BROWSER_PROXY_SECRET_ENV: &str = "YAFVS_API_BROWSER_PROXY_SECRET";
    let probe = repo_root.join("tools/runtime_scope.py");
    let artifact_dir = runtime_dir(repo_root).join("artifacts/scope-reports");
    let (running, service_environment) = running_service_state(repo_root, runner, "yafvs-api");
    let browser_proxy_secret = service_environment
        .get(BROWSER_PROXY_SECRET_ENV)
        .is_some_and(|value| !value.trim().is_empty());
    let mut findings = vec![
        Finding::new(
            if running { "pass" } else { "fail" },
            "native-api.container",
            if running {
                "yafvs-api container is running."
            } else {
                "yafvs-api container is not running; start the app profile before reading scope reports through the native API."
            }
            .into(),
        ),
        Finding::new(
            if browser_proxy_secret { "pass" } else { "fail" },
            "native-api.browser-proxy-secret",
            if browser_proxy_secret {
                "yafvs-api browser-proxy secret is configured for native cleanup."
            } else {
                "yafvs-api is running without the browser-proxy secret; refresh the app profile before runtime scope cleanup."
            }
            .into(),
        ),
        file_prerequisite(
            repo_root,
            &probe,
            "runtime-scope.probe",
            "Runtime scope helper exists.",
            "Runtime scope helper is missing.",
        ),
    ];
    match prepare_artifact_dir(&artifact_dir) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "runtime-scope.artifact-dir",
                "Runtime scope artifact directory is ready.".into(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-scope.artifact-dir",
                format!("Runtime scope artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, COMMAND, runner),
            "Runtime scope command stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![artifact_dir.display().to_string()]);
    }

    let artifact_text = artifact_dir.display().to_string();
    let repo_text = repo_root.display().to_string();
    let output = run_probe_with_env(
        repo_root,
        runner,
        &probe,
        &[
            "smoke",
            "--username",
            ADMIN_USER,
            "--artifact-dir",
            &artifact_text,
            "--repo-root",
            &repo_text,
        ],
        Duration::from_secs(180),
        runtime_environment(repo_root),
    );
    let parsed = parse_bounded_helper_output(&output);
    let helper_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let finding_status = if output.success && matches!(helper_status, Some("pass" | "warn")) {
        helper_status.unwrap_or("fail")
    } else {
        "fail"
    };
    let exit_code = output.exit_code.unwrap_or(1);
    let summary = parsed
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!("Runtime scope smoke command completed with exit code {exit_code}.")
        });
    findings.push(
        Finding::new(finding_status, "runtime-scope.smoke", summary.clone()).with_details(json!({
            "helper": parsed,
            "output_tail": output_tail(&output.stdout, 120),
        })),
    );
    if let Some(proof) = runtime_scope_organization_proof_finding(parsed.as_ref()) {
        findings.push(proof);
    }
    let artifacts = parsed_artifacts(parsed.as_ref())
        .unwrap_or_else(|| vec![artifact_dir.display().to_string()]);
    make_result(metadata(repo_root, COMMAND, runner), summary, findings).with_artifacts(artifacts)
}

fn running_service_state(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    service: &str,
) -> (bool, std::collections::BTreeMap<String, String>) {
    let environment = runtime_environment(repo_root);
    let command = compose_command(
        repo_root,
        &["ps".to_string(), "-q".to_string(), service.to_string()],
    );
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(container) = runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(&environment),
            Some(Duration::from_secs(30)),
        )
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .map(str::to_string)
        })
        .filter(|container| !container.is_empty())
    else {
        return (false, std::collections::BTreeMap::new());
    };
    let running = runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &container],
            Some(repo_root),
            Some(&environment),
            Some(Duration::from_secs(30)),
        )
        .is_some_and(|output| output.success && output.stdout.trim() == "true");
    if !running {
        return (false, std::collections::BTreeMap::new());
    }
    let Some(output) = runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{json .Config.Env}}", &container],
            Some(repo_root),
            Some(&environment),
            Some(Duration::from_secs(30)),
        )
        .filter(|output| output.success && !output.stdout.trim().is_empty())
    else {
        return (true, std::collections::BTreeMap::new());
    };
    let Ok(values) = serde_json::from_str::<Vec<String>>(&output.stdout) else {
        return (true, std::collections::BTreeMap::new());
    };
    let values = values
        .into_iter()
        .filter_map(|value| {
            let (name, value) = value.split_once('=')?;
            Some((name.to_string(), value.to_string()))
        })
        .collect();
    (true, values)
}

fn runtime_scope_organization_proof_finding(parsed: Option<&Value>) -> Option<Finding> {
    let parsed = parsed?;
    if !matches!(
        parsed.get("status").and_then(Value::as_str),
        Some("pass" | "warn")
    ) {
        return None;
    }
    let details = parsed.get("details")?.as_object()?;
    let organization = details.get("organization_scope")?.as_object()?;
    let organization_report = details.get("organization_scope_report")?.as_object()?;
    let scope_after_add = details.get("scope_after_add")?.as_object()?;
    let scope_after_remove = details.get("scope_after_remove")?.as_object()?;
    let cleanup = details.get("cleanup")?.as_object()?;
    let proof = json!({
        "organization_target_count": organization.get("target_count"),
        "organization_host_count": organization.get("host_count"),
        "organization_source_report_count": organization_report.get("source_report_count"),
        "scope_after_add_target_count": scope_after_add.get("target_count"),
        "scope_after_add_host_count": scope_after_add.get("host_count"),
        "scope_after_remove_target_count": scope_after_remove.get("target_count"),
        "scope_after_remove_host_count": scope_after_remove.get("host_count"),
        "cleanup_scope": cleanup.get("scope"),
        "cleanup_scope_report": cleanup.get("scope_report"),
        "cleanup_organization_scope_report": cleanup.get("organization_scope_report"),
    });
    let complete = integer_at_least(&proof, "organization_target_count", 1)
        && integer_at_least(&proof, "organization_host_count", 1)
        && integer_at_least(&proof, "organization_source_report_count", 1)
        && integer_at_least(&proof, "scope_after_add_target_count", 2)
        && integer_at_least(&proof, "scope_after_add_host_count", 2)
        && integer_at_least(&proof, "scope_after_remove_target_count", 1)
        && integer_at_least(&proof, "scope_after_remove_host_count", 1)
        && proof.get("scope_after_remove_target_count")?.as_i64() == Some(1)
        && proof.get("scope_after_remove_host_count")?.as_i64() == Some(1)
        && [
            "cleanup_scope",
            "cleanup_scope_report",
            "cleanup_organization_scope_report",
        ]
        .iter()
        .all(|key| proof.get(key).and_then(Value::as_str) == Some("deleted"));
    Some(
        Finding::new(
            if complete { "pass" } else { "warn" },
            "runtime-scope.organization-proof",
            if complete {
                "Organization scope membership and source-report proof is available."
            } else {
                "Organization scope membership proof is incomplete; inspect the scope smoke artifact."
            }
            .into(),
        )
        .with_details(proof),
    )
}

fn integer_at_least(value: &Value, key: &str, minimum: i64) -> bool {
    value
        .get(key)
        .and_then(Value::as_i64)
        .is_some_and(|number| number >= minimum)
}

fn redact_json_value(value: &mut Value, secrets: &[String]) {
    match value {
        Value::String(text) => *text = redact_text(text, secrets),
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, secrets);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                redact_json_value(item, secrets);
            }
        }
        _ => {}
    }
}

fn gvmd_socket_path(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("run/gvmd-gmp/gvmd.sock")
}

fn append_secret_prerequisite(
    repo_root: &Path,
    path: &Path,
    missing_message: &str,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    match read_existing_runtime_secret(repo_root, ADMIN_SECRET) {
        Ok(Some(secret)) => {
            findings.push(
                Finding::new(
                    "pass",
                    "runtime.admin-secret",
                    "Development admin secret exists.".into(),
                )
                .with_path(&path.display().to_string()),
            );
            Some(secret)
        }
        Ok(None) => {
            findings.push(
                Finding::new("fail", "runtime.admin-secret", missing_message.into())
                    .with_path(&path.display().to_string()),
            );
            None
        }
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "runtime.admin-secret",
                    format!("Development admin secret is unsafe or unreadable: {error}"),
                )
                .with_path(&path.display().to_string()),
            );
            None
        }
    }
}

fn file_prerequisite(
    repo_root: &Path,
    path: &Path,
    check: &str,
    present: &str,
    missing: &str,
) -> Finding {
    let exists = path.is_file();
    let display = path
        .strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string();
    Finding::new(
        if exists { "pass" } else { "fail" },
        check,
        if exists {
            present.into()
        } else {
            missing.into()
        },
    )
    .with_path(&display)
}

fn simple_socket_prerequisite(path: &Path) -> Finding {
    let ready = fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket());
    Finding::new(
        if ready { "pass" } else { "fail" },
        "gvmd.socket",
        if ready {
            "gvmd socket is ready.".into()
        } else {
            "gvmd socket is not ready.".into()
        },
    )
    .with_path(&path.display().to_string())
}

pub(crate) fn socket_readiness_finding(
    check: &str,
    label: &str,
    path: &Path,
    missing_status: &str,
) -> Finding {
    let mut details = serde_json::Map::new();
    details.insert("path".into(), Value::String(path.display().to_string()));
    let (status, state, message) = match fs::metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            missing_status,
            "missing",
            format!("{label} socket is missing."),
        ),
        Err(error) => {
            append_socket_error(&mut details, &error);
            (
                "fail",
                "error",
                format!("{label} socket connection failed."),
            )
        }
        Ok(metadata) if !metadata.file_type().is_socket() => (
            "fail",
            "not-socket",
            format!("{label} path exists but is not a socket."),
        ),
        Ok(_) => match connect_unix_timeout(path, Duration::from_secs(1)) {
            Ok(()) => (
                "pass",
                "ready",
                format!("{label} socket accepts connections."),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                append_socket_error(&mut details, &error);
                (
                    "fail",
                    "stale",
                    format!("{label} socket path exists but no process is listening."),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                append_socket_error(&mut details, &error);
                (
                    "fail",
                    "timeout",
                    format!("{label} socket connection timed out."),
                )
            }
            Err(error) => {
                append_socket_error(&mut details, &error);
                (
                    "fail",
                    "error",
                    format!("{label} socket connection failed."),
                )
            }
        },
    };
    details.insert("state".into(), Value::String(state.into()));
    Finding::new(status, check, message)
        .with_path(&path.display().to_string())
        .with_details(json!({ "socket": details }))
}

fn connect_unix_timeout(path: &Path, timeout: Duration) -> io::Result<()> {
    let path_bytes = path.as_os_str().as_bytes();
    let path_capacity = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path);
    if path_bytes.is_empty()
        || path_bytes.contains(&0)
        || path_bytes.len().saturating_add(1) > path_capacity
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket path is empty, contains NUL, or is too long",
        ));
    }
    // SAFETY: socket has no pointer arguments and returns a new descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is a valid initialization for sockaddr_un before its family
    // and NUL-terminated path fields are populated.
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *destination = *source as libc::c_char;
    }
    let address_length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path_bytes.len() + 1)
        as libc::socklen_t;
    // SAFETY: address contains an initialized family and bounded,
    // NUL-terminated filesystem path; address_length covers those fields.
    let connected = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if connected == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN
    ) {
        return Err(error);
    }
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: descriptor points to one valid pollfd and timeout_ms is bounded.
    let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout_ms) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    if ready == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Unix socket connection timed out",
        ));
    }
    let mut socket_error: libc::c_int = 0;
    let mut socket_error_length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
    // SAFETY: the socket descriptor is valid and the output pointers refer to
    // correctly sized writable storage.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut socket_error).cast(),
            &raw mut socket_error_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if socket_error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(socket_error))
    }
}

fn append_socket_error(details: &mut serde_json::Map<String, Value>, error: &std::io::Error) {
    details.insert("error".into(), Value::String(python_style_error(error)));
    if let Some(errno) = error.raw_os_error() {
        details.insert("errno".into(), Value::from(errno));
    }
}

fn python_style_error(error: &std::io::Error) -> String {
    let Some(errno) = error.raw_os_error() else {
        return error.to_string();
    };
    let suffix = format!(" (os error {errno})");
    let rendered = error.to_string();
    let message = rendered
        .strip_suffix(&suffix)
        .unwrap_or(&rendered)
        .to_string();
    format!("[Errno {errno}] {message}")
}

fn prepare_artifact_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("path is not a real, current-user-owned directory".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())
}

fn run_probe(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    probe: &Path,
    arguments: &[&str],
    timeout: Duration,
) -> ProcessOutput {
    run_probe_with_env(
        repo_root,
        runner,
        probe,
        arguments,
        timeout,
        build_env(repo_root),
    )
}

fn run_probe_with_env(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    probe: &Path,
    arguments: &[&str],
    timeout: Duration,
    environment: std::collections::BTreeMap<OsString, OsString>,
) -> ProcessOutput {
    let python = executable_path("python3").unwrap_or_else(|| PathBuf::from("python3"));
    let mut owned = vec![probe.display().to_string()];
    owned.extend(arguments.iter().map(|argument| (*argument).to_string()));
    let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with(
            &python.display().to_string(),
            &refs,
            Some(repo_root),
            Some(&environment),
            Some(timeout),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: Some(127),
            stdout: String::new(),
            stderr: String::new(),
        })
}

fn parse_bounded_helper_output(output: &ProcessOutput) -> Option<Value> {
    (output.stdout.len() <= MAX_HELPER_OUTPUT_BYTES)
        .then(|| serde_json::from_str::<Value>(&output.stdout).ok())
        .flatten()
        .filter(Value::is_object)
}

fn parsed_artifacts(parsed: Option<&Value>) -> Option<Vec<String>> {
    let artifacts = parsed?.get("artifacts")?.as_array()?;
    let artifacts = artifacts
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()?;
    Some(artifacts.into_iter().map(str::to_string).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct ProbeRunner {
        output: Option<ProcessOutput>,
    }

    type CredentialInvocation = (Vec<String>, BTreeMap<OsString, OsString>, Duration);

    #[derive(Default)]
    struct CredentialRunner {
        calls: Mutex<Vec<CredentialInvocation>>,
    }

    impl CommandRunner for CredentialRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            _program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            env: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            let environment = env.cloned().unwrap_or_default();
            let password = environment
                .get(&OsString::from(
                    "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD",
                ))?
                .to_string_lossy()
                .into_owned();
            self.calls.lock().unwrap().push((
                args.iter().map(|arg| (*arg).to_string()).collect(),
                environment,
                timeout?,
            ));
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: format!(
                    "{{\"status\":\"pass\",\"summary\":\"{password}\",\"nested\":{{\"password\":\"{password}\"}}}}"
                ),
                stderr: String::new(),
            })
        }
    }

    #[derive(Default)]
    struct ScopeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        helper: Option<ProcessOutput>,
    }

    impl CommandRunner for ScopeRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program.to_string())
                    .chain(args.iter().map(|arg| (*arg).to_string()))
                    .collect(),
            );
            if program.ends_with("python3") {
                assert_eq!(timeout, Some(Duration::from_secs(180)));
                return self.helper.clone();
            }
            let stdout = if args.contains(&"{{.State.Running}}") {
                "true\n"
            } else if args.contains(&"{{json .Config.Env}}") {
                "[\"YAFVS_API_BROWSER_PROXY_SECRET=scope-secret\"]\n"
            } else {
                "scope-container\n"
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: stdout.into(),
                stderr: String::new(),
            })
        }
    }

    impl CommandRunner for ProbeRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            _args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            let _ = program;
            self.output.clone()
        }
    }

    #[test]
    fn credential_smoke_uses_secret_environment_and_redacts_result() {
        let (root, repo) = fixture("credential");
        prepare_secret(&repo, "admin-secret");
        fs::write(repo.join("tools/runtime_credential_smoke.py"), "# helper\n").unwrap();
        let runner = CredentialRunner::default();
        let result = command_runtime_credential_smoke_with(&repo, &runner, true, || {
            Ok((
                "yafvs-credential-smoke-001122aa".into(),
                "credential-secret-material-1234".into(),
            ))
        });
        assert_eq!(result.status, "pass");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|item| item.check.as_str())
                .collect::<Vec<_>>(),
            [
                "runtime.admin-secret",
                "credential-smoke.probe",
                "node.available",
                "credential-smoke.artifact-dir",
                "gsad.urls",
                "credential-smoke.run"
            ]
        );
        let calls = runner.calls.lock().unwrap();
        let (args, env, timeout) = &calls[0];
        let password = env
            .get(&OsString::from(
                "YAFVS_CREDENTIAL_SMOKE_CREDENTIAL_PASSWORD",
            ))
            .unwrap()
            .to_string_lossy();
        assert_eq!(*timeout, Duration::from_secs(300));
        assert_eq!(password, "credential-secret-material-1234");
        assert!(!args.iter().any(|arg| arg == &password));
        assert!(
            args.iter()
                .any(|arg| arg == "yafvs-credential-smoke-001122aa")
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(password.as_ref()));
        assert!(serialized.contains("[redacted]"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scope_smoke_stops_before_helper_when_runtime_is_missing() {
        let (root, repo) = fixture("scope-missing");
        fs::write(repo.join("tools/runtime_scope.py"), "# helper\n").unwrap();
        let result = command_runtime_scope_smoke_with(&repo, &ProbeRunner::default());
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime scope command stopped at prerequisites."
        );
        assert_eq!(
            result
                .findings
                .iter()
                .map(|item| item.check.as_str())
                .collect::<Vec<_>>(),
            [
                "native-api.container",
                "native-api.browser-proxy-secret",
                "runtime-scope.probe",
                "runtime-scope.artifact-dir",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scope_smoke_preserves_helper_contract_and_complete_proof() {
        let (root, repo) = fixture("scope-success");
        fs::write(repo.join("tools/runtime_scope.py"), "# helper\n").unwrap();
        let runner = ScopeRunner {
            helper: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: serde_json::to_string(&json!({
                    "status": "warn",
                    "summary": "scope coverage partial",
                    "artifacts": ["scope.json"],
                    "details": {
                        "organization_scope": {"target_count": 4, "host_count": 7},
                        "organization_scope_report": {"source_report_count": 4},
                        "scope_after_add": {"target_count": 2, "host_count": 2},
                        "scope_after_remove": {"target_count": 1, "host_count": 1},
                        "cleanup": {
                            "scope": "deleted",
                            "scope_report": "deleted",
                            "organization_scope_report": "deleted"
                        }
                    }
                }))
                .unwrap(),
                stderr: String::new(),
            }),
            ..ScopeRunner::default()
        };
        let result = command_runtime_scope_smoke_with(&repo, &runner);
        assert_eq!(result.status, "warn");
        assert_eq!(result.summary, "scope coverage partial");
        assert_eq!(result.artifacts, ["scope.json"]);
        assert_eq!(result.findings.last().unwrap().status, "pass");
        assert_eq!(
            result.findings.last().unwrap().check,
            "runtime-scope.organization-proof"
        );
        let calls = runner.calls.lock().unwrap();
        let python = calls
            .iter()
            .find(|call| call[0].ends_with("python3"))
            .unwrap();
        assert!(python.iter().any(|argument| argument == "smoke"));
        assert!(python.iter().any(|argument| argument == "--username"));
        assert!(python.iter().any(|argument| argument == ADMIN_USER));
        assert!(python.iter().any(|argument| argument == "--artifact-dir"));
        assert!(python.iter().any(|argument| argument == "--repo-root"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_scope_proof_warns_and_malformed_helper_fails_closed() {
        let proof = runtime_scope_organization_proof_finding(Some(&json!({
            "status": "pass",
            "details": {
                "organization_scope": {"target_count": 0, "host_count": 1},
                "organization_scope_report": {"source_report_count": 1},
                "scope_after_add": {"target_count": 2, "host_count": 2},
                "scope_after_remove": {"target_count": 1, "host_count": 1},
                "cleanup": {
                    "scope": "deleted",
                    "scope_report": "deleted",
                    "organization_scope_report": "deleted"
                }
            }
        })))
        .unwrap();
        assert_eq!(proof.status, "warn");
        let (root, repo) = fixture("scope-malformed");
        fs::write(repo.join("tools/runtime_scope.py"), "# helper\n").unwrap();
        let runner = ScopeRunner {
            helper: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "[]".into(),
                stderr: String::new(),
            }),
            ..ScopeRunner::default()
        };
        assert_eq!(
            command_runtime_scope_smoke_with(&repo, &runner).status,
            "fail"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gsad_urls_are_trimmed_deduplicated_and_prefer_plural() {
        let environment = BTreeMap::from([
            (
                OsString::from("YAFVS_GSAD_HOSTS"),
                OsString::from(" alpha, ,beta,alpha "),
            ),
            (OsString::from("YAFVS_GSAD_HOST"), OsString::from("ignored")),
        ]);
        assert_eq!(
            gsad_urls_from_env(&environment),
            ["https://alpha:19392", "https://beta:19392"]
        );
        assert_eq!(
            gsad_urls_from_env(&BTreeMap::new()),
            ["https://127.0.0.1:19392"]
        );
    }

    #[test]
    fn temporary_credential_material_has_exact_shapes() {
        let (name, password) = temporary_credential_material().unwrap();
        let suffix = name.strip_prefix("yafvs-credential-smoke-").unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(password.len(), 32);
        assert!(
            password
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
    }

    #[test]
    fn credential_smoke_entropy_failure_does_not_run_helper() {
        let (root, repo) = fixture("credential-entropy");
        prepare_secret(&repo, "admin-secret");
        fs::write(repo.join("tools/runtime_credential_smoke.py"), "# helper\n").unwrap();
        let runner = CredentialRunner::default();
        let result = command_runtime_credential_smoke_with(&repo, &runner, true, || {
            Err(io::Error::other("entropy unavailable"))
        });
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.findings.last().unwrap().check,
            "credential-smoke.run"
        );
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-probe-{}-{}-{name}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(repo.join("tools")).unwrap();
        (root, repo)
    }

    fn prepare_secret(repo: &Path, value: &str) {
        let path = runtime_secret_path(repo, ADMIN_SECRET);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, format!("{value}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn gmp_prerequisites_fail_without_running_helper() {
        let (root, repo) = fixture("gmp-missing");
        let result = command_runtime_gmp_smoke_with(&repo, &ProbeRunner::default());
        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "GMP smoke stopped at prerequisites.");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|item| item.check.as_str())
                .collect::<Vec<_>>(),
            ["gvmd.socket", "runtime.admin-secret", "gmp.probe"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gmp_success_preserves_helper_contract_and_redacts_output() {
        let (root, repo) = fixture("gmp-success");
        let socket = gvmd_socket_path(&repo);
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        prepare_secret(&repo, "long-runtime-secret");
        fs::write(repo.join("tools/runtime_gmp_smoke.py"), "# helper\n").unwrap();
        let runner = ProbeRunner {
            output: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "{\"status\":\"pass\",\"summary\":\"ok\",\"details\":{\"echo\":\"long-runtime-secret\"}}".into(),
                stderr: String::new(),
            }),
        };
        let result = command_runtime_gmp_smoke_with(&repo, &runner);
        assert_eq!(result.status, "pass");
        assert_eq!(result.findings.last().unwrap().check, "gvmd.gmp");
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("long-runtime-secret"));
        assert!(serialized.contains("[redacted]"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rbac_helper_warn_and_artifacts_are_preserved() {
        let (root, repo) = fixture("rbac-warn");
        let socket = gvmd_socket_path(&repo);
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        prepare_secret(&repo, "admin-secret");
        fs::write(repo.join("tools/runtime_rbac_smoke.py"), "# helper\n").unwrap();
        let runner = ProbeRunner {
            output: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "{\"status\":\"warn\",\"summary\":\"coverage partial\",\"artifacts\":[\"one.json\"]}".into(),
                stderr: String::new(),
            }),
        };
        let result = command_runtime_rbac_smoke_with(&repo, &runner);
        assert_eq!(result.status, "warn");
        assert_eq!(result.summary, "coverage partial");
        assert_eq!(result.artifacts, ["one.json"]);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|item| item.check.as_str())
                .collect::<Vec<_>>(),
            [
                "gvmd.socket",
                "runtime.admin-secret",
                "runtime-rbac.probe",
                "runtime-rbac.artifact-dir",
                "runtime-rbac.operator-account",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_secret_hardlink_stops_before_helper() {
        let (root, repo) = fixture("unsafe-secret");
        let socket = gvmd_socket_path(&repo);
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::write(repo.join("tools/runtime_rbac_smoke.py"), "# helper\n").unwrap();
        prepare_secret(&repo, "unsafe-secret");
        let secret = runtime_secret_path(&repo, ADMIN_SECRET);
        fs::hard_link(&secret, secret.with_extension("copy")).unwrap();
        let result = command_runtime_rbac_smoke_with(&repo, &ProbeRunner::default());
        assert_eq!(result.status, "fail");
        let secret_finding = result
            .findings
            .iter()
            .find(|item| item.check == "runtime.admin-secret")
            .unwrap();
        assert!(secret_finding.message.contains("unsafe or unreadable"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_or_malformed_helper_output_fails_closed() {
        let output = ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: "x".repeat(MAX_HELPER_OUTPUT_BYTES + 1),
            stderr: String::new(),
        };
        assert!(parse_bounded_helper_output(&output).is_none());
        let output = ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: "[]".into(),
            stderr: String::new(),
        };
        assert!(parse_bounded_helper_output(&output).is_none());
    }

    #[test]
    fn full_test_target_validation_is_canonical_bounded_and_dual_stack() {
        assert_eq!(
            validated_full_test_target_cidr(" 192.0.2.0/24 ").unwrap(),
            "192.0.2.0/24"
        );
        assert_eq!(
            validated_full_test_target_cidr("2001:0db8::/120").unwrap(),
            "2001:db8::/120"
        );
        assert_eq!(
            validated_full_test_target_cidr("0.0.0.0/31").unwrap(),
            "0.0.0.0/31"
        );
        assert_eq!(validated_full_test_target_cidr("::/120").unwrap(), "::/120");
        for (target, message) in [
            ("192.0.2.1/24", "canonical CIDR"),
            ("10.0.0.0/16", "at most 256"),
            ("2001:db8::/64", "at most 256"),
            ("0.0.0.0/32", "unspecified or multicast"),
            ("ff02::1/128", "unspecified or multicast"),
            ("missing-prefix", "canonical CIDR"),
        ] {
            let error = validated_full_test_target_cidr(target).unwrap_err();
            assert!(error.contains(message), "{target}: {error}");
        }
    }

    #[test]
    fn full_test_start_refuses_missing_or_mismatched_confirmation_first() {
        let (root, repo) = fixture("full-test-confirmation");
        let missing = command_runtime_full_test_scan_with(
            &repo,
            FullTestAction::Start,
            "192.0.2.0/24",
            None,
            &ProbeRunner::default(),
            |_| panic!("capability checks must not run"),
        );
        assert_eq!(missing.status, "fail");
        assert_eq!(missing.findings[0].check, "full-test-scan.confirmation");

        let mismatch = command_runtime_full_test_scan_with(
            &repo,
            FullTestAction::Start,
            "192.0.2.0/24",
            Some("192.0.2.1/32"),
            &ProbeRunner::default(),
            |_| panic!("capability checks must not run"),
        );
        assert_eq!(mismatch.status, "fail");
        assert_eq!(mismatch.findings[0].check, "full-test-scan.confirmation");
        assert!(mismatch.summary.contains("mismatched"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn full_test_preflight_stops_on_injected_capability_failure() {
        let (root, repo) = fixture("full-test-capability");
        fs::write(repo.join("tools/runtime_full_test_scan.py"), "# helper\n").unwrap();
        let result = command_runtime_full_test_scan_with(
            &repo,
            FullTestAction::Preflight,
            "192.0.2.0/24",
            None,
            &ProbeRunner::default(),
            |_| {
                vec![Finding::new(
                    "fail",
                    "ospd.capability-check",
                    "capability failed".into(),
                )]
            },
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Full test scan command stopped at prerequisites."
        );
        assert_eq!(
            result.findings.last().unwrap().check,
            "ospd.capability-check"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn full_test_status_preserves_helper_result_without_capability_checks() {
        let (root, repo) = fixture("full-test-status");
        fs::write(repo.join("tools/runtime_full_test_scan.py"), "# helper\n").unwrap();
        let runner = ProbeRunner {
            output: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "{\"status\":\"pass\",\"summary\":\"status collected\",\"artifacts\":[\"status.json\"],\"details\":{\"transport\":\"native\"}}".into(),
                stderr: String::new(),
            }),
        };
        let result = command_runtime_full_test_scan_with(
            &repo,
            FullTestAction::Status,
            "192.0.2.0/24",
            None,
            &runner,
            |_| panic!("status must not run capability checks"),
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.summary, "status collected");
        assert_eq!(result.artifacts, ["status.json"]);
        assert_eq!(
            result.findings.last().unwrap().check,
            "full-test-scan.status"
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(serialized.contains("native"));
        fs::remove_dir_all(root).unwrap();
    }
}
