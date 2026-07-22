// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Observational application-runtime smoke orchestration.

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_app_environment, runtime_environment};
use super::feed::command_feed_state;
use super::feed_generation::{query_ospd_vts_version_once, run_retained_native_api_smoke};
use super::native_runtime::native_api_get_json;
use super::runtime_certs::{runtime_certificate_findings, runtime_certificates_complete};
use super::runtime_feed_keyring::feed_keyring_fingerprint_finding;
use super::runtime_health::{container_running, pg_gvm_extension_finding};
use super::runtime_lock::{RuntimeLockStatus, inspect_runtime_lock};
use super::runtime_probe::{
    command_runtime_gmp_smoke_with, gsad_urls_from_env, socket_readiness_finding,
};
use super::runtime_scanner_capability::{
    command_runtime_nmap_capability_check_with, command_runtime_scanner_capability_check_with,
};
use super::runtime_scanner_process::command_runtime_scanner_process_check_with;
use super::runtime_scanner_register::{
    SCANNER_ID as OPENVAS_DEFAULT_SCANNER_ID, default_scanner_api_object_is_exact,
};
use super::secret::{read_existing_runtime_secret, runtime_secret_path};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

const ADMIN_SECRET: &str = "gvmd-admin-password";
const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];
const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const HTTPS_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FILE_LOG_BYTES: u64 = 1024 * 1024;
const MAX_COMPOSE_LOG_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_HTTPS_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct NestedCheck {
    status: String,
    summary: String,
    findings: Vec<Value>,
}

impl NestedCheck {
    fn from_result(result: ResultEnvelope) -> Self {
        let findings = serde_json::to_value(&result.findings)
            .ok()
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        Self {
            status: result.status,
            summary: result.summary,
            findings,
        }
    }
}

trait AppSmokeContext {
    fn manager_lock_finding(&mut self) -> Option<Finding>;
    fn feed_findings(&mut self) -> Vec<Finding>;
    fn certificate_findings(&mut self) -> (Vec<Finding>, bool);
    fn pg_gvm_finding(&mut self) -> Finding;
    fn admin_secret(&mut self) -> (Finding, String);
    fn keyring_finding(&mut self) -> Finding;
    fn service_running(&mut self, service: &str) -> bool;
    fn service_logs(&mut self, service: &str, lines: usize, secret: &str) -> Vec<String>;
    fn gvmd_socket_finding(&mut self) -> Finding;
    fn gmp_smoke(&mut self) -> NestedCheck;
    fn ospd_socket_finding(&mut self) -> Finding;
    fn ospd_vt_version(&mut self) -> Result<String, String>;
    fn scanner_capability(&mut self) -> NestedCheck;
    fn scanner_process(&mut self) -> NestedCheck;
    fn nmap_capability(&mut self) -> NestedCheck;
    fn notus_file_logs(&mut self, lines: usize, secret: &str) -> Vec<String>;
    fn scanner_listing(&mut self) -> Result<Value, String>;
    fn gsad_urls(&mut self) -> Vec<String>;
    fn https_headers(&mut self, url: &str) -> Option<ProcessOutput>;
    fn native_api_smoke(&mut self) -> Result<NestedCheck, String>;
}

struct SystemContext<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
    environment: BTreeMap<OsString, OsString>,
}

impl<'a> SystemContext<'a> {
    fn new(repo_root: &'a Path, runner: &'a dyn CommandRunner) -> Self {
        Self {
            repo_root,
            runner,
            environment: runtime_app_environment(repo_root)
                .unwrap_or_else(|_| runtime_environment(repo_root)),
        }
    }
}

impl AppSmokeContext for SystemContext<'_> {
    fn manager_lock_finding(&mut self) -> Option<Finding> {
        match inspect_runtime_lock(self.repo_root, "runtime-manager") {
            Ok(status) if status.active => Some(
                Finding::new(
                    "fail",
                    "runtime.manager-lock",
                    "A manager initialization or manager operation is active; app smoke would race transient state."
                        .into(),
                )
                .with_details(json!({"lock": runtime_lock_details(status)})),
            ),
            Ok(_) => None,
            Err(_) => Some(Finding::new(
                "fail",
                "runtime.manager-lock",
                "Manager operation lock status could not be inspected safely.".into(),
            )),
        }
    }

    fn feed_findings(&mut self) -> Vec<Finding> {
        command_feed_state(self.repo_root).findings
    }

    fn certificate_findings(&mut self) -> (Vec<Finding>, bool) {
        (
            runtime_certificate_findings(self.repo_root),
            runtime_certificates_complete(self.repo_root),
        )
    }

    fn pg_gvm_finding(&mut self) -> Finding {
        if !container_running(self.runner, self.repo_root, "postgres", &self.environment) {
            return Finding::new(
                "warn",
                "postgres.pg-gvm",
                "Postgres is not running; pg-gvm extension status is unavailable.".into(),
            );
        }
        pg_gvm_extension_finding(
            self.runner,
            self.repo_root,
            &self.environment,
            "yafvs",
            false,
        )
    }

    fn admin_secret(&mut self) -> (Finding, String) {
        let path = runtime_secret_path(self.repo_root, ADMIN_SECRET);
        match read_existing_runtime_secret(self.repo_root, ADMIN_SECRET) {
            Ok(Some(secret)) => (
                Finding::new(
                    "pass",
                    "runtime.admin-secret",
                    "Development admin secret exists.".into(),
                )
                .with_path(&path.display().to_string()),
                secret,
            ),
            Ok(None) => (
                Finding::new(
                    "warn",
                    "runtime.admin-secret",
                    "Development admin secret is missing; run just runtime-manager-init.".into(),
                )
                .with_path(&path.display().to_string()),
                String::new(),
            ),
            Err(_) => (
                Finding::new(
                    "warn",
                    "runtime.admin-secret",
                    "Development admin secret is unavailable or unsafe.".into(),
                )
                .with_path(&path.display().to_string()),
                String::new(),
            ),
        }
    }

    fn keyring_finding(&mut self) -> Finding {
        feed_keyring_fingerprint_finding(self.repo_root, self.runner)
    }

    fn service_running(&mut self, service: &str) -> bool {
        container_running(self.runner, self.repo_root, service, &self.environment)
    }

    fn service_logs(&mut self, service: &str, lines: usize, secret: &str) -> Vec<String> {
        run_compose(
            self.repo_root,
            self.runner,
            &self.environment,
            &[
                "logs".into(),
                "--tail".into(),
                lines.to_string(),
                service.into(),
            ],
            PROCESS_TIMEOUT,
        )
        .map(|output| redact_lines(output_tail(&output.stdout, lines), secret))
        .unwrap_or_default()
    }

    fn gvmd_socket_finding(&mut self) -> Finding {
        socket_readiness_finding(
            "gvmd.socket",
            "gvmd",
            &runtime_dir(self.repo_root).join("run/gvmd-gmp/gvmd.sock"),
            "warn",
        )
    }

    fn gmp_smoke(&mut self) -> NestedCheck {
        NestedCheck::from_result(command_runtime_gmp_smoke_with(self.repo_root, self.runner))
    }

    fn ospd_socket_finding(&mut self) -> Finding {
        socket_readiness_finding(
            "ospd.socket",
            "ospd-openvas",
            &runtime_dir(self.repo_root).join("run/ospd/ospd-openvas.sock"),
            "warn",
        )
    }

    fn ospd_vt_version(&mut self) -> Result<String, String> {
        query_ospd_vts_version_once(
            &runtime_dir(self.repo_root).join("run/ospd/ospd-openvas.sock"),
            Duration::from_secs(5),
        )
    }

    fn scanner_capability(&mut self) -> NestedCheck {
        NestedCheck::from_result(command_runtime_scanner_capability_check_with(
            self.repo_root,
            self.runner,
        ))
    }

    fn scanner_process(&mut self) -> NestedCheck {
        NestedCheck::from_result(command_runtime_scanner_process_check_with(
            self.repo_root,
            self.runner,
        ))
    }

    fn nmap_capability(&mut self) -> NestedCheck {
        NestedCheck::from_result(command_runtime_nmap_capability_check_with(
            self.repo_root,
            self.runner,
        ))
    }

    fn notus_file_logs(&mut self, lines: usize, secret: &str) -> Vec<String> {
        bounded_log_tail(
            &runtime_dir(self.repo_root).join("logs/notus/notus-scanner.log"),
            lines,
        )
        .map(|lines| redact_lines(lines, secret))
        .unwrap_or_default()
    }

    fn scanner_listing(&mut self) -> Result<Value, String> {
        let response = native_api_get_json(
            self.repo_root,
            "/api/v1/scanners?page=1&page_size=500&sort=name",
            self.runner,
        );
        if !response.usable_object() {
            return Err(response
                .error
                .unwrap_or_else(|| "native scanner collection request failed".into()));
        }
        response
            .parsed
            .ok_or_else(|| "native scanner collection response was unavailable".into())
    }

    fn gsad_urls(&mut self) -> Vec<String> {
        gsad_urls_from_env(&self.environment)
    }

    fn https_headers(&mut self, url: &str) -> Option<ProcessOutput> {
        self.runner.run_with_output_limit(
            "curl",
            &["-kIsS", "--max-time", "10", url],
            Some(self.repo_root),
            Some(&self.environment),
            Some(HTTPS_TIMEOUT),
            MAX_HTTPS_OUTPUT_BYTES,
        )
    }

    fn native_api_smoke(&mut self) -> Result<NestedCheck, String> {
        run_retained_native_api_smoke(self.repo_root, self.runner, &self.environment).map(
            |outcome| NestedCheck {
                status: outcome.status,
                summary: outcome.summary,
                findings: outcome.findings,
            },
        )
    }
}

pub fn command_runtime_app_smoke(repo_root: &Path) -> ResultEnvelope {
    let runner = SystemCommandRunner;
    let mut context = SystemContext::new(repo_root, &runner);
    command_with_context(repo_root, &runner, &mut context)
}

fn command_with_context(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    context: &mut dyn AppSmokeContext,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    if let Some(finding) = context.manager_lock_finding() {
        findings.push(finding);
    }
    findings.extend(context.feed_findings());
    let (certificate_findings, certificates_complete) = context.certificate_findings();
    findings.extend(certificate_findings);
    if !certificates_complete {
        findings.push(Finding::new(
            "fail",
            "runtime.cert.complete",
            "Runtime certificates are incomplete; run just runtime-certs-init.".into(),
        ));
    }
    findings.push(context.pg_gvm_finding());
    let (secret_finding, password) = context.admin_secret();
    findings.push(secret_finding);
    findings.push(context.keyring_finding());

    let mut running = BTreeMap::new();
    for service in APP_SERVICES {
        let is_running = context.service_running(service);
        let logs = if is_running {
            Vec::new()
        } else {
            context.service_logs(service, 80, &password)
        };
        findings.push(
            Finding::new(
                if is_running { "pass" } else { "warn" },
                "runtime.app.running",
                format!(
                    "{service} container is {}.",
                    if is_running { "running" } else { "not running" }
                ),
            )
            .with_details(json!({"service": service, "logs_tail": logs})),
        );
        running.insert(service, is_running);
    }

    let gvmd_socket = context.gvmd_socket_finding();
    let gvmd_ready = gvmd_socket.status == "pass";
    findings.push(gvmd_socket);
    if gvmd_ready && !password.is_empty() {
        findings.push(summarized(context.gmp_smoke(), "gvmd.gmp"));
    }

    let ospd_socket = context.ospd_socket_finding();
    let ospd_ready = ospd_socket.status == "pass";
    findings.push(ospd_socket);
    if running.get("ospd-openvas").copied().unwrap_or(false) {
        append_ospd_findings(context, &password, ospd_ready, &mut findings);
    }
    if running.get("notus-scanner").copied().unwrap_or(false) {
        append_notus_findings(context, &password, &mut findings);
    }
    if ospd_ready {
        append_scanner_findings(context, &mut findings);
    }
    for base_url in context.gsad_urls() {
        let url = format!("{}/", base_url.trim_end_matches('/'));
        let output = context.https_headers(&url);
        let exit_code = output
            .as_ref()
            .and_then(|output| output.exit_code)
            .unwrap_or(1);
        let tail = output
            .map(|output| redact_lines(output_tail(&output.stdout, 80), &password))
            .unwrap_or_default();
        findings.push(
            Finding::new(
                if exit_code == 0 { "pass" } else { "warn" },
                "gsad.https",
                format!("Configured HTTPS header probe exit code {exit_code}."),
            )
            .with_details(json!({"url": url, "output_tail": tail})),
        );
    }
    if running.get("yafvs-api").copied().unwrap_or(false) {
        findings.push(match context.native_api_smoke() {
            Ok(outcome) => summarized(outcome, "native-api.smoke"),
            Err(error) => Finding::new("fail", "native-api.smoke", error),
        });
    }

    make_result(
        metadata(repo_root, "runtime-app-smoke", runner),
        "Application runtime smoke checks completed.".into(),
        findings,
    )
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

fn append_ospd_findings(
    context: &mut dyn AppSmokeContext,
    password: &str,
    ospd_ready: bool,
    findings: &mut Vec<Finding>,
) {
    findings.push(summarized(
        context.scanner_capability(),
        "ospd.capability-check",
    ));
    findings.push(summarized(context.scanner_process(), "ospd.process-check"));
    findings.push(summarized(
        context.nmap_capability(),
        "nmap.capability-check",
    ));
    let logs = context.service_logs("ospd-openvas", 120, password);
    let errors = logs
        .iter()
        .filter(|line| line.contains("ERROR"))
        .cloned()
        .collect::<Vec<_>>();
    let feed_errors = feed_signature_log_errors(&logs);
    let known_feed_gap = errors
        .iter()
        .any(|line| line.contains("failed to load VTs") || line.contains("Updating VTs failed"));
    findings.push(
        Finding::new(
            if errors.is_empty() { "pass" } else { "warn" },
            "ospd.logs",
            if errors.is_empty() {
                "ospd-openvas logs contain no ERROR lines in the inspected tail."
            } else if known_feed_gap {
                "ospd-openvas logs contain errors; current known blocker is missing feed/plugin cache."
            } else {
                "ospd-openvas logs contain errors that require investigation."
            }
            .into(),
        )
        .with_details(json!({
            "known_deferred_feed_state": known_feed_gap,
            "error_tail": tail_values(&errors, 20),
        })),
    );
    findings.push(
        Finding::new(
            if feed_errors.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "ospd.feed-signature-logs",
            if feed_errors.is_empty() {
                "ospd-openvas logs contain no feed signature or Notus advisory load errors in the inspected tail."
            } else {
                "ospd-openvas logs contain feed signature or Notus advisory load errors."
            }
            .into(),
        )
        .with_details(json!({"error_tail": tail_values(&feed_errors, 20)})),
    );
    let live_version = ospd_ready
        .then(|| context.ospd_vt_version())
        .and_then(Result::ok);
    let (vt_status, vt_lines, vt_version) = match live_version {
        Some(version) => (VtStatus::Pass, Vec::new(), Some(version)),
        _ => {
            let (status, lines) = ospd_vt_load_status(&logs);
            (status, lines, None)
        }
    };
    findings.push(
        Finding::new(
            match vt_status {
                VtStatus::Pass => "pass",
                VtStatus::Fail => "fail",
                VtStatus::Wait => "warn",
            },
            "ospd.vt-load",
            match vt_status {
                VtStatus::Pass => "ospd-openvas reports VTs are loaded.",
                VtStatus::Fail => "ospd-openvas VT loading failed.",
                VtStatus::Wait => "ospd-openvas is still loading VTs.",
            }
            .into(),
        )
        .with_details(json!({
            "status": vt_status.as_str(),
            "version": vt_version,
            "log_lines": tail_values(&vt_lines, 20),
        })),
    );
}

fn append_notus_findings(
    context: &mut dyn AppSmokeContext,
    password: &str,
    findings: &mut Vec<Finding>,
) {
    let mut logs = context.service_logs("notus-scanner", 120, password);
    logs.extend(context.notus_file_logs(120, password));
    let errors = logs
        .iter()
        .filter(|line| line.contains("ERROR") || line.contains("CRITICAL"))
        .cloned()
        .collect::<Vec<_>>();
    let feed_errors = feed_signature_log_errors(&logs);
    findings.push(
        Finding::new(
            if errors.is_empty() { "pass" } else { "fail" },
            "notus.logs",
            if errors.is_empty() {
                "notus-scanner logs contain no ERROR/CRITICAL lines in the inspected tail."
            } else {
                "notus-scanner logs contain ERROR/CRITICAL lines."
            }
            .into(),
        )
        .with_details(json!({"error_tail": tail_values(&errors, 20)})),
    );
    findings.push(
        Finding::new(
            if feed_errors.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "notus.feed-signature-logs",
            if feed_errors.is_empty() {
                "notus-scanner logs contain no GPG, signature, or advisory-load errors in the inspected tail."
            } else {
                "notus-scanner logs contain GPG, signature, or advisory-load errors."
            }
            .into(),
        )
        .with_details(json!({"error_tail": tail_values(&feed_errors, 20)})),
    );
}

fn append_scanner_findings(context: &mut dyn AppSmokeContext, findings: &mut Vec<Finding>) {
    let listing = context.scanner_listing();
    let items = listing
        .as_ref()
        .ok()
        .and_then(Value::as_object)
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array);
    findings.push(
        Finding::new(
            if items.is_some() { "pass" } else { "warn" },
            "native.scanners",
            if items.is_some() {
                "Native scanner collection is readable."
            } else {
                "Native scanner collection is unavailable or malformed."
            }
            .into(),
        )
        .with_details(json!({
            "item_count": items.map(Vec::len),
            "error": listing.as_ref().err(),
        })),
    );
    let scanner = items
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find(|object| {
            object.get("id").and_then(Value::as_str) == Some(OPENVAS_DEFAULT_SCANNER_ID)
        });
    let exact = scanner.is_some_and(default_scanner_api_object_is_exact);
    findings.push(
        Finding::new(
            if exact { "pass" } else { "warn" },
            "native.scanner.openvas-default",
            if exact {
                "OpenVAS Default scanner has the supported fixed native configuration."
            } else {
                "OpenVAS Default scanner is absent or its supported native configuration has drifted."
            }
            .into(),
        )
        .with_details(json!({"scanner_id": scanner.and_then(|object| object.get("id"))})),
    );
}

fn summarized(result: NestedCheck, check: &str) -> Finding {
    Finding::new(&result.status, check, result.summary)
        .with_details(json!({"status": result.status, "findings": result.findings}))
}

fn runtime_lock_details(status: RuntimeLockStatus) -> Value {
    json!({
        "name": status.name,
        "active": status.active,
        "path": status.path.display().to_string(),
        "metadata_path": status.metadata_path.display().to_string(),
        "metadata": status.metadata,
    })
}

fn run_compose(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    arguments: &[String],
    timeout: Duration,
) -> Option<ProcessOutput> {
    let command = compose_command(repo_root, arguments);
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with_output_limit(
        "docker",
        &arguments,
        Some(repo_root),
        Some(environment),
        Some(timeout),
        MAX_COMPOSE_LOG_OUTPUT_BYTES,
    )
}

#[cfg(test)]
fn redact_process(mut output: ProcessOutput, secret: &str) -> ProcessOutput {
    if !secret.is_empty() {
        output.stdout = output.stdout.replace(secret, "[REDACTED]");
        output.stderr = output.stderr.replace(secret, "[REDACTED]");
    }
    output
}

fn redact_lines(lines: Vec<String>, secret: &str) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| {
            if secret.is_empty() {
                line
            } else {
                line.replace(secret, "[REDACTED]")
            }
        })
        .collect()
}

fn bounded_log_tail(path: &Path, lines: usize) -> Option<Vec<String>> {
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.file_type().is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.len() > MAX_FILE_LOG_BYTES
    {
        return None;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let opened = file.metadata().ok()?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return None;
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize + 1);
    file.by_ref()
        .take(MAX_FILE_LOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_FILE_LOG_BYTES {
        return None;
    }
    let after = file.metadata().ok()?;
    if after.dev() != opened.dev() || after.ino() != opened.ino() {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    let all = text.lines().map(str::to_owned).collect::<Vec<_>>();
    Some(tail_values(&all, lines))
}

fn feed_signature_log_errors(lines: &[String]) -> Vec<String> {
    const MARKERS: [&str; 5] = ["gpg", "signature", "sha256", "advisories", "notus"];
    const ERRORS: [&str; 5] = ["error", "failed", "failure", "invalid", "not loaded"];
    lines
        .iter()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            MARKERS.iter().any(|marker| lower.contains(marker))
                && ERRORS.iter().any(|word| lower.contains(word))
        })
        .cloned()
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VtStatus {
    Pass,
    Fail,
    Wait,
}

impl VtStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Wait => "wait",
        }
    }
}

fn ospd_vt_load_status(lines: &[String]) -> (VtStatus, Vec<String>) {
    let mut relevant = Vec::new();
    for line in lines {
        if line.contains("Finished loading VTs") || line.contains("VTs were up to date") {
            relevant.push(line.clone());
            return (VtStatus::Pass, relevant);
        }
        if line.contains("Updating VTs failed")
            || line.contains("failed to load VTs")
            || line.contains("OpenVAS Scanner failed to load VTs")
        {
            relevant.push(line.clone());
            return (VtStatus::Fail, relevant);
        }
        if line.contains("Loading VTs") {
            relevant.push(line.clone());
        }
    }
    (VtStatus::Wait, relevant)
}

fn tail_values(values: &[String], maximum: usize) -> Vec<String> {
    values[values.len().saturating_sub(maximum)..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct NoopRunner;

    impl CommandRunner for NoopRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }
    }

    struct MockContext {
        manager_active: bool,
        certs_complete: bool,
        secret: String,
        running: BTreeMap<&'static str, bool>,
        gvmd_socket_status: &'static str,
        ospd_socket_status: &'static str,
        ospd_vt_version: Result<String, String>,
        ospd_logs: Vec<String>,
        notus_logs: Vec<String>,
        notus_file_logs: Vec<String>,
        scanner_listing: Result<Value, String>,
        gsad_urls: Vec<String>,
        native_running_result: Result<NestedCheck, String>,
        calls: Vec<String>,
    }

    impl Default for MockContext {
        fn default() -> Self {
            Self {
                manager_active: false,
                certs_complete: false,
                secret: String::new(),
                running: BTreeMap::new(),
                gvmd_socket_status: "warn",
                ospd_socket_status: "warn",
                ospd_vt_version: Err("unavailable".into()),
                ospd_logs: Vec::new(),
                notus_logs: Vec::new(),
                notus_file_logs: Vec::new(),
                scanner_listing: Err("unavailable".into()),
                gsad_urls: Vec::new(),
                native_running_result: Ok(nested("pass", "native API passed")),
                calls: Vec::new(),
            }
        }
    }

    impl AppSmokeContext for MockContext {
        fn manager_lock_finding(&mut self) -> Option<Finding> {
            self.calls.push("manager-lock".into());
            self.manager_active.then(|| {
                Finding::new(
                    "fail",
                    "runtime.manager-lock",
                    "manager operation active".into(),
                )
            })
        }

        fn feed_findings(&mut self) -> Vec<Finding> {
            self.calls.push("feed".into());
            vec![Finding::new("warn", "feed.current", "feed missing".into())]
        }

        fn certificate_findings(&mut self) -> (Vec<Finding>, bool) {
            self.calls.push("certificates".into());
            (
                vec![Finding::new(
                    if self.certs_complete { "pass" } else { "warn" },
                    "runtime.cert.ca-cert",
                    "certificate state".into(),
                )],
                self.certs_complete,
            )
        }

        fn pg_gvm_finding(&mut self) -> Finding {
            self.calls.push("pg-gvm".into());
            Finding::new("warn", "postgres.pg-gvm", "pg-gvm missing".into())
        }

        fn admin_secret(&mut self) -> (Finding, String) {
            self.calls.push("admin-secret".into());
            (
                Finding::new(
                    if self.secret.is_empty() {
                        "warn"
                    } else {
                        "pass"
                    },
                    "runtime.admin-secret",
                    "secret state".into(),
                ),
                self.secret.clone(),
            )
        }

        fn keyring_finding(&mut self) -> Finding {
            self.calls.push("keyring".into());
            Finding::new("fail", "feed-keyring.fingerprint", "keyring missing".into())
        }

        fn service_running(&mut self, service: &str) -> bool {
            self.calls.push(format!("running:{service}"));
            self.running.get(service).copied().unwrap_or(false)
        }

        fn service_logs(&mut self, service: &str, _lines: usize, _secret: &str) -> Vec<String> {
            self.calls.push(format!("logs:{service}"));
            match service {
                "ospd-openvas" => self.ospd_logs.clone(),
                "notus-scanner" => self.notus_logs.clone(),
                _ => vec!["stopped".into()],
            }
        }

        fn gvmd_socket_finding(&mut self) -> Finding {
            self.calls.push("gvmd-socket".into());
            Finding::new(
                self.gvmd_socket_status,
                "gvmd.socket",
                "socket state".into(),
            )
        }

        fn gmp_smoke(&mut self) -> NestedCheck {
            self.calls.push("gmp".into());
            nested("pass", "GMP passed")
        }

        fn ospd_socket_finding(&mut self) -> Finding {
            self.calls.push("ospd-socket".into());
            Finding::new(
                self.ospd_socket_status,
                "ospd.socket",
                "socket state".into(),
            )
        }

        fn ospd_vt_version(&mut self) -> Result<String, String> {
            self.calls.push("ospd-vt-version".into());
            self.ospd_vt_version.clone()
        }

        fn scanner_capability(&mut self) -> NestedCheck {
            self.calls.push("scanner-capability".into());
            nested("pass", "scanner capability passed")
        }

        fn scanner_process(&mut self) -> NestedCheck {
            self.calls.push("scanner-process".into());
            nested("pass", "scanner process passed")
        }

        fn nmap_capability(&mut self) -> NestedCheck {
            self.calls.push("nmap-capability".into());
            nested("pass", "nmap capability passed")
        }

        fn notus_file_logs(&mut self, _lines: usize, _secret: &str) -> Vec<String> {
            self.calls.push("notus-file-logs".into());
            self.notus_file_logs.clone()
        }

        fn scanner_listing(&mut self) -> Result<Value, String> {
            self.calls.push("scanner-listing".into());
            self.scanner_listing.clone()
        }

        fn gsad_urls(&mut self) -> Vec<String> {
            self.calls.push("gsad-urls".into());
            self.gsad_urls.clone()
        }

        fn https_headers(&mut self, url: &str) -> Option<ProcessOutput> {
            self.calls.push(format!("https:{url}"));
            Some(process(true, "HTTP/1.1 200 OK"))
        }

        fn native_api_smoke(&mut self) -> Result<NestedCheck, String> {
            self.calls.push("native-api".into());
            self.native_running_result.clone()
        }
    }

    fn nested(status: &str, summary: &str) -> NestedCheck {
        NestedCheck {
            status: status.into(),
            summary: summary.into(),
            findings: vec![json!({
                "status": status,
                "check": "nested.check",
                "message": summary,
            })],
        }
    }

    fn process(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn repo() -> PathBuf {
        std::env::temp_dir().join(format!(
            "yafvsctl-runtime-app-smoke-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn checks(result: &ResultEnvelope) -> Vec<&str> {
        result
            .findings
            .iter()
            .map(|finding| finding.check.as_str())
            .collect()
    }

    #[test]
    fn incomplete_state_preserves_order_and_suppresses_dependent_probes() {
        let repo = repo();
        let mut context = MockContext {
            manager_active: true,
            ..Default::default()
        };
        let result = command_with_context(&repo, &NoopRunner, &mut context);
        assert_eq!(result.status, "fail");
        assert_eq!(
            checks(&result),
            vec![
                "runtime.manager-lock",
                "feed.current",
                "runtime.cert.ca-cert",
                "runtime.cert.complete",
                "postgres.pg-gvm",
                "runtime.admin-secret",
                "feed-keyring.fingerprint",
                "runtime.app.running",
                "runtime.app.running",
                "runtime.app.running",
                "runtime.app.running",
                "runtime.app.running",
                "gvmd.socket",
                "ospd.socket",
            ]
        );
        assert_eq!(
            result.findings[7..12]
                .iter()
                .map(|finding| finding.details.as_ref().unwrap()["service"]
                    .as_str()
                    .unwrap())
                .collect::<Vec<_>>(),
            APP_SERVICES
        );
        for skipped in [
            "gmp",
            "scanner-capability",
            "scanner-process",
            "nmap-capability",
            "scanner-listing",
            "native-api",
        ] {
            assert!(!context.calls.iter().any(|call| call == skipped));
        }
        assert_eq!(result.metadata.command, "runtime-app-smoke");
        assert_eq!(
            result.artifacts,
            vec![runtime_dir(&repo).display().to_string()]
        );
    }

    #[test]
    fn full_path_preserves_nested_order_and_registration_identity() {
        let repo = repo();
        let mut context = MockContext {
            certs_complete: true,
            secret: "sensitive-password".into(),
            running: APP_SERVICES
                .into_iter()
                .map(|service| (service, true))
                .collect(),
            gvmd_socket_status: "pass",
            ospd_socket_status: "pass",
            ospd_vt_version: Ok("202607200000".into()),
            ospd_logs: vec!["Loading VTs".into(), "Finished loading VTs".into()],
            scanner_listing: Ok(json!({
                "items": [{
                    "id": OPENVAS_DEFAULT_SCANNER_ID,
                    "name": "OpenVAS Default",
                    "comment": "",
                    "host": "/runtime/run/ospd/ospd-openvas.sock",
                    "port": 0,
                    "scanner_type": 2,
                    "relay_host": null,
                    "relay_port": 0
                }],
                "page": {"total": 1}
            })),
            gsad_urls: vec!["https://127.0.0.1:19392".into()],
            ..Default::default()
        };
        let result = command_with_context(&repo, &NoopRunner, &mut context);
        assert_eq!(
            checks(&result),
            vec![
                "feed.current",
                "runtime.cert.ca-cert",
                "postgres.pg-gvm",
                "runtime.admin-secret",
                "feed-keyring.fingerprint",
                "runtime.app.running",
                "runtime.app.running",
                "runtime.app.running",
                "runtime.app.running",
                "runtime.app.running",
                "gvmd.socket",
                "gvmd.gmp",
                "ospd.socket",
                "ospd.capability-check",
                "ospd.process-check",
                "nmap.capability-check",
                "ospd.logs",
                "ospd.feed-signature-logs",
                "ospd.vt-load",
                "notus.logs",
                "notus.feed-signature-logs",
                "native.scanners",
                "native.scanner.openvas-default",
                "gsad.https",
                "native-api.smoke",
            ]
        );
        let registration = result
            .findings
            .iter()
            .find(|finding| finding.check == "native.scanner.openvas-default")
            .unwrap();
        assert_eq!(registration.status, "pass");
        assert_eq!(
            registration.details.as_ref().unwrap()["scanner_id"],
            OPENVAS_DEFAULT_SCANNER_ID
        );
        let vt = result
            .findings
            .iter()
            .find(|finding| finding.check == "ospd.vt-load")
            .unwrap();
        assert_eq!(vt.status, "pass");
        assert_eq!(vt.details.as_ref().unwrap()["version"], "202607200000");
    }

    #[test]
    fn empty_secret_suppresses_gmp_even_when_gvmd_socket_is_ready() {
        let repo = repo();
        let mut context = MockContext {
            gvmd_socket_status: "pass",
            ..Default::default()
        };
        command_with_context(&repo, &NoopRunner, &mut context);
        assert!(!context.calls.iter().any(|call| call == "gmp"));
    }

    #[test]
    fn log_classification_requires_error_meaning_and_preserves_vt_state() {
        let benign = vec!["GPG signature verification started".into()];
        assert!(feed_signature_log_errors(&benign).is_empty());
        let failure = vec!["GPG signature verification failed".into()];
        assert_eq!(feed_signature_log_errors(&failure), failure);
        assert_eq!(
            ospd_vt_load_status(&["Loading VTs".into(), "Finished loading VTs".into()]).0,
            VtStatus::Pass
        );
        assert_eq!(
            ospd_vt_load_status(&["Loading VTs".into(), "Updating VTs failed".into()]).0,
            VtStatus::Fail
        );
        assert_eq!(ospd_vt_load_status(&[]).0, VtStatus::Wait);
    }

    #[test]
    fn redaction_removes_secret_from_lines_and_process_output() {
        assert_eq!(
            redact_lines(vec!["before hidden after".into()], "hidden"),
            vec!["before [REDACTED] after"]
        );
        let output = redact_process(
            ProcessOutput {
                success: false,
                exit_code: Some(1),
                stdout: "hidden stdout".into(),
                stderr: "hidden stderr".into(),
            },
            "hidden",
        );
        assert!(!format!("{}{}", output.stdout, output.stderr).contains("hidden"));
    }

    #[test]
    fn bounded_file_log_refuses_links_and_oversized_inputs() {
        let root = repo();
        std::fs::create_dir_all(&root).unwrap();
        let log = root.join("notus.log");
        std::fs::write(&log, "first\nsecond\nthird\n").unwrap();
        assert_eq!(bounded_log_tail(&log, 2).unwrap(), vec!["second", "third"]);

        let link = root.join("linked.log");
        std::os::unix::fs::symlink(&log, &link).unwrap();
        assert!(bounded_log_tail(&link, 2).is_none());

        let oversized = root.join("oversized.log");
        std::fs::write(&oversized, vec![b'x'; MAX_FILE_LOG_BYTES as usize + 1]).unwrap();
        assert!(bounded_log_tail(&oversized, 2).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}
