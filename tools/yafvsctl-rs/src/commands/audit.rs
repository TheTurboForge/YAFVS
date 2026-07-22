// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, executable_path, metadata, output_tail};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

const NATIVE_API_CRATE: &str = "services/yafvs-api";
const NATIVE_API_LOCKFILE: &str = "services/yafvs-api/Cargo.lock";
const GSA_COMPONENT: &str = "components/gsa";
const GSA_LOCKFILE: &str = "components/gsa/package-lock.json";
const NATIVE_API_SEMGREP_CONFIG: &str = "policy/semgrep-native-api.yml";
const NATIVE_API_SOURCE: &str = "services/yafvs-api/src";
const OSV_LOCKFILES: [&str; 4] = [
    NATIVE_API_LOCKFILE,
    "tools/yafvsctl-rs/Cargo.lock",
    "components/openvas-scanner/rust/Cargo.lock",
    GSA_LOCKFILE,
];

pub fn command_native_api_cargo_audit(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_native_api_cargo_audit_with(
        repo_root,
        status_only,
        executable_path("cargo-audit").is_some(),
        &SystemCommandRunner,
    )
}

pub fn command_osv_lockfile_audit(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_osv_lockfile_audit_with(
        repo_root,
        status_only,
        executable_path("osv-scanner").is_some(),
        &SystemCommandRunner,
    )
}

fn command_osv_lockfile_audit_with(
    repo_root: &Path,
    status_only: bool,
    tool_available: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifacts = OSV_LOCKFILES
        .iter()
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    let missing = OSV_LOCKFILES
        .iter()
        .filter(|path| !repo_root.join(path).is_file())
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    let mut findings = vec![
        Finding::new(
            if missing.is_empty() { "pass" } else { "fail" },
            "osv-lockfile-audit.lockfiles",
            if missing.is_empty() {
                "Expected lockfiles exist.".to_string()
            } else {
                "One or more expected lockfiles are missing.".to_string()
            },
        )
        .with_details(json!({
            "missing": missing,
            "lockfile_count": OSV_LOCKFILES.len(),
        })),
    ];
    if !tool_available {
        findings.push(Finding::new(
            "warn",
            "osv-lockfile-audit.tool",
            "osv-scanner is not installed; OSV lockfile audit was skipped.".to_string(),
        ));
        return osv_audit_result(
            repo_root,
            "OSV lockfile audit could not run because osv-scanner is unavailable.",
            findings,
            artifacts,
            None,
            status_only,
            runner,
        );
    }
    if !missing.is_empty() {
        return osv_audit_result(
            repo_root,
            "OSV lockfile audit could not run because required lockfiles are missing.",
            findings,
            artifacts,
            None,
            status_only,
            runner,
        );
    }

    let mut arguments = vec!["scan", "source", "--format", "json", "--verbosity", "error"];
    for lockfile in OSV_LOCKFILES {
        arguments.extend(["--lockfile", lockfile]);
    }
    let Some(audit) = runner.run_with(
        "osv-scanner",
        &arguments,
        Some(repo_root),
        None,
        Some(Duration::from_secs(120)),
    ) else {
        findings.push(Finding::new(
            "fail",
            "osv-lockfile-audit.parse",
            "osv-scanner did not emit parseable JSON.".to_string(),
        ));
        return osv_audit_result(
            repo_root,
            "OSV lockfile audit failed before results could be parsed.",
            findings,
            artifacts,
            None,
            status_only,
            runner,
        );
    };
    let payload = match serde_json::from_str::<Value>(&audit.stdout) {
        Ok(payload) => payload,
        Err(_) => {
            findings.push(
                Finding::new(
                    "fail",
                    "osv-lockfile-audit.parse",
                    "osv-scanner did not emit parseable JSON.".to_string(),
                )
                .with_details(json!({
                    "returncode": audit.exit_code,
                    "output_tail": output_tail(&audit.stdout, 40),
                })),
            );
            return osv_audit_result(
                repo_root,
                "OSV lockfile audit failed before results could be parsed.",
                findings,
                artifacts,
                None,
                status_only,
                runner,
            );
        }
    };
    let summary = summarize_osv_payload(&payload, repo_root);
    findings.extend([
        Finding::new(
            "pass",
            "osv-lockfile-audit.tool",
            "osv-scanner is installed and runnable.".to_string(),
        ),
        Finding::new(
            if summary.high_or_critical_count == 0 {
                "pass"
            } else {
                "fail"
            },
            "osv-lockfile-audit.high-critical",
            format!(
                "OSV reported {} high/critical lockfile vulnerabilit(y/ies).",
                summary.high_or_critical_count
            ),
        )
        .with_details(json!({
            "high_or_critical_count": summary.high_or_critical_count,
        })),
        if summary.vulnerability_count > 0 && summary.high_or_critical_count == 0 {
            Finding::new(
                "warn",
                "osv-lockfile-audit.vulnerabilities",
                format!(
                    "OSV reported {} lower-severity lockfile vulnerabilit(y/ies).",
                    summary.vulnerability_count
                ),
            )
            .with_details(json!({
                "vulnerability_count": summary.vulnerability_count,
                "top_findings": summary.top_findings,
            }))
        } else {
            Finding::new(
                "pass",
                "osv-lockfile-audit.vulnerabilities",
                format!(
                    "OSV reported {} total lockfile vulnerabilit(y/ies).",
                    summary.vulnerability_count
                ),
            )
            .with_details(json!({
                "vulnerability_count": summary.vulnerability_count,
            }))
        },
    ]);
    if audit.exit_code != Some(0) && summary.vulnerability_count == 0 {
        findings.push(
            Finding::new(
                "warn",
                "osv-lockfile-audit.exit-code",
                format!(
                    "osv-scanner exited {} without parsed vulnerabilities.",
                    display_exit_code(audit.exit_code)
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&audit.stdout, 40) })),
        );
    }
    let details = json!({
        "lockfile_count": OSV_LOCKFILES.len(),
        "vulnerable_package_count": summary.vulnerable_package_count,
        "vulnerability_count": summary.vulnerability_count,
        "high_or_critical_count": summary.high_or_critical_count,
        "returncode": audit.exit_code,
        "top_findings": summary.top_findings,
    });
    osv_audit_result(
        repo_root,
        "OSV lockfile audit completed.",
        findings,
        artifacts,
        Some(details),
        status_only,
        runner,
    )
}

pub fn command_native_api_semgrep_audit(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_native_api_semgrep_audit_with(
        repo_root,
        status_only,
        executable_path("semgrep").is_some(),
        &SystemCommandRunner,
    )
}

fn osv_audit_result(
    repo_root: &Path,
    summary: &str,
    findings: Vec<Finding>,
    artifacts: Vec<String>,
    details: Option<Value>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut result = make_result(
        metadata(repo_root, "osv-lockfile-audit", runner),
        summary.to_string(),
        findings,
    )
    .with_artifacts(artifacts);
    if let Some(details) = details {
        result.details = Some(details);
    }
    if status_only {
        compact_osv_audit(&mut result);
    }
    result
}

fn compact_osv_audit(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let details = result.details.as_ref().and_then(Value::as_object);
    let top_findings = details
        .and_then(|details| details.get("top_findings"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(|finding| {
            let compact = compact_finding(finding);
            if matches!(
                compact.check.as_str(),
                "osv-lockfile-audit.vulnerabilities" | "osv-lockfile-audit.high-critical"
            ) && !top_findings.is_empty()
            {
                compact.with_top_findings(top_findings.iter().take(5).cloned().collect())
            } else {
                compact
            }
        })
        .collect::<Vec<_>>();
    result.details = Some(json!({
        "lockfile_count": detail_or_zero(details, "lockfile_count"),
        "vulnerable_package_count": detail_or_zero(details, "vulnerable_package_count"),
        "vulnerability_count": detail_or_zero(details, "vulnerability_count"),
        "high_or_critical_count": detail_or_zero(details, "high_or_critical_count"),
        "finding_count": finding_count,
        "non_pass_count": non_pass.len(),
    }));
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "osv-lockfile-audit.status-only",
            "OSV lockfile audit passed; no non-pass findings.".to_string(),
        ));
    }
    result.findings = non_pass;
}

#[derive(Debug, PartialEq)]
struct OsvSummary {
    vulnerable_package_count: u64,
    vulnerability_count: u64,
    high_or_critical_count: u64,
    top_findings: Vec<Value>,
}

fn summarize_osv_payload(payload: &Value, repo_root: &Path) -> OsvSummary {
    let mut summary = OsvSummary {
        vulnerable_package_count: 0,
        vulnerability_count: 0,
        high_or_critical_count: 0,
        top_findings: Vec::new(),
    };
    let results = payload
        .get("results")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for result in results.iter().filter_map(Value::as_object) {
        let path = result
            .get("source")
            .and_then(Value::as_object)
            .and_then(|source| source.get("path"))
            .and_then(Value::as_str)
            .map(|path| compact_tool_path(path, repo_root))
            .unwrap_or_default();
        let packages = result
            .get("packages")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for package_row in packages.iter().filter_map(Value::as_object) {
            let vulnerabilities = package_row
                .get("vulnerabilities")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if vulnerabilities.is_empty() {
                continue;
            }
            summary.vulnerable_package_count += 1;
            let package = package_row.get("package").and_then(Value::as_object);
            let ecosystem = string_field(package, "ecosystem", "unknown");
            let name = string_field(package, "name", "unknown");
            let version = string_field(package, "version", "");
            for vulnerability in vulnerabilities.iter().filter_map(Value::as_object) {
                summary.vulnerability_count += 1;
                let severity = osv_severity(vulnerability);
                let high = matches!(severity.as_str(), "high" | "critical");
                if high {
                    summary.high_or_critical_count += 1;
                }
                if summary.top_findings.len() < 5 {
                    summary.top_findings.push(json!({
                        "status": if high { "fail" } else { "warn" },
                        "check": "osv-lockfile-audit.vulnerability",
                        "package": name,
                        "ecosystem": ecosystem,
                        "version": version,
                        "severity": severity,
                        "advisory": vulnerability
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        "path": path,
                    }));
                }
            }
        }
    }
    summary
}

fn osv_severity(vulnerability: &serde_json::Map<String, Value>) -> String {
    if let Some(severity) = vulnerability
        .get("database_specific")
        .and_then(Value::as_object)
        .and_then(|specific| specific.get("severity"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|severity| !severity.is_empty())
    {
        return severity.to_lowercase();
    }
    vulnerability
        .get("severity")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter_map(|row| row.get("score"))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|score| !score.is_empty())
        .map(str::to_lowercase)
        .unwrap_or_else(|| "unknown".to_string())
}

fn string_field(
    object: Option<&serde_json::Map<String, Value>>,
    key: &str,
    default: &str,
) -> String {
    object
        .and_then(|object| object.get(key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .to_string()
}

fn command_native_api_semgrep_audit_with(
    repo_root: &Path,
    status_only: bool,
    tool_available: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let config = repo_root.join(NATIVE_API_SEMGREP_CONFIG);
    let source_dir = repo_root.join(NATIVE_API_SOURCE);
    let mut findings = vec![
        Finding::new(
            if config.is_file() { "pass" } else { "fail" },
            "native-api-semgrep-audit.config",
            if config.is_file() {
                "Native API Semgrep policy exists.".to_string()
            } else {
                "Native API Semgrep policy is missing.".to_string()
            },
        )
        .with_path(NATIVE_API_SEMGREP_CONFIG),
        Finding::new(
            if source_dir.is_dir() { "pass" } else { "fail" },
            "native-api-semgrep-audit.source",
            if source_dir.is_dir() {
                "Native API source directory exists.".to_string()
            } else {
                "Native API source directory is missing.".to_string()
            },
        )
        .with_path(NATIVE_API_SOURCE),
    ];
    if !tool_available {
        findings.push(Finding::new(
            "warn",
            "native-api-semgrep-audit.tool",
            "semgrep is not installed; native API static security check was skipped.".to_string(),
        ));
        return semgrep_audit_result(
            repo_root,
            "Native API Semgrep audit could not run because semgrep is unavailable.",
            findings,
            None,
            status_only,
            runner,
        );
    }
    if !config.is_file() || !source_dir.is_dir() {
        return semgrep_audit_result(
            repo_root,
            "Native API Semgrep audit could not run because required files are missing.",
            findings,
            None,
            status_only,
            runner,
        );
    }

    let Some(audit) = runner.run_with(
        "semgrep",
        &[
            "--quiet",
            "--config",
            NATIVE_API_SEMGREP_CONFIG,
            "--json",
            "--error",
            "--metrics=off",
            NATIVE_API_SOURCE,
        ],
        Some(repo_root),
        None,
        Some(Duration::from_secs(120)),
    ) else {
        findings.push(Finding::new(
            "fail",
            "native-api-semgrep-audit.parse",
            "semgrep did not emit parseable JSON.".to_string(),
        ));
        return semgrep_audit_result(
            repo_root,
            "Native API Semgrep audit failed before results could be parsed.",
            findings,
            None,
            status_only,
            runner,
        );
    };
    let payload = match serde_json::from_str::<Value>(&audit.stdout) {
        Ok(payload) => payload,
        Err(_) => {
            findings.push(
                Finding::new(
                    "fail",
                    "native-api-semgrep-audit.parse",
                    "semgrep did not emit parseable JSON.".to_string(),
                )
                .with_details(json!({
                    "returncode": audit.exit_code,
                    "output_tail": output_tail(&audit.stdout, 40),
                })),
            );
            return semgrep_audit_result(
                repo_root,
                "Native API Semgrep audit failed before results could be parsed.",
                findings,
                None,
                status_only,
                runner,
            );
        }
    };
    let results = payload
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let errors = payload
        .get("errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let top_findings = semgrep_top_findings(repo_root, &results);
    let result_count = results.len() as u64;
    let error_count = errors.len() as u64;
    findings.extend([
        Finding::new(
            "pass",
            "native-api-semgrep-audit.tool",
            "semgrep is installed and runnable.".to_string(),
        ),
        Finding::new(
            if error_count == 0 { "pass" } else { "fail" },
            "native-api-semgrep-audit.errors",
            format!("semgrep reported {error_count} execution error(s)."),
        )
        .with_details(json!({ "error_count": error_count })),
        {
            let finding = Finding::new(
                if result_count == 0 { "pass" } else { "fail" },
                "native-api-semgrep-audit.findings",
                format!("semgrep reported {result_count} native API static security finding(s)."),
            )
            .with_details(json!({ "result_count": result_count }));
            if top_findings.is_empty() {
                finding
            } else {
                finding.with_top_findings(top_findings.clone())
            }
        },
    ]);
    if audit.exit_code != Some(0) && result_count == 0 && error_count == 0 {
        findings.push(
            Finding::new(
                "warn",
                "native-api-semgrep-audit.exit-code",
                format!(
                    "semgrep exited {} without parsed findings or errors.",
                    display_exit_code(audit.exit_code)
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&audit.stdout, 40) })),
        );
    }
    semgrep_audit_result(
        repo_root,
        "Native API Semgrep audit completed.",
        findings,
        Some(json!({
            "result_count": result_count,
            "error_count": error_count,
            "returncode": audit.exit_code,
            "top_findings": top_findings,
        })),
        status_only,
        runner,
    )
}

pub fn command_gsa_npm_audit(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_gsa_npm_audit_with(
        repo_root,
        status_only,
        executable_path("npm").is_some(),
        &SystemCommandRunner,
    )
}

fn semgrep_audit_result(
    repo_root: &Path,
    summary: &str,
    findings: Vec<Finding>,
    details: Option<Value>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut result = make_result(
        metadata(repo_root, "native-api-semgrep-audit", runner),
        summary.to_string(),
        findings,
    )
    .with_artifacts(vec![
        NATIVE_API_SEMGREP_CONFIG.to_string(),
        NATIVE_API_SOURCE.to_string(),
    ]);
    if let Some(details) = details {
        result.details = Some(details);
    }
    if status_only {
        compact_semgrep_audit(&mut result);
    }
    result
}

fn compact_semgrep_audit(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let details = result.details.as_ref().and_then(Value::as_object);
    let top_findings = details
        .and_then(|details| details.get("top_findings"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(|finding| {
            let compact = compact_finding(finding);
            if compact.check == "native-api-semgrep-audit.findings" && !top_findings.is_empty() {
                compact.with_top_findings(top_findings.iter().take(5).cloned().collect())
            } else {
                compact
            }
        })
        .collect::<Vec<_>>();
    result.details = Some(json!({
        "result_count": detail_or_zero(details, "result_count"),
        "error_count": detail_or_zero(details, "error_count"),
        "finding_count": finding_count,
        "non_pass_count": non_pass.len(),
    }));
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "native-api-semgrep-audit.status-only",
            "Native API Semgrep audit passed; no non-pass findings.".to_string(),
        ));
    }
    result.findings = non_pass;
}

fn semgrep_top_findings(repo_root: &Path, results: &[Value]) -> Vec<Value> {
    results
        .iter()
        .take(5)
        .filter_map(Value::as_object)
        .map(|item| {
            let extra = item.get("extra").and_then(Value::as_object);
            let start = item.get("start").and_then(Value::as_object);
            json!({
                "status": "fail",
                "check": item.get("check_id").and_then(Value::as_str).unwrap_or("unknown"),
                "path": compact_tool_path(
                    item.get("path").and_then(Value::as_str).unwrap_or(""),
                    repo_root,
                ),
                "line": start
                    .and_then(|start| start.get("line"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                "message": extra
                    .and_then(|extra| extra.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("Semgrep finding"),
            })
        })
        .collect()
}

fn compact_tool_path(path: &str, repo_root: &Path) -> String {
    if path.is_empty() {
        return String::new();
    }
    let source_path = Path::new(path);
    if !source_path.is_absolute() {
        return path.to_string();
    }
    if let (Ok(source), Ok(root)) = (source_path.canonicalize(), repo_root.canonicalize())
        && let Ok(relative) = source.strip_prefix(root)
    {
        return relative.display().to_string();
    }
    path.split_once("/YAFVS/")
        .or_else(|| path.split_once("/TurboVAS/"))
        .map(|(_, relative)| relative.to_string())
        .or_else(|| {
            source_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default()
}

fn command_gsa_npm_audit_with(
    repo_root: &Path,
    status_only: bool,
    tool_available: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let component_dir = repo_root.join(GSA_COMPONENT);
    let lockfile = repo_root.join(GSA_LOCKFILE);
    let mut findings = vec![
        Finding::new(
            if component_dir.is_dir() {
                "pass"
            } else {
                "fail"
            },
            "gsa-npm-audit.component",
            if component_dir.is_dir() {
                "GSA component exists.".to_string()
            } else {
                "GSA component is missing.".to_string()
            },
        )
        .with_path(GSA_COMPONENT),
        Finding::new(
            if lockfile.is_file() { "pass" } else { "fail" },
            "gsa-npm-audit.lockfile",
            if lockfile.is_file() {
                "GSA package-lock.json exists.".to_string()
            } else {
                "GSA package-lock.json is missing.".to_string()
            },
        )
        .with_path(GSA_LOCKFILE),
    ];
    if !tool_available {
        findings.push(Finding::new(
            "warn",
            "gsa-npm-audit.tool",
            "npm is not installed; GSA dependency audit was skipped.".to_string(),
        ));
        return gsa_npm_audit_result(
            repo_root,
            "GSA npm audit could not run because npm is unavailable.",
            findings,
            None,
            status_only,
            runner,
        );
    }
    if !component_dir.is_dir() || !lockfile.is_file() {
        return gsa_npm_audit_result(
            repo_root,
            "GSA npm audit could not run because required files are missing.",
            findings,
            None,
            status_only,
            runner,
        );
    }

    let Some(audit) = runner.run_with(
        "npm",
        &["audit", "--audit-level=high", "--json", "--offline"],
        Some(&component_dir),
        None,
        Some(Duration::from_secs(120)),
    ) else {
        findings.push(Finding::new(
            "fail",
            "gsa-npm-audit.parse",
            "npm audit did not emit parseable JSON.".to_string(),
        ));
        return gsa_npm_audit_result(
            repo_root,
            "GSA npm audit failed before results could be parsed.",
            findings,
            None,
            status_only,
            runner,
        );
    };
    let payload = match serde_json::from_str::<Value>(&audit.stdout) {
        Ok(payload) => payload,
        Err(_) => {
            findings.push(
                Finding::new(
                    "fail",
                    "gsa-npm-audit.parse",
                    "npm audit did not emit parseable JSON.".to_string(),
                )
                .with_details(json!({
                    "returncode": audit.exit_code,
                    "output_tail": output_tail(&audit.stdout, 40),
                })),
            );
            return gsa_npm_audit_result(
                repo_root,
                "GSA npm audit failed before results could be parsed.",
                findings,
                None,
                status_only,
                runner,
            );
        }
    };
    let high_count = integer_at(&payload, "/metadata/vulnerabilities/high");
    let critical_count = integer_at(&payload, "/metadata/vulnerabilities/critical");
    let total_count = integer_at(&payload, "/metadata/vulnerabilities/total");
    let dependency_count = integer_at(&payload, "/metadata/dependencies/total");
    let severe_count = high_count + critical_count;
    findings.extend([
        Finding::new(
            "pass",
            "gsa-npm-audit.tool",
            "npm audit is installed and runnable.".to_string(),
        ),
        Finding::new(
            if severe_count == 0 { "pass" } else { "fail" },
            "gsa-npm-audit.high-critical",
            format!(
                "npm audit reported {high_count} high and {critical_count} critical GSA dependency vulnerabilities."
            ),
        )
        .with_path(GSA_LOCKFILE)
        .with_details(json!({
            "high_count": high_count,
            "critical_count": critical_count,
        })),
    ]);
    if audit.exit_code != Some(0) && severe_count == 0 {
        findings.push(
            Finding::new(
                "warn",
                "gsa-npm-audit.exit-code",
                format!(
                    "npm audit exited {} without parsed high or critical vulnerabilities.",
                    display_exit_code(audit.exit_code)
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&audit.stdout, 40) })),
        );
    }
    gsa_npm_audit_result(
        repo_root,
        "GSA npm audit completed.",
        findings,
        Some(json!({
            "high_count": high_count,
            "critical_count": critical_count,
            "total_count": total_count,
            "dependency_count": dependency_count,
            "returncode": audit.exit_code,
        })),
        status_only,
        runner,
    )
}

fn command_native_api_cargo_audit_with(
    repo_root: &Path,
    status_only: bool,
    tool_available: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let crate_dir = repo_root.join(NATIVE_API_CRATE);
    let lockfile = repo_root.join(NATIVE_API_LOCKFILE);
    let mut findings = vec![
        Finding::new(
            if crate_dir.is_dir() { "pass" } else { "fail" },
            "native-api-cargo-audit.crate",
            if crate_dir.is_dir() {
                "Native API crate exists.".to_string()
            } else {
                "Native API crate is missing.".to_string()
            },
        )
        .with_path(NATIVE_API_CRATE),
        Finding::new(
            if lockfile.is_file() { "pass" } else { "fail" },
            "native-api-cargo-audit.lockfile",
            if lockfile.is_file() {
                "Native API Cargo.lock exists.".to_string()
            } else {
                "Native API Cargo.lock is missing.".to_string()
            },
        )
        .with_path(NATIVE_API_LOCKFILE),
    ];
    if !tool_available {
        findings.push(Finding::new(
            "warn",
            "native-api-cargo-audit.tool",
            "cargo-audit is not installed; native API dependency advisory check was skipped."
                .to_string(),
        ));
        return cargo_audit_result(
            repo_root,
            "Native API cargo audit could not run because cargo-audit is unavailable.",
            findings,
            None,
            status_only,
            runner,
        );
    }
    if !crate_dir.is_dir() || !lockfile.is_file() {
        return cargo_audit_result(
            repo_root,
            "Native API cargo audit could not run because required files are missing.",
            findings,
            None,
            status_only,
            runner,
        );
    }

    let Some(audit) = runner.run_with(
        "cargo",
        &["audit", "--no-fetch", "--stale", "--json", "--quiet"],
        Some(&crate_dir),
        None,
        Some(Duration::from_secs(120)),
    ) else {
        findings.push(Finding::new(
            "fail",
            "native-api-cargo-audit.parse",
            "cargo audit did not emit parseable JSON.".to_string(),
        ));
        return cargo_audit_result(
            repo_root,
            "Native API cargo audit failed before advisory results could be parsed.",
            findings,
            None,
            status_only,
            runner,
        );
    };
    let payload = match serde_json::from_str::<Value>(&audit.stdout) {
        Ok(payload) => payload,
        Err(_) => {
            findings.push(
                Finding::new(
                    "fail",
                    "native-api-cargo-audit.parse",
                    "cargo audit did not emit parseable JSON.".to_string(),
                )
                .with_details(json!({
                    "returncode": audit.exit_code,
                    "output_tail": output_tail(&audit.stdout, 40),
                })),
            );
            return cargo_audit_result(
                repo_root,
                "Native API cargo audit failed before advisory results could be parsed.",
                findings,
                None,
                status_only,
                runner,
            );
        }
    };
    let vulnerability_count = integer_at(&payload, "/vulnerabilities/count");
    let warning_count = payload
        .get("warnings")
        .and_then(Value::as_object)
        .map(|warnings| {
            warnings
                .values()
                .filter_map(Value::as_array)
                .map(Vec::len)
                .sum::<usize>() as u64
        })
        .unwrap_or(0);
    let advisory_count = integer_at(&payload, "/database/advisory-count");
    let dependency_count = integer_at(&payload, "/lockfile/dependency-count");
    findings.extend([
        Finding::new(
            "pass",
            "native-api-cargo-audit.tool",
            "cargo-audit is installed and runnable.".to_string(),
        ),
        Finding::new(
            if vulnerability_count == 0 { "pass" } else { "fail" },
            "native-api-cargo-audit.vulnerabilities",
            format!(
                "cargo audit reported {vulnerability_count} vulnerable native API dependency package(s)."
            ),
        )
        .with_path(NATIVE_API_LOCKFILE)
        .with_details(json!({ "vulnerability_count": vulnerability_count })),
        Finding::new(
            if warning_count == 0 { "pass" } else { "warn" },
            "native-api-cargo-audit.warnings",
            format!("cargo audit reported {warning_count} warning item(s)."),
        )
        .with_path(NATIVE_API_LOCKFILE)
        .with_details(json!({ "warning_count": warning_count })),
    ]);
    if audit.exit_code != Some(0) && vulnerability_count == 0 && warning_count == 0 {
        findings.push(
            Finding::new(
                "warn",
                "native-api-cargo-audit.exit-code",
                format!(
                    "cargo audit exited {} without parsed vulnerabilities or warnings.",
                    display_exit_code(audit.exit_code)
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&audit.stdout, 40) })),
        );
    }
    cargo_audit_result(
        repo_root,
        "Native API cargo audit completed.",
        findings,
        Some(json!({
            "vulnerability_count": vulnerability_count,
            "warning_count": warning_count,
            "dependency_count": dependency_count,
            "advisory_count": advisory_count,
            "returncode": audit.exit_code,
        })),
        status_only,
        runner,
    )
}

fn gsa_npm_audit_result(
    repo_root: &Path,
    summary: &str,
    findings: Vec<Finding>,
    details: Option<Value>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut result = make_result(
        metadata(repo_root, "gsa-npm-audit", runner),
        summary.to_string(),
        findings,
    )
    .with_artifacts(vec![GSA_LOCKFILE.to_string()]);
    if let Some(details) = details {
        result.details = Some(details);
    }
    if status_only {
        compact_gsa_npm_audit(&mut result);
    }
    result
}

fn compact_gsa_npm_audit(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let details = result.details.as_ref().and_then(Value::as_object);
    result.details = Some(json!({
        "high_count": detail_or_zero(details, "high_count"),
        "critical_count": detail_or_zero(details, "critical_count"),
        "total_count": detail_or_zero(details, "total_count"),
        "dependency_count": detail_or_zero(details, "dependency_count"),
        "finding_count": finding_count,
        "non_pass_count": non_pass.len(),
    }));
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "gsa-npm-audit.status-only",
            "GSA npm audit passed; no non-pass findings.".to_string(),
        ));
    }
    result.findings = non_pass;
}

fn cargo_audit_result(
    repo_root: &Path,
    summary: &str,
    findings: Vec<Finding>,
    details: Option<Value>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut result = make_result(
        metadata(repo_root, "native-api-cargo-audit", runner),
        summary.to_string(),
        findings,
    )
    .with_artifacts(vec![NATIVE_API_LOCKFILE.to_string()]);
    if let Some(details) = details {
        result.details = Some(details);
    }
    if status_only {
        compact_cargo_audit(&mut result);
    }
    result
}

fn compact_cargo_audit(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let details = result.details.as_ref().and_then(Value::as_object);
    result.details = Some(json!({
        "vulnerability_count": detail_or_zero(details, "vulnerability_count"),
        "warning_count": detail_or_zero(details, "warning_count"),
        "dependency_count": detail_or_zero(details, "dependency_count"),
        "advisory_count": detail_or_zero(details, "advisory_count"),
        "finding_count": finding_count,
        "non_pass_count": non_pass.len(),
    }));
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "native-api-cargo-audit.status-only",
            "Native API cargo audit passed; no non-pass findings.".to_string(),
        ));
    }
    result.findings = non_pass;
}

fn detail_or_zero(details: Option<&serde_json::Map<String, Value>>, key: &str) -> Value {
    details
        .and_then(|details| details.get(key))
        .cloned()
        .unwrap_or_else(|| json!(0))
}

fn integer_at(payload: &Value, pointer: &str) -> u64 {
    payload
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn display_exit_code(exit_code: Option<i32>) -> String {
    exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "None".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "yafvsctl-audit-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct AuditRunner {
        tool_output: ProcessOutput,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl AuditRunner {
        fn new(stdout: &str) -> Self {
            Self {
                tool_output: output(true, stdout),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn audit_calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls
                .borrow()
                .iter()
                .filter(|(program, _)| program != "git")
                .cloned()
                .collect()
        }
    }

    impl CommandRunner for AuditRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.calls.borrow_mut().push((
                program.to_string(),
                args.iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
            ));
            Some(if program == "git" {
                output(true, "audit-test-head\n")
            } else {
                self.tool_output.clone()
            })
        }
    }

    fn output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn audit_repo() -> TestDir {
        let temporary = TestDir::new();
        let repo = temporary.path();
        for lockfile in OSV_LOCKFILES {
            let path = repo.join(lockfile);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "{}\n").unwrap();
        }
        fs::create_dir_all(repo.join(NATIVE_API_SOURCE)).unwrap();
        let config = repo.join(NATIVE_API_SEMGREP_CONFIG);
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(config, "rules: []\n").unwrap();
        temporary
    }

    fn assert_metadata(result: &ResultEnvelope, command: &str) {
        assert_eq!(result.metadata.command, command);
        assert_eq!(result.metadata.head.as_deref(), Some("audit-test-head"));
    }

    fn has_finding(result: &ResultEnvelope, check: &str, status: &str) -> bool {
        result
            .findings
            .iter()
            .any(|finding| finding.check == check && finding.status == status)
    }

    #[test]
    fn cargo_audit_command_paths_are_deterministic() {
        let temporary = audit_repo();
        let repo = temporary.path();
        let unavailable = AuditRunner::new("{}");
        let result = command_native_api_cargo_audit_with(repo, false, false, &unavailable);
        assert_eq!(result.status, "warn");
        assert!(has_finding(&result, "native-api-cargo-audit.tool", "warn"));
        assert!(unavailable.audit_calls().is_empty());

        let malformed = AuditRunner::new("not json");
        let result = command_native_api_cargo_audit_with(repo, false, true, &malformed);
        assert_eq!(result.status, "fail");
        assert!(has_finding(&result, "native-api-cargo-audit.parse", "fail"));

        let clean = AuditRunner::new(
            r#"{"vulnerabilities":{"count":0},"warnings":{},"database":{"advisory-count":7},"lockfile":{"dependency-count":3}}"#,
        );
        let result = command_native_api_cargo_audit_with(repo, true, true, &clean);
        assert_eq!(result.status, "pass");
        assert_metadata(&result, "native-api-cargo-audit");
        assert_eq!(
            result.findings[0].check,
            "native-api-cargo-audit.status-only"
        );
        assert_eq!(result.details.as_ref().unwrap()["vulnerability_count"], 0);
        assert_eq!(
            clean.audit_calls(),
            vec![(
                "cargo".to_string(),
                vec!["audit", "--no-fetch", "--stale", "--json", "--quiet"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            )]
        );

        let vulnerable = AuditRunner::new(
            r#"{"vulnerabilities":{"count":2},"warnings":{},"database":{},"lockfile":{}}"#,
        );
        let result = command_native_api_cargo_audit_with(repo, true, true, &vulnerable);
        assert_eq!(result.status, "fail");
        assert!(has_finding(
            &result,
            "native-api-cargo-audit.vulnerabilities",
            "fail"
        ));
        assert_eq!(result.details.as_ref().unwrap()["vulnerability_count"], 2);
        assert_eq!(result.details.as_ref().unwrap()["non_pass_count"], 1);
    }

    #[test]
    fn npm_audit_command_paths_are_deterministic() {
        let temporary = audit_repo();
        let repo = temporary.path();
        let unavailable = AuditRunner::new("{}");
        let result = command_gsa_npm_audit_with(repo, false, false, &unavailable);
        assert_eq!(result.status, "warn");
        assert!(has_finding(&result, "gsa-npm-audit.tool", "warn"));
        assert!(unavailable.audit_calls().is_empty());

        let malformed = AuditRunner::new("not json");
        let result = command_gsa_npm_audit_with(repo, false, true, &malformed);
        assert_eq!(result.status, "fail");
        assert!(has_finding(&result, "gsa-npm-audit.parse", "fail"));

        let clean = AuditRunner::new(
            r#"{"metadata":{"vulnerabilities":{"high":0,"critical":0,"total":0},"dependencies":{"total":12}}}"#,
        );
        let result = command_gsa_npm_audit_with(repo, true, true, &clean);
        assert_eq!(result.status, "pass");
        assert_metadata(&result, "gsa-npm-audit");
        assert_eq!(result.findings[0].check, "gsa-npm-audit.status-only");
        assert_eq!(result.details.as_ref().unwrap()["dependency_count"], 12);
        assert_eq!(
            clean.audit_calls(),
            vec![(
                "npm".to_string(),
                vec!["audit", "--audit-level=high", "--json", "--offline"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            )]
        );

        let vulnerable = AuditRunner::new(
            r#"{"metadata":{"vulnerabilities":{"high":1,"critical":2,"total":3},"dependencies":{"total":12}}}"#,
        );
        let result = command_gsa_npm_audit_with(repo, true, true, &vulnerable);
        assert_eq!(result.status, "fail");
        assert!(has_finding(&result, "gsa-npm-audit.high-critical", "fail"));
        assert_eq!(result.details.as_ref().unwrap()["high_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["critical_count"], 2);
        assert_eq!(result.details.as_ref().unwrap()["non_pass_count"], 1);
    }

    #[test]
    fn semgrep_audit_command_paths_are_deterministic() {
        let temporary = audit_repo();
        let repo = temporary.path();
        let unavailable = AuditRunner::new("{}");
        let result = command_native_api_semgrep_audit_with(repo, false, false, &unavailable);
        assert_eq!(result.status, "warn");
        assert!(has_finding(
            &result,
            "native-api-semgrep-audit.tool",
            "warn"
        ));
        assert!(unavailable.audit_calls().is_empty());

        let malformed = AuditRunner::new("not json");
        let result = command_native_api_semgrep_audit_with(repo, false, true, &malformed);
        assert_eq!(result.status, "fail");
        assert!(has_finding(
            &result,
            "native-api-semgrep-audit.parse",
            "fail"
        ));

        let clean = AuditRunner::new(r#"{"results":[],"errors":[]}"#);
        let result = command_native_api_semgrep_audit_with(repo, true, true, &clean);
        assert_eq!(result.status, "pass");
        assert_metadata(&result, "native-api-semgrep-audit");
        assert_eq!(
            result.findings[0].check,
            "native-api-semgrep-audit.status-only"
        );
        assert_eq!(result.details.as_ref().unwrap()["result_count"], 0);
        assert_eq!(
            clean.audit_calls(),
            vec![(
                "semgrep".to_string(),
                vec![
                    "--quiet",
                    "--config",
                    NATIVE_API_SEMGREP_CONFIG,
                    "--json",
                    "--error",
                    "--metrics=off",
                    NATIVE_API_SOURCE,
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            )]
        );

        let findings = AuditRunner::new(
            r#"{"results":[{"check_id":"rust.security","path":"services/yafvs-api/src/main.rs","start":{"line":9},"extra":{"message":"unsafe"}}],"errors":[{"message":"rule error"}]}"#,
        );
        let result = command_native_api_semgrep_audit_with(repo, true, true, &findings);
        assert_eq!(result.status, "fail");
        assert!(has_finding(
            &result,
            "native-api-semgrep-audit.findings",
            "fail"
        ));
        assert!(has_finding(
            &result,
            "native-api-semgrep-audit.errors",
            "fail"
        ));
        assert_eq!(result.details.as_ref().unwrap()["result_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["error_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["non_pass_count"], 2);
    }

    #[test]
    fn osv_audit_command_paths_are_deterministic() {
        let temporary = audit_repo();
        let repo = temporary.path();
        let unavailable = AuditRunner::new("{}");
        let result = command_osv_lockfile_audit_with(repo, false, false, &unavailable);
        assert_eq!(result.status, "warn");
        assert!(has_finding(&result, "osv-lockfile-audit.tool", "warn"));
        assert!(unavailable.audit_calls().is_empty());

        let malformed = AuditRunner::new("not json");
        let result = command_osv_lockfile_audit_with(repo, false, true, &malformed);
        assert_eq!(result.status, "fail");
        assert!(has_finding(&result, "osv-lockfile-audit.parse", "fail"));

        let clean = AuditRunner::new(r#"{"results":[]}"#);
        let result = command_osv_lockfile_audit_with(repo, true, true, &clean);
        assert_eq!(result.status, "pass");
        assert_metadata(&result, "osv-lockfile-audit");
        assert_eq!(result.findings[0].check, "osv-lockfile-audit.status-only");
        assert_eq!(result.details.as_ref().unwrap()["vulnerability_count"], 0);
        assert_eq!(
            clean.audit_calls(),
            vec![(
                "osv-scanner".to_string(),
                vec![
                    "scan",
                    "source",
                    "--format",
                    "json",
                    "--verbosity",
                    "error",
                    "--lockfile",
                    NATIVE_API_LOCKFILE,
                    "--lockfile",
                    "tools/yafvsctl-rs/Cargo.lock",
                    "--lockfile",
                    "components/openvas-scanner/rust/Cargo.lock",
                    "--lockfile",
                    GSA_LOCKFILE,
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            )]
        );

        let lower = AuditRunner::new(
            r#"{"results":[{"packages":[{"package":{"name":"low","ecosystem":"crates.io","version":"1"},"vulnerabilities":[{"id":"GHSA-low","database_specific":{"severity":"low"}}]}]}]}"#,
        );
        let result = command_osv_lockfile_audit_with(repo, true, true, &lower);
        assert_eq!(result.status, "warn");
        assert!(has_finding(
            &result,
            "osv-lockfile-audit.vulnerabilities",
            "warn"
        ));
        assert_eq!(result.details.as_ref().unwrap()["vulnerability_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["non_pass_count"], 1);

        let severe = AuditRunner::new(
            r#"{"results":[{"packages":[{"package":{"name":"high","ecosystem":"crates.io","version":"1"},"vulnerabilities":[{"id":"GHSA-high","database_specific":{"severity":"high"}}]}]}]}"#,
        );
        let result = command_osv_lockfile_audit_with(repo, true, true, &severe);
        assert_eq!(result.status, "fail");
        assert!(has_finding(
            &result,
            "osv-lockfile-audit.high-critical",
            "fail"
        ));
        assert_eq!(
            result.details.as_ref().unwrap()["high_or_critical_count"],
            1
        );
        assert_eq!(result.details.as_ref().unwrap()["non_pass_count"], 1);
    }

    #[test]
    fn counts_warning_arrays_only() {
        let payload = json!({
            "warnings": {"yanked": [{"name": "a"}], "ignored": "not-an-array"},
        });
        let count = payload["warnings"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(Value::as_array)
            .map(Vec::len)
            .sum::<usize>();
        assert_eq!(count, 1);
    }

    #[test]
    fn missing_integer_is_zero() {
        assert_eq!(integer_at(&json!({}), "/missing/count"), 0);
    }

    #[test]
    fn semgrep_paths_are_repository_relative() {
        let root = Path::new("/tmp/YAFVS");
        assert_eq!(
            compact_tool_path("/tmp/YAFVS/services/yafvs-api/src/main.rs", root),
            "services/yafvs-api/src/main.rs"
        );
        assert_eq!(
            compact_tool_path("/archived/TurboVAS/services/yafvs-api/src/main.rs", root),
            "services/yafvs-api/src/main.rs"
        );
        assert_eq!(compact_tool_path("relative.rs", root), "relative.rs");
    }

    #[test]
    fn summarizes_osv_severity_and_packages() {
        let payload = json!({
            "results": [{
                "source": {"path": "/repo/YAFVS/Cargo.lock"},
                "packages": [{
                    "package": {"ecosystem": "crates.io", "name": "example", "version": "1"},
                    "vulnerabilities": [
                        {"id": "GHSA-high", "database_specific": {"severity": "HIGH"}},
                        {"id": "RUSTSEC-low", "severity": [{"score": "CVSS:3.1/AV:L"}]},
                    ],
                }],
            }],
        });
        let summary = summarize_osv_payload(&payload, Path::new("/repo/YAFVS"));
        assert_eq!(summary.vulnerable_package_count, 1);
        assert_eq!(summary.vulnerability_count, 2);
        assert_eq!(summary.high_or_critical_count, 1);
        assert_eq!(summary.top_findings[0]["status"], "fail");
    }
}
