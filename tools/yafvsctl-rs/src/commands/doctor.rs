// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, executable_path, metadata, run_git};
use super::license::command_license_report_with_runner;
use super::repository::component_specs;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::fs;
use std::path::Path;

const EXPECTED_ROOT_DOCS: [&str; 3] = ["README.md", "UPSTREAMS.md", "LICENSE_AUDIT.md"];
const BASELINE_TOOLS: [&str; 15] = [
    "git",
    "rg",
    "fd",
    "jq",
    "just",
    "python3",
    "docker",
    "cmake",
    "ninja",
    "pkg-config",
    "gcc",
    "g++",
    "clang",
    "cargo",
    "bear",
];
const BUILD_SURFACE: [&str; 8] = [
    "just deps",
    "just configure",
    "just build",
    "just build-core-c",
    "just build-c-services",
    "just build-ui",
    "just build-python",
    "just build-baseline",
];
const RUNTIME_SURFACE: [&str; 50] = [
    "just runtime-plan",
    "just up",
    "just down",
    "just logs",
    "just runtime-init",
    "just runtime-certs-init",
    "just runtime-manager-init",
    "just runtime-scanner-redis-init",
    "just runtime-gmp-smoke",
    "just runtime-scanner-register",
    "just runtime-scanner-capability-check",
    "just runtime-scanner-process-check",
    "just runtime-nmap-capability-check",
    "just runtime-feed-keyring-init",
    "just feed-generation-stage",
    "just feed-generation-state",
    "just feed-generation-activate",
    "just feed-generation-rollback",
    "just runtime-full-test-scan-preflight",
    "just runtime-full-test-scan-start",
    "just runtime-full-test-scan-status",
    "just runtime-report-summary",
    "just runtime-report-export",
    "just runtime-certbund-report",
    "just runtime-report-metrics",
    "just runtime-scope-smoke",
    "just runtime-scope-report-summary",
    "just runtime-scope-report-metrics",
    "just runtime-rbac-smoke",
    "just feed-state",
    "just feed-cache-sync",
    "just runtime-status",
    "just runtime-smoke",
    "just runtime-log-review",
    "just runtime-data-state",
    "just runtime-db-introspect",
    "just runtime-performance-snapshot",
    "just runtime-app-up",
    "just runtime-app-smoke",
    "just runtime-native-api-smoke",
    "just runtime-native-api-rebuild",
    "just runtime-webui-smoke",
    "just runtime-browser-smoke",
    "just runtime-browser-regression",
    "just runtime-credential-smoke",
    "just runtime-app-down",
    "just gvmd-smoke",
    "just quality-gate",
    "just quality-gate-state",
    "just quality-gate-schedule",
];

pub fn command_doctor(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_doctor_with_runner(repo_root, status_only, &SystemCommandRunner)
}

fn command_doctor_with_runner(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    findings.push(
        Finding::new(
            if repo_root.join(".git").exists() {
                "pass"
            } else {
                "fail"
            },
            "repo.git",
            if repo_root.join(".git").exists() {
                "Repository metadata is present.".to_string()
            } else {
                "Repository metadata is missing.".to_string()
            },
        )
        .with_path(".git"),
    );
    let porcelain = run_git(runner, repo_root, &["status", "--short"]).unwrap_or_default();
    findings.push(Finding::new(
        if porcelain.is_empty() { "pass" } else { "warn" },
        "git.worktree",
        if porcelain.is_empty() {
            "Worktree is clean.".to_string()
        } else {
            "Worktree has uncommitted changes.".to_string()
        },
    ));
    for document in EXPECTED_ROOT_DOCS {
        findings.push(
            Finding::new(
                if repo_root.join(document).is_file() {
                    "pass"
                } else {
                    "fail"
                },
                "root.doc",
                format!("Expected root document {document}"),
            )
            .with_path(document),
        );
    }
    for component in component_specs() {
        findings.push(
            Finding::new(
                if repo_root.join(component.path).is_dir() {
                    "pass"
                } else {
                    "fail"
                },
                "component.exists",
                format!("Expected component {}", component.name),
            )
            .with_path(component.path),
        );
        for license in component.licenses {
            let relative = format!("{}/{}", component.path, license);
            findings.push(
                Finding::new(
                    if repo_root.join(&relative).is_file() {
                        "pass"
                    } else {
                        "fail"
                    },
                    "component.license",
                    format!("Expected license/provenance file for {}", component.name),
                )
                .with_path(&relative),
            );
        }
    }
    let nested = nested_git_paths(repo_root);
    let mut nested_finding = Finding::new(
        if nested.is_empty() { "pass" } else { "fail" },
        "component.nested_git",
        if nested.is_empty() {
            "No nested .git directories found under components/.".to_string()
        } else {
            "Nested .git directories were found.".to_string()
        },
    );
    if !nested.is_empty() {
        nested_finding = nested_finding.with_details(json!({ "paths": nested }));
    }
    findings.push(nested_finding);
    for tool in BASELINE_TOOLS {
        let available = executable_path(tool).is_some();
        findings.push(Finding::new(
            if available { "pass" } else { "warn" },
            "tool.available",
            if available {
                format!("{tool} is available.")
            } else {
                format!("{tool} is not available on PATH.")
            },
        ));
    }
    findings.push(python_version_finding(runner, repo_root));

    let license = command_license_report_with_runner(
        repo_root,
        false,
        "source-public",
        "baseline",
        false,
        false,
        runner,
    );
    findings.push(
        Finding::new(
            &license.status,
            "license.compliance",
            license.summary.clone(),
        )
        .with_details(json!({
            "status": license.status,
            "findings": license.findings,
        })),
    );
    findings.push(
        Finding::new(
            "pass",
            "surface.available",
            "Build readiness surface is available.".to_string(),
        )
        .with_details(json!({ "commands": BUILD_SURFACE })),
    );
    let compose_available = repo_root.join("compose/dev.yaml").is_file();
    findings.push(
        Finding::new(
            if compose_available { "pass" } else { "warn" },
            "surface.available",
            if compose_available {
                "Runtime infrastructure command surface is available.".to_string()
            } else {
                "Runtime infrastructure command surface is not available.".to_string()
            },
        )
        .with_details(json!({ "commands": &RUNTIME_SURFACE[..] })),
    );
    findings.push(
        Finding::new(
            "pass",
            "surface.diagnostics",
            "Native API, Redis, path-coupling, and security-policy diagnostics are available."
                .to_string(),
        )
        .with_details(json!({
            "commands": [
                "just native-tooling-state",
                "just runtime-redis-state",
                "just path-coupling-state",
                "just security-policy-check",
            ]
        })),
    );
    findings.push(
        Finding::new(
            "warn",
            "surface.deferred",
            "Test command surface is deferred until component checks are mapped.".to_string(),
        )
        .with_details(json!({ "command": "just test" })),
    );
    findings.push(
        Finding::new(
            "warn",
            "surface.deferred",
            "Full inherited service orchestration remains experimental until feed, scanner registration, and first UI/API connectivity are stabilized."
                .to_string(),
        )
        .with_details(json!({
            "commands": ["gvmd", "gsad", "ospd-openvas", "notus-scanner"]
        })),
    );
    let mut result = make_result(
        metadata(repo_root, "doctor", runner),
        "Monorepo health checks completed.".to_string(),
        findings,
    );
    if status_only {
        result = doctor_status_only_result(result);
    }
    result
}

fn nested_git_paths(repo_root: &Path) -> Vec<String> {
    let root = repo_root.join("components");
    if !root.is_dir() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().is_some_and(|name| name == ".git") {
                if let Ok(relative) = path.strip_prefix(repo_root) {
                    found.push(relative.display().to_string());
                }
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            }
        }
    }
    found.sort();
    found
}

fn python_version_finding(runner: &dyn CommandRunner, repo_root: &Path) -> Finding {
    let version = executable_path("python3").and_then(|_| {
        runner
            .run_with("python3", &["--version"], Some(repo_root), None, None)
            .filter(|output| output.success)
            .and_then(|output| output.stdout.trim().lines().next().map(str::to_string))
    });
    let Some(version) = version else {
        return Finding::new(
            "warn",
            "tool.python-version",
            "python3 version could not be detected.".to_string(),
        );
    };
    let parsed = version_tuple(version.strip_prefix("Python ").unwrap_or(&version));
    let passed = parsed.as_slice() >= &[3, 11];
    Finding::new(
        if passed { "pass" } else { "warn" },
        "tool.python-version",
        if passed {
            format!("python3 version {version} satisfies YAFVS tooling requirement >= 3.11.")
        } else {
            format!("python3 version {version} is older than YAFVS tooling requirement >= 3.11; TOML-backed checks need Python 3.11+.")
        },
    )
    .with_details(json!({ "version": version, "minimum": "3.11" }))
}

fn version_tuple(version: &str) -> Vec<u64> {
    version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map_while(|piece| {
            let digits = piece
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
        })
        .collect()
}

fn doctor_status_only_result(mut result: ResultEnvelope) -> ResultEnvelope {
    let findings = std::mem::take(&mut result.findings);
    let finding_count = findings.len();
    let mut non_pass = findings
        .into_iter()
        .filter(|finding| finding.status != "pass")
        .map(|finding| compact_finding(&finding))
        .collect::<Vec<_>>();
    let non_pass_count = non_pass.len();
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "doctor.status-only",
            "Doctor passed; no non-pass findings.".to_string(),
        ));
    }
    result.details = Some(json!({
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
    }));
    result.findings = non_pass;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parser_handles_python_versions() {
        assert_eq!(version_tuple("3.11.8"), vec![3, 11, 8]);
        assert!(version_tuple("3.11.0") >= vec![3, 11]);
    }

    #[test]
    fn nested_git_search_is_empty_for_missing_components() {
        assert!(nested_git_paths(Path::new("/definitely/missing")).is_empty());
    }
}
