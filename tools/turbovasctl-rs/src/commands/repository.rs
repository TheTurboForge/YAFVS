// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, run_git};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::path::{Component as PathComponent, Path, PathBuf};

#[derive(Clone, Copy)]
struct ComponentSpec {
    name: &'static str,
    path: &'static str,
    role: &'static str,
}

const COMPONENTS: [ComponentSpec; 10] = [
    ComponentSpec {
        name: "openvas-scanner",
        path: "components/openvas-scanner",
        role: "scanner engine and NASL runtime",
    },
    ComponentSpec {
        name: "gvm-libs",
        path: "components/gvm-libs",
        role: "shared Greenbone/OpenVAS libraries",
    },
    ComponentSpec {
        name: "pg-gvm",
        path: "components/pg-gvm",
        role: "PostgreSQL extension for gvmd helper functions",
    },
    ComponentSpec {
        name: "gvmd",
        path: "components/gvmd",
        role: "manager daemon and GMP API",
    },
    ComponentSpec {
        name: "ospd-openvas",
        path: "components/ospd-openvas",
        role: "scanner adapter service",
    },
    ComponentSpec {
        name: "gsad",
        path: "components/gsad",
        role: "web service daemon",
    },
    ComponentSpec {
        name: "gsa",
        path: "components/gsa",
        role: "web user interface",
    },
    ComponentSpec {
        name: "openvas-smb",
        path: "components/openvas-smb",
        role: "SMB support library",
    },
    ComponentSpec {
        name: "notus-scanner",
        path: "components/notus-scanner",
        role: "Notus local security check scanner",
    },
    ComponentSpec {
        name: "greenbone-feed-sync",
        path: "components/greenbone-feed-sync",
        role: "feed synchronization tooling",
    },
];

pub fn find_repo_root(start: &Path) -> PathBuf {
    find_repo_root_with(start, &SystemCommandRunner)
}

pub fn command_status(repo_root: &Path) -> ResultEnvelope {
    command_status_with(repo_root, &SystemCommandRunner)
}

pub fn command_inventory(repo_root: &Path, scope: Option<&str>) -> ResultEnvelope {
    command_inventory_with(repo_root, scope, &SystemCommandRunner)
}

pub(crate) fn find_repo_root_with(start: &Path, runner: &dyn CommandRunner) -> PathBuf {
    run_git(runner, start, &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .unwrap_or_else(|| start.canonicalize().unwrap_or_else(|_| start.to_path_buf()))
}

pub(crate) fn command_status_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let branch = run_git(runner, repo_root, &["branch", "--show-current"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "(detached or unavailable)".to_string());
    let head = run_git(runner, repo_root, &["rev-parse", "--short", "HEAD"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string());
    let porcelain = run_git(runner, repo_root, &["status", "--short"]).unwrap_or_default();
    let upstream = run_git(
        runner,
        repo_root,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )
    .filter(|value| !value.is_empty());
    let mut findings = vec![
        Finding::new(
            "pass",
            "git.repository",
            format!("Repository root: {}", repo_root.display()),
        ),
        Finding::new(
            "pass",
            "git.head",
            format!("Current branch {branch} at {head}"),
        ),
        Finding::new(
            if upstream.is_some() { "pass" } else { "warn" },
            "git.upstream",
            upstream
                .map(|value| format!("Tracking upstream: {value}"))
                .unwrap_or_else(|| "No upstream tracking branch is configured.".to_string()),
        ),
    ];
    if porcelain.is_empty() {
        findings.push(Finding::new(
            "pass",
            "git.worktree",
            "Worktree is clean.".to_string(),
        ));
    } else {
        findings.push(
            Finding::new(
                "warn",
                "git.worktree",
                "Worktree has uncommitted changes.".to_string(),
            )
            .with_details(json!({
                "changed_files": porcelain.lines().collect::<Vec<_>>()
            })),
        );
    }
    make_result(
        metadata(repo_root, "status", runner),
        "Repository status collected.".to_string(),
        findings,
    )
}

pub(crate) fn command_inventory_with(
    repo_root: &Path,
    scope: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let scope_path = scope.map(|value| resolved_path(&repo_root.join(value)));
    let selected: Vec<_> = COMPONENTS
        .iter()
        .filter(|component| {
            scope_path.as_ref().is_none_or(|scope| {
                resolved_path(&repo_root.join(component.path)).starts_with(scope)
            })
        })
        .collect();
    let mut findings = Vec::new();
    if let Some(scope) = scope
        && selected.is_empty()
    {
        findings.push(Finding::new(
            "warn",
            "inventory.scope",
            format!("No expected components matched scope {scope}."),
        ));
    }
    for component in selected {
        findings.push(
            Finding::new(
                if repo_root.join(component.path).is_dir() {
                    "pass"
                } else {
                    "fail"
                },
                "component.exists",
                format!("{}: {}", component.name, component.role),
            )
            .with_path(component.path),
        );
    }
    make_result(
        metadata(repo_root, "inventory", runner),
        format!(
            "Inventory contains {} expected component(s).",
            findings
                .iter()
                .filter(|finding| finding.check == "component.exists")
                .count()
        ),
        findings,
    )
}

fn resolved_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| normalize_path(path))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            PathComponent::CurDir => {}
            PathComponent::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;

    struct FakeRunner;

    impl CommandRunner for FakeRunner {
        fn run(&self, _program: &str, args: &[&str]) -> Option<ProcessOutput> {
            let stdout = match *args.last()? {
                "--show-current" => "main",
                "HEAD" => "abc1234",
                "--short" => " M tracked-file",
                "@{upstream}" => "origin/main",
                _ => "",
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn status_uses_injected_process_runner() {
        let result = command_status_with(Path::new("/repo"), &FakeRunner);
        assert_eq!(result.status, "warn");
        assert_eq!(result.findings[1].message, "Current branch main at abc1234");
    }
}
