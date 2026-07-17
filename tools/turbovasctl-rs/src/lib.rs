// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use serde_json::{Value, json};
use std::env;
use std::ffi::OsStr;
use std::path::{Component as PathComponent, Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const STATUSES: [&str; 3] = ["pass", "warn", "fail"];

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

#[derive(Debug, PartialEq, Eq)]
pub struct Cli {
    pub command: CliCommand,
    pub json: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliCommand {
    Status,
    Inventory { scope: Option<String> },
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ResultEnvelope {
    status: String,
    summary: String,
    findings: Vec<Finding>,
    artifacts: Vec<String>,
    metadata: Metadata,
}

#[derive(Debug, Serialize, PartialEq)]
struct Finding {
    status: String,
    check: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

#[derive(Debug, Serialize, PartialEq)]
struct Metadata {
    command: String,
    generated_at: String,
    repo_root: String,
    head: Option<String>,
}

impl Finding {
    fn new(status: &str, check: &str, message: String) -> Self {
        Self {
            status: status.to_string(),
            check: check.to_string(),
            message,
            path: None,
            details: None,
        }
    }

    fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

pub fn parse_cli<I, S>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string_lossy().into_owned())
        .collect();
    let mut json = false;
    let mut command: Option<String> = None;
    let mut scope: Option<String> = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Err(usage().to_string()),
            "--scope" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--scope requires a value".to_string())?;
                scope = Some(value.clone());
            }
            value if value.starts_with("--scope=") => {
                scope = Some(value["--scope=".len()..].to_string());
            }
            value if value.starts_with('-') => {
                return Err(format!("unrecognized argument: {value}"));
            }
            value if command.is_none() => command = Some(value.to_string()),
            value => return Err(format!("unexpected argument: {value}")),
        }
        index += 1;
    }

    match command.as_deref() {
        Some("status") if scope.is_none() => Ok(Cli {
            command: CliCommand::Status,
            json,
        }),
        Some("status") => Err("--scope is valid only with inventory".to_string()),
        Some("inventory") => Ok(Cli {
            command: CliCommand::Inventory { scope },
            json,
        }),
        Some(value) => Err(format!("unsupported Rust command: {value}")),
        None => Err("a command is required".to_string()),
    }
}

pub fn usage() -> &'static str {
    "usage: turbovasctl [--json] {status,inventory} [--scope PATH]"
}

pub fn find_repo_root(start: &Path) -> PathBuf {
    run_git(start, &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .unwrap_or_else(|| start.canonicalize().unwrap_or_else(|_| start.to_path_buf()))
}

fn run_git(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn generated_at() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn metadata(repo_root: &Path, command: &str) -> Metadata {
    Metadata {
        command: command.to_string(),
        generated_at: generated_at(),
        repo_root: repo_root.display().to_string(),
        head: run_git(repo_root, &["rev-parse", "--short", "HEAD"]),
    }
}

fn status_rank(status: &str) -> usize {
    STATUSES
        .iter()
        .position(|candidate| *candidate == status)
        .unwrap_or(2)
}

fn aggregate_status(findings: &[Finding]) -> String {
    findings
        .iter()
        .max_by_key(|finding| status_rank(&finding.status))
        .map(|finding| finding.status.clone())
        .unwrap_or_else(|| "pass".to_string())
}

fn make_result(
    command: &str,
    repo_root: &Path,
    summary: String,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    ResultEnvelope {
        status: aggregate_status(&findings),
        summary,
        findings,
        artifacts: Vec::new(),
        metadata: metadata(repo_root, command),
    }
}

pub fn command_status(repo_root: &Path) -> ResultEnvelope {
    let branch = run_git(repo_root, &["branch", "--show-current"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "(detached or unavailable)".to_string());
    let head = run_git(repo_root, &["rev-parse", "--short", "HEAD"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string());
    let porcelain = run_git(repo_root, &["status", "--short"]).unwrap_or_default();
    let upstream = run_git(
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
        "status",
        repo_root,
        "Repository status collected.".to_string(),
        findings,
    )
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

fn resolved_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| normalize_path(path))
}

pub fn command_inventory(repo_root: &Path, scope: Option<&str>) -> ResultEnvelope {
    let scope_path = scope.map(|value| resolved_path(&repo_root.join(value)));
    let mut selected = Vec::new();
    for component in COMPONENTS {
        let component_path = repo_root.join(component.path);
        if scope_path
            .as_ref()
            .is_some_and(|scope| !resolved_path(&component_path).starts_with(scope))
        {
            continue;
        }
        selected.push(component);
    }

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
    for component in &selected {
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
        "inventory",
        repo_root,
        format!(
            "Inventory contains {} expected component(s).",
            selected.len()
        ),
        findings,
    )
}

pub fn render_human(result: &ResultEnvelope) -> String {
    let mut lines = vec![format!(
        "{}: {}",
        result.status.to_uppercase(),
        result.summary
    )];
    for finding in &result.findings {
        let mut line = format!(
            "[{}] {}: {}",
            finding.status, finding.check, finding.message
        );
        if let Some(path) = &finding.path {
            line.push_str(&format!(" ({path})"));
        }
        lines.push(line);
    }
    format!("{}\n", lines.join("\n"))
}

pub fn render_json(result: &ResultEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(result).map(|text| format!("{text}\n"))
}

pub fn exit_code(result: &ResultEnvelope) -> i32 {
    i32::from(result.status == "fail")
}

pub fn run(cli: &Cli, cwd: &Path) -> ResultEnvelope {
    let repo_root = find_repo_root(cwd);
    match &cli.command {
        CliCommand::Status => command_status(&repo_root),
        CliCommand::Inventory { scope } => command_inventory(&repo_root, scope.as_deref()),
    }
}

pub fn current_dir() -> Result<PathBuf, String> {
    env::current_dir().map_err(|error| format!("could not read current directory: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_before_or_after_the_command() {
        assert_eq!(
            parse_cli(["--json", "status"]).unwrap(),
            Cli {
                command: CliCommand::Status,
                json: true,
            }
        );
        assert_eq!(
            parse_cli(["inventory", "--scope", "components/gsa", "--json"]).unwrap(),
            Cli {
                command: CliCommand::Inventory {
                    scope: Some("components/gsa".to_string()),
                },
                json: true,
            }
        );
    }

    #[test]
    fn rejects_scope_for_status() {
        assert_eq!(
            parse_cli(["status", "--scope", "components"]).unwrap_err(),
            "--scope is valid only with inventory"
        );
    }

    #[test]
    fn empty_inventory_is_a_warning_and_success_exit() {
        let root = Path::new("/definitely/not/a/turbovas/repository");
        let result = command_inventory(root, Some("not-a-component"));
        assert_eq!(result.status, "warn");
        assert_eq!(exit_code(&result), 0);
    }
}
