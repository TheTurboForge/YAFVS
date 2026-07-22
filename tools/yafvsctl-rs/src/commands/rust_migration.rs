// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{build_env, executable_path, metadata, runtime_dir};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::path::Path;
use std::time::Duration;

const MIGRATION_TOOLS: [(&str, &[&str]); 6] = [
    ("bindgen", &["bindgen", "--version"]),
    ("cbindgen", &["cbindgen", "--version"]),
    ("c2rust", &["c2rust", "--version"]),
    ("c2rust-transpile", &["c2rust-transpile", "--version"]),
    ("cargo-llvm-cov", &["cargo", "llvm-cov", "--version"]),
    ("cargo-mutants", &["cargo", "mutants", "--version"]),
];

const TOOLCHAIN: [(&str, &[&str]); 4] = [
    ("rustc", &["rustc", "--version"]),
    ("cargo", &["cargo", "--version"]),
    ("clang", &["clang", "--version"]),
    ("llvm-config", &["llvm-config", "--version"]),
];

#[derive(Clone, Debug, Serialize)]
struct ToolState {
    name: String,
    command: Vec<String>,
    path: Option<String>,
    status: String,
    version: Option<String>,
    exit_code: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
struct ToolchainState {
    path: Option<String>,
    status: String,
    version: Option<String>,
    exit_code: Option<i32>,
}

pub fn command_rust_migration_state(repo_root: &Path) -> ResultEnvelope {
    command_rust_migration_state_with(repo_root, &SystemCommandRunner)
}

fn command_rust_migration_state_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let tools = MIGRATION_TOOLS
        .iter()
        .map(|(name, command)| migration_tool_state(repo_root, runner, name, command))
        .collect::<Vec<_>>();
    let toolchain_states = TOOLCHAIN
        .iter()
        .map(|(name, command)| {
            (
                (*name).to_string(),
                toolchain_state(repo_root, runner, command),
            )
        })
        .collect::<Vec<_>>();
    let candidate = migration_candidate(repo_root);
    let scanner_workspace = repo_root.join("components/openvas-scanner/rust/Cargo.toml");
    let artifact_dir = runtime_dir(repo_root).join("artifacts/rust-migration");

    let missing_tools = tools
        .iter()
        .filter(|tool| tool.status == "fail")
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    let warning_tools = tools
        .iter()
        .filter(|tool| tool.status == "warn")
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    let failed_toolchain = toolchain_states
        .iter()
        .filter(|(_, state)| state.get("status") == Some(&json!("fail")))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let toolchain = toolchain_states.into_iter().collect::<Map<String, Value>>();
    let candidate_ready = ["c_file_exists", "header_exists", "test_file_exists"]
        .iter()
        .all(|key| candidate.get(*key) == Some(&Value::Bool(true)));

    let mut findings = vec![
        Finding::new(
            if missing_tools.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "rust-migration.tools",
            if missing_tools.is_empty() {
                "All Rust migration tools are available.".to_string()
            } else {
                "Some Rust migration tools are missing.".to_string()
            },
        )
        .with_details(json!({
            "missing": missing_tools,
            "warnings": warning_tools,
            "tools": tools,
        })),
        Finding::new(
            if failed_toolchain.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "rust-migration.toolchain",
            if failed_toolchain.is_empty() {
                "Rust, Cargo, Clang, and LLVM config are available.".to_string()
            } else {
                "Rust/LLVM toolchain prerequisite is missing.".to_string()
            },
        )
        .with_details(json!({
            "missing": failed_toolchain,
            "toolchain": toolchain,
        })),
        Finding::new(
            if scanner_workspace.is_file() {
                "pass"
            } else {
                "warn"
            },
            "rust-migration.scanner-workspace",
            if scanner_workspace.is_file() {
                "Inherited scanner Rust workspace exists.".to_string()
            } else {
                "Inherited scanner Rust workspace was not found.".to_string()
            },
        )
        .with_path(&scanner_workspace.display().to_string()),
        Finding::new(
            if candidate_ready { "pass" } else { "fail" },
            "rust-migration.first-candidate",
            if candidate_ready {
                "First dry-run C-to-Rust candidate exists and has tests.".to_string()
            } else {
                "First dry-run C-to-Rust candidate is incomplete.".to_string()
            },
        )
        .with_details(Value::Object(candidate.clone())),
    ];
    match std::fs::create_dir_all(&artifact_dir) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "rust-migration.artifact-dir",
                "Rust migration artifact directory is ready.".to_string(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "rust-migration.artifact-dir",
                format!("Rust migration artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }

    make_result(
        metadata(repo_root, "rust-migration-state", runner),
        "Rust migration tooling and first dry-run candidate state collected.".to_string(),
        findings,
    )
    .with_artifacts(vec![artifact_dir.display().to_string()])
    .with_details(json!({
        "tools": tools,
        "toolchain": toolchain,
        "scanner_workspace": scanner_workspace,
        "first_candidate": candidate,
        "artifact_dir": artifact_dir,
    }))
}

fn migration_tool_state(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    name: &str,
    command: &[&str],
) -> ToolState {
    let path = executable_path(command[0]);
    let probe = path.as_ref().and_then(|_| {
        runner.run_with(
            command[0],
            &command[1..],
            Some(repo_root),
            Some(&build_env(repo_root)),
            Some(Duration::from_secs(30)),
        )
    });
    ToolState {
        name: name.to_string(),
        command: command.iter().map(|part| (*part).to_string()).collect(),
        path: path.map(|path| path.display().to_string()),
        status: match &probe {
            Some(output) if output.success => "pass",
            Some(_) => "warn",
            None => "fail",
        }
        .to_string(),
        version: probe.as_ref().and_then(first_output_line),
        exit_code: probe.and_then(|output| output.exit_code),
    }
}

fn toolchain_state(repo_root: &Path, runner: &dyn CommandRunner, command: &[&str]) -> Value {
    let path = executable_path(command[0]);
    let probe = path.as_ref().and_then(|_| {
        runner.run_with(
            command[0],
            &command[1..],
            Some(repo_root),
            Some(&build_env(repo_root)),
            Some(Duration::from_secs(30)),
        )
    });
    json!(ToolchainState {
        path: path.map(|path| path.display().to_string()),
        status: match &probe {
            Some(output) if output.success => "pass",
            Some(_) => "warn",
            None => "fail",
        }
        .to_string(),
        version: probe.as_ref().and_then(first_output_line),
        exit_code: probe.and_then(|output| output.exit_code),
    })
}

fn first_output_line(output: &crate::process::ProcessOutput) -> Option<String> {
    let trimmed = output.stdout.trim();
    (!trimmed.is_empty()).then(|| trimmed.lines().next().unwrap_or_default().to_string())
}

fn migration_candidate(repo_root: &Path) -> Map<String, Value> {
    let mut candidate = Map::new();
    for (key, value) in [
        ("c_file", "components/gvm-libs/base/version.c"),
        ("header", "components/gvm-libs/base/version.h"),
        ("test_file", "components/gvm-libs/base/version_tests.c"),
        (
            "reason",
            "Tiny production-adjacent C module with existing test coverage; suitable for non-production dry-run translation only.",
        ),
    ] {
        candidate.insert(key.to_string(), json!(value));
    }
    for key in ["c_file", "header", "test_file"] {
        let path = candidate[key].as_str().unwrap_or_default();
        candidate.insert(
            format!("{key}_exists"),
            json!(repo_root.join(path).is_file()),
        );
    }
    candidate.insert(
        "production_replacement_allowed_in_current_slice".to_string(),
        json!(false),
    );
    candidate.insert(
        "production_replacement_requirements".to_string(),
        json!([
            "CMake/Rust integration for the owning C library",
            "exported C ABI if retained C callers continue to call the symbol",
            "version-string injection equivalent to current GVM_LIBS_VERSION handling",
            "preserved upstream license notices plus TurboVAS modification notice where required",
            "existing C test parity and Rust-side tests before deleting the C implementation",
        ]),
    );
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;

    #[test]
    fn candidate_requires_all_three_source_files() {
        let root =
            std::env::temp_dir().join(format!("yafvsctl-rust-migration-{}", std::process::id()));
        std::fs::create_dir_all(root.join("components/gvm-libs/base")).unwrap();
        std::fs::write(root.join("components/gvm-libs/base/version.c"), b"c").unwrap();
        let candidate = migration_candidate(&root);
        assert_eq!(candidate["c_file_exists"], json!(true));
        assert_eq!(candidate["header_exists"], json!(false));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_output_line_ignores_empty_output() {
        let output = ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: "\n".to_string(),
            stderr: String::new(),
        };
        assert_eq!(first_output_line(&output), None);
    }
}
