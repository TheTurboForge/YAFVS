// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ordinary component configure and build orchestration.

use super::common::{build_env, metadata, output_tail};
use super::compose::{compose_command, runtime_environment};
use super::deps::{
    BASELINE_CHAIN, BuildMeta, C_SERVICES_CHAIN, CORE_C_CHAIN, PYTHON_CHAIN, build_meta,
};
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const GSA_OPERATION_LOCK: &str = "gsa-quality";
const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];

pub fn command_configure(
    repo_root: &Path,
    component: &str,
    profile: Option<&str>,
) -> ResultEnvelope {
    command_configure_with_runner(repo_root, component, profile, &SystemCommandRunner)
}

pub fn command_build(
    repo_root: &Path,
    component: &str,
    install: bool,
    configure_first: bool,
    profile: Option<&str>,
) -> ResultEnvelope {
    command_build_with_runner(
        repo_root,
        component,
        install,
        configure_first,
        profile,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

pub fn command_build_core_c(repo_root: &Path, profile: Option<&str>) -> ResultEnvelope {
    command_build_chain(
        repo_root,
        "build-core-c",
        CORE_C_CHAIN,
        profile,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

pub fn command_build_c_services(repo_root: &Path, profile: Option<&str>) -> ResultEnvelope {
    command_build_chain(
        repo_root,
        "build-c-services",
        C_SERVICES_CHAIN,
        profile,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

pub fn command_build_python(repo_root: &Path) -> ResultEnvelope {
    command_build_chain(
        repo_root,
        "build-python",
        PYTHON_CHAIN,
        None,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

pub fn command_build_baseline(repo_root: &Path) -> ResultEnvelope {
    command_build_chain(
        repo_root,
        "build-baseline",
        BASELINE_CHAIN,
        None,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

pub fn command_build_ui(repo_root: &Path) -> ResultEnvelope {
    command_build_ui_with_runner(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_configure_with_runner(
    repo_root: &Path,
    component: &str,
    profile: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    if let Some(profile) = profile {
        return profile_failure(repo_root, "configure", profile, runner);
    }
    let Some(meta) = build_meta(component) else {
        return unknown_component(repo_root, "configure", component, runner);
    };
    if meta.build_system != "cmake" {
        return make_result(
            metadata(repo_root, "configure", runner),
            format!("{component} is not a CMake component."),
            vec![Finding::new(
                "warn",
                "build.unsupported",
                format!("{component} uses {}, not cmake.", meta.build_system),
            )],
        );
    }
    if let Some(result) = live_app_build_guard(repo_root, "configure", runner) {
        return result;
    }
    let (build, output) = match cmake_configure(repo_root, meta, runner) {
        Ok(result) => result,
        Err(error) => {
            return make_result(
                metadata(repo_root, "configure", runner),
                format!("Configure {component} failed before CMake could start."),
                vec![Finding::new("fail", "cmake.configure", error)],
            );
        }
    };
    let status = process_status(&output);
    make_result(
        metadata(repo_root, "configure", runner),
        format!(
            "Configure {component} completed with exit code {}.",
            process_exit(&output)
        ),
        vec![
            Finding::new(
                status,
                "cmake.configure",
                format!(
                    "{component} configure {}.",
                    if output.success {
                        "succeeded"
                    } else {
                        "failed"
                    }
                ),
            )
            .with_path(&relative(repo_root, &build))
            .with_details(json!({"output_tail": output_tail(&output.stdout, 80)})),
        ],
    )
    .with_artifacts(vec![relative(repo_root, &build)])
}

#[allow(clippy::too_many_arguments)]
fn command_build_with_runner(
    repo_root: &Path,
    component: &str,
    install: bool,
    configure_first: bool,
    profile: Option<&str>,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    if let Some(profile) = profile {
        return profile_failure(repo_root, "build", profile, runner);
    }
    let operation = format!("build {component}");
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, &operation, timeout) {
            Ok(lock) => lock,
            Err(error) => {
                return lock_failure(
                    repo_root,
                    "build",
                    format!("Build {component} stopped while waiting for the feed lifecycle lock."),
                    "feed-generation.activation-lock",
                    error,
                    runner,
                );
            }
        };
    command_build_unlocked(
        repo_root,
        component,
        install,
        configure_first,
        runner,
        timeout,
    )
}

fn command_build_unlocked(
    repo_root: &Path,
    component: &str,
    install: bool,
    configure_first: bool,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let Some(meta) = build_meta(component) else {
        return unknown_component(repo_root, "build", component, runner);
    };
    if meta.name != "gsa"
        && let Some(result) = live_app_build_guard(repo_root, "build", runner)
    {
        return result;
    }
    match meta.build_system {
        "cmake" => build_cmake(repo_root, meta, install, configure_first, runner),
        "node-npm" => build_node(repo_root, meta, runner, timeout),
        "python-uv" | "python-poetry-core" => build_python_component(repo_root, meta, runner),
        other => make_result(
            metadata(repo_root, "build", runner),
            format!("{component} is not a CMake component."),
            vec![Finding::new(
                "warn",
                "build.unsupported",
                format!("{component} uses {other}, not cmake."),
            )],
        ),
    }
}

fn build_cmake(
    repo_root: &Path,
    meta: &BuildMeta,
    install: bool,
    configure_first: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let (_, build, prefix) = cmake_paths(repo_root, meta.name);
    let mut findings = Vec::new();
    if configure_first {
        let output = match cmake_configure(repo_root, meta, runner) {
            Ok((_, output)) => output,
            Err(error) => {
                return make_result(
                    metadata(repo_root, "build", runner),
                    format!("Build {} stopped at configure.", meta.name),
                    vec![Finding::new("fail", "cmake.configure", error)],
                )
                .with_artifacts(vec![relative(repo_root, &build)]);
            }
        };
        findings.push(process_finding(
            "cmake.configure",
            format!(
                "{} configure exit code {}.",
                meta.name,
                process_exit(&output)
            ),
            &build,
            repo_root,
            &output,
            60,
        ));
        if !output.success {
            return make_result(
                metadata(repo_root, "build", runner),
                format!("Build {} stopped at configure.", meta.name),
                findings,
            )
            .with_artifacts(vec![relative(repo_root, &build)]);
        }
    }
    let environment = build_env(repo_root);
    let output = run(
        runner,
        "cmake",
        vec![
            "--build".into(),
            build.display().to_string(),
            "--parallel".into(),
        ],
        repo_root,
        &environment,
    );
    findings.push(process_finding(
        "cmake.build",
        format!("{} build exit code {}.", meta.name, process_exit(&output)),
        &build,
        repo_root,
        &output,
        80,
    ));
    if output.success && (install || meta.install_for_dependents) {
        let output = run(
            runner,
            "cmake",
            vec!["--install".into(), build.display().to_string()],
            repo_root,
            &environment,
        );
        findings.push(process_finding(
            "cmake.install",
            format!("{} install exit code {}.", meta.name, process_exit(&output)),
            &prefix,
            repo_root,
            &output,
            60,
        ));
    }
    make_result(
        metadata(repo_root, "build", runner),
        format!("Build {} completed.", meta.name),
        findings,
    )
    .with_artifacts(vec![
        relative(repo_root, &build),
        relative(repo_root, &prefix),
    ])
}

fn build_node(
    repo_root: &Path,
    meta: &BuildMeta,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let _lock = if meta.name == "gsa" {
        match RuntimeOperationLock::acquire(
            repo_root,
            GSA_OPERATION_LOCK,
            &format!("build {}", meta.name),
            timeout,
        ) {
            Ok(lock) => Some(lock),
            Err(error) => {
                return lock_failure(
                    repo_root,
                    "build",
                    format!(
                        "Build {} stopped while waiting for the GSA operation lock.",
                        meta.name
                    ),
                    "gsa.lock",
                    error,
                    runner,
                );
            }
        }
    } else {
        None
    };
    let path = repo_root.join("components").join(meta.name);
    let environment = build_env(repo_root);
    let mut findings = Vec::new();
    let output = run(runner, "npm", vec!["ci".into()], &path, &environment);
    findings.push(process_finding(
        "npm.ci",
        format!("{} npm ci exit code {}.", meta.name, process_exit(&output)),
        &path,
        repo_root,
        &output,
        80,
    ));
    if !output.success {
        return make_result(
            metadata(repo_root, "build", runner),
            format!("Build {} stopped at npm ci.", meta.name),
            findings,
        )
        .with_artifacts(vec![format!("components/{}/node_modules", meta.name)]);
    }
    for script in meta.node_scripts {
        let output = run(
            runner,
            "npm",
            vec!["run".into(), (*script).into()],
            &path,
            &environment,
        );
        findings.push(
            process_finding(
                "npm.script",
                format!(
                    "{} npm run {script} exit code {}.",
                    meta.name,
                    process_exit(&output)
                ),
                &path,
                repo_root,
                &output,
                80,
            )
            .with_details(json!({
                "script": script,
                "output_tail": output_tail(&output.stdout, 80),
            })),
        );
        if !output.success {
            break;
        }
    }
    make_result(
        metadata(repo_root, "build", runner),
        format!("Build {} completed.", meta.name),
        findings,
    )
    .with_artifacts(vec![
        format!("components/{}/node_modules", meta.name),
        format!("components/{}/build", meta.name),
    ])
}

fn build_python_component(
    repo_root: &Path,
    meta: &BuildMeta,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let component_path = repo_root.join("components").join(meta.name);
    let venv = repo_root.join("build/venvs").join(meta.name);
    let python = venv.join("bin/python");
    let environment = build_env(repo_root);
    let mut findings = Vec::new();
    let output = run(
        runner,
        "uv",
        vec!["venv".into(), "--clear".into(), venv.display().to_string()],
        repo_root,
        &environment,
    );
    findings.push(process_finding(
        "python.venv",
        format!("{} uv venv exit code {}.", meta.name, process_exit(&output)),
        &venv,
        repo_root,
        &output,
        40,
    ));
    if !output.success {
        return python_result(
            repo_root,
            meta,
            "stopped at venv creation",
            findings,
            runner,
        );
    }
    for local_dep in meta.python_local_deps {
        let dep_path = repo_root.join("components").join(local_dep);
        let output = run(
            runner,
            "uv",
            vec![
                "pip".into(),
                "install".into(),
                "--python".into(),
                python.display().to_string(),
                "-e".into(),
                dep_path.display().to_string(),
            ],
            repo_root,
            &environment,
        );
        findings.push(
            process_finding(
                "python.local-dep",
                format!(
                    "{} install local dependency {local_dep} exit code {}.",
                    meta.name,
                    process_exit(&output)
                ),
                &dep_path,
                repo_root,
                &output,
                60,
            )
            .with_details(json!({
                "dependency": local_dep,
                "output_tail": output_tail(&output.stdout, 60),
            })),
        );
        if !output.success {
            return python_result(
                repo_root,
                meta,
                &format!("stopped at local dependency {local_dep}"),
                findings,
                runner,
            );
        }
    }
    let output = run(
        runner,
        "uv",
        vec![
            "pip".into(),
            "install".into(),
            "--python".into(),
            python.display().to_string(),
            "-e".into(),
            component_path.display().to_string(),
        ],
        repo_root,
        &environment,
    );
    findings.push(process_finding(
        "python.install",
        format!(
            "{} editable install exit code {}.",
            meta.name,
            process_exit(&output)
        ),
        &component_path,
        repo_root,
        &output,
        80,
    ));
    if !output.success {
        return python_result(repo_root, meta, "stopped at install", findings, runner);
    }
    for import_name in meta.python_imports {
        let output = run(
            runner,
            &python.display().to_string(),
            vec!["-c".into(), format!("import {import_name}")],
            repo_root,
            &environment,
        );
        findings.push(
            process_finding(
                "python.import",
                format!(
                    "{} import {import_name} exit code {}.",
                    meta.name,
                    process_exit(&output)
                ),
                &component_path,
                repo_root,
                &output,
                40,
            )
            .with_details(json!({
                "import": import_name,
                "output_tail": output_tail(&output.stdout, 40),
            })),
        );
        if !output.success {
            break;
        }
    }
    python_result(repo_root, meta, "completed", findings, runner)
}

fn python_result(
    repo_root: &Path,
    meta: &BuildMeta,
    state: &str,
    findings: Vec<Finding>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, "build", runner),
        format!("Build {} {state}.", meta.name),
        findings,
    )
    .with_artifacts(vec![format!("build/venvs/{}", meta.name)])
}

fn command_build_chain(
    repo_root: &Path,
    command: &str,
    chain: &[&str],
    profile: Option<&str>,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    if let Some(profile) = profile {
        return profile_failure(repo_root, command, profile, runner);
    }
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, command, timeout) {
            Ok(lock) => lock,
            Err(error) => {
                return lock_failure(
                    repo_root,
                    command,
                    format!("{command} stopped while waiting for the feed lifecycle lock."),
                    "feed-generation.activation-lock",
                    error,
                    runner,
                );
            }
        };
    build_chain_unlocked(repo_root, command, chain, runner, timeout)
}

fn build_chain_unlocked(
    repo_root: &Path,
    command: &str,
    chain: &[&str],
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let mut artifacts = BTreeSet::new();
    for component in chain {
        let Some(meta) = build_meta(component) else {
            findings.push(Finding::new(
                "fail",
                &format!("{command}.component"),
                format!("Build chain contains unknown component {component}."),
            ));
            break;
        };
        let mut result = command_build_unlocked(
            repo_root,
            component,
            meta.install_for_dependents,
            true,
            runner,
            timeout,
        );
        artifacts.extend(result.artifacts.iter().cloned());
        findings.push(
            Finding::new(
                &result.status,
                &format!("{command}.component"),
                format!("{component}: {}", result.summary),
            )
            .with_details(json!({"component": component})),
        );
        for mut finding in result.findings.drain(..) {
            finding.check = format!("{component}.{}", finding.check);
            findings.push(finding);
        }
        if result.status == "fail" {
            break;
        }
    }
    make_result(
        metadata(repo_root, command, runner),
        format!("{command} attempted."),
        findings,
    )
    .with_artifacts(artifacts.into_iter().collect())
}

fn command_build_ui_with_runner(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, "build-ui", timeout) {
            Ok(lock) => lock,
            Err(error) => {
                return lock_failure(
                    repo_root,
                    "build-ui",
                    "Web UI build stopped while waiting for the feed lifecycle lock.".into(),
                    "feed-generation.activation-lock",
                    error,
                    runner,
                );
            }
        };
    let mut result = command_build_unlocked(repo_root, "gsa", false, true, runner, timeout);
    if result.status == "pass" {
        result.findings.push(Finding::new(
            "pass",
            "gsa.deployment-deferred",
            "Web UI build completed without changing the prepared or running application deployment; runtime-app-build stages it explicitly.".into(),
        ));
    }
    make_result(
        metadata(repo_root, "build-ui", runner),
        "Web UI build completed.".into(),
        result.findings,
    )
    .with_artifacts(result.artifacts)
}

fn cmake_paths(repo_root: &Path, component: &str) -> (PathBuf, PathBuf, PathBuf) {
    (
        repo_root.join("components").join(component),
        repo_root.join("build").join(component),
        repo_root.join("build/prefix"),
    )
}

fn cmake_arguments(repo_root: &Path, meta: &BuildMeta) -> Vec<String> {
    let (source, build, prefix) = cmake_paths(repo_root, meta.name);
    let run_dir = repo_root.join("build/run/gvm");
    let gvmd_run_dir = repo_root.join("build/run/gvmd");
    let gsad_run_dir = repo_root.join("build/run/gsad");
    let state_dir = repo_root.join("build/var");
    let log_dir = repo_root.join("build/logs");
    let sysconf_dir = prefix.join("etc");
    let mut arguments = vec![
        "-S".into(),
        source.display().to_string(),
        "-B".into(),
        build.display().to_string(),
        "-G".into(),
        "Ninja".into(),
        format!("-DCMAKE_INSTALL_PREFIX={}", prefix.display()),
        format!("-DCMAKE_PREFIX_PATH={}", prefix.display()),
        format!("-DSYSCONFDIR={}", sysconf_dir.display()),
        format!("-DLOCALSTATEDIR={}", state_dir.display()),
        format!("-DGVM_RUN_DIR={}", run_dir.display()),
        format!("-DGVMD_RUN_DIR={}", gvmd_run_dir.display()),
        format!("-DGSAD_RUN_DIR={}", gsad_run_dir.display()),
        format!("-DGVM_STATE_DIR={}", state_dir.join("lib/gvm").display()),
        format!(
            "-DGVMD_STATE_DIR={}",
            state_dir.join("lib/gvm/gvmd").display()
        ),
        format!("-DGVM_LOG_DIR={}", log_dir.display()),
    ];
    arguments.extend(meta.cmake_args.iter().map(|argument| (*argument).into()));
    if meta.name == "pg-gvm" {
        arguments.push(format!("-DCMAKE_INSTALL_DEV_PREFIX={}", prefix.display()));
    }
    arguments
}

fn cmake_configure(
    repo_root: &Path,
    meta: &BuildMeta,
    runner: &dyn CommandRunner,
) -> Result<(PathBuf, ProcessOutput), String> {
    let (_, build, prefix) = cmake_paths(repo_root, meta.name);
    fs::create_dir_all(&build)
        .map_err(|error| format!("Could not create {}: {error}", build.display()))?;
    fs::create_dir_all(&prefix)
        .map_err(|error| format!("Could not create {}: {error}", prefix.display()))?;
    let environment = build_env(repo_root);
    let output = run(
        runner,
        "cmake",
        cmake_arguments(repo_root, meta),
        repo_root,
        &environment,
    );
    Ok((build, output))
}

fn live_app_build_guard(
    repo_root: &Path,
    command: &str,
    runner: &dyn CommandRunner,
) -> Option<ResultEnvelope> {
    let running = running_app_services(repo_root, runner);
    if running.is_empty() {
        return None;
    }
    Some(make_result(
        metadata(repo_root, command, runner),
        "Build refused because running application services consume bind-mounted build artifacts."
            .into(),
        vec![
            Finding::new(
                "fail",
                "runtime.app-services-stopped",
                "Stop the application deployment with runtime-app-down before changing runtime build artifacts.".into(),
            )
            .with_details(json!({"running_services": running})),
        ],
    ))
}

fn running_app_services(repo_root: &Path, runner: &dyn CommandRunner) -> Vec<String> {
    let environment = runtime_environment(repo_root);
    APP_SERVICES
        .into_iter()
        .filter(|service| {
            let arguments =
                compose_command(repo_root, &["ps".into(), "-q".into(), (*service).into()]);
            let output = run(runner, "docker", arguments, repo_root, &environment);
            output.success && !output.stdout.trim().is_empty()
        })
        .map(str::to_string)
        .collect()
}

fn profile_failure(
    repo_root: &Path,
    command: &str,
    profile: &str,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, command, runner),
        format!("Build profile {profile} is not yet owned by the ordinary Rust build layer."),
        vec![Finding::new(
            "fail",
            "build.profile-unsupported",
            format!("Profile {profile} requires the separately reviewed hardened build layer."),
        )],
    )
}

fn unknown_component(
    repo_root: &Path,
    command: &str,
    component: &str,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, command, runner),
        format!("Unknown component {component}."),
        vec![Finding::new(
            "fail",
            "component.known",
            format!("Unknown component {component}."),
        )],
    )
}

fn lock_failure(
    repo_root: &Path,
    command: &str,
    summary: String,
    check: &str,
    error: RuntimeLockError,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let finding = match error {
        RuntimeLockError::Timeout {
            name,
            operation,
            holder,
        } => Finding::new(
            "fail",
            check,
            format!("Timed out waiting for runtime lock '{name}'; another operation may still be running."),
        )
        .with_details(json!({"operation": operation, "holder": holder})),
        RuntimeLockError::Setup(error) => Finding::new(
            "fail",
            check,
            format!("Runtime operation lock failed closed: {error}"),
        ),
    };
    make_result(metadata(repo_root, command, runner), summary, vec![finding])
}

fn process_finding(
    check: &str,
    message: String,
    path: &Path,
    repo_root: &Path,
    output: &ProcessOutput,
    tail_lines: usize,
) -> Finding {
    Finding::new(process_status(output), check, message)
        .with_path(&relative(repo_root, path))
        .with_details(json!({"output_tail": output_tail(&output.stdout, tail_lines)}))
}

fn process_status(output: &ProcessOutput) -> &'static str {
    if output.success { "pass" } else { "fail" }
}

fn process_exit(output: &ProcessOutput) -> String {
    output
        .exit_code
        .map_or_else(|| "unavailable".into(), |code| code.to_string())
}

fn run(
    runner: &dyn CommandRunner,
    program: &str,
    arguments: Vec<String>,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> ProcessOutput {
    let refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with(program, &refs, Some(cwd), Some(environment), None)
        .unwrap_or_else(|| ProcessOutput {
            success: false,
            exit_code: None,
            stdout: format!("Could not execute {program}."),
            stderr: String::new(),
        })
}

fn relative(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockRunner {
        outputs: Mutex<Vec<ProcessOutput>>,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().rev().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.run_with(program, args, None, None, None)
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|item| (*item).to_string()).collect(),
            ));
            self.outputs.lock().unwrap().pop()
        }
    }

    fn output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn ordinary_cmake_arguments_preserve_component_contracts() {
        let root = Path::new("/repo");
        let gvmd = cmake_arguments(root, build_meta("gvmd").unwrap());
        assert_eq!(
            &gvmd[..6],
            [
                "-S",
                "/repo/components/gvmd",
                "-B",
                "/repo/build/gvmd",
                "-G",
                "Ninja"
            ]
        );
        assert!(gvmd.contains(&"-DENABLE_AGENTS=0".into()));
        assert!(gvmd.contains(&"-DWITH_LIBTHEIA=0".into()));
        assert!(!gvmd.iter().any(|argument| argument == "--fresh"));

        let pg_gvm = cmake_arguments(root, build_meta("pg-gvm").unwrap());
        assert_eq!(
            pg_gvm.last().map(String::as_str),
            Some("-DCMAKE_INSTALL_DEV_PREFIX=/repo/build/prefix")
        );
    }

    #[test]
    fn profile_rejection_does_not_run_build_or_compose_processes() {
        let runner = MockRunner::new(vec![output(true, "")]);
        let result =
            command_configure_with_runner(Path::new("/repo"), "gvmd", Some("hardened"), &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "build.profile-unsupported");
        assert!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(program, _)| program == "git")
        );
    }

    #[test]
    fn successful_nonempty_compose_query_refuses_a_live_artifact_build() {
        let runner = MockRunner::new(vec![
            output(true, ""),
            output(true, "container-id\n"),
            output(false, "error"),
            output(true, ""),
            output(true, ""),
            output(true, "deadbeef\n"),
        ]);
        let result = live_app_build_guard(Path::new("/repo"), "build", &runner).unwrap();
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "runtime.app-services-stopped");
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["running_services"],
            json!(["ospd-openvas"])
        );
    }

    #[test]
    fn python_and_node_metadata_construct_exact_commands() {
        assert_eq!(build_meta("gsa").unwrap().node_scripts, ["build"]);
        assert_eq!(
            build_meta("greenbone-feed-sync").unwrap().python_imports,
            ["greenbone.feed.sync"]
        );
        assert_eq!(
            build_meta("notus-scanner").unwrap().python_imports,
            ["notus.scanner"]
        );
    }
}
