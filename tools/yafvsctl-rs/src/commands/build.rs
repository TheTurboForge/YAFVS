// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Component configure and build orchestration.

use super::build_hardening;
use super::c_hardening::command_c_hardening_manifest_write;
use super::common::{build_env, ensure_real_directory_tree, metadata, output_tail};
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
    command_build_c_services_with_runner(
        repo_root,
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
    if let Some(profile) = profile.filter(|profile| *profile != build_hardening::PROFILE) {
        return profile_failure(repo_root, "configure", profile, runner);
    }
    let Some(meta) = build_meta(component) else {
        return unknown_component(repo_root, "configure", component, runner);
    };
    if meta.build_system != "cmake" {
        if let Some(profile) = profile {
            return non_cmake_profile_failure(
                repo_root,
                "configure",
                component,
                meta.build_system,
                profile,
                runner,
            );
        }
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
    if profile.is_none()
        && let Some(result) = live_app_build_guard(repo_root, "configure", runner)
    {
        return result;
    }
    let _lock = if profile == Some(build_hardening::PROFILE) {
        match RuntimeOperationLock::acquire(
            repo_root,
            FEED_ACTIVATION_LOCK,
            &format!("configure {component}"),
            DEFAULT_RUNTIME_LOCK_TIMEOUT,
        ) {
            Ok(lock) => Some(lock),
            Err(error) => {
                return lock_failure(
                    repo_root,
                    "configure",
                    format!(
                        "Configure {component} stopped while waiting for the feed lifecycle lock."
                    ),
                    "feed-generation.activation-lock",
                    error,
                    runner,
                );
            }
        }
    } else {
        None
    };
    let (build, output) = match cmake_configure(repo_root, meta, profile, runner) {
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
    if let Some(profile) = profile.filter(|profile| *profile != build_hardening::PROFILE) {
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
        profile,
        runner,
        timeout,
    )
}

fn command_build_unlocked(
    repo_root: &Path,
    component: &str,
    install: bool,
    configure_first: bool,
    profile: Option<&str>,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let Some(meta) = build_meta(component) else {
        return unknown_component(repo_root, "build", component, runner);
    };
    if let Some(profile) = profile
        && meta.build_system != "cmake"
    {
        return non_cmake_profile_failure(
            repo_root,
            "build",
            component,
            meta.build_system,
            profile,
            runner,
        );
    }
    if profile.is_none()
        && meta.name != "gsa"
        && let Some(result) = live_app_build_guard(repo_root, "build", runner)
    {
        return result;
    }
    match meta.build_system {
        "cmake" => build_cmake(repo_root, meta, install, configure_first, profile, runner),
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
    profile: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let (_, build, prefix) = cmake_paths(repo_root, meta.name, profile);
    let mut findings = Vec::new();
    if configure_first {
        let output = match cmake_configure(repo_root, meta, profile, runner) {
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
    let environment = build_environment(repo_root, profile);
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
    if let Some(profile) = profile.filter(|profile| *profile != build_hardening::PROFILE) {
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
    build_chain_unlocked(repo_root, command, chain, profile, runner, timeout)
}

fn build_chain_unlocked(
    repo_root: &Path,
    command: &str,
    chain: &[&str],
    profile: Option<&str>,
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
            profile,
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
    let mut result = command_build_unlocked(repo_root, "gsa", false, true, None, runner, timeout);
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

fn cmake_paths(
    repo_root: &Path,
    component: &str,
    profile: Option<&str>,
) -> (PathBuf, PathBuf, PathBuf) {
    let build_root = profile.map_or_else(
        || repo_root.join("build"),
        |profile| repo_root.join("build").join(profile),
    );
    (
        repo_root.join("components").join(component),
        build_root.join(component),
        build_root.join("prefix"),
    )
}

fn cmake_arguments(
    repo_root: &Path,
    meta: &BuildMeta,
    profile: Option<&str>,
    profile_args: &[String],
) -> Vec<String> {
    let (source, build, prefix) = cmake_paths(repo_root, meta.name, profile);
    let run_dir = repo_root.join("build/run/gvm");
    let gvmd_run_dir = repo_root.join("build/run/gvmd");
    let gsad_run_dir = repo_root.join("build/run/gsad");
    let state_dir = repo_root.join("build/var");
    let log_dir = repo_root.join("build/logs");
    let sysconf_dir = prefix.join("etc");
    let mut arguments = Vec::new();
    if profile == Some(build_hardening::PROFILE) {
        arguments.push("--fresh".into());
    }
    arguments.extend(vec![
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
    ]);
    arguments.extend(meta.cmake_args.iter().map(|argument| (*argument).into()));
    arguments.extend_from_slice(profile_args);
    if meta.name == "pg-gvm" {
        arguments.push(format!("-DCMAKE_INSTALL_DEV_PREFIX={}", prefix.display()));
    }
    arguments
}

fn cmake_configure(
    repo_root: &Path,
    meta: &BuildMeta,
    profile: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<(PathBuf, ProcessOutput), String> {
    if profile == Some(build_hardening::PROFILE) {
        build_hardening::validate_profile_parent(repo_root)?;
        let (_, build, prefix) = cmake_paths(repo_root, meta.name, profile);
        build_hardening::validate_existing_profile_directory(repo_root, &build)?;
        build_hardening::validate_existing_profile_directory(repo_root, &prefix)?;
        if let Err(error) = build_hardening::cmake_fresh_support(repo_root, runner) {
            return Ok((
                cmake_paths(repo_root, meta.name, profile).1,
                synthetic_failure(2, error),
            ));
        }
    }
    let (_, build, prefix) = cmake_paths(repo_root, meta.name, profile);
    if profile == Some(build_hardening::PROFILE) {
        let build_relative = build
            .strip_prefix(repo_root)
            .map_err(|_| "hardened build path escaped the repository".to_string())?;
        let prefix_relative = prefix
            .strip_prefix(repo_root)
            .map_err(|_| "hardened prefix path escaped the repository".to_string())?;
        ensure_real_directory_tree(repo_root, build_relative)
            .map_err(|error| format!("Could not create {} safely: {error}", build.display()))?;
        ensure_real_directory_tree(repo_root, prefix_relative)
            .map_err(|error| format!("Could not create {} safely: {error}", prefix.display()))?;
    } else {
        fs::create_dir_all(&build)
            .map_err(|error| format!("Could not create {}: {error}", build.display()))?;
        fs::create_dir_all(&prefix)
            .map_err(|error| format!("Could not create {}: {error}", prefix.display()))?;
    }
    let profile_configuration = if profile == Some(build_hardening::PROFILE) {
        let configuration = build_hardening::profile_configuration(repo_root, runner)?;
        if !configuration.failed_required.is_empty() {
            return Ok((
                build,
                synthetic_failure(
                    2,
                    format!(
                        "Required hardened profile feature probe(s) failed: {}",
                        configuration.failed_required.join(", ")
                    ),
                ),
            ));
        }
        configuration.cmake_args
    } else {
        Vec::new()
    };
    let environment = build_environment(repo_root, profile);
    let output = run(
        runner,
        "cmake",
        cmake_arguments(repo_root, meta, profile, &profile_configuration),
        repo_root,
        &environment,
    );
    Ok((build, output))
}

fn command_build_c_services_with_runner(
    repo_root: &Path,
    profile: Option<&str>,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    if profile != Some(build_hardening::PROFILE) {
        return command_build_chain(
            repo_root,
            "build-c-services",
            C_SERVICES_CHAIN,
            profile,
            runner,
            timeout,
        );
    }
    let _lock = match RuntimeOperationLock::acquire(
        repo_root,
        FEED_ACTIVATION_LOCK,
        "build-c-services",
        timeout,
    ) {
        Ok(lock) => lock,
        Err(error) => {
            return lock_failure(
                repo_root,
                "build-c-services",
                "build-c-services stopped while waiting for the feed lifecycle lock.".into(),
                "feed-generation.activation-lock",
                error,
                runner,
            );
        }
    };
    let cleanup = build_hardening::preflight_cleanup(repo_root);
    if cleanup.status == "fail" {
        return make_result(
            metadata(repo_root, "build-c-services", runner),
            "Hardened build stopped during generated-tree cleanup.".into(),
            vec![cleanup],
        );
    }
    if let Err(error) = build_hardening::invalidate_manifest(repo_root) {
        return make_result(
            metadata(repo_root, "build-c-services", runner),
            "Hardened build stopped while invalidating prior evidence.".into(),
            vec![
                Finding::new(
                    "fail",
                    "build-c-services.hardening-manifest",
                    format!("Prior hardened manifest could not be removed: {error}."),
                )
                .with_path(build_hardening::BUILD_MANIFEST),
            ],
        );
    }
    let mut result = build_chain_unlocked(
        repo_root,
        "build-c-services",
        C_SERVICES_CHAIN,
        profile,
        runner,
        timeout,
    );
    result.findings.insert(0, cleanup);
    if result.status == "pass" {
        let mut manifest = command_c_hardening_manifest_write(repo_root);
        result.artifacts.extend(manifest.artifacts);
        result.findings.append(&mut manifest.findings);
    }
    let artifacts = result
        .artifacts
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    make_result(
        metadata(repo_root, "build-c-services", runner),
        result.summary,
        result.findings,
    )
    .with_artifacts(artifacts)
}

fn build_environment(repo_root: &Path, profile: Option<&str>) -> BTreeMap<OsString, OsString> {
    if profile == Some(build_hardening::PROFILE) {
        build_hardening::hardened_environment(repo_root)
    } else {
        build_env(repo_root)
    }
}

fn synthetic_failure(exit_code: i32, message: String) -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(exit_code),
        stdout: message,
        stderr: String::new(),
    }
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
        format!("Unknown build profile {profile}."),
        vec![Finding::new(
            "fail",
            "build.profile-unsupported",
            format!("Build profile {profile} is not supported."),
        )],
    )
}

fn non_cmake_profile_failure(
    repo_root: &Path,
    command: &str,
    component: &str,
    build_system: &str,
    profile: &str,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, command, runner),
        format!("{command} profile {profile} only supports CMake components."),
        vec![Finding::new(
            "fail",
            "build.profile-unsupported",
            format!("{component} uses {build_system}, not cmake."),
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

    struct AlwaysSuccessfulBuildRunner;

    impl CommandRunner for AlwaysSuccessfulBuildRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.run_with(program, args, None, None, None)
        }

        fn run_with(
            &self,
            _program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            Some(output(
                true,
                if args == ["--help"] {
                    "CMake help includes --fresh\n"
                } else {
                    "deadbeef\n"
                },
            ))
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
        let gvmd = cmake_arguments(root, build_meta("gvmd").unwrap(), None, &[]);
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

        let pg_gvm = cmake_arguments(root, build_meta("pg-gvm").unwrap(), None, &[]);
        assert_eq!(
            pg_gvm.last().map(String::as_str),
            Some("-DCMAKE_INSTALL_DEV_PREFIX=/repo/build/prefix")
        );
    }

    #[test]
    fn hardened_cmake_arguments_are_fresh_and_follow_component_flags() {
        let root = Path::new("/repo");
        let profile_args = vec![
            "-DCMAKE_BUILD_TYPE=Release".into(),
            "-DCMAKE_PROJECT_INCLUDE=/repo/build/hardened/yafvs-hardening.cmake".into(),
        ];
        let scanner = cmake_arguments(
            root,
            build_meta("openvas-scanner").unwrap(),
            Some(build_hardening::PROFILE),
            &profile_args,
        );
        assert_eq!(scanner[0], "--fresh");
        let component_flags = scanner
            .iter()
            .position(|argument| argument.starts_with("-DCMAKE_C_FLAGS="))
            .unwrap();
        let profile_flags = scanner
            .iter()
            .position(|argument| argument == "-DCMAKE_BUILD_TYPE=Release")
            .unwrap();
        assert!(component_flags < profile_flags);

        let pg_gvm = cmake_arguments(
            root,
            build_meta("pg-gvm").unwrap(),
            Some(build_hardening::PROFILE),
            &profile_args,
        );
        assert_eq!(
            pg_gvm.last().map(String::as_str),
            Some("-DCMAKE_INSTALL_DEV_PREFIX=/repo/build/hardened/prefix")
        );
    }

    #[test]
    fn hardened_configure_fails_before_creating_paths_without_fresh_support() {
        let parent =
            std::env::temp_dir().join(format!("yafvsctl-build-fresh-{}", std::process::id()));
        let root = parent.join("repo");
        fs::create_dir_all(&root).unwrap();
        let runner = MockRunner::new(vec![
            output(true, "CMake help without the required option"),
            output(true, "deadbeef\n"),
        ]);
        let result = command_configure_with_runner(
            &root,
            "gvm-libs",
            Some(build_hardening::PROFILE),
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert!(
            result.findings[0].details.as_ref().unwrap()["output_tail"]
                .as_array()
                .unwrap()
                .iter()
                .any(|line| line
                    .as_str()
                    .is_some_and(|line| line.contains("cmake >= 3.24")))
        );
        assert!(!root.join("build").exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn hardened_manifest_failure_downgrades_a_passing_mock_build_chain() {
        let parent =
            std::env::temp_dir().join(format!("yafvsctl-build-manifest-{}", std::process::id()));
        let root = parent.join("repo");
        fs::create_dir_all(&root).unwrap();
        let result = command_build_c_services_with_runner(
            &root,
            Some(build_hardening::PROFILE),
            &AlwaysSuccessfulBuildRunner,
            Duration::ZERO,
        );
        assert_eq!(result.status, "fail");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "build-c-services.hardening-manifest" && finding.status == "fail"
        }));
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn direct_hardened_configure_refuses_a_linked_component_tree() {
        let parent =
            std::env::temp_dir().join(format!("yafvsctl-build-linked-{}", std::process::id()));
        let root = parent.join("repo");
        let outside = parent.join("outside");
        fs::create_dir_all(root.join("build/hardened")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel"), "keep").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("build/hardened/gvm-libs")).unwrap();
        let runner = MockRunner::new(vec![output(true, "deadbeef\n")]);
        let result = command_configure_with_runner(
            &root,
            "gvm-libs",
            Some(build_hardening::PROFILE),
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "cmake.configure");
        assert_eq!(
            fs::read_to_string(outside.join("sentinel")).unwrap(),
            "keep"
        );
        assert!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(program, _)| program == "git")
        );
        fs::remove_file(root.join("build/hardened/gvm-libs")).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn hardened_service_cleanup_refuses_symlink_before_any_build_process() {
        let parent =
            std::env::temp_dir().join(format!("yafvsctl-build-cleanup-{}", std::process::id()));
        let root = parent.join("repo");
        let outside = parent.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel"), "keep").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("build")).unwrap();
        let runner = MockRunner::new(vec![output(true, "deadbeef\n")]);
        let result = command_build_c_services_with_runner(
            &root,
            Some(build_hardening::PROFILE),
            &runner,
            Duration::ZERO,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.findings[0].check,
            "build-c-services.hardened-preflight"
        );
        assert_eq!(
            fs::read_to_string(outside.join("sentinel")).unwrap(),
            "keep"
        );
        assert!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(program, _)| program == "git")
        );
        fs::remove_file(root.join("build")).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn unknown_profile_rejection_does_not_run_build_or_compose_processes() {
        let runner = MockRunner::new(vec![output(true, "")]);
        let result =
            command_configure_with_runner(Path::new("/repo"), "gvmd", Some("unknown"), &runner);
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
