// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::direct_posture::direct_posture_findings;
use super::license::command_license_report_with_runner;
use super::secret::{read_existing_runtime_secret, runtime_secret_path};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
#[cfg(test)]
use serde_json::Map;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const COMMAND: &str = "production-posture-check";
const ADMIN_SECRET: &str = "gvmd-admin-password";
const DEVELOPMENT_ADMIN_PASSWORD: &str = "admin";
const GSAD_PORT: &str = "19392";
const GSAD_CONTAINER_PORT: &str = "9392";
const APP_EXECUTION_MOUNT_SERVICES: [&str; 4] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad"];
const REQUIRED_DOCS: [&str; 7] = [
    "docs/USER_MANUAL.md",
    "docs/CHANGES_FROM_UPSTREAM.md",
    "docs/PRODUCTION_POSTURE.md",
    "docs/PUBLIC_RELEASE_READINESS.md",
    "docs/VALIDATION_STANDARDS.md",
    "UPSTREAMS.md",
    "LICENSE_AUDIT.md",
];
const CERT_FILES: [(&str, &str); 6] = [
    ("ca_key", "certs/private/CA/cakey.pem"),
    ("ca_cert", "certs/CA/cacert.pem"),
    ("server_key", "certs/private/CA/serverkey.pem"),
    ("server_cert", "certs/CA/servercert.pem"),
    ("client_key", "certs/private/CA/clientkey.pem"),
    ("client_cert", "certs/CA/clientcert.pem"),
];

struct LicenseGate {
    status: String,
    summary: String,
}

pub fn command_production_posture_check(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_production_posture_check_with_runner(repo_root, status_only, &SystemCommandRunner)
}

pub(crate) fn command_production_posture_check_with_runner(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let environment = runtime_environment(repo_root);
    let license_result = command_license_report_with_runner(
        repo_root,
        true,
        "source-public",
        "baseline",
        false,
        false,
        runner,
    );
    let license_gate = LicenseGate {
        status: license_result.status,
        summary: license_result.summary,
    };
    let direct_findings = direct_posture_findings(repo_root, &environment, runner);
    production_posture_result(
        repo_root,
        status_only,
        runner,
        &environment,
        license_gate,
        direct_findings,
    )
}

fn production_posture_result(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    license_gate: LicenseGate,
    direct_findings: Vec<Finding>,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    for relative in REQUIRED_DOCS {
        let exists = repo_root.join(relative).is_file();
        findings.push(
            Finding::new(
                if exists { "pass" } else { "fail" },
                "production.docs",
                format!(
                    "{relative} {}.",
                    if exists { "exists" } else { "is missing" }
                ),
            )
            .with_path(relative),
        );
    }

    let license_details = json!({
        "status": license_gate.status,
        "summary": license_gate.summary,
    });
    findings.push(
        Finding::new(
            if license_details["status"] == "pass" {
                "pass"
            } else {
                "fail"
            },
            "production.public-release-license-gate",
            if license_details["status"] == "pass" {
                "Public-release license gate passes.".to_string()
            } else {
                "Public-release license gate is not satisfied; do not publish or distribute."
                    .to_string()
            },
        )
        .with_details(license_details.clone()),
    );

    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    let credential_finding = match read_existing_runtime_secret(repo_root, ADMIN_SECRET) {
        Ok(Some(value)) if value == DEVELOPMENT_ADMIN_PASSWORD => Finding::new(
            "fail",
            "production.default-credentials",
            "Development admin password is still the default value; rotate before production exposure."
                .to_string(),
        ),
        Ok(Some(_)) => Finding::new(
            "pass",
            "production.default-credentials",
            "Development admin password is not the default value.".to_string(),
        ),
        Ok(None) => Finding::new(
            "warn",
            "production.default-credentials",
            "Development admin password secret is not initialized; verify first-login/password-rotation workflow before production."
                .to_string(),
        ),
        Err(error) => Finding::new(
            "fail",
            "production.default-credentials",
            "Development admin password secret could not be read safely.".to_string(),
        )
        .with_details(json!({ "error": error.to_string() })),
    }
    .with_path(&secret_path.display().to_string());
    findings.push(credential_finding);
    findings.push(Finding::new(
        "fail",
        "production.first-login-password-rotation",
        "Production first-login/password-rotation bootstrap is not implemented yet; do not deploy beyond private development."
            .to_string(),
    ));

    let hosts = gsad_hosts(environment);
    let wildcard = hosts.iter().any(|host| host_is_wildcard(host));
    let non_loopback = hosts.iter().any(|host| !host_is_loopback(host));
    let (binding_status, binding_message) = if wildcard {
        ("fail", "GSA is configured for broad wildcard host binding.")
    } else if non_loopback {
        (
            "warn",
            "GSA is configured for explicit non-loopback development access; review network exposure before production.",
        )
    } else {
        ("pass", "GSA host binding is loopback-only by default.")
    };
    let bindings = hosts
        .iter()
        .map(|host| format!("{host}:{GSAD_PORT}:{GSAD_CONTAINER_PORT}"))
        .collect::<Vec<_>>();
    findings.push(
        Finding::new(
            binding_status,
            "production.gsad-binding",
            binding_message.to_string(),
        )
        .with_details(json!({ "hosts": hosts, "bindings": bindings })),
    );
    findings.extend(direct_findings);

    let quiet_arguments =
        compose_command(repo_root, &["config".to_string(), "--quiet".to_string()]);
    let quiet = run_docker(runner, repo_root, environment, &quiet_arguments);
    let quiet_success = quiet.as_ref().is_some_and(|output| output.success);
    let quiet_exit = quiet
        .as_ref()
        .and_then(|output| output.exit_code)
        .unwrap_or(-1);
    let quiet_tail = quiet
        .as_ref()
        .map(|output| output_tail(&output.stdout, 40))
        .unwrap_or_default();
    findings.push(
        Finding::new(
            if quiet_success { "pass" } else { "fail" },
            "production.compose-config",
            format!("Compose config validation exit code {quiet_exit}."),
        )
        .with_path("compose/dev.yaml")
        .with_details(json!({ "output_tail": quiet_tail })),
    );
    findings.push(rendered_app_execution_mount_finding(
        repo_root,
        environment,
        runner,
    ));

    let root = runtime_dir(repo_root);
    let cert_paths = CERT_FILES
        .iter()
        .map(|(_, relative)| root.join(relative))
        .collect::<Vec<_>>();
    let certs_complete = cert_paths
        .iter()
        .all(|path| path.is_file() && path.metadata().is_ok_and(|item| item.len() > 0));
    findings.push(
        Finding::new(
            if certs_complete { "warn" } else { "fail" },
            "production.tls",
            if certs_complete {
                "Development TLS files exist, but trusted production certificates and hostname/SAN policy still need deployment review."
                    .to_string()
            } else {
                "Runtime TLS files are incomplete; production exposure requires a complete trusted TLS setup."
                    .to_string()
            },
        )
        .with_details(json!({
            "cert_files": cert_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
        })),
    );
    findings.push(Finding::new(
        "warn",
        "production.runtime-model",
        "The current Docker runtime is documented as development-only; production deployment architecture remains a release blocker."
            .to_string(),
    ));

    let mut result = make_result(
        metadata(repo_root, COMMAND, runner),
        "Production posture checklist completed.".to_string(),
        findings,
    )
    .with_details(json!({ "public_release_license_gate": license_details }));
    if status_only {
        result = production_posture_status_only_result(result);
    }
    result
}

fn run_docker(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    arguments: &[String],
) -> Option<crate::process::ProcessOutput> {
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with(
        "docker",
        &arguments,
        Some(repo_root),
        Some(environment),
        None,
    )
}

pub(crate) fn rendered_app_execution_mount_finding(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> Finding {
    let arguments = compose_command(
        repo_root,
        &[
            "--profile".to_string(),
            "app".to_string(),
            "config".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
    );
    let Some(rendered) = run_docker(runner, repo_root, environment, &arguments) else {
        return Finding::new(
            "fail",
            "production.app-execution-mounts",
            "Rendered Compose configuration could not be inspected for the exact source/build mount graph."
                .to_string(),
        )
        .with_path("compose/dev.yaml");
    };
    if !rendered.success {
        return Finding::new(
            "fail",
            "production.app-execution-mounts",
            "Rendered Compose configuration could not be inspected for the exact source/build mount graph."
                .to_string(),
        )
        .with_path("compose/dev.yaml");
    }
    let Ok(payload) = serde_json::from_str::<Value>(&rendered.stdout) else {
        return Finding::new(
            "fail",
            "production.app-execution-mounts",
            "Rendered Compose configuration was not valid JSON.".to_string(),
        )
        .with_path("compose/dev.yaml");
    };
    app_execution_mount_finding(repo_root, &payload)
}

fn app_execution_mount_finding(repo_root: &Path, compose_config: &Value) -> Finding {
    app_execution_mount_finding_with_runtime(repo_root, &runtime_dir(repo_root), compose_config)
}

fn app_execution_mount_finding_with_runtime(
    repo_root: &Path,
    runtime_root: &Path,
    compose_config: &Value,
) -> Finding {
    let services = compose_config.get("services").and_then(Value::as_object);
    let mut missing_services = Vec::new();
    let mut violations = Vec::new();
    let mut validated_mounts = Vec::new();

    let canonical_repo = match open_absolute_directory_nofollow(repo_root) {
        Ok((descriptor, path)) => {
            drop(descriptor);
            path
        }
        Err(error) => {
            return mount_root_failure(error);
        }
    };
    let canonical_runtime = match open_absolute_directory_nofollow(runtime_root) {
        Ok((descriptor, path)) => {
            drop(descriptor);
            path
        }
        Err(error) => {
            return mount_root_failure(error);
        }
    };
    if path_is_within(&canonical_runtime, &canonical_repo) {
        violations.push(json!({
            "reason": "runtime root is inside the repository",
            "source": canonical_runtime.display().to_string(),
        }));
    }

    let alias_target = canonical_repo.display().to_string();
    let mut required_mounts = BTreeMap::new();
    required_mounts.insert("/workspace".to_string(), (canonical_repo.clone(), true));
    required_mounts.insert(
        "/workspace/build".to_string(),
        (canonical_repo.join("build"), true),
    );
    required_mounts.insert(alias_target.clone(), (canonical_repo.clone(), true));

    for service_name in APP_EXECUTION_MOUNT_SERVICES {
        let Some(service) = services
            .and_then(|items| items.get(service_name))
            .and_then(Value::as_object)
        else {
            missing_services.push(service_name.to_string());
            continue;
        };
        let volumes = match service.get("volumes").and_then(Value::as_array) {
            Some(volumes) => volumes.as_slice(),
            None => {
                violations.push(json!({
                    "service": service_name,
                    "reason": "service volumes are not a list",
                }));
                &[]
            }
        };
        let overlays =
            app_execution_overlay_contract(&canonical_repo, &canonical_runtime, service_name);
        let mut expected_mounts = required_mounts.clone();
        expected_mounts.extend(overlays.clone());
        let mut target_counts = BTreeMap::<String, usize>::new();

        for (index, volume) in volumes.iter().enumerate() {
            let Some(volume) = volume.as_object() else {
                violations.push(json!({
                    "service": service_name,
                    "index": index,
                    "reason": "mount entry is not an object",
                }));
                continue;
            };
            let raw_target = value_text(volume.get("target"));
            let target = match normalize_compose_mount_target(&raw_target) {
                Ok(target) => target,
                Err(error) => {
                    violations.push(json!({
                        "service": service_name,
                        "index": index,
                        "target": raw_target,
                        "reason": error,
                    }));
                    continue;
                }
            };
            *target_counts.entry(target.clone()).or_default() += 1;
            let protected = posix_path_within(&target, "/workspace")
                || posix_path_within(&target, &alias_target);
            let Some((expected_source, expected_read_only)) = expected_mounts.get(&target) else {
                if protected {
                    violations.push(json!({
                        "service": service_name,
                        "index": index,
                        "target": target,
                        "reason": "non-allowlisted mount is nested under a protected target",
                    }));
                } else if volume.get("type").and_then(Value::as_str) == Some("bind")
                    && canonical_nofollow_mount_source(&value_text(volume.get("source")))
                        .is_ok_and(|(source, _)| path_is_within(&source, &canonical_repo))
                {
                    violations.push(json!({
                        "service": service_name,
                        "index": index,
                        "target": target,
                        "reason": "repository source is mounted outside the exact execution-mount contract",
                    }));
                }
                continue;
            };
            let mount_type = volume.get("type").and_then(Value::as_str).unwrap_or("");
            if mount_type != "bind" {
                violations.push(json!({
                    "service": service_name,
                    "index": index,
                    "target": target,
                    "reason": "protected mount must be a bind mount",
                    "type": mount_type,
                }));
                continue;
            }
            let source = match canonical_nofollow_mount_source(&value_text(volume.get("source"))) {
                Ok((source, _kind)) => source,
                Err(error) => {
                    violations.push(json!({
                        "service": service_name,
                        "index": index,
                        "target": target,
                        "reason": format!("bind source is unsafe: {error}"),
                    }));
                    continue;
                }
            };
            if source != *expected_source {
                violations.push(json!({
                    "service": service_name,
                    "index": index,
                    "target": target,
                    "source": source.display().to_string(),
                    "reason": format!("bind source must be {}", expected_source.display()),
                }));
                continue;
            }
            if overlays.contains_key(&target)
                && (!path_is_within(&source, &canonical_runtime)
                    || path_is_within(&source, &canonical_repo))
            {
                violations.push(json!({
                    "service": service_name,
                    "index": index,
                    "target": target,
                    "source": source.display().to_string(),
                    "reason": "runtime overlay source is not canonically outside the repository",
                }));
                continue;
            }
            let read_only = volume
                .get("read_only")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if read_only != *expected_read_only {
                violations.push(json!({
                    "service": service_name,
                    "index": index,
                    "target": target,
                    "reason": format!("read_only must be {expected_read_only}"),
                }));
                continue;
            }
            validated_mounts.push(json!({
                "service": service_name,
                "source": source.display().to_string(),
                "target": target,
                "read_only": expected_read_only,
            }));
        }

        for target in expected_mounts.keys() {
            let count = target_counts.get(target).copied().unwrap_or(0);
            if count != 1 {
                violations.push(json!({
                    "service": service_name,
                    "target": target,
                    "count": count,
                    "reason": "required mount must appear exactly once",
                }));
            }
        }
    }

    let passed = missing_services.is_empty() && violations.is_empty();
    Finding::new(
        if passed { "pass" } else { "fail" },
        "production.app-execution-mounts",
        if passed {
            "Target-facing application services match the exact source/build mount graph."
                .to_string()
        } else {
            "One or more target-facing application services violate the exact source/build mount graph."
                .to_string()
        },
    )
    .with_path("compose/dev.yaml")
    .with_details(json!({
        "services": APP_EXECUTION_MOUNT_SERVICES,
        "missing_services": missing_services,
        "violations": violations,
        "validated_mounts": validated_mounts,
    }))
}

fn mount_root_failure(error: io::Error) -> Finding {
    Finding::new(
        "fail",
        "production.app-execution-mounts",
        "Canonical repository or runtime mount roots could not be validated.".to_string(),
    )
    .with_path("compose/dev.yaml")
    .with_details(json!({
        "services": APP_EXECUTION_MOUNT_SERVICES,
        "violations": [{ "reason": error.to_string() }],
    }))
}

fn app_execution_overlay_contract(
    repo_root: &Path,
    runtime_root: &Path,
    service_name: &str,
) -> BTreeMap<String, (PathBuf, bool)> {
    let alias = repo_root.display().to_string();
    let mut overlays = BTreeMap::new();
    match service_name {
        "gvmd" => {
            overlays.insert(
                format!("{alias}/build/run/gvmd"),
                (runtime_root.join("run/gvmd"), false),
            );
            overlays.insert(
                format!("{alias}/build/logs"),
                (runtime_root.join("logs/gvmd"), false),
            );
            overlays.insert(
                format!("{alias}/build/var/lib/gvm/gvmd"),
                (runtime_root.join("state/gvmd"), false),
            );
            overlays.insert(
                format!("{alias}/build/var/lib/gvm/gvmd.sem"),
                (runtime_root.join("state/gvmd-bind-files/gvmd.sem"), false),
            );
        }
        "ospd-openvas" => {
            overlays.insert(
                "/workspace/build/prefix/etc/openvas/openvas.conf".to_string(),
                (runtime_root.join("state/ospd/openvas.conf"), true),
            );
        }
        "gsad" => {
            overlays.insert(
                format!("{alias}/build/logs"),
                (runtime_root.join("logs/gsad"), false),
            );
            overlays.insert(
                format!("{alias}/build/run/gsad"),
                (runtime_root.join("run/gsad"), false),
            );
        }
        _ => {}
    }
    overlays
}

fn normalize_compose_mount_target(target: &str) -> Result<String, &'static str> {
    if !target.starts_with('/') || target.starts_with("//") {
        return Err("mount target must be a normalized absolute path");
    }
    if target
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return Err("mount target contains dot path components");
    }
    let components = target
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    Ok(if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    })
}

fn posix_path_within(path: &str, parent: &str) -> bool {
    path == parent
        || (parent == "/" && path.starts_with('/'))
        || path
            .strip_prefix(parent)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn path_is_within(path: &Path, parent: &Path) -> bool {
    path == parent || path.starts_with(parent)
}

fn canonical_nofollow_mount_source(source: &str) -> io::Result<(PathBuf, &'static str)> {
    let path = clean_absolute_path(Path::new(source))?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bind source has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bind source has no name"))?;
    let (parent_fd, canonical_parent) = open_absolute_directory_nofollow(parent)?;
    let name = c_string(name)?;
    let before = stat_at_nofollow(&parent_fd, &name)?;
    let kind = before.st_mode & libc::S_IFMT;
    let kind_name = if kind == libc::S_IFDIR {
        "directory"
    } else if kind == libc::S_IFREG {
        "file"
    } else if kind == libc::S_IFLNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bind source is a symlink",
        ));
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bind source is a special file",
        ));
    };
    let descriptor = open_at(
        &parent_fd,
        &name,
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let after = stat_fd(&descriptor)?;
    if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
        return Err(io::Error::other("bind source changed while inspecting it"));
    }
    Ok((canonical_parent.join(path.file_name().unwrap()), kind_name))
}

fn open_absolute_directory_nofollow(path: &Path) -> io::Result<(OwnedFd, PathBuf)> {
    let absolute = clean_absolute_path(path)?;
    let root = CString::new("/").expect("static root path");
    // SAFETY: root is NUL-terminated and the flags are valid.
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new owned descriptor.
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    for component in absolute.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory path is not normalized",
            ));
        };
        let name = c_string(name)?;
        let before = stat_at_nofollow(&current, &name)?;
        let kind = before.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "directory path component is a symlink: {}",
                    absolute.display()
                ),
            ));
        }
        if kind != libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "directory path component is not a real directory: {}",
                    absolute.display()
                ),
            ));
        }
        let next = open_at(
            &current,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )?;
        let after = stat_fd(&next)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(io::Error::other(format!(
                "directory path changed while opening: {}",
                absolute.display()
            )));
        }
        current = next;
    }
    Ok((current, absolute))
}

fn clean_absolute_path(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        ));
    }
    let mut clean = PathBuf::from("/");
    for component in path.components().skip(1) {
        match component {
            Component::Normal(name) => clean.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path must be normalized",
                ));
            }
        }
    }
    Ok(clean)
}

fn c_string(value: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn stat_at_nofollow(directory: &OwnedFd, name: &CString) -> io::Result<libc::stat> {
    // SAFETY: zero is a valid initial representation for stat before fstatat fills it.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: directory and name are valid, and stat points to writable memory.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn open_at(directory: &OwnedFd, name: &CString, flags: i32) -> io::Result<OwnedFd> {
    // SAFETY: directory and name are valid and flags do not require a mode argument.
    let raw = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn stat_fd(descriptor: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: zero is a valid initial representation for stat before fstat fills it.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: descriptor is valid and stat points to writable memory.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn value_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string(),
    }
}

fn gsad_hosts(environment: &BTreeMap<OsString, OsString>) -> Vec<String> {
    let plural = environment
        .get(&OsString::from("YAFVS_GSAD_HOSTS"))
        .and_then(|value| value.to_str());
    let hosts = split_hosts(plural);
    if !hosts.is_empty() {
        return hosts;
    }
    let singular = environment
        .get(&OsString::from("YAFVS_GSAD_HOST"))
        .and_then(|value| value.to_str());
    let hosts = split_hosts(singular);
    if hosts.is_empty() {
        vec!["127.0.0.1".to_string()]
    } else {
        hosts
    }
}

fn split_hosts(value: Option<&str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .filter(|host| seen.insert((*host).to_string()))
        .map(str::to_string)
        .collect()
}

fn host_is_wildcard(host: &str) -> bool {
    matches!(
        host.trim().to_ascii_lowercase().trim_matches(['[', ']']),
        "0.0.0.0" | "::"
    )
}

fn host_is_loopback(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_matches(['[', ']']);
    matches!(host, "localhost" | "::1") || host.starts_with("127.")
}

fn production_posture_status_only_result(mut result: ResultEnvelope) -> ResultEnvelope {
    let sensitive_parts = ["secret", "token", "password", "credential", "bearer"];
    let sensitive = |value: &str| {
        let value = value.to_ascii_lowercase();
        sensitive_parts.iter().any(|part| value.contains(part))
    };
    let finding_count = result.findings.len();
    let mut findings = Vec::new();
    for finding in &result.findings {
        if finding.status == "pass" {
            continue;
        }
        let mut compact = compact_finding(finding);
        if compact
            .path
            .as_deref()
            .is_some_and(|path| path.starts_with('/') || sensitive(path))
        {
            compact.path = Some("[redacted]".to_string());
        }
        if let Some(Value::Object(details)) = compact.details.as_mut() {
            for (key, value) in details.iter_mut() {
                if sensitive(key) || sensitive(&value.to_string()) {
                    *value = Value::String("[redacted]".to_string());
                }
            }
        }
        findings.push(compact);
    }
    let license_status = result
        .details
        .as_ref()
        .and_then(|details| details.get("public_release_license_gate"))
        .and_then(|gate| gate.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let non_pass_count = findings.len();
    if findings.is_empty() {
        findings.push(Finding::new(
            "pass",
            "production-posture.status-only",
            "Production posture check passed; no non-pass findings.".to_string(),
        ));
    }
    result.findings = findings;
    result.details = Some(json!({
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
        "public_release_license_status": license_status,
    }));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::Metadata;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn fixture() -> (PathBuf, PathBuf, Value) {
        let base = std::env::temp_dir().join(format!(
            "yafvsctl-production-posture-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("YAFVS");
        let runtime = base.join("YAFVS-runtime");
        fs::create_dir_all(repo.join("build")).unwrap();
        for relative in [
            "logs/gvmd",
            "logs/gsad",
            "run/gvmd",
            "run/gsad",
            "state/gvmd",
            "state/gvmd-bind-files",
            "state/ospd",
        ] {
            fs::create_dir_all(runtime.join(relative)).unwrap();
        }
        fs::write(runtime.join("state/gvmd-bind-files/gvmd.sem"), "").unwrap();
        fs::write(
            runtime.join("state/ospd/openvas.conf"),
            "db_address = /runtime/run/redis-openvas/redis.sock\n",
        )
        .unwrap();
        let mut services = Map::new();
        for service in APP_EXECUTION_MOUNT_SERVICES {
            let mut volumes = vec![
                json!({"type": "bind", "source": repo, "target": "/workspace", "read_only": true}),
                json!({"type": "bind", "source": repo.join("build"), "target": "/workspace/build", "read_only": true}),
                json!({"type": "bind", "source": repo, "target": repo, "read_only": true}),
            ];
            for (target, (source, read_only)) in
                app_execution_overlay_contract(&repo, &runtime, service)
            {
                volumes.push(json!({
                    "type": "bind",
                    "source": source,
                    "target": target,
                    "read_only": read_only,
                }));
            }
            services.insert(service.to_string(), json!({ "volumes": volumes }));
        }
        (repo, runtime, json!({ "services": services }))
    }

    fn violations(finding: &Finding) -> &Vec<Value> {
        finding.details.as_ref().unwrap()["violations"]
            .as_array()
            .unwrap()
    }

    #[test]
    fn exact_application_mount_graph_passes() {
        let (repo, runtime, payload) = fixture();
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        assert_eq!(finding.status, "pass");
        assert!(violations(&finding).is_empty());
        assert_eq!(
            finding.details.as_ref().unwrap()["validated_mounts"]
                .as_array()
                .unwrap()
                .len(),
            19
        );
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn protected_mounts_reject_leading_double_slash_targets() {
        let (repo, runtime, mut payload) = fixture();
        payload["services"]["gsad"]["volumes"][0]["target"] =
            Value::String("//workspace".to_string());
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        assert!(violations(&finding).iter().any(|item| {
            item["reason"]
                .as_str()
                .unwrap()
                .contains("normalized absolute path")
        }));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn runtime_root_inside_repository_fails() {
        let (repo, runtime, payload) = fixture();
        let nested_runtime = repo.join("runtime");
        fs::rename(&runtime, &nested_runtime).unwrap();
        let finding = app_execution_mount_finding_with_runtime(&repo, &nested_runtime, &payload);
        assert!(
            violations(&finding)
                .iter()
                .any(|item| { item["reason"] == "runtime root is inside the repository" })
        );
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn malformed_service_volume_shapes_fail_closed() {
        let (repo, runtime, mut payload) = fixture();
        payload["services"]["gvmd"]["volumes"] = json!({ "unexpected": true });
        payload["services"]["gsad"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("not-an-object".to_string()));
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        let violations = violations(&finding);
        assert!(
            violations
                .iter()
                .any(|item| item["reason"] == "service volumes are not a list")
        );
        assert!(
            violations
                .iter()
                .any(|item| item["reason"] == "mount entry is not an object")
        );
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn protected_mounts_reject_named_volumes_and_source_replacement() {
        let (repo, runtime, mut payload) = fixture();
        payload["services"]["gvmd"]["volumes"][1] = json!({
            "type": "volume",
            "source": "build-bypass",
            "target": "/workspace/build",
        });
        payload["services"]["notus-scanner"]["volumes"][2]["source"] =
            Value::String("/tmp".to_string());
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        let violations = violations(&finding);
        assert!(
            violations
                .iter()
                .any(|item| item["type"] == "volume" && item["target"] == "/workspace/build")
        );
        assert!(violations.iter().any(|item| {
            item["source"] == "/tmp"
                && item["reason"]
                    .as_str()
                    .unwrap()
                    .contains("bind source must be")
        }));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn protected_mounts_reject_wrong_type_permissions_and_duplicates() {
        let (repo, runtime, mut payload) = fixture();
        let volumes = payload["services"]["gvmd"]["volumes"]
            .as_array_mut()
            .unwrap();
        volumes[0] = json!({"type": "tmpfs", "target": "/workspace"});
        volumes[1]["read_only"] = Value::Bool(false);
        volumes.push(volumes[2].clone());
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        let violations = violations(&finding);
        assert!(violations.iter().any(|item| item["type"] == "tmpfs"));
        assert!(
            violations
                .iter()
                .any(|item| item["target"] == "/workspace/build"
                    && item["reason"].as_str().unwrap().contains("read_only"))
        );
        assert!(
            violations
                .iter()
                .any(|item| item["target"] == repo.display().to_string() && item["count"] == 2)
        );
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn protected_mounts_reject_dotdot_and_nonallowlisted_nested_targets() {
        let (repo, runtime, mut payload) = fixture();
        let volumes = payload["services"]["ospd-openvas"]["volumes"]
            .as_array_mut()
            .unwrap();
        volumes[1]["target"] = Value::String("/workspace/../workspace/build".to_string());
        volumes.push(json!({
            "type": "bind",
            "source": runtime.join("logs/gvmd"),
            "target": "/workspace/build/extra",
            "read_only": true,
        }));
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        let violations = violations(&finding);
        assert!(violations.iter().any(|item| {
            item["reason"]
                .as_str()
                .unwrap()
                .contains("dot path components")
        }));
        assert!(
            violations
                .iter()
                .any(|item| item["target"] == "/workspace/build/extra"
                    && item["reason"].as_str().unwrap().contains("non-allowlisted"))
        );
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn runtime_overlay_symlink_is_rejected() {
        let (repo, runtime, payload) = fixture();
        fs::remove_dir(runtime.join("logs/gvmd")).unwrap();
        symlink(runtime.join("logs/gsad"), runtime.join("logs/gvmd")).unwrap();
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        assert!(violations(&finding).iter().any(|item| {
            item["reason"].as_str().unwrap().contains("symlink")
                && item["target"] == repo.join("build/logs").display().to_string()
        }));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn repository_source_cannot_escape_the_exact_contract() {
        let (repo, runtime, mut payload) = fixture();
        payload["services"]["notus-scanner"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "type": "bind",
                "source": repo.join("build"),
                "target": "/tmp/build",
                "read_only": true,
            }));
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        assert!(violations(&finding).iter().any(|item| {
            item["reason"]
                .as_str()
                .unwrap()
                .contains("mounted outside the exact")
        }));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn missing_service_and_mount_fail_closed() {
        let (repo, runtime, mut payload) = fixture();
        payload["services"].as_object_mut().unwrap().remove("gsad");
        payload["services"]["notus-scanner"]["volumes"]
            .as_array_mut()
            .unwrap()
            .pop();
        let finding = app_execution_mount_finding_with_runtime(&repo, &runtime, &payload);
        assert_eq!(finding.status, "fail");
        assert_eq!(
            finding.details.as_ref().unwrap()["missing_services"],
            json!(["gsad"])
        );
        assert!(violations(&finding).iter().any(|item| item["count"] == 0));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn status_only_omits_passes_and_redacts_sensitive_values() {
        let result = ResultEnvelope {
            status: "fail".to_string(),
            summary: "test".to_string(),
            findings: vec![
                Finding::new("pass", "pass", "pass".to_string()),
                Finding::new("fail", "secret-check", "fail".to_string())
                    .with_path("/runtime/secrets/token")
                    .with_details(json!({
                        "token_path": "/runtime/secrets/token",
                        "items": [1, 2],
                    })),
            ],
            artifacts: Vec::new(),
            metadata: Metadata {
                command: COMMAND.to_string(),
                generated_at: "2026-01-01T00:00:00Z".to_string(),
                repo_root: "/repo".to_string(),
                head: None,
            },
            details: Some(json!({
                "public_release_license_gate": { "status": "fail" }
            })),
        };
        let compact = production_posture_status_only_result(result);
        assert_eq!(compact.findings.len(), 1);
        assert_eq!(compact.findings[0].path.as_deref(), Some("[redacted]"));
        assert_eq!(
            compact.findings[0].details.as_ref().unwrap()["token_path"],
            "[redacted]"
        );
        assert_eq!(
            compact.details.as_ref().unwrap(),
            &json!({
                "finding_count": 2,
                "non_pass_count": 1,
                "public_release_license_status": "fail",
            })
        );
    }
}
