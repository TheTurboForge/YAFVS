// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Observational runtime-health inspection.
//!
//! Status must not create runtime state merely to inspect it. Lifecycle
//! commands own directory and secret initialization; this module reports
//! missing prerequisites without manufacturing them.

use super::common::{executable_path, metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::runtime_lock::{RuntimeLockError, RuntimeLockStatus, inspect_runtime_lock};
use super::runtime_probe::socket_readiness_finding;
use super::runtime_setup::RUNTIME_DIRS;
use super::secret::runtime_secret_path;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

const RUNTIME_MANAGER_LOCK: &str = "runtime-manager";
const RUNTIME_SERVICES: [&str; 3] = ["postgres", "redis-openvas", "mosquitto"];
const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];
const POSTGRES_COLLATION_BASE_DATABASES: [&str; 2] = ["postgres", "template1"];
const ADMIN_SECRET: &str = "gvmd-admin-password";

pub fn command_runtime_status(repo_root: &Path) -> ResultEnvelope {
    command_runtime_status_with_runner(
        repo_root,
        &SystemCommandRunner,
        executable_path("docker").is_some(),
    )
}

fn command_runtime_status_with_runner(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    docker_available: bool,
) -> ResultEnvelope {
    let mut findings = vec![
        manager_lock_finding(repo_root),
        Finding::new(
            if docker_available { "pass" } else { "fail" },
            "docker.available",
            if docker_available {
                "docker is available."
            } else {
                "docker is not available."
            }
            .into(),
        ),
    ];

    let environment = runtime_environment(repo_root);
    let docker = run_docker(runner, &["info".into()], repo_root, &environment);
    findings.push(process_finding(
        &docker,
        "docker.daemon",
        "docker info",
        40,
        None,
    ));

    let compose_path = repo_root.join("compose/dev.yaml");
    let config = run_compose(
        runner,
        repo_root,
        &["config".into(), "--quiet".into()],
        &environment,
    );
    findings.push(process_finding(
        &config,
        "compose.config",
        "Compose config validation",
        40,
        Some(relative_or_absolute(repo_root, &compose_path)),
    ));

    findings.extend(runtime_directory_findings(repo_root));

    let ps = run_compose(
        runner,
        repo_root,
        &["ps".into(), "--format".into(), "json".into()],
        &environment,
    );
    findings.push(process_finding(
        &ps,
        "compose.ps",
        "docker compose ps",
        80,
        None,
    ));

    let service_states = RUNTIME_SERVICES
        .iter()
        .chain(APP_SERVICES.iter())
        .map(|service| {
            (
                *service,
                container_running(runner, repo_root, service, &environment),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for service in RUNTIME_SERVICES {
        let running = service_states.get(service).copied().unwrap_or(false);
        findings.push(
            Finding::new(
                if running { "pass" } else { "warn" },
                "runtime.running",
                format!(
                    "{service} container is {}.",
                    if running { "running" } else { "not running" }
                ),
            )
            .with_details(json!({ "service": service })),
        );
    }

    if service_states.get("postgres").copied().unwrap_or(false) {
        findings.extend(postgres_findings(
            runner,
            repo_root,
            &environment,
            false,
            true,
        ));
    }

    findings.extend(certificate_findings(repo_root));
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    findings.push(
        Finding::new(
            if secret_path.is_file() {
                "pass"
            } else {
                "warn"
            },
            "runtime.admin-secret",
            if secret_path.is_file() {
                "Development admin secret exists."
            } else {
                "Development admin secret is not initialized yet."
            }
            .into(),
        )
        .with_path(&secret_path.display().to_string()),
    );

    for service in APP_SERVICES {
        let running = service_states.get(service).copied().unwrap_or(false);
        findings.push(
            Finding::new(
                if running { "pass" } else { "warn" },
                "runtime.app.running",
                format!(
                    "{service} container is {}.",
                    if running { "running" } else { "not running" }
                ),
            )
            .with_details(json!({ "service": service })),
        );
    }
    findings.push(socket_readiness_finding(
        "gvmd.socket",
        "gvmd",
        &runtime_dir(repo_root).join("run/gvmd-gmp/gvmd.sock"),
        "warn",
    ));
    findings.push(socket_readiness_finding(
        "ospd.socket",
        "ospd-openvas",
        &runtime_dir(repo_root).join("run/ospd/ospd-openvas.sock"),
        "warn",
    ));

    make_result(
        metadata(repo_root, "runtime-status", runner),
        "Runtime status collected.".into(),
        findings,
    )
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

pub fn command_runtime_smoke(repo_root: &Path) -> ResultEnvelope {
    command_runtime_smoke_with_runner(repo_root, &SystemCommandRunner)
}

fn command_runtime_smoke_with_runner(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let environment = runtime_environment(repo_root);
    let mut findings = strict_runtime_directory_findings(repo_root);
    let compose_path = repo_root.join("compose/dev.yaml");
    let config = run_compose(
        runner,
        repo_root,
        &["config".into(), "--quiet".into()],
        &environment,
    );
    findings.push(process_finding(
        &config,
        "compose.config",
        "Compose config validation",
        40,
        Some(relative_or_absolute(repo_root, &compose_path)),
    ));

    let port_config = run_compose(runner, repo_root, &["config".into()], &environment);
    let broad_bindings = port_config
        .stdout
        .lines()
        .filter(|line| line.contains("0.0.0.0:") || line.contains("[::]:"))
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let port_status = if port_config.exit_code != Some(0) || !broad_bindings.is_empty() {
        "fail"
    } else {
        "pass"
    };
    let port_message = if port_config.exit_code != Some(0) {
        format!(
            "Compose port configuration could not be rendered; exit code {}.",
            port_config.exit_code.unwrap_or(1)
        )
    } else if broad_bindings.is_empty() {
        "No broad host port bindings found.".into()
    } else {
        "Broad host port bindings found.".into()
    };
    findings.push(
        Finding::new(port_status, "runtime.ports", port_message).with_details(json!({
            "broad_bindings": broad_bindings,
            "output_tail": output_tail(&port_config.stdout, 40),
        })),
    );

    let service_states = RUNTIME_SERVICES
        .iter()
        .map(|service| {
            (
                *service,
                container_running(runner, repo_root, service, &environment),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for service in RUNTIME_SERVICES {
        let running = service_states.get(service).copied().unwrap_or(false);
        findings.push(
            Finding::new(
                if running { "pass" } else { "fail" },
                "runtime.running",
                format!(
                    "{service} container is {}.",
                    if running { "running" } else { "not running" }
                ),
            )
            .with_details(json!({ "service": service })),
        );
    }

    if service_states.get("postgres").copied().unwrap_or(false) {
        findings.extend(postgres_findings(
            runner,
            repo_root,
            &environment,
            true,
            false,
        ));
    }
    if service_states
        .get("redis-openvas")
        .copied()
        .unwrap_or(false)
    {
        let ping = exec_in_service(
            runner,
            repo_root,
            "redis-openvas",
            &[
                "redis-cli".into(),
                "-s".into(),
                "/run/redis-openvas/redis.sock".into(),
                "ping".into(),
            ],
            &environment,
        );
        let socket_path = runtime_dir(repo_root).join("run/redis-openvas/redis.sock");
        findings.push(
            Finding::new(
                if ping.exit_code == Some(0) && ping.stdout.contains("PONG") {
                    "pass"
                } else {
                    "fail"
                },
                "redis-openvas.ready",
                format!(
                    "scanner Redis Unix socket ping exit code {}.",
                    ping.exit_code.unwrap_or(1)
                ),
            )
            .with_path(&socket_path.display().to_string())
            .with_details(json!({ "output_tail": output_tail(&ping.stdout, 20) })),
        );
        let socket_exists = fs::symlink_metadata(&socket_path)
            .is_ok_and(|metadata| metadata.file_type().is_socket());
        findings.push(
            Finding::new(
                if socket_exists { "pass" } else { "fail" },
                "redis-openvas.socket",
                if socket_exists {
                    "scanner Redis Unix socket exists."
                } else {
                    "scanner Redis Unix socket is missing."
                }
                .into(),
            )
            .with_path(&socket_path.display().to_string()),
        );
    }
    if service_states.get("mosquitto").copied().unwrap_or(false) {
        let probe = exec_in_service(
            runner,
            repo_root,
            "mosquitto",
            &[
                "mosquitto_pub".into(),
                "-o".into(),
                "/tmp/yafvs-mqtt-health.options".into(),
            ],
            &environment,
        );
        findings.push(
            Finding::new(
                if probe.exit_code == Some(0) {
                    "pass"
                } else {
                    "fail"
                },
                "mosquitto.ready",
                format!(
                    "mosquitto_pub broker check exit code {}.",
                    probe.exit_code.unwrap_or(1)
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&probe.stdout, 20) })),
        );
    }

    make_result(
        metadata(repo_root, "runtime-smoke", runner),
        "Runtime smoke checks completed.".into(),
        findings,
    )
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

fn manager_lock_finding(repo_root: &Path) -> Finding {
    match inspect_runtime_lock(repo_root, RUNTIME_MANAGER_LOCK) {
        Ok(status) => {
            let active = status.active;
            Finding::new(
                if active { "warn" } else { "pass" },
                "runtime.manager-lock",
                if active {
                    "A manager operation is currently active."
                } else {
                    "No manager operation lock is active."
                }
                .into(),
            )
            .with_details(json!({ "lock": lock_status_json(status) }))
        }
        Err(error) => Finding::new(
            "fail",
            "runtime.manager-lock",
            format!(
                "Manager operation lock status could not be inspected: {}.",
                runtime_lock_error_message(&error)
            ),
        ),
    }
}

fn lock_status_json(status: RuntimeLockStatus) -> serde_json::Value {
    json!({
        "name": status.name,
        "active": status.active,
        "path": status.path.display().to_string(),
        "metadata_path": status.metadata_path.display().to_string(),
        "metadata": status.metadata,
    })
}

fn runtime_lock_error_message(error: &RuntimeLockError) -> String {
    match error {
        RuntimeLockError::Timeout {
            name, operation, ..
        } => format!("timed out waiting for lock {name} during {operation}"),
        RuntimeLockError::Setup(message) => message.clone(),
    }
}

fn runtime_directory_findings(repo_root: &Path) -> Vec<Finding> {
    let root = runtime_dir(repo_root);
    RUNTIME_DIRS
        .iter()
        .map(|relative| {
            let path = root.join(relative);
            let path_text = path.display().to_string();
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    match directory_accessible(&path) {
                        Ok(true) => Finding::new(
                            "pass",
                            "runtime.dir",
                            format!("Runtime directory is writable: {path_text}"),
                        )
                        .with_path(&path_text),
                        Ok(false) => Finding::new(
                            "fail",
                            "runtime.dir",
                            format!("Runtime directory is not writable: {path_text}"),
                        )
                        .with_path(&path_text),
                        Err(error) => Finding::new(
                            "fail",
                            "runtime.dir",
                            format!("Runtime directory could not be checked: {path_text}: {error}"),
                        )
                        .with_path(&path_text),
                    }
                }
                Ok(_) => Finding::new(
                    "fail",
                    "runtime.dir",
                    format!("Runtime path is not a real directory: {path_text}"),
                )
                .with_path(&path_text),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Finding::new(
                    "warn",
                    "runtime.dir",
                    format!("Runtime directory is missing: {path_text}"),
                )
                .with_path(&path_text),
                Err(error) => Finding::new(
                    "fail",
                    "runtime.dir",
                    format!("Runtime directory could not be inspected: {path_text}: {error}"),
                )
                .with_path(&path_text),
            }
        })
        .chain([
            runtime_file_finding(
                &root.join("run/feed-update.lock"),
                "runtime.feed-lock",
                "Runtime feed lock file",
            ),
            runtime_file_finding(
                &root.join("run/ospd/feed-update.lock"),
                "runtime.feed-lock",
                "OSPD feed lock file",
            ),
        ])
        .collect()
}

fn strict_runtime_directory_findings(repo_root: &Path) -> Vec<Finding> {
    runtime_directory_findings(repo_root)
        .into_iter()
        .map(|mut finding| {
            if finding.status == "warn" {
                finding.status = "fail".into();
            }
            finding
        })
        .collect()
}

fn directory_accessible(path: &Path) -> std::io::Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let result = unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) };
    if result == 0 {
        Ok(true)
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            Ok(false)
        } else {
            Err(error)
        }
    }
}

fn runtime_file_finding(path: &Path, check: &str, label: &str) -> Finding {
    let path_text = path.display().to_string();
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            Finding::new("pass", check, format!("{label} exists: {path_text}"))
                .with_path(&path_text)
        }
        Ok(_) => Finding::new(
            "fail",
            check,
            format!("{label} is not a regular file: {path_text}"),
        )
        .with_path(&path_text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Finding::new("warn", check, format!("{label} is missing: {path_text}"))
                .with_path(&path_text)
        }
        Err(error) => Finding::new(
            "fail",
            check,
            format!("{label} could not be inspected: {path_text}: {error}"),
        )
        .with_path(&path_text),
    }
}

fn run_docker(
    runner: &dyn CommandRunner,
    arguments: &[String],
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> ProcessOutput {
    let refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with("docker", &refs, Some(repo_root), Some(environment), None)
        .unwrap_or_else(unavailable_process)
}

fn run_compose(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    arguments: &[String],
    environment: &BTreeMap<OsString, OsString>,
) -> ProcessOutput {
    run_docker(
        runner,
        &compose_command(repo_root, arguments),
        repo_root,
        environment,
    )
}

fn unavailable_process() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn process_finding(
    output: &ProcessOutput,
    check: &str,
    label: &str,
    tail_lines: usize,
    path: Option<String>,
) -> Finding {
    let exit_code = output.exit_code.unwrap_or(1);
    let mut finding = Finding::new(
        if exit_code == 0 { "pass" } else { "fail" },
        check,
        format!("{label} exit code {exit_code}."),
    )
    .with_details(json!({ "output_tail": output_tail(&output.stdout, tail_lines) }));
    if let Some(path) = path {
        finding = finding.with_path(&path);
    }
    finding
}

fn relative_or_absolute(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn container_running(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    service: &str,
    environment: &BTreeMap<OsString, OsString>,
) -> bool {
    let ps = run_compose(
        runner,
        repo_root,
        &["ps".into(), "-q".into(), service.into()],
        environment,
    );
    let Some(container_id) = (ps.exit_code == Some(0))
        .then(|| ps.stdout.lines().find(|line| !line.trim().is_empty()))
        .flatten()
        .map(str::trim)
    else {
        return false;
    };
    let inspect = run_docker(
        runner,
        &[
            "inspect".into(),
            "-f".into(),
            "{{.State.Running}}".into(),
            container_id.into(),
        ],
        repo_root,
        environment,
    );
    inspect.exit_code == Some(0) && inspect.stdout.trim() == "true"
}

fn postgres_findings(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    strict: bool,
    include_roles: bool,
) -> Vec<Finding> {
    let user = environment_value(environment, "POSTGRES_USER", "yafvs");
    let database = environment_value(environment, "POSTGRES_DB", "yafvs");
    let ready = exec_in_service(
        runner,
        repo_root,
        "postgres",
        &[
            "pg_isready".into(),
            "-U".into(),
            user.clone(),
            "-d".into(),
            database.clone(),
        ],
        environment,
    );
    let ready_status = if ready.exit_code == Some(0) {
        "pass"
    } else if strict {
        "fail"
    } else {
        "warn"
    };
    let mut findings = vec![
        Finding::new(
            ready_status,
            "postgres.ready",
            format!("pg_isready exit code {}.", ready.exit_code.unwrap_or(1)),
        )
        .with_details(json!({ "output_tail": output_tail(&ready.stdout, 20) })),
    ];
    findings.extend(postgres_collation_findings(
        runner,
        repo_root,
        environment,
        &database,
        strict,
    ));

    if include_roles {
        let dba = psql(
            runner,
            repo_root,
            environment,
            &database,
            "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dba');",
        );
        let dba_value = psql_value(&dba.stdout);
        findings.push(
            Finding::new(
                if dba.exit_code == Some(0) && dba_value == "t" {
                    "pass"
                } else if strict {
                    "fail"
                } else {
                    "warn"
                },
                "postgres.role.dba",
                format!(
                    "dba role exists: {}.",
                    if dba_value.is_empty() {
                        "unknown"
                    } else {
                        &dba_value
                    }
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&dba.stdout, 20) })),
        );

        let membership = psql(
            runner,
            repo_root,
            environment,
            &database,
            &format!(
                "SELECT pg_has_role({}, 'dba', 'member');",
                sql_literal(&user)
            ),
        );
        let membership_value = psql_value(&membership.stdout);
        findings.push(
            Finding::new(
                if membership.exit_code == Some(0) && membership_value == "t" {
                    "pass"
                } else if strict {
                    "fail"
                } else {
                    "warn"
                },
                "postgres.role.membership",
                format!(
                    "{user} has dba role membership: {}.",
                    if membership_value.is_empty() {
                        "unknown"
                    } else {
                        &membership_value
                    }
                ),
            )
            .with_details(json!({ "output_tail": output_tail(&membership.stdout, 20) })),
        );
    }
    findings.push(pg_gvm_extension_finding(
        runner,
        repo_root,
        environment,
        &database,
        strict,
    ));
    findings
}

fn postgres_collation_findings(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    database: &str,
    strict: bool,
) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    std::iter::once(database)
        .chain(POSTGRES_COLLATION_BASE_DATABASES)
        .filter(|database| seen.insert((*database).to_string()))
        .map(|database| {
            let result = psql(
                runner,
                repo_root,
                environment,
                database,
                "SELECT datcollversion || '|' || pg_database_collation_actual_version(oid) FROM pg_database WHERE datname = current_database();",
            );
            if result.exit_code != Some(0) {
                return Finding::new(
                    "fail",
                    "postgres.collation",
                    format!(
                        "{database}: collation version check exit code {}.",
                        result.exit_code.unwrap_or(1)
                    ),
                )
                .with_details(json!({
                    "database": database,
                    "output_tail": output_tail(&result.stdout, 40),
                }));
            }
            let value = psql_value(&result.stdout);
            let Some((recorded, actual)) = value.split_once('|') else {
                return Finding::new(
                    if strict { "fail" } else { "warn" },
                    "postgres.collation",
                    format!("{database}: could not parse database collation version check."),
                )
                .with_details(json!({
                    "database": database,
                    "output_tail": output_tail(&result.stdout, 40),
                }));
            };
            if recorded == actual {
                return Finding::new(
                    "pass",
                    "postgres.collation",
                    format!("{database}: database collation version is current: {actual}."),
                )
                .with_details(json!({
                    "database": database,
                    "recorded": recorded,
                    "actual": actual,
                }));
            }

            let count = psql(
                runner,
                repo_root,
                environment,
                database,
                "SELECT count(*) FROM pg_class WHERE relkind IN ('r','i','S','v','m') AND relnamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname LIKE 'pg_%' OR nspname = 'information_schema');",
            );
            if count.exit_code != Some(0) {
                return Finding::new(
                    "fail",
                    "postgres.collation",
                    format!(
                        "{database}: collation mismatch {recorded} != {actual}; relation-count check failed."
                    ),
                )
                .with_details(json!({
                    "database": database,
                    "recorded": recorded,
                    "actual": actual,
                    "output_tail": output_tail(&count.stdout, 40),
                }));
            }
            let relation_count = psql_value(&count.stdout);
            let status = if strict { "fail" } else { "warn" };
            let message = if relation_count == "0" {
                format!(
                    "{database}: database collation version mismatch {recorded} != {actual}; runtime-init can refresh this empty development database."
                )
            } else {
                format!(
                    "{database}: database collation version mismatch {recorded} != {actual}; manual review required before refreshing a database with objects."
                )
            };
            Finding::new(status, "postgres.collation", message).with_details(json!({
                "database": database,
                "recorded": recorded,
                "actual": actual,
                "relation_count": relation_count,
            }))
        })
        .collect()
}

pub(crate) fn pg_gvm_extension_finding(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    database: &str,
    strict: bool,
) -> Finding {
    let result = psql(
        runner,
        repo_root,
        environment,
        database,
        "SELECT COALESCE((SELECT extversion FROM pg_extension WHERE extname = 'pg-gvm'), 'missing');",
    );
    if result.exit_code != Some(0) {
        return Finding::new(
            "fail",
            "postgres.pg-gvm",
            format!(
                "pg-gvm extension status query exit code {}.",
                result.exit_code.unwrap_or(1)
            ),
        )
        .with_details(json!({ "output_tail": output_tail(&result.stdout, 40) }));
    }
    let version = psql_value(&result.stdout);
    Finding::new(
        if !version.is_empty() && version != "missing" {
            "pass"
        } else if strict {
            "fail"
        } else {
            "warn"
        },
        "postgres.pg-gvm",
        format!("pg-gvm extension is {version}."),
    )
    .with_details(json!({ "version": version }))
}

fn psql(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    database: &str,
    sql: &str,
) -> ProcessOutput {
    let user = environment_value(environment, "POSTGRES_USER", "yafvs");
    let password = environment_value(environment, "POSTGRES_PASSWORD", "yafvs-dev");
    let mut environment = environment.clone();
    environment.insert(OsString::from("PGPASSWORD"), OsString::from(password));
    exec_in_service(
        runner,
        repo_root,
        "postgres",
        &[
            "-e".into(),
            "PGPASSWORD".into(),
            "psql".into(),
            "-v".into(),
            "ON_ERROR_STOP=1".into(),
            "-U".into(),
            user,
            "-d".into(),
            database.into(),
            "-At".into(),
            "-c".into(),
            sql.into(),
        ],
        &environment,
    )
}

fn exec_in_service(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    service: &str,
    command: &[String],
    environment: &BTreeMap<OsString, OsString>,
) -> ProcessOutput {
    let mut arguments = vec!["exec".into(), "-T".into()];
    arguments.extend_from_slice(command);
    let service_position = if arguments.get(2).is_some_and(|part| part == "-e") {
        4
    } else {
        2
    };
    arguments.insert(service_position, service.into());
    run_compose(runner, repo_root, &arguments, environment)
}

fn environment_value(
    environment: &BTreeMap<OsString, OsString>,
    name: &str,
    default: &str,
) -> String {
    environment
        .get(&OsString::from(name))
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn psql_value(output: &str) -> String {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !["WARNING:", "DETAIL:", "HINT:", "NOTICE:"]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
        })
        .unwrap_or_default()
        .to_string()
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn certificate_findings(repo_root: &Path) -> Vec<Finding> {
    let root = runtime_dir(repo_root);
    [
        ("ca_key", root.join("certs/private/CA/cakey.pem")),
        ("ca_cert", root.join("certs/CA/cacert.pem")),
        ("server_key", root.join("certs/private/CA/serverkey.pem")),
        ("server_cert", root.join("certs/CA/servercert.pem")),
        ("client_key", root.join("certs/private/CA/clientkey.pem")),
        ("client_cert", root.join("certs/CA/clientcert.pem")),
    ]
    .into_iter()
    .map(|(name, path)| {
        let exists = path
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0);
        Finding::new(
            if exists { "pass" } else { "warn" },
            "runtime.cert",
            format!(
                "{name} {}.",
                if path.is_file() {
                    "exists"
                } else {
                    "is missing"
                }
            ),
        )
        .with_path(&path.display().to_string())
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvs-runtime-health-{name}-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let repo = root.join("YAFVS");
            fs::create_dir_all(repo.join("compose")).unwrap();
            fs::write(repo.join("compose/dev.yaml"), "services: {}\n").unwrap();
            Self { root, repo }
        }

        fn runtime(&self) -> PathBuf {
            self.root.join("YAFVS-runtime")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Clone, Debug)]
    struct RecordedCall {
        args: Vec<String>,
        environment: BTreeMap<OsString, OsString>,
    }

    #[derive(Default)]
    struct HealthyRunner {
        calls: Mutex<Vec<RecordedCall>>,
        broad_bindings: bool,
    }

    impl HealthyRunner {
        fn calls(&self) -> MutexGuard<'_, Vec<RecordedCall>> {
            self.calls.lock().unwrap()
        }
    }

    struct UnavailableRunner;

    impl CommandRunner for UnavailableRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| successful("deadbee\n"))
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _environment: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            self.run(program, args)
        }
    }

    impl CommandRunner for HealthyRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| successful("deadbee\n"))
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            if program != "docker" {
                return self.run(program, args);
            }
            let call = RecordedCall {
                args: args
                    .iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
                environment: environment.cloned().unwrap_or_default(),
            };
            self.calls.lock().unwrap().push(call.clone());
            let joined = call.args.join(" ");
            if self.broad_bindings
                && call
                    .args
                    .last()
                    .is_some_and(|argument| argument == "config")
            {
                return Some(successful("published: 0.0.0.0:9392\n"));
            }
            if joined.contains(" ps -q ") {
                let service = call.args.last().unwrap();
                return Some(successful(&format!("{service}-container\n")));
            }
            if call
                .args
                .first()
                .is_some_and(|argument| argument == "inspect")
            {
                return Some(successful("true\n"));
            }
            if joined.contains("datcollversion") {
                return Some(successful("same|same\n"));
            }
            if joined.contains("rolname = 'dba'") || joined.contains("pg_has_role") {
                return Some(successful("t\n"));
            }
            if joined.contains("extname = 'pg-gvm'") {
                return Some(successful("1.0\n"));
            }
            if joined.contains("redis-cli") {
                return Some(successful("PONG\n"));
            }
            Some(successful(""))
        }
    }

    fn successful(stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn prepare_runtime_smoke_prerequisites(fixture: &Fixture) -> std::os::unix::net::UnixListener {
        let runtime = fixture.runtime();
        for relative in RUNTIME_DIRS {
            fs::create_dir_all(runtime.join(relative)).unwrap();
        }
        fs::write(runtime.join("run/feed-update.lock"), "").unwrap();
        fs::write(runtime.join("run/ospd/feed-update.lock"), "").unwrap();
        std::os::unix::net::UnixListener::bind(runtime.join("run/redis-openvas/redis.sock"))
            .unwrap()
    }

    #[test]
    fn smoke_is_observational_and_strict_when_runtime_state_is_absent() {
        let fixture = Fixture::new("smoke-observational");
        assert!(!fixture.runtime().exists());

        let result = command_runtime_smoke_with_runner(&fixture.repo, &HealthyRunner::default());

        assert_eq!(result.status, "fail");
        assert_eq!(result.metadata.command, "runtime-smoke");
        assert!(!fixture.runtime().exists());
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime.dir"
                && finding.status == "fail"
                && finding.message.contains("is missing")
        }));
    }

    #[test]
    fn smoke_reuses_health_primitives_without_role_or_duplicate_service_probes() {
        let fixture = Fixture::new("smoke-healthy");
        let _redis_listener = prepare_runtime_smoke_prerequisites(&fixture);
        let runner = HealthyRunner::default();

        let result = command_runtime_smoke_with_runner(&fixture.repo, &runner);
        let calls = runner.calls();
        assert_eq!(result.status, "pass");
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.args.join(" ").contains(" ps -q "))
                .count(),
            RUNTIME_SERVICES.len()
        );
        let psql_calls = calls
            .iter()
            .filter(|call| call.args.iter().any(|argument| argument == "psql"))
            .collect::<Vec<_>>();
        assert_eq!(psql_calls.len(), 4);
        assert!(psql_calls.iter().all(|call| {
            !call
                .args
                .iter()
                .any(|argument| argument.contains("pg_has_role"))
                && !call
                    .args
                    .iter()
                    .any(|argument| argument.contains("rolname"))
        }));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "redis-openvas.ready" && finding.status == "pass")
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "mosquitto.ready" && finding.status == "pass")
        );
    }

    #[test]
    fn smoke_fails_broad_host_bindings() {
        let fixture = Fixture::new("smoke-broad-binding");
        let runner = HealthyRunner {
            broad_bindings: true,
            ..HealthyRunner::default()
        };

        let result = command_runtime_smoke_with_runner(&fixture.repo, &runner);
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.check == "runtime.ports")
            .unwrap();
        assert_eq!(finding.status, "fail");
        assert_eq!(finding.message, "Broad host port bindings found.");
        assert!(
            finding.details.as_ref().unwrap()["broad_bindings"]
                .as_array()
                .is_some_and(|bindings| bindings == &vec![json!("published: 0.0.0.0:9392")])
        );
    }

    #[test]
    fn status_is_observational_when_runtime_state_is_absent() {
        let fixture = Fixture::new("observational");
        let runner = HealthyRunner::default();
        assert!(!fixture.runtime().exists());

        let result = command_runtime_status_with_runner(&fixture.repo, &runner, true);

        assert!(!fixture.runtime().exists());
        assert_eq!(result.metadata.command, "runtime-status");
        assert_eq!(result.summary, "Runtime status collected.");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime.dir"
                && finding.status == "warn"
                && finding.message.contains("is missing")
        }));
    }

    #[test]
    fn status_probes_each_container_once_and_keeps_password_out_of_arguments() {
        let fixture = Fixture::new("single-probe");
        let runner = HealthyRunner::default();

        let result = command_runtime_status_with_runner(&fixture.repo, &runner, true);
        let calls = runner.calls();
        let ps_calls = calls
            .iter()
            .filter(|call| call.args.join(" ").contains(" ps -q "))
            .collect::<Vec<_>>();
        assert_eq!(ps_calls.len(), RUNTIME_SERVICES.len() + APP_SERVICES.len());
        for service in RUNTIME_SERVICES.iter().chain(APP_SERVICES.iter()) {
            assert_eq!(
                ps_calls
                    .iter()
                    .filter(|call| call.args.last().is_some_and(|value| value == service))
                    .count(),
                1
            );
        }
        let psql_calls = calls
            .iter()
            .filter(|call| call.args.iter().any(|argument| argument == "psql"))
            .collect::<Vec<_>>();
        assert_eq!(psql_calls.len(), 6);
        assert!(psql_calls.iter().all(|call| {
            !call.args.iter().any(|argument| argument == "yafvs-dev")
                && call
                    .environment
                    .get(&OsString::from("PGPASSWORD"))
                    .is_some_and(|value| value == "yafvs-dev")
        }));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "postgres.pg-gvm" && finding.status == "pass")
        );
    }

    #[test]
    fn unavailable_docker_fails_closed_without_creating_runtime_state() {
        let fixture = Fixture::new("docker-unavailable");

        let result = command_runtime_status_with_runner(&fixture.repo, &UnavailableRunner, false);

        assert_eq!(result.status, "fail");
        for check in [
            "docker.available",
            "docker.daemon",
            "compose.config",
            "compose.ps",
        ] {
            assert!(
                result
                    .findings
                    .iter()
                    .any(|finding| { finding.check == check && finding.status == "fail" })
            );
        }
        assert!(!fixture.runtime().exists());
    }

    #[test]
    fn unsafe_runtime_root_is_reported_instead_of_repaired() {
        let fixture = Fixture::new("unsafe-root");
        fs::write(fixture.runtime(), "not a directory\n").unwrap();

        let result =
            command_runtime_status_with_runner(&fixture.repo, &HealthyRunner::default(), true);

        let lock = result
            .findings
            .iter()
            .find(|finding| finding.check == "runtime.manager-lock")
            .unwrap();
        assert_eq!(lock.status, "fail");
        assert!(
            lock.message
                .contains("not a real, current-user-owned directory")
        );
        assert_eq!(
            fs::read_to_string(fixture.runtime()).unwrap(),
            "not a directory\n"
        );
    }

    #[test]
    fn runtime_directory_inspection_rejects_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("symlink");
        let runtime = fixture.runtime();
        fs::create_dir_all(&runtime).unwrap();
        symlink("/tmp", runtime.join("postgres")).unwrap();

        let findings = runtime_directory_findings(&fixture.repo);
        let postgres = findings
            .iter()
            .find(|finding| {
                finding.path.as_deref() == Some(&runtime.join("postgres").display().to_string())
            })
            .unwrap();
        assert_eq!(postgres.status, "fail");
        assert!(postgres.message.contains("not a real directory"));
    }

    #[test]
    fn psql_value_ignores_postgres_notice_lines() {
        assert_eq!(
            psql_value("NOTICE: setup\nvalue\nHINT: ignored after value\n"),
            "value"
        );
    }
}
