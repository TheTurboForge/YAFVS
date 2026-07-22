// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Receipt-pinned rebuild and restart of only the native API sidecar.

use super::app_build::{run_compose, write_app_deployment_receipt};
use super::artifact_identity::app_runtime_artifact_manifest;
use super::compose_identity::{compose_contract_manifest, unavailable_images};
use super::deployment::{
    APP_SERVICES, validate_app_deployment_receipt, validate_app_runtime_artifact_manifest,
    validate_app_service_image_ids,
};
use super::{
    CurrentAppDeployment, command_feed_generation_runtime_guard_with_runner,
    pinned_app_compose_command, require_current_app_deployment_snapshot,
};
use crate::commands::common::{metadata, output_tail, runtime_dir};
use crate::commands::compose::{compose_command, runtime_app_environment};
use crate::commands::direct_api::{
    DIRECT_BIND_ENV, DIRECT_CONTAINER_PORT, DIRECT_ENV, DIRECT_HOST_ENV, DIRECT_PORT_ENV,
};
use crate::commands::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use crate::commands::runtime_native_api_smoke::command_runtime_native_api_smoke_with_runner;
use crate::commands::runtime_setup::ensure_runtime_setup;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env::var_os;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "runtime-native-api-rebuild";
const CONFIG_TIMEOUT: Duration = Duration::from_secs(120);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1200);
const START_TIMEOUT: Duration = Duration::from_secs(300);
const GSAD_CONTAINER_PORT: &str = "9392";
const GSAD_HOST_PORT: &str = "19392";
const GSAD_HOSTS_ENV: &str = "YAFVS_GSAD_HOSTS";

pub fn command_runtime_native_api_rebuild(repo_root: &Path) -> ResultEnvelope {
    command_with_runner_and_timeout(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_with_runner_and_timeout(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
            Ok(lock) => lock,
            Err(error) => return lock_failure(repo_root, runner, error),
        };
    command_unlocked(repo_root, runner)
}

fn command_unlocked(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let mut findings = ensure_runtime_setup(repo_root, runner);
    let feed_guard = command_feed_generation_runtime_guard_with_runner(repo_root, false, runner);
    findings.extend(feed_guard.findings);

    let environment = match deployed_app_environment(repo_root, runner) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new("fail", "runtime.app-environment", error));
            return result(
                repo_root,
                runner,
                "Native API rebuild stopped at prerequisites.",
                findings,
                runtime_artifact(repo_root),
            );
        }
    };
    let config = run_compose(
        repo_root,
        runner,
        &environment,
        &["config", "--quiet"],
        CONFIG_TIMEOUT,
    );
    findings.push(process_finding(
        config.as_ref(),
        "compose.config",
        "Compose config validation",
    ));
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Native API rebuild stopped at prerequisites.",
            findings,
            runtime_artifact(repo_root),
        );
    }

    let deployment = match require_current_app_deployment_snapshot(repo_root, runner, &environment)
    {
        Ok(deployment) => deployment,
        Err(error) => {
            findings.push(
                Finding::new("fail", "runtime.app-deployment-receipt", error)
                    .with_path(&receipt_path(repo_root)),
            );
            return result(
                repo_root,
                runner,
                "Native API rebuild stopped because no verified application deployment was prepared.",
                findings,
                runtime_artifact(repo_root),
            );
        }
    };
    findings.push(
        Finding::new(
            "pass",
            "runtime.app-deployment-receipt",
            "Prepared application deployment receipt is valid before the API-only rebuild.".into(),
        )
        .with_path(&receipt_path(repo_root)),
    );

    let build = run_compose(
        repo_root,
        runner,
        &environment,
        &["build", "yafvs-api"],
        BUILD_TIMEOUT,
    );
    findings.push(process_finding(
        build.as_ref(),
        "compose.yafvs-api-build",
        "docker compose build yafvs-api",
    ));
    if !process_passed(build.as_ref()) {
        return result(
            repo_root,
            runner,
            "Native API rebuild stopped because image build failed.",
            findings,
            runtime_artifact(repo_root),
        );
    }

    let refreshed = match refresh_deployment(
        repo_root,
        runner,
        &environment,
        deployment,
        "yafvs-api",
    ) {
        Ok(deployment) => deployment,
        Err(error) => {
            findings.push(
                Finding::new("fail", "runtime.app-deployment-receipt-refresh", error)
                    .with_path(&receipt_path(repo_root)),
            );
            return result(
                repo_root,
                runner,
                "Native API rebuild stopped because the deployment receipt could not be refreshed.",
                findings,
                runtime_artifact(repo_root),
            );
        }
    };
    findings.push(
        Finding::new(
            "pass",
            "runtime.app-deployment-receipt-refresh",
            "Prepared application deployment receipt now identifies the rebuilt native API image."
                .into(),
        )
        .with_path(&receipt_path(repo_root)),
    );

    let up_arguments = native_api_up_arguments();
    let up_command = match pinned_app_compose_command(
        repo_root,
        &environment,
        &refreshed.image_ids,
        &up_arguments,
    ) {
        Ok(command) => command,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "compose.yafvs-api-up",
                format!("Pinned native API restart command could not be prepared: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Native API rebuild stopped because yafvs-api restart failed.",
                findings,
                runtime_artifact(repo_root),
            );
        }
    };
    let up_refs = up_command.iter().map(String::as_str).collect::<Vec<_>>();
    let up = runner.run_with(
        "docker",
        &up_refs,
        Some(repo_root),
        Some(&environment),
        Some(START_TIMEOUT),
    );
    findings.push(process_finding(
        up.as_ref(),
        "compose.yafvs-api-up",
        "docker compose up --no-deps yafvs-api",
    ));
    if !process_passed(up.as_ref()) {
        return result(
            repo_root,
            runner,
            "Native API rebuild stopped because yafvs-api restart failed.",
            findings,
            runtime_artifact(repo_root),
        );
    }

    let smoke = match run_retained_native_api_smoke(repo_root, runner, &environment) {
        Ok(smoke) => smoke,
        Err(error) => {
            findings.push(Finding::new("fail", "native-api.smoke", error));
            return result(
                repo_root,
                runner,
                "Native API sidecar rebuild attempted.",
                findings,
                vec![runtime_dir(repo_root).display().to_string()],
            );
        }
    };
    findings.push(
        Finding::new(&smoke.status, "native-api.smoke", smoke.summary).with_details(json!({
            "status": smoke.status,
            "artifacts": smoke.artifacts,
            "findings": smoke.findings,
        })),
    );
    let mut artifacts = vec![runtime_dir(repo_root).display().to_string()];
    artifacts.extend(smoke.artifacts);
    artifacts.sort();
    artifacts.dedup();
    result(
        repo_root,
        runner,
        "Native API sidecar rebuild attempted.",
        findings,
        artifacts,
    )
}

pub(crate) fn refresh_deployment(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    deployment: CurrentAppDeployment,
    service: &str,
) -> Result<CurrentAppDeployment, String> {
    if service != "yafvs-api" {
        return Err("Application deployment receipt refresh requested invalid services".into());
    }
    let receipt = validate_app_deployment_receipt(&deployment.receipt)?;
    let expected_artifacts = receipt
        .get("runtime_artifacts")
        .ok_or("application deployment receipt is invalid")?;
    validate_app_runtime_artifact_manifest(expected_artifacts)?;
    let observed_artifacts = app_runtime_artifact_manifest(repo_root).map_err(|error| {
        format!("Runtime deployment artifact identity could not be verified: {error}")
    })?;
    if observed_artifacts.get("digest") != expected_artifacts.get("digest") {
        return Err("Bind-mounted runtime artifacts changed during the feed transition.".into());
    }

    let rebuilt_image = configured_service_image_id(repo_root, runner, environment, service)?;
    let image_ids = refreshed_image_ids(deployment.image_ids, service, rebuilt_image)?;
    let unavailable = unavailable_images(repo_root, runner, environment, &image_ids)?;
    if !unavailable.is_empty() {
        return Err(format!(
            "Pinned application image objects are unavailable for {}; restore those exact image objects by digest from a trusted registry or docker load before continuing",
            unavailable.join(", ")
        ));
    }
    let compose_contract = compose_contract_manifest(repo_root, runner, environment, &image_ids)?;
    let refreshed =
        write_app_deployment_receipt(repo_root, &image_ids, expected_artifacts, &compose_contract)?;
    Ok(CurrentAppDeployment {
        receipt: refreshed,
        image_ids,
    })
}

fn configured_service_image_id(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    service: &str,
) -> Result<String, String> {
    if !APP_SERVICES.contains(&service) {
        return Err(format!("unknown application service {service}"));
    }
    let configured = run_compose(
        repo_root,
        runner,
        environment,
        &["--profile", "app", "config", "--format", "json"],
        CONFIG_TIMEOUT,
    )
    .ok_or_else(|| "Compose config could not be started".to_owned())?;
    if !configured.success {
        return Err(format!(
            "Compose config failed: {}",
            output_tail(&format!("{}\n{}", configured.stdout, configured.stderr), 20).join("; ")
        ));
    }
    let config: Value = serde_json::from_str(&configured.stdout)
        .map_err(|error| format!("Compose config was not valid JSON: {error}"))?;
    let image = config
        .get("services")
        .and_then(Value::as_object)
        .and_then(|services| services.get(service))
        .and_then(Value::as_object)
        .and_then(|service| service.get("image"))
        .and_then(Value::as_str)
        .filter(|image| !image.is_empty())
        .ok_or_else(|| format!("Compose service {service} has no explicit image name"))?;
    let inspected = runner
        .run_with(
            "docker",
            &["image", "inspect", "--format", "{{.Id}}", image],
            Some(repo_root),
            Some(environment),
            Some(CONFIG_TIMEOUT),
        )
        .ok_or_else(|| format!("Rebuilt image identity is unavailable for {service}"))?;
    let image_id = inspected
        .stdout
        .lines()
        .next_back()
        .map(str::trim)
        .unwrap_or("");
    if inspected.success && valid_image_id(image_id) {
        Ok(image_id.to_owned())
    } else {
        Err(format!(
            "Rebuilt image identity is unavailable for {service}"
        ))
    }
}

fn refreshed_image_ids(
    mut image_ids: BTreeMap<String, String>,
    service: &str,
    rebuilt_image: String,
) -> Result<BTreeMap<String, String>, String> {
    if !APP_SERVICES.contains(&service) || !valid_image_id(&rebuilt_image) {
        return Err("Application deployment receipt refresh requested invalid services".into());
    }
    image_ids.insert(service.to_owned(), rebuilt_image);
    validate_app_service_image_ids(&serde_json::to_value(&image_ids).map_err(|error| {
        format!("Application deployment receipt refresh serialization failed: {error}")
    })?)?;
    Ok(image_ids)
}

fn valid_image_id(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn deployed_app_environment(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> Result<BTreeMap<OsString, OsString>, String> {
    let mut environment = runtime_app_environment(repo_root)
        .map_err(|error| format!("Application runtime environment is unavailable: {error}"))?;
    let explicit = [
        GSAD_HOSTS_ENV,
        DIRECT_ENV,
        DIRECT_HOST_ENV,
        DIRECT_PORT_ENV,
        DIRECT_BIND_ENV,
    ]
    .into_iter()
    .filter(|name| var_os(name).is_some())
    .collect::<BTreeSet<_>>();
    recover_deployed_bindings(repo_root, runner, &mut environment, &explicit)?;
    Ok(environment)
}

fn recover_deployed_bindings(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &mut BTreeMap<OsString, OsString>,
    explicit: &BTreeSet<&str>,
) -> Result<(), String> {
    if !explicit.contains(GSAD_HOSTS_ENV) {
        let hosts =
            published_bindings(repo_root, runner, environment, "gsad", GSAD_CONTAINER_PORT)?
                .into_iter()
                .filter_map(|(host, port)| {
                    (port == GSAD_HOST_PORT && !host.is_empty())
                        .then_some(compose_binding_host(&host))
                })
                .collect::<Vec<_>>();
        if !hosts.is_empty() {
            environment.insert(
                OsString::from(GSAD_HOSTS_ENV),
                OsString::from(hosts.join(",")),
            );
        }
    }
    if ![
        DIRECT_ENV,
        DIRECT_HOST_ENV,
        DIRECT_PORT_ENV,
        DIRECT_BIND_ENV,
    ]
    .iter()
    .any(|name| explicit.contains(name))
    {
        let bindings = published_bindings(
            repo_root,
            runner,
            environment,
            "yafvs-api",
            DIRECT_CONTAINER_PORT,
        )?;
        if let [(host, port)] = bindings.as_slice() {
            let host = compose_binding_host(if host.is_empty() { "0.0.0.0" } else { host });
            environment.insert(OsString::from(DIRECT_ENV), OsString::from("1"));
            environment.insert(OsString::from(DIRECT_HOST_ENV), OsString::from(host));
            environment.insert(OsString::from(DIRECT_PORT_ENV), OsString::from(port));
            environment.insert(
                OsString::from(DIRECT_BIND_ENV),
                OsString::from(format!("0.0.0.0:{DIRECT_CONTAINER_PORT}")),
            );
        }
    }
    Ok(())
}

fn published_bindings(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    service: &str,
    container_port: &str,
) -> Result<Vec<(String, String)>, String> {
    let command = compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]);
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    let container = runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(environment),
            Some(CONFIG_TIMEOUT),
        )
        .ok_or_else(|| format!("could not inspect {service} container state"))?;
    if !container.success {
        return Err(format!(
            "Compose could not inspect {service} container state"
        ));
    }
    let Some(container_id) = container
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
    else {
        return Ok(Vec::new());
    };
    let inspected = runner
        .run_with(
            "docker",
            &[
                "inspect",
                "-f",
                "{{json .NetworkSettings.Ports}}",
                container_id,
            ],
            Some(repo_root),
            Some(environment),
            Some(CONFIG_TIMEOUT),
        )
        .ok_or_else(|| format!("could not inspect {service} published ports"))?;
    if !inspected.success {
        return Err(format!(
            "Docker could not inspect {service} published ports"
        ));
    }
    let ports: Value = serde_json::from_str(&inspected.stdout)
        .map_err(|error| format!("Docker returned invalid {service} published ports: {error}"))?;
    let bindings = ports
        .get(format!("{container_port}/tcp"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for binding in bindings {
        let Some(binding) = binding.as_object() else {
            return Err(format!("Docker returned invalid {service} published ports"));
        };
        let host = binding
            .get("HostIp")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0")
            .trim()
            .to_owned();
        let port = binding
            .get("HostPort")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !port.is_empty() && seen.insert((host.clone(), port.clone())) {
            result.push((host, port));
        }
    }
    Ok(result)
}

fn compose_binding_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

pub(crate) struct SmokeOutcome {
    pub(crate) status: String,
    pub(crate) summary: String,
    pub(crate) artifacts: Vec<String>,
    pub(crate) findings: Vec<Value>,
}

pub(crate) fn run_retained_native_api_smoke(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    _environment: &BTreeMap<OsString, OsString>,
) -> Result<SmokeOutcome, String> {
    let result = command_runtime_native_api_smoke_with_runner(repo_root, true, runner);
    let findings = result
        .findings
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Native API smoke findings could not be serialized: {error}"))?;
    Ok(SmokeOutcome {
        status: result.status,
        summary: result.summary,
        artifacts: result.artifacts,
        findings,
    })
}

pub(crate) fn native_api_up_arguments() -> Vec<String> {
    [
        "--profile",
        "app",
        "up",
        "-d",
        "--no-deps",
        "--force-recreate",
        "--no-build",
        "--pull",
        "never",
        "yafvs-api",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn process_finding(output: Option<&ProcessOutput>, check: &str, label: &str) -> Finding {
    let exit = output.and_then(|output| output.exit_code).unwrap_or(1);
    let combined = output
        .map(|output| format!("{}\n{}", output.stdout, output.stderr))
        .unwrap_or_default();
    Finding::new(
        if process_passed(output) {
            "pass"
        } else {
            "fail"
        },
        check,
        format!("{label} exit code {exit}."),
    )
    .with_details(json!({"output_tail": output_tail(&combined, 40)}))
}

fn process_passed(output: Option<&ProcessOutput>) -> bool {
    output.is_some_and(|output| output.success)
}

fn failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn receipt_path(repo_root: &Path) -> String {
    runtime_dir(repo_root)
        .join("state/app-deployment.json")
        .display()
        .to_string()
}

fn runtime_artifact(repo_root: &Path) -> Vec<String> {
    vec![runtime_dir(repo_root).display().to_string()]
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    artifacts: Vec<String>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_artifacts(artifacts)
}

fn lock_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    error: RuntimeLockError,
) -> ResultEnvelope {
    let (summary, message, details) = match error {
        RuntimeLockError::Timeout {
            name,
            operation,
            holder,
        } => (
            "Native API rebuild stopped while waiting for the feed lifecycle lock.",
            format!(
                "Timed out waiting for runtime lock '{name}'; another operation may still be running."
            ),
            json!({"operation": operation, "holder": holder}),
        ),
        RuntimeLockError::Setup(error) => (
            "Native API rebuild stopped because the feed lifecycle lock failed closed.",
            format!("Feed lifecycle lock failed closed: {error}"),
            json!({}),
        ),
    };
    result(
        repo_root,
        runner,
        summary,
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message).with_details(details),
        ],
        vec![runtime_lock_dir(repo_root).display().to_string()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct BindingRunner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl BindingRunner {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for BindingRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program.to_owned())
                    .chain(args.iter().map(|argument| (*argument).to_owned()))
                    .collect(),
            );
            let stdout = if args.ends_with(&["ps", "-q", "gsad"]) {
                "gsad-id\n".to_owned()
            } else if args.ends_with(&["ps", "-q", "yafvs-api"]) {
                "api-id\n".to_owned()
            } else if args.last() == Some(&"gsad-id") {
                json!({"9392/tcp": [{"HostIp": "::1", "HostPort": "19392"}]}).to_string()
            } else if args.last() == Some(&"api-id") {
                json!({"9081/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19080"}]}).to_string()
            } else {
                return None;
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn restart_arguments_pin_one_service_without_dependencies_or_build() {
        assert_eq!(
            native_api_up_arguments(),
            vec![
                "--profile",
                "app",
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "--no-build",
                "--pull",
                "never",
                "yafvs-api",
            ]
        );
    }

    #[test]
    fn deployed_binding_recovery_preserves_ipv6_gsad_and_direct_api() {
        let runner = BindingRunner::new();
        let mut environment = BTreeMap::new();
        recover_deployed_bindings(
            Path::new("/srv/YAFVS"),
            &runner,
            &mut environment,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            environment.get(&OsString::from(GSAD_HOSTS_ENV)),
            Some(&OsString::from("[::1]"))
        );
        assert_eq!(
            environment.get(&OsString::from(DIRECT_ENV)),
            Some(&OsString::from("1"))
        );
        assert_eq!(
            environment.get(&OsString::from(DIRECT_HOST_ENV)),
            Some(&OsString::from("127.0.0.1"))
        );
        assert_eq!(
            environment.get(&OsString::from(DIRECT_PORT_ENV)),
            Some(&OsString::from("19080"))
        );
        assert_eq!(
            environment.get(&OsString::from(DIRECT_BIND_ENV)),
            Some(&OsString::from("0.0.0.0:9081"))
        );
    }

    #[test]
    fn receipt_refresh_changes_only_the_named_image() {
        let original = APP_SERVICES
            .iter()
            .enumerate()
            .map(|(index, service)| {
                (
                    (*service).to_owned(),
                    format!("sha256:{}", format!("{index:x}").repeat(64)),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let rebuilt = format!("sha256:{}", "f".repeat(64));
        let refreshed =
            refreshed_image_ids(original.clone(), "yafvs-api", rebuilt.clone()).unwrap();
        for service in APP_SERVICES {
            if service == "yafvs-api" {
                assert_eq!(refreshed.get(service), Some(&rebuilt));
            } else {
                assert_eq!(refreshed.get(service), original.get(service));
            }
        }
    }
}
