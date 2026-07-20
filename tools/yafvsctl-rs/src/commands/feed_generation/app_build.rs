// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guarded construction and attestation of the application deployment.

use super::artifact_identity::app_runtime_artifact_manifest;
use super::compose_identity::{compose_contract_manifest, unavailable_images};
use super::deployment::{
    APP_SERVICES, validate_app_deployment_receipt, validate_app_runtime_artifact_manifest,
};
use crate::commands::common::{ensure_real_directory_tree, metadata, output_tail, runtime_dir};
use crate::commands::compose::{
    compose_command_with_environment_and_files, runtime_app_environment,
};
use crate::commands::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use crate::commands::secret::write_private_text;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const COMMAND: &str = "runtime-app-build";
const GSAD_PORT: u16 = 19392;
const CONFIG_TIMEOUT: Duration = Duration::from_secs(120);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1800);

pub fn command_runtime_app_build(repo_root: &Path) -> ResultEnvelope {
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
    let mut context = SystemBuildContext { repo_root, runner };
    command_unlocked(repo_root, runner, &mut context)
}

trait BuildContext {
    fn environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String>;
    fn running_services(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<Vec<String>, String>;
    fn compose_config(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Option<ProcessOutput>;
    fn compose_build(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Option<ProcessOutput>;
    fn stage_gsa(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<Vec<Finding>, String>;
    fn image_ids(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<BTreeMap<String, String>, String>;
    fn runtime_artifacts(&mut self) -> Result<Value, String>;
    fn compose_contract(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
        image_ids: &BTreeMap<String, String>,
    ) -> Result<Value, String>;
    fn write_receipt(
        &mut self,
        image_ids: &BTreeMap<String, String>,
        runtime_artifacts: &Value,
        compose_contract: &Value,
    ) -> Result<Value, String>;
}

struct SystemBuildContext<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
}

impl BuildContext for SystemBuildContext<'_> {
    fn environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
        runtime_app_environment(self.repo_root)
            .map_err(|error| format!("Application runtime environment is unavailable: {error}"))
    }

    fn running_services(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<Vec<String>, String> {
        running_app_services(self.repo_root, self.runner, environment)
    }

    fn compose_config(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Option<ProcessOutput> {
        run_compose(
            self.repo_root,
            self.runner,
            environment,
            &["--profile", "app", "config", "--quiet"],
            CONFIG_TIMEOUT,
        )
    }

    fn compose_build(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Option<ProcessOutput> {
        let mut arguments = vec!["--profile", "app", "build"];
        arguments.extend(APP_SERVICES);
        run_compose(
            self.repo_root,
            self.runner,
            environment,
            &arguments,
            BUILD_TIMEOUT,
        )
    }

    fn stage_gsa(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<Vec<Finding>, String> {
        stage_gsa_static(self.repo_root, environment)
    }

    fn image_ids(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<BTreeMap<String, String>, String> {
        resolve_app_service_image_ids(self.repo_root, self.runner, environment)
    }

    fn runtime_artifacts(&mut self) -> Result<Value, String> {
        let manifest = app_runtime_artifact_manifest(self.repo_root)?;
        validate_app_runtime_artifact_manifest(&manifest)?;
        Ok(manifest)
    }

    fn compose_contract(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
        image_ids: &BTreeMap<String, String>,
    ) -> Result<Value, String> {
        compose_contract_manifest(self.repo_root, self.runner, environment, image_ids)
    }

    fn write_receipt(
        &mut self,
        image_ids: &BTreeMap<String, String>,
        runtime_artifacts: &Value,
        compose_contract: &Value,
    ) -> Result<Value, String> {
        write_app_deployment_receipt(
            self.repo_root,
            image_ids,
            runtime_artifacts,
            compose_contract,
        )
    }
}

fn command_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    context: &mut dyn BuildContext,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let environment = match context.environment() {
        Ok(value) => value,
        Err(error) => {
            return result(
                repo_root,
                runner,
                "Application image build stopped at safe runtime setup.",
                vec![Finding::new("fail", "runtime.app-environment", error)],
            );
        }
    };
    match context.running_services(&environment) {
        Ok(running) if running.is_empty() => findings.push(Finding::new(
            "pass",
            "runtime.app-services-stopped",
            "No running application service consumes bind-mounted build artifacts.".into(),
        )),
        Ok(running) => {
            findings.push(
                Finding::new(
                    "fail",
                    "runtime.app-services-stopped",
                    "Stop the application deployment with runtime-app-down before changing runtime build artifacts.".into(),
                )
                .with_details(json!({"running_services": running})),
            );
            return result(
                repo_root,
                runner,
                "Build refused because running application services consume bind-mounted build artifacts.",
                findings,
            );
        }
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.app-services-stopped",
                format!("Application service state could not be determined safely: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Build refused because application service state is unknown.",
                findings,
            );
        }
    }

    let config = context.compose_config(&environment);
    let config_ok = config.as_ref().is_some_and(|output| output.success);
    findings.push(process_finding(
        config.as_ref(),
        "compose.config",
        "Compose app config validation",
    ));
    if !config_ok {
        return result(
            repo_root,
            runner,
            "Application image build stopped at Compose validation.",
            findings,
        );
    }

    let built = context.compose_build(&environment);
    let build_ok = built.as_ref().is_some_and(|output| output.success);
    findings.push(process_finding(
        built.as_ref(),
        "compose.app-build",
        "Build explicit application images",
    ));
    if !build_ok {
        return result(
            repo_root,
            runner,
            "Application image build failed.",
            findings,
        );
    }

    match context.stage_gsa(&environment) {
        Ok(mut staged) => findings.append(&mut staged),
        Err(error) => findings.push(Finding::new("fail", "gsa.static-stage", error)),
    }
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Application deployment preparation failed.",
            findings,
        );
    }

    let image_ids = match context.image_ids(&environment) {
        Ok(value) => {
            findings.push(
                Finding::new(
                    "pass",
                    "compose.app-images",
                    "All application image identities were resolved after the explicit build."
                        .into(),
                )
                .with_details(json!({"image_ids": value})),
            );
            value
        }
        Err(error) => {
            findings.push(
                Finding::new("fail", "compose.app-images", error)
                    .with_details(json!({"image_ids": {}})),
            );
            return result(
                repo_root,
                runner,
                "Application deployment preparation failed.",
                findings,
            );
        }
    };

    let runtime_artifacts = match context.runtime_artifacts() {
        Ok(value) => value,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.app-deployment-receipt",
                format!("Prepared application deployment receipt could not be written: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Application deployment preparation failed.",
                findings,
            );
        }
    };
    let compose_contract = match context.compose_contract(&environment, &image_ids) {
        Ok(value) => value,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.app-deployment-receipt",
                format!("Prepared application deployment receipt could not be written: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Application deployment preparation failed.",
                findings,
            );
        }
    };
    match context.write_receipt(&image_ids, &runtime_artifacts, &compose_contract) {
        Ok(receipt) => findings.push(
            Finding::new(
                "pass",
                "runtime.app-deployment-receipt",
                "Prepared application images and bind-mounted runtime artifacts were recorded for explicit deployment.".into(),
            )
            .with_path(
                &runtime_dir(repo_root)
                    .join("state/app-deployment.json")
                    .display()
                    .to_string(),
            )
            .with_details(receipt),
        ),
        Err(error) => findings.push(Finding::new(
            "fail",
            "runtime.app-deployment-receipt",
            format!("Prepared application deployment receipt could not be written: {error}"),
        )),
    }
    let summary = if failed(&findings) {
        "Application deployment preparation failed."
    } else {
        "Application deployment was built and recorded explicitly."
    };
    result(repo_root, runner, summary, findings)
}

fn run_compose(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    arguments: &[&str],
    timeout: Duration,
) -> Option<ProcessOutput> {
    let owned = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let command =
        match compose_command_with_environment_and_files(repo_root, environment, &[], &owned) {
            Ok(command) => command,
            Err(error) => {
                return Some(ProcessOutput {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("runtime Compose override generation failed: {error}"),
                });
            }
        };
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with(
        "docker",
        &arguments,
        Some(repo_root),
        Some(environment),
        Some(timeout),
    )
}

fn running_app_services(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<Vec<String>, String> {
    let mut running = Vec::new();
    for service in APP_SERVICES {
        let container = run_compose(
            repo_root,
            runner,
            environment,
            &["ps", "-q", service],
            CONFIG_TIMEOUT,
        )
        .ok_or_else(|| format!("could not inspect {service} container state"))?;
        if !container.success {
            return Err(format!(
                "Compose could not inspect {service} container state"
            ));
        }
        let Some(id) = container
            .stdout
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
        else {
            continue;
        };
        let inspected = runner
            .run_with(
                "docker",
                &["inspect", "-f", "{{.State.Running}}", id],
                Some(repo_root),
                Some(environment),
                Some(CONFIG_TIMEOUT),
            )
            .ok_or_else(|| format!("could not inspect {service} container state"))?;
        if !inspected.success {
            return Err(format!(
                "Docker could not inspect {service} container state"
            ));
        }
        match inspected.stdout.trim() {
            "true" => running.push(service.to_owned()),
            "false" => {}
            _ => return Err(format!("Docker returned invalid {service} container state")),
        }
    }
    Ok(running)
}

fn resolve_app_service_image_ids(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<BTreeMap<String, String>, String> {
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
    let services = config
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| "Compose config does not contain services".to_owned())?;
    let mut image_ids = BTreeMap::new();
    for service in APP_SERVICES {
        let image = services
            .get(service)
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
            .ok_or_else(|| format!("No built image identity is available for {service}"))?;
        let id = inspected
            .stdout
            .lines()
            .next_back()
            .map(str::trim)
            .unwrap_or("");
        if !inspected.success || !valid_image_id(id) {
            return Err(format!(
                "No built image identity is available for {service}; run runtime-app-build first"
            ));
        }
        image_ids.insert(service.to_owned(), id.to_owned());
    }
    let unavailable = unavailable_images(repo_root, runner, environment, &image_ids)?;
    if unavailable.is_empty() {
        Ok(image_ids)
    } else {
        Err(format!(
            "Pinned application image objects are unavailable for {}; restore those exact image objects by digest from a trusted registry or docker load before continuing",
            unavailable.join(", ")
        ))
    }
}

fn valid_image_id(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_app_deployment_receipt(
    repo_root: &Path,
    image_ids: &BTreeMap<String, String>,
    runtime_artifacts: &Value,
    compose_contract: &Value,
) -> Result<Value, String> {
    let image_ids = image_ids
        .iter()
        .map(|(service, image)| (service.clone(), Value::from(image.clone())))
        .collect::<Map<_, _>>();
    let receipt = json!({
        "schema_version": 1,
        "image_ids": image_ids,
        "runtime_artifacts": runtime_artifacts,
        "compose_contract": compose_contract,
        "prepared_at": OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| format!("deployment receipt timestamp failed: {error}"))?,
    });
    let receipt = validate_app_deployment_receipt(&receipt)?;
    let mut text = serde_json::to_string_pretty(&receipt)
        .map_err(|error| format!("deployment receipt serialization failed: {error}"))?;
    text.push('\n');
    write_private_text(
        &runtime_dir(repo_root).join("state/app-deployment.json"),
        &text,
    )
    .map_err(|error| format!("deployment receipt write failed: {error}"))?;
    Ok(receipt)
}

fn stage_gsa_static(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<Vec<Finding>, String> {
    let source = repo_root.join("components/gsa/build");
    let index = source.join("index.html");
    if !regular_file(&index) {
        return Ok(vec![
            Finding::new(
                "fail",
                "gsa.build.index",
                "GSA production build is missing index.html; run just build-ui.".into(),
            )
            .with_path(&index.display().to_string()),
        ]);
    }
    let parent = ensure_real_directory_tree(repo_root, Path::new("build/prefix/share/gvm/gsad"))
        .map_err(|error| format!("gsad static destination could not be created: {error}"))?;
    let destination = parent.join("web");
    if fs::symlink_metadata(&destination).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("gsad static destination is a symbolic link".into());
    }
    let temporary = parent.join(format!(".web.stage-{}", std::process::id()));
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err("gsad static staging path already exists".into());
    }
    copy_tree_without_links(&source, &temporary)?;
    let host = first_gsad_host(environment);
    let fallback = serde_json::to_string(&format!("{host}:{GSAD_PORT}"))
        .map_err(|error| format!("GSA fallback endpoint could not be encoded: {error}"))?;
    fs::write(
        temporary.join("config.js"),
        format!(
            "config = {{\n  apiProtocol: (window.location.protocol || 'https:').replace(':', ''),\n  apiServer: window.location.host || {fallback},\n}};\n"
        ),
    )
    .map_err(|error| format!("GSA config.js could not be staged: {error}"))?;
    if destination.exists() {
        fs::remove_dir_all(&destination)
            .map_err(|error| format!("old gsad static directory could not be removed: {error}"))?;
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(format!(
            "gsad static directory could not be installed: {error}"
        ));
    }
    Ok(vec![
        Finding::new(
            "pass",
            "gsa.build.index",
            "GSA production build index.html exists.".into(),
        )
        .with_path(&index.display().to_string()),
        Finding::new(
            "pass",
            "gsa.static-stage",
            "GSA production build is staged for gsad.".into(),
        )
        .with_path(&destination.display().to_string()),
        Finding::new(
            "pass",
            "gsa.config-js",
            "GSA config.js uses the browser host with a fallback gsad endpoint.".into(),
        )
        .with_path(&destination.join("config.js").display().to_string())
        .with_details(json!({
            "api_protocol": "browser",
            "api_server_fallback": format!("{host}:{GSAD_PORT}"),
            "hosts": gsad_hosts(environment),
        })),
    ])
}

fn copy_tree_without_links(source: &Path, destination: &Path) -> Result<(), String> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("GSA build directory is unavailable: {error}"))?;
    if !source_metadata.file_type().is_dir() || source_metadata.file_type().is_symlink() {
        return Err("GSA build path is not a real directory".into());
    }
    fs::create_dir(destination)
        .map_err(|error| format!("GSA staging directory could not be created: {error}"))?;
    copy_directory_entries(source, destination).inspect_err(|_| {
        let _ = fs::remove_dir_all(destination);
    })
}

fn copy_directory_entries(source: &Path, destination: &Path) -> Result<(), String> {
    let entries = fs::read_dir(source)
        .map_err(|error| format!("GSA build directory could not be read: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("GSA build directory entry is invalid: {error}"))?;
        let metadata = entry
            .metadata()
            .map_err(|error| format!("GSA build entry could not be inspected: {error}"))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|error| format!("GSA build entry type is unavailable: {error}"))?
            .is_symlink()
        {
            return Err(format!(
                "GSA build contains unsupported symbolic link: {}",
                source_path.display()
            ));
        }
        if metadata.is_dir() {
            fs::create_dir(&destination_path)
                .map_err(|error| format!("GSA staging directory could not be created: {error}"))?;
            copy_directory_entries(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)
                .map_err(|error| format!("GSA build file could not be copied: {error}"))?;
        } else {
            return Err(format!(
                "GSA build contains unsupported file type: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
}

fn first_gsad_host(environment: &BTreeMap<OsString, OsString>) -> String {
    gsad_hosts(environment)
        .into_iter()
        .next()
        .unwrap_or_else(|| "127.0.0.1".into())
}

fn gsad_hosts(environment: &BTreeMap<OsString, OsString>) -> Vec<String> {
    for name in ["YAFVS_GSAD_HOSTS", "YAFVS_GSAD_HOST"] {
        let hosts = environment
            .get(&OsString::from(name))
            .and_then(|value| value.to_str())
            .map(|value| {
                let mut seen = std::collections::BTreeSet::new();
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|host| !host.is_empty())
                    .filter(|host| seen.insert((*host).to_owned()))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !hosts.is_empty() {
            return hosts;
        }
    }
    vec!["127.0.0.1".into()]
}

fn process_finding(output: Option<&ProcessOutput>, check: &str, label: &str) -> Finding {
    let success = output.is_some_and(|output| output.success);
    let exit_code = output.and_then(|output| output.exit_code);
    let combined = output
        .map(|output| format!("{}\n{}", output.stdout, output.stderr))
        .unwrap_or_default();
    Finding::new(
        if success { "pass" } else { "fail" },
        check,
        match exit_code {
            Some(code) => format!("{label} exit code {code}."),
            None => format!("{label} could not be started."),
        },
    )
    .with_details(json!({
        "exit_code": exit_code,
        "output_tail": output_tail(&combined, 80),
    }))
}

fn failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_artifacts(vec![
        repo_root.join("compose/dev.yaml").display().to_string(),
    ])
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
            "Application image build stopped while waiting for the feed lifecycle lock.",
            format!(
                "Timed out waiting for runtime lock '{name}'; another operation may still be running."
            ),
            json!({"operation": operation, "holder": holder}),
        ),
        RuntimeLockError::Setup(error) => (
            "Application image build stopped because the feed lifecycle lock failed closed.",
            format!("Feed lifecycle lock failed closed: {error}"),
            json!({}),
        ),
    };
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message).with_details(details),
        ],
    )
    .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct FakeContext {
        running: Result<Vec<String>, String>,
        config: Option<ProcessOutput>,
        build: Option<ProcessOutput>,
        stage: Result<Vec<Finding>, String>,
        image_ids: Result<BTreeMap<String, String>, String>,
        artifacts: Result<Value, String>,
        contract: Result<Value, String>,
        wrote: bool,
        config_calls: usize,
    }

    impl FakeContext {
        fn successful() -> Self {
            Self {
                running: Ok(Vec::new()),
                config: successful_output(),
                build: successful_output(),
                stage: Ok(vec![Finding::new(
                    "pass",
                    "gsa.static-stage",
                    "staged".into(),
                )]),
                image_ids: Ok(image_ids()),
                artifacts: Ok(artifacts()),
                contract: Ok(contract()),
                wrote: false,
                config_calls: 0,
            }
        }
    }

    impl BuildContext for FakeContext {
        fn environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
            Ok(BTreeMap::new())
        }
        fn running_services(
            &mut self,
            _environment: &BTreeMap<OsString, OsString>,
        ) -> Result<Vec<String>, String> {
            self.running.clone()
        }
        fn compose_config(
            &mut self,
            _environment: &BTreeMap<OsString, OsString>,
        ) -> Option<ProcessOutput> {
            self.config_calls += 1;
            self.config.clone()
        }
        fn compose_build(
            &mut self,
            _environment: &BTreeMap<OsString, OsString>,
        ) -> Option<ProcessOutput> {
            self.build.clone()
        }
        fn stage_gsa(
            &mut self,
            _environment: &BTreeMap<OsString, OsString>,
        ) -> Result<Vec<Finding>, String> {
            std::mem::replace(&mut self.stage, Ok(Vec::new()))
        }
        fn image_ids(
            &mut self,
            _environment: &BTreeMap<OsString, OsString>,
        ) -> Result<BTreeMap<String, String>, String> {
            self.image_ids.clone()
        }
        fn runtime_artifacts(&mut self) -> Result<Value, String> {
            self.artifacts.clone()
        }
        fn compose_contract(
            &mut self,
            _environment: &BTreeMap<OsString, OsString>,
            _image_ids: &BTreeMap<String, String>,
        ) -> Result<Value, String> {
            self.contract.clone()
        }
        fn write_receipt(
            &mut self,
            image_ids: &BTreeMap<String, String>,
            runtime_artifacts: &Value,
            compose_contract: &Value,
        ) -> Result<Value, String> {
            self.wrote = true;
            Ok(json!({
                "schema_version": 1,
                "image_ids": image_ids,
                "runtime_artifacts": runtime_artifacts,
                "compose_contract": compose_contract,
                "prepared_at": "2026-07-19T00:00:00Z",
            }))
        }
    }

    fn successful_output() -> Option<ProcessOutput> {
        Some(ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn image_ids() -> BTreeMap<String, String> {
        APP_SERVICES
            .into_iter()
            .enumerate()
            .map(|(index, service)| {
                (
                    service.to_owned(),
                    format!("sha256:{}", format!("{:x}", index + 1).repeat(64)),
                )
            })
            .collect()
    }

    fn artifacts() -> Value {
        json!({
            "schema_version": 1,
            "algorithm": "sha256",
            "digest": "a".repeat(64),
            "entry_count": 1,
            "byte_count": 1,
            "roots": [
                "build/prefix",
                "build/venvs/ospd-openvas",
                "build/venvs/notus-scanner",
                "build/openvas-scanner/nasl",
                "build/openvas-scanner/misc",
                "components/ospd-openvas/ospd",
                "components/ospd-openvas/ospd_openvas",
                "components/notus-scanner/notus/scanner",
                "build/openvas-scanner/src/openvas",
            ],
        })
    }

    fn contract() -> Value {
        json!({
            "schema_version": 1,
            "algorithm": "sha256",
            "digest": "b".repeat(64),
            "services": APP_SERVICES,
        })
    }

    fn fixture_repo() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-app-build-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    struct NoopRunner;
    impl CommandRunner for NoopRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }
    }

    #[test]
    fn running_services_refuse_build_before_compose_validation() {
        let (_root, repo) = fixture_repo();
        let mut context = FakeContext::successful();
        context.running = Ok(vec!["gvmd".into(), "gsad".into()]);
        let result = command_unlocked(&repo, &NoopRunner, &mut context);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["running_services"],
            json!(["gvmd", "gsad"])
        );
        assert_eq!(context.config_calls, 0);
    }

    #[test]
    fn unknown_service_state_fails_closed() {
        let (_root, repo) = fixture_repo();
        let mut context = FakeContext::successful();
        context.running = Err("docker unavailable".into());
        let result = command_unlocked(&repo, &NoopRunner, &mut context);
        assert_eq!(result.status, "fail");
        assert!(result.summary.contains("state is unknown"));
        assert_eq!(context.config_calls, 0);
    }

    #[test]
    fn successful_build_records_receipt() {
        let (_root, repo) = fixture_repo();
        let mut context = FakeContext::successful();
        let result = command_unlocked(&repo, &NoopRunner, &mut context);
        assert_eq!(result.status, "pass");
        assert!(context.wrote);
        assert_eq!(
            result.findings.last().unwrap().check,
            "runtime.app-deployment-receipt"
        );
    }

    #[test]
    fn gsa_staging_is_browser_relative_and_refuses_links() {
        let (root, repo) = fixture_repo();
        let source = repo.join("components/gsa/build");
        fs::create_dir_all(source.join("assets")).unwrap();
        fs::write(source.join("index.html"), "<div id=\"app\"></div>").unwrap();
        fs::write(source.join("assets/index.js"), "console.log('ok');").unwrap();
        let environment = BTreeMap::from([(
            OsString::from("YAFVS_GSAD_HOSTS"),
            OsString::from("192.0.2.10,198.51.100.20"),
        )]);
        let findings = stage_gsa_static(&repo, &environment).unwrap();
        assert!(findings.iter().all(|finding| finding.status == "pass"));
        let config =
            fs::read_to_string(repo.join("build/prefix/share/gvm/gsad/web/config.js")).unwrap();
        assert!(config.contains("window.location.host"));
        assert!(config.contains("\"192.0.2.10:19392\""));

        fs::remove_dir_all(repo.join("build/prefix/share/gvm/gsad/web")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", source.join("unsafe")).unwrap();
        assert!(stage_gsa_static(&repo, &environment).is_err());
        fs::remove_file(source.join("unsafe")).unwrap();
        fs::remove_dir_all(repo.join("build/prefix/share/gvm")).unwrap();
        std::os::unix::fs::symlink("/tmp", repo.join("build/prefix/share/gvm")).unwrap();
        assert!(stage_gsa_static(&repo, &environment).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn receipt_writer_round_trips_through_secure_reader() {
        let root = std::env::current_dir().unwrap().join(format!(
            ".yafvsctl-app-build-receipt-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        let runtime = root.join("YAFVS-runtime");
        let receipt =
            write_app_deployment_receipt(&repo, &image_ids(), &artifacts(), &contract()).unwrap();
        assert_eq!(
            super::super::deployment::read_app_deployment_receipt(&runtime)
                .unwrap()
                .unwrap(),
            receipt
        );
        let _ = fs::remove_dir_all(root);
    }
}
