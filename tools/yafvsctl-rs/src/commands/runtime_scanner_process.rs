// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only scanner process and MQTT credential hygiene diagnostics.

use super::common::metadata;
use super::compose::{compose_command, runtime_environment};
use super::secret::{read_private_text, runtime_secret_path};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SECRET_BYTES: usize = 4096;
const MAX_JSON_OUTPUT_BYTES: usize = 1_048_576;
const SERVICE: &str = "ospd-openvas";
const OSPD_SECRET: &str = "mqtt-ospd-password";
const OSPD_SECRET_FILE: &str = "/run/secrets/yafvs-mqtt-ospd-password";
const NOTUS_SECRET_FILE: &str = "/run/secrets/yafvs-mqtt-notus-password";
const ENVIRONMENT_SERVICES: [&str; 3] = ["mosquitto", "ospd-openvas", "notus-scanner"];
const MQTT_SECRETS: [(&str, &str, &str); 4] = [
    (
        "YAFVS_MQTT_OPENVAS_PASSWORD",
        "mqtt-openvas-password",
        "/run/secrets/yafvs-mqtt-openvas-password",
    ),
    (
        "YAFVS_MQTT_NOTUS_PASSWORD",
        "mqtt-notus-password",
        NOTUS_SECRET_FILE,
    ),
    ("YAFVS_MQTT_OSPD_PASSWORD", OSPD_SECRET, OSPD_SECRET_FILE),
    (
        "YAFVS_MQTT_HEALTH_PASSWORD",
        "mqtt-health-password",
        "/run/secrets/yafvs-mqtt-health-password",
    ),
];

#[derive(Clone, Default)]
struct ServiceInspection {
    environment: Option<Value>,
    config: Option<Value>,
    mounts: Option<Value>,
}

#[derive(Clone, Default)]
struct Exposure {
    cmdline_secret_pids: Vec<String>,
    inline_password_option_pids: Vec<String>,
    exact_password_file_option_pids: Vec<String>,
    unexpected_password_file_option_pids: Vec<String>,
    cmdline_unreadable_pids: Vec<String>,
}

pub fn command_runtime_scanner_process_check(repo_root: &Path) -> ResultEnvelope {
    command_runtime_scanner_process_check_with(repo_root, &SystemCommandRunner)
}

pub(crate) fn command_runtime_scanner_process_check_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let environment = runtime_environment(repo_root);
    let expected_uid = environment_value(&environment, "YAFVS_UID")
        .parse::<u32>()
        .unwrap_or(u32::MAX);
    let secret_path = runtime_secret_path(repo_root, OSPD_SECRET);
    let (secret_metadata, secret_file_ok) = secret_file_evidence(&secret_path, expected_uid);
    findings.push(
        Finding::new(
            if secret_file_ok { "pass" } else { "fail" },
            "ospd.mqtt-secret-file",
            if secret_file_ok {
                "OSPD MQTT secret file exists with owner-only permissions.".into()
            } else {
                "OSPD MQTT secret file is missing or accessible outside its owner.".into()
            },
        )
        .with_details(secret_metadata),
    );

    let ospd_id = container_id(repo_root, runner, SERVICE);
    let running = ospd_id
        .as_deref()
        .is_some_and(|container| container_running(repo_root, runner, container));
    findings.push(
        Finding::new(
            if running { "pass" } else { "fail" },
            "ospd.running",
            if running {
                "ospd-openvas container is running.".into()
            } else {
                "ospd-openvas container is not running; run just runtime-app-up.".into()
            },
        )
        .with_details(json!({"service": SERVICE})),
    );
    if !running {
        return make_result(
            metadata(repo_root, "runtime-scanner-process-check", runner),
            "Scanner process check stopped because ospd-openvas is not running.".into(),
            findings,
        );
    }

    let process_probe = exec_in_service(
        repo_root,
        runner,
        SERVICE,
        &["ps", "-eo", "pid,ppid,stat,comm"],
    );
    let process_summary = summarize_processes(&process_probe.stdout);
    let zombie_count = process_summary["zombie_count"].as_u64().unwrap_or_default();
    let active_count = process_summary["active_scanner_child_count"]
        .as_u64()
        .unwrap_or_default();
    let (process_status, process_message) = if !process_probe.success {
        (
            "fail",
            format!(
                "Scanner process table probe exit code {}.",
                exit_code(&process_probe)
            ),
        )
    } else if zombie_count > 0 && active_count > 0 {
        (
            "warn",
            format!(
                "ospd-openvas has {zombie_count} zombie child process(es) while scanner children are active."
            ),
        )
    } else if zombie_count > 0 {
        (
            "fail",
            format!(
                "ospd-openvas has {zombie_count} zombie child process(es) with no active scanner children."
            ),
        )
    } else {
        ("pass", "ospd-openvas has no zombie child processes.".into())
    };
    findings.push(
        Finding::new(process_status, "ospd.process-zombies", process_message)
            .with_details(json!({"process_summary": process_summary})),
    );

    let ospd_exposure_probe = exec_in_service_owned(
        repo_root,
        runner,
        SERVICE,
        &exposure_probe_arguments(
            "ospd-openvas",
            OSPD_SECRET_FILE,
            "/workspace/build/venvs/ospd-openvas/bin/python",
            true,
            &environment,
        ),
    );
    let ospd_exposure = parse_exposure(&ospd_exposure_probe);

    let inspections = inspect_services(repo_root, runner, ospd_id);
    let mqtt_environment = environment_evidence(repo_root, &inspections);
    let environment_ok = mqtt_environment["inspected_pair_count"]
        == mqtt_environment["expected_pair_count"]
        && empty_arrays(
            &mqtt_environment,
            &[
                "unreadable_secret_names",
                "uninspected_pairs",
                "key_exposure_pairs",
                "value_exposure_pairs",
                "uninspected_config_services",
                "config_secret_exposure_services",
            ],
        );
    findings.push(
        Finding::new(
            if environment_ok { "pass" } else { "fail" },
            "mqtt.environment-secret-exposure",
            if environment_ok {
                "MQTT credentials are absent from broker and scanner service environments.".into()
            } else {
                "MQTT credential environment exposure remains or could not be verified.".into()
            },
        )
        .with_details(mqtt_environment),
    );

    let mqtt_mounts = mount_evidence(repo_root, runner, &inspections);
    let mounts_ok = mqtt_mounts["matched_mount_count"] == mqtt_mounts["expected_mount_count"]
        && empty_arrays(
            &mqtt_mounts,
            &["uninspected_mounts", "unmatched_mounts", "stale_mounts"],
        );
    findings.push(
        Finding::new(
            if mounts_ok { "pass" } else { "fail" },
            "mqtt.read-only-secret-mounts",
            if mounts_ok {
                "MQTT consumers use the exact expected read-only secret-file mounts.".into()
            } else {
                "MQTT secret-file mounts are missing, writable, or could not be verified.".into()
            },
        )
        .with_details(mqtt_mounts),
    );

    let ospd_exposure_ok = ospd_exposure.as_ref().is_some_and(exposure_is_clean);
    findings.push(
        Finding::new(
            if ospd_exposure_ok { "pass" } else { "fail" },
            "ospd.mqtt-secret-exposure",
            if ospd_exposure_ok {
                "OSPD MQTT password is absent from process arguments.".into()
            } else {
                "OSPD MQTT password or plaintext option remains exposed or could not be verified."
                    .into()
            },
        )
        .with_details(exposure_details(
            &ospd_exposure_probe,
            ospd_exposure.as_ref(),
            false,
        )),
    );
    let ospd_file_count = ospd_exposure
        .as_ref()
        .map(|value| value.exact_password_file_option_pids.len())
        .unwrap_or_default();
    findings.push(
        Finding::new(
            if ospd_file_count > 0 { "pass" } else { "fail" },
            "ospd.mqtt-password-file-option",
            if ospd_file_count > 0 {
                "ospd-openvas uses the file-backed MQTT password option.".into()
            } else {
                "ospd-openvas is not using the file-backed MQTT password option.".into()
            },
        )
        .with_details(json!({
            "probe_exit_code": exit_code(&ospd_exposure_probe),
            "configured_process_count": ospd_file_count,
        })),
    );

    let notus_exposure_probe = exec_in_service_owned(
        repo_root,
        runner,
        "notus-scanner",
        &exposure_probe_arguments(
            "notus-scanner",
            NOTUS_SECRET_FILE,
            "/workspace/build/venvs/notus-scanner/bin/python",
            false,
            &environment,
        ),
    );
    let notus_exposure = parse_exposure(&notus_exposure_probe);
    let notus_file_count = notus_exposure
        .as_ref()
        .map(|value| value.exact_password_file_option_pids.len())
        .unwrap_or_default();
    let notus_ok = notus_exposure.as_ref().is_some_and(exposure_is_clean) && notus_file_count > 0;
    findings.push(
        Finding::new(
            if notus_ok { "pass" } else { "fail" },
            "notus.mqtt-secret-exposure",
            if notus_ok {
                "Notus MQTT password is absent from process arguments and the exact file option is active.".into()
            } else {
                "Notus MQTT password handling remains exposed or could not be verified.".into()
            },
        )
        .with_details(exposure_details(
            &notus_exposure_probe,
            notus_exposure.as_ref(),
            true,
        )),
    );

    for (service, username, secret_file, python, drop_privileges) in [
        (
            "ospd-openvas",
            "ospd",
            OSPD_SECRET_FILE,
            "/workspace/build/venvs/ospd-openvas/bin/python",
            true,
        ),
        (
            "notus-scanner",
            "notus",
            NOTUS_SECRET_FILE,
            "/workspace/build/venvs/notus-scanner/bin/python",
            false,
        ),
    ] {
        let probe = exec_in_service_owned(
            repo_root,
            runner,
            service,
            &authentication_probe_arguments(
                username,
                secret_file,
                python,
                drop_privileges,
                &environment,
            ),
        );
        let authenticated = probe.success && probe.stdout.contains("mqtt-auth-ok");
        findings.push(
            Finding::new(
                if authenticated { "pass" } else { "fail" },
                &format!("{username}.mqtt-authentication"),
                if authenticated {
                    format!("{username} authenticated to the MQTT broker from its service context.")
                } else {
                    format!("{username} could not authenticate to the MQTT broker from its service context.")
                },
            )
            .with_details(json!({
                "service": service,
                "probe_exit_code": exit_code(&probe),
                "authenticated": authenticated,
            })),
        );
    }

    make_result(
        metadata(repo_root, "runtime-scanner-process-check", runner),
        "Scanner process check completed.".into(),
        findings,
    )
}

fn secret_file_evidence(path: &Path, expected_uid: u32) -> (Value, bool) {
    let mut details = Map::new();
    let metadata = fs::symlink_metadata(path).ok();
    let exists = metadata.is_some();
    let mode = metadata
        .as_ref()
        .map(|value| value.permissions().mode() & 0o7777);
    let regular = metadata
        .as_ref()
        .is_some_and(|value| value.file_type().is_file());
    let symlink = metadata
        .as_ref()
        .is_some_and(|value| value.file_type().is_symlink());
    let accessible = mode.is_some_and(|value| value & 0o077 != 0);
    let owner_uid = metadata.as_ref().map(MetadataExt::uid);
    let permission_ok = regular && !accessible;
    let mut content_ok = false;
    if exists && permission_ok && owner_uid == Some(expected_uid) {
        content_ok = read_private_text(path, MAX_SECRET_BYTES)
            .ok()
            .and_then(normalize_secret)
            .is_some();
    }
    details.insert("exists".into(), json!(exists));
    details.insert(
        "mode".into(),
        mode.map(|value| Value::String(format!("{value:04o}")))
            .unwrap_or(Value::Null),
    );
    details.insert("permission_ok".into(), json!(permission_ok));
    details.insert("group_or_world_accessible".into(), json!(accessible));
    details.insert("regular_file".into(), json!(regular));
    details.insert("symlink".into(), json!(symlink));
    details.insert("owner_uid".into(), json!(owner_uid));
    details.insert("expected_owner_uid".into(), json!(expected_uid));
    details.insert("owner_ok".into(), json!(owner_uid == Some(expected_uid)));
    (Value::Object(details), content_ok)
}

fn normalize_secret(mut value: String) -> Option<String> {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    (!value.is_empty()
        && !value
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b'\0' | b'\n' | b'\r')))
    .then_some(value)
}

fn summarize_processes(output: &str) -> Value {
    let mut count = 0_u64;
    let mut zombie_count = 0_u64;
    let mut active_count = 0_u64;
    let mut zombies = Vec::new();
    let mut active = Vec::new();
    for line in output.lines().skip(1) {
        let parts = line.split_whitespace().take(4).collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }
        count += 1;
        let row = json!({
            "pid": parts[0], "ppid": parts[1], "stat": parts[2], "comm": parts[3],
        });
        if parts[2].contains('Z') {
            zombie_count += 1;
            if zombies.len() < 50 {
                zombies.push(row);
            }
        } else if matches!(parts[3], "openvas" | "nmap") {
            active_count += 1;
            if active.len() < 50 {
                active.push(row);
            }
        }
    }
    json!({
        "process_count": count,
        "zombie_count": zombie_count,
        "active_scanner_child_count": active_count,
        "zombies": zombies,
        "active_scanner_children": active,
    })
}

fn inspect_services(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    ospd_id: Option<String>,
) -> BTreeMap<String, ServiceInspection> {
    ENVIRONMENT_SERVICES
        .iter()
        .map(|service| {
            let id = if *service == SERVICE {
                ospd_id.clone()
            } else {
                container_id(repo_root, runner, service)
            };
            let mut inspection = ServiceInspection {
                ..ServiceInspection::default()
            };
            if let Some(id) = id.as_deref() {
                inspection.environment =
                    inspect_json(repo_root, runner, id, "{{json .Config.Env}}");
                inspection.config = inspect_json(repo_root, runner, id, "{{json .Config}}");
                inspection.mounts = inspect_json(repo_root, runner, id, "{{json .Mounts}}");
            }
            ((*service).to_string(), inspection)
        })
        .collect()
}

fn environment_evidence(
    repo_root: &Path,
    inspections: &BTreeMap<String, ServiceInspection>,
) -> Value {
    let mut inspected_pair_count = 0_usize;
    let mut unreadable = Vec::new();
    let mut uninspected = Vec::new();
    let mut key_exposure = Vec::new();
    let mut value_exposure = Vec::new();
    let mut secret_values = Vec::new();
    for (environment_name, secret_name, _) in MQTT_SECRETS {
        let secret = read_private_text(
            &runtime_secret_path(repo_root, secret_name),
            MAX_SECRET_BYTES,
        )
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
        let Some(secret) = secret else {
            unreadable.push(secret_name);
            continue;
        };
        secret_values.push(secret.clone());
        for service in ENVIRONMENT_SERVICES {
            let label = format!("{service}:{environment_name}");
            let values = inspections
                .get(service)
                .and_then(|value| value.environment.as_ref())
                .and_then(Value::as_array);
            let Some(values) = values else {
                uninspected.push(label);
                continue;
            };
            if !values.iter().all(Value::is_string) {
                uninspected.push(label);
                continue;
            }
            inspected_pair_count += 1;
            let prefix = format!("{environment_name}=");
            if values
                .iter()
                .filter_map(Value::as_str)
                .any(|value| value.starts_with(&prefix))
            {
                key_exposure.push(label.clone());
            }
            if values
                .iter()
                .filter_map(Value::as_str)
                .any(|value| value.contains(&secret))
            {
                value_exposure.push(label);
            }
        }
    }
    let mut uninspected_config = Vec::new();
    let mut config_exposure = Vec::new();
    for service in ENVIRONMENT_SERVICES {
        let Some(config) = inspections
            .get(service)
            .and_then(|value| value.config.as_ref())
        else {
            uninspected_config.push(service);
            continue;
        };
        let rendered = serde_json::to_string(config).unwrap_or_default();
        if secret_values
            .iter()
            .any(|secret| !secret.is_empty() && rendered.contains(secret))
        {
            config_exposure.push(service);
        }
    }
    json!({
        "expected_pair_count": MQTT_SECRETS.len() * ENVIRONMENT_SERVICES.len(),
        "inspected_pair_count": inspected_pair_count,
        "unreadable_secret_names": unreadable,
        "uninspected_pairs": uninspected,
        "key_exposure_pairs": key_exposure,
        "value_exposure_pairs": value_exposure,
        "uninspected_config_services": uninspected_config,
        "config_secret_exposure_services": config_exposure,
    })
}

fn mount_evidence(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    inspections: &BTreeMap<String, ServiceInspection>,
) -> Value {
    let mut specs = vec![
        (SERVICE, OSPD_SECRET, OSPD_SECRET_FILE),
        ("notus-scanner", "mqtt-notus-password", NOTUS_SECRET_FILE),
    ];
    specs.extend(
        MQTT_SECRETS
            .iter()
            .map(|(_, secret_name, destination)| ("mosquitto", *secret_name, *destination)),
    );
    let mut uninspected = Vec::new();
    let mut unmatched = Vec::new();
    let mut stale = Vec::new();
    for (service, secret_name, destination) in &specs {
        let label = format!("{service}:{secret_name}");
        let Some(mounts) = inspections
            .get(*service)
            .and_then(|value| value.mounts.as_ref())
            .and_then(Value::as_array)
        else {
            uninspected.push(label);
            continue;
        };
        let source = runtime_secret_path(repo_root, secret_name);
        let expected_source = source.display().to_string();
        let matched = mounts.iter().any(|mount| {
            mount.get("Type").and_then(Value::as_str) == Some("bind")
                && mount.get("Source").and_then(Value::as_str) == Some(&expected_source)
                && mount.get("Destination").and_then(Value::as_str) == Some(*destination)
                && mount.get("RW").and_then(Value::as_bool) == Some(false)
        });
        if !matched {
            unmatched.push(label);
            continue;
        }
        if !mounted_content_matches(repo_root, runner, service, &source, destination) {
            stale.push(label);
        }
    }
    json!({
        "expected_mount_count": specs.len(),
        "matched_mount_count": specs.len() - uninspected.len() - unmatched.len() - stale.len(),
        "uninspected_mounts": uninspected,
        "unmatched_mounts": unmatched,
        "stale_mounts": stale,
    })
}

fn mounted_content_matches(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    service: &str,
    source: &Path,
    destination: &str,
) -> bool {
    let before = fs::symlink_metadata(source).ok();
    let first = read_private_text(source, MAX_SECRET_BYTES).ok();
    let digest = exec_in_service(repo_root, runner, service, &["sha256sum", destination]);
    let second = read_private_text(source, MAX_SECRET_BYTES).ok();
    let after = fs::symlink_metadata(source).ok();
    let stable = before
        .as_ref()
        .zip(after.as_ref())
        .is_some_and(|(before, after)| {
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
        })
        && first == second;
    let expected = second.map(|value| format!("{:x}", Sha256::digest(value.as_bytes())));
    let observed = digest.stdout.split_whitespace().next();
    stable
        && digest.success
        && expected
            .as_deref()
            .is_some_and(|value| Some(value) == observed)
}

fn parse_exposure(output: &ProcessOutput) -> Option<Exposure> {
    if !output.success || output.stdout.len() > MAX_JSON_OUTPUT_BYTES {
        return None;
    }
    let value: Value = serde_json::from_str(&output.stdout).ok()?;
    let object = value.as_object()?;
    let exact = [
        "cmdline_secret_pids",
        "inline_password_option_pids",
        "exact_password_file_option_pids",
        "unexpected_password_file_option_pids",
        "cmdline_unreadable_pids",
    ];
    if object.len() != exact.len() || !exact.iter().all(|key| object.contains_key(*key)) {
        return None;
    }
    Some(Exposure {
        cmdline_secret_pids: pid_array(object, exact[0])?,
        inline_password_option_pids: pid_array(object, exact[1])?,
        exact_password_file_option_pids: pid_array(object, exact[2])?,
        unexpected_password_file_option_pids: pid_array(object, exact[3])?,
        cmdline_unreadable_pids: pid_array(object, exact[4])?,
    })
}

fn pid_array(object: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
    let values = object.get(key)?.as_array()?;
    if values.len() > 50 {
        return None;
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_str()?;
            (!value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| value.to_string())
        })
        .collect()
}

fn exposure_is_clean(exposure: &Exposure) -> bool {
    exposure.cmdline_secret_pids.is_empty()
        && exposure.inline_password_option_pids.is_empty()
        && exposure.cmdline_unreadable_pids.is_empty()
        && exposure.unexpected_password_file_option_pids.is_empty()
}

fn exposure_details(
    probe: &ProcessOutput,
    exposure: Option<&Exposure>,
    include_count: bool,
) -> Value {
    let mut details = Map::new();
    details.insert("probe_exit_code".into(), json!(exit_code(probe)));
    if include_count {
        details.insert(
            "configured_process_count".into(),
            json!(
                exposure
                    .map(|value| value.exact_password_file_option_pids.len())
                    .unwrap_or_default()
            ),
        );
    }
    for (key, values) in [
        (
            "cmdline_secret_pids",
            exposure.map(|value| &value.cmdline_secret_pids),
        ),
        (
            "inline_password_option_pids",
            exposure.map(|value| &value.inline_password_option_pids),
        ),
        (
            "cmdline_unreadable_pids",
            exposure.map(|value| &value.cmdline_unreadable_pids),
        ),
        (
            "unexpected_password_file_option_pids",
            exposure.map(|value| &value.unexpected_password_file_option_pids),
        ),
    ] {
        details.insert(key.into(), json!(values.cloned().unwrap_or_default()));
    }
    Value::Object(details)
}

fn exposure_probe_arguments(
    process_name: &str,
    secret_file: &str,
    python: &str,
    drop_privileges: bool,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Vec<String> {
    let script = format!(
        "import json\nfrom pathlib import Path\n\nprocess_name = {process_name:?}\nsecret_path = Path({secret_file:?})\n{}",
        EXPOSURE_PROBE_BODY
    );
    privileged_python_arguments(python, script, drop_privileges, environment)
}

const EXPOSURE_PROBE_BODY: &str = r#"secret = secret_path.read_bytes()
if secret.endswith(b'\n'):
    secret = secret[:-1]
    if secret.endswith(b'\r'):
        secret = secret[:-1]

result = {
    'cmdline_secret_pids': [],
    'inline_password_option_pids': [],
    'exact_password_file_option_pids': [],
    'unexpected_password_file_option_pids': [],
    'cmdline_unreadable_pids': [],
}
for process_dir in Path('/proc').iterdir():
    if not process_dir.name.isdigit():
        continue
    try:
        if (process_dir / 'comm').read_text().strip() != process_name:
            continue
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    try:
        cmdline = (process_dir / 'cmdline').read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        result['cmdline_unreadable_pids'].append(process_dir.name)
        cmdline = b''
    arguments = [value for value in cmdline.split(b'\0') if value]
    if any(value == b'--mqtt-broker-password' or value.startswith(b'--mqtt-broker-password=') for value in arguments):
        result['inline_password_option_pids'].append(process_dir.name)
    file_options = [value for value in arguments if value == b'--mqtt-broker-password-file' or value.startswith(b'--mqtt-broker-password-file=')]
    expected_file_option = b'--mqtt-broker-password-file=' + str(secret_path).encode()
    if expected_file_option in file_options:
        result['exact_password_file_option_pids'].append(process_dir.name)
    if any(value != expected_file_option for value in file_options):
        result['unexpected_password_file_option_pids'].append(process_dir.name)
    if secret and secret in cmdline:
        result['cmdline_secret_pids'].append(process_dir.name)
print(json.dumps(result, sort_keys=True))
"#;

fn authentication_probe_arguments(
    username: &str,
    secret_file: &str,
    python: &str,
    drop_privileges: bool,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Vec<String> {
    let script = format!(
        "import time\nfrom pathlib import Path\nimport paho.mqtt.client as mqtt\n\nsecret = Path({secret_file:?}).read_text(encoding='utf-8')\n{}\nclient.username_pw_set({username:?}, secret)\n{}",
        AUTH_CLIENT_BODY, AUTH_CONNECT_BODY
    );
    privileged_python_arguments(python, script, drop_privileges, environment)
}

const AUTH_CLIENT_BODY: &str = r#"if secret.endswith('\n'):
    secret = secret[:-1]
    if secret.endswith('\r'):
        secret = secret[:-1]
if not secret or any(value in secret for value in ('\x00', '\n', '\r')):
    raise SystemExit('invalid-secret-file')
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2) if hasattr(mqtt, 'CallbackAPIVersion') else mqtt.Client()"#;

const AUTH_CONNECT_BODY: &str = r#"client.connect('mosquitto', 1883, 5)
deadline = time.monotonic() + 5
while time.monotonic() < deadline and not client.is_connected():
    client.loop(timeout=0.2)
if not client.is_connected():
    raise SystemExit('mqtt-authentication-failed')
client.disconnect()
client.loop(timeout=0.2)
print('mqtt-auth-ok')
"#;

fn privileged_python_arguments(
    python: &str,
    script: String,
    drop_privileges: bool,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Vec<String> {
    let mut command = Vec::new();
    if drop_privileges {
        command.extend([
            "setpriv".into(),
            "--reuid".into(),
            environment_value(environment, "YAFVS_UID"),
            "--regid".into(),
            environment_value(environment, "YAFVS_GID"),
            "--clear-groups".into(),
        ]);
    }
    command.extend([python.into(), "-c".into(), script]);
    command
}

fn inspect_json(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    container_id: &str,
    format: &str,
) -> Option<Value> {
    let output = run_docker(
        repo_root,
        runner,
        &[
            "inspect".into(),
            "-f".into(),
            format.into(),
            container_id.into(),
        ],
    );
    (output.success && output.stdout.len() <= MAX_JSON_OUTPUT_BYTES)
        .then(|| serde_json::from_str(&output.stdout).ok())
        .flatten()
}

fn container_id(repo_root: &Path, runner: &dyn CommandRunner, service: &str) -> Option<String> {
    let output = run_docker(
        repo_root,
        runner,
        &compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]),
    );
    let value = output.stdout.lines().next().unwrap_or("").trim();
    (output.success && valid_container_id(value)).then(|| value.to_string())
}

fn valid_container_id(value: &str) -> bool {
    (12..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn container_running(repo_root: &Path, runner: &dyn CommandRunner, container_id: &str) -> bool {
    let output = run_docker(
        repo_root,
        runner,
        &[
            "inspect".into(),
            "-f".into(),
            "{{.State.Running}}".into(),
            container_id.into(),
        ],
    );
    output.success && output.stdout.trim() == "true"
}

fn exec_in_service(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    service: &str,
    command: &[&str],
) -> ProcessOutput {
    exec_in_service_owned(
        repo_root,
        runner,
        service,
        &command
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    )
}

fn exec_in_service_owned(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    service: &str,
    command: &[String],
) -> ProcessOutput {
    let mut arguments = vec!["exec".into(), "-T".into(), service.into()];
    arguments.extend_from_slice(command);
    run_docker(repo_root, runner, &compose_command(repo_root, &arguments))
}

fn run_docker(repo_root: &Path, runner: &dyn CommandRunner, arguments: &[String]) -> ProcessOutput {
    let mut output = runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or_else(failed_process);
    if output.stdout.len() > MAX_JSON_OUTPUT_BYTES || output.stderr.len() > MAX_JSON_OUTPUT_BYTES {
        output.success = false;
        output.exit_code = Some(125);
        output.stdout.clear();
        output.stderr.clear();
    }
    output
}

fn failed_process() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn exit_code(output: &ProcessOutput) -> i32 {
    output.exit_code.unwrap_or(1)
}

fn environment_value(
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    key: &str,
) -> String {
    environment
        .get(&std::ffi::OsString::from(key))
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn empty_arrays(value: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| {
        value
            .get(*key)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct ScriptedRunner {
        outputs: Mutex<VecDeque<ProcessOutput>>,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ScriptedRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for ScriptedRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| output(true, "deadbee\n"))
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
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            self.outputs.lock().unwrap().pop_front()
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

    fn fixture() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-scanner-process-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        for (_, secret_name, _) in MQTT_SECRETS {
            let path = runtime_secret_path(&repo, secret_name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture-secret\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        (root, repo)
    }

    fn mount(source: &Path, destination: &str) -> Value {
        json!({
            "Type": "bind",
            "Source": source,
            "Destination": destination,
            "RW": false,
        })
    }

    fn successful_outputs(repo: &Path) -> Vec<ProcessOutput> {
        let exposure = json!({
            "cmdline_secret_pids": [],
            "inline_password_option_pids": [],
            "exact_password_file_option_pids": ["7"],
            "unexpected_password_file_option_pids": [],
            "cmdline_unreadable_pids": [],
        })
        .to_string();
        let mosquitto_mounts = MQTT_SECRETS
            .iter()
            .map(|(_, name, destination)| mount(&runtime_secret_path(repo, name), destination))
            .collect::<Vec<_>>();
        let ospd_mounts = vec![mount(
            &runtime_secret_path(repo, OSPD_SECRET),
            OSPD_SECRET_FILE,
        )];
        let notus_mounts = vec![mount(
            &runtime_secret_path(repo, "mqtt-notus-password"),
            NOTUS_SECRET_FILE,
        )];
        let digest = format!("{:x}", Sha256::digest(b"fixture-secret\n"));
        let mut outputs = vec![
            output(true, &format!("{}\n", "a".repeat(64))),
            output(true, "true\n"),
            output(
                true,
                "PID PPID STAT COMMAND\n1 0 Ss docker-init\n7 1 Sl ospd-openvas\n",
            ),
            output(true, &exposure),
            output(true, &format!("{}\n", "b".repeat(64))),
            output(true, "[]"),
            output(true, "{}"),
            output(true, &Value::Array(mosquitto_mounts).to_string()),
            output(true, "[]"),
            output(true, "{}"),
            output(true, &Value::Array(ospd_mounts).to_string()),
            output(true, &format!("{}\n", "c".repeat(64))),
            output(true, "[]"),
            output(true, "{}"),
            output(true, &Value::Array(notus_mounts).to_string()),
        ];
        outputs.extend((0..6).map(|_| output(true, &format!("{digest}  secret\n"))));
        outputs.extend([
            output(true, &exposure),
            output(true, "mqtt-auth-ok\n"),
            output(true, "mqtt-auth-ok\n"),
        ]);
        outputs
    }

    #[test]
    fn process_summary_counts_all_rows_and_bounds_metadata() {
        let mut process_table = String::from("PID PPID STAT COMMAND\n");
        for index in 0..55 {
            process_table.push_str(&format!("{} 1 Z nmap\n", index + 10));
        }
        process_table.push_str("99 1 S openvas\n100 1 S docker-init\n");
        let summary = summarize_processes(&process_table);
        assert_eq!(summary["process_count"], 57);
        assert_eq!(summary["zombie_count"], 55);
        assert_eq!(summary["zombies"].as_array().unwrap().len(), 50);
        assert_eq!(summary["active_scanner_child_count"], 1);
        assert_eq!(summary["active_scanner_children"][0]["comm"], "openvas");
    }

    #[test]
    fn exposure_schema_is_exact_bounded_and_pid_only() {
        let valid = output(
            true,
            r#"{"cmdline_secret_pids":[],"inline_password_option_pids":[],"exact_password_file_option_pids":["7"],"unexpected_password_file_option_pids":[],"cmdline_unreadable_pids":[]}"#,
        );
        assert_eq!(
            parse_exposure(&valid)
                .unwrap()
                .exact_password_file_option_pids,
            ["7"]
        );
        let leaked = output(
            true,
            r#"{"cmdline_secret_pids":["fixture-secret"],"inline_password_option_pids":[],"exact_password_file_option_pids":[],"unexpected_password_file_option_pids":[],"cmdline_unreadable_pids":[]}"#,
        );
        assert!(parse_exposure(&leaked).is_none());
        let extra = output(
            true,
            r#"{"cmdline_secret_pids":[],"inline_password_option_pids":[],"exact_password_file_option_pids":[],"unexpected_password_file_option_pids":[],"cmdline_unreadable_pids":[],"extra":[]}"#,
        );
        assert!(parse_exposure(&extra).is_none());
    }

    #[test]
    fn embedded_probes_keep_exact_non_root_and_file_backed_contracts() {
        let environment = runtime_environment(Path::new("/srv/YAFVS"));
        let exposure = exposure_probe_arguments(
            "ospd-openvas",
            OSPD_SECRET_FILE,
            "/venv/python",
            true,
            &environment,
        );
        assert_eq!(exposure[0], "setpriv");
        let expected_uid = environment_value(&environment, "YAFVS_UID");
        assert!(
            exposure
                .windows(2)
                .any(|pair| pair == ["--reuid", expected_uid.as_str()])
        );
        assert!(exposure.contains(&"--clear-groups".into()));
        assert!(exposure.last().unwrap().contains(OSPD_SECRET_FILE));
        assert!(
            !exposure
                .last()
                .unwrap()
                .contains("YAFVS_MQTT_OSPD_PASSWORD")
        );

        let auth = authentication_probe_arguments(
            "notus",
            NOTUS_SECRET_FILE,
            "/venv/python",
            false,
            &environment,
        );
        assert_eq!(auth[0], "/venv/python");
        assert!(auth[2].contains("CallbackAPIVersion"));
        assert!(auth[2].contains("mosquitto', 1883, 5"));
        assert!(auth[2].contains("time.monotonic() + 5"));
    }

    #[test]
    fn stopped_runtime_fails_closed_before_service_probes() {
        let (root, repo) = fixture();
        let runner = ScriptedRunner::new(vec![output(true, "")]);
        let result = command_runtime_scanner_process_check_with(&repo, &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].check, "ospd.mqtt-secret-file");
        assert_eq!(result.findings[1].check, "ospd.running");
        assert_eq!(runner.calls().len(), 1);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("fixture-secret")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_output_and_stale_mount_content_fail_closed() {
        let (root, repo) = fixture();
        let oversized =
            ScriptedRunner::new(vec![output(true, &"x".repeat(MAX_JSON_OUTPUT_BYTES + 1))]);
        assert!(container_id(&repo, &oversized, SERVICE).is_none());
        assert_eq!(oversized.calls().len(), 1);

        let stale =
            ScriptedRunner::new(vec![output(true, &format!("{}  secret\n", "0".repeat(64)))]);
        assert!(!mounted_content_matches(
            &repo,
            &stale,
            SERVICE,
            &runtime_secret_path(&repo, OSPD_SECRET),
            OSPD_SECRET_FILE,
        ));
        let missing = root.join("missing-secret");
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        assert!(!secret_file_evidence(&missing, uid).1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_container_identity_stops_before_docker_inspect() {
        let (root, repo) = fixture();
        let runner = ScriptedRunner::new(vec![output(true, "--format\n")]);
        let result = command_runtime_scanner_process_check_with(&repo, &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings.len(), 2);
        assert_eq!(runner.calls().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn success_preserves_finding_order_commands_and_non_disclosure() {
        let (root, repo) = fixture();
        let runner = ScriptedRunner::new(successful_outputs(&repo));
        let result = command_runtime_scanner_process_check_with(&repo, &runner);
        assert_eq!(result.status, "pass");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            [
                "ospd.mqtt-secret-file",
                "ospd.running",
                "ospd.process-zombies",
                "mqtt.environment-secret-exposure",
                "mqtt.read-only-secret-mounts",
                "ospd.mqtt-secret-exposure",
                "ospd.mqtt-password-file-option",
                "notus.mqtt-secret-exposure",
                "ospd.mqtt-authentication",
                "notus.mqtt-authentication",
            ]
        );
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(!rendered.contains("fixture-secret"));
        let calls = runner.calls();
        assert_eq!(calls.len(), 24);
        assert!(calls.iter().all(|(program, _)| program == "docker"));
        assert!(
            calls
                .iter()
                .all(|(_, arguments)| { !arguments.iter().any(|value| value == "fixture-secret") })
        );
        assert_eq!(calls.last().unwrap().1[5], "notus-scanner");
        fs::remove_dir_all(root).unwrap();
    }
}
