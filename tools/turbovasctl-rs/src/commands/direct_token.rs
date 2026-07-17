// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::metadata;
use super::compose::{compose_command, runtime_environment};
use super::secret::{rotate_runtime_secret, runtime_secret_path};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const SECRET_NAME: &str = "native-api-bearer-token";
const CONTAINER_PORT: &str = "9081";

pub fn command_runtime_native_api_direct_token(repo_root: &Path, rotate: bool) -> ResultEnvelope {
    command_runtime_native_api_direct_token_with_runner(repo_root, rotate, &SystemCommandRunner)
}

fn command_runtime_native_api_direct_token_with_runner(
    repo_root: &Path,
    rotate: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let path = runtime_secret_path(repo_root, SECRET_NAME);
    let mut findings = Vec::new();
    if rotate {
        rotate_runtime_secret(repo_root, SECRET_NAME)
            .expect("could not rotate native API bearer token");
        findings.push(
            Finding::new(
                "pass",
                "native-api-direct-token.rotate",
                "Direct native API runtime bearer token was rotated without printing the secret value."
                    .to_string(),
            )
            .with_path(&path.display().to_string()),
        );
    }
    let token = if path.is_file() {
        fs::read_to_string(&path)
            .map(|text| text.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let exists = !token.is_empty();
    let acceptable = exists && bearer_token_is_acceptable(&token);
    let file = secret_file_metadata(&path);
    let permission_ok = file
        .get("permission_ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = if exists && acceptable && permission_ok {
        "pass"
    } else if exists && acceptable {
        "fail"
    } else {
        "warn"
    };
    findings.push(
        Finding::new(
            status,
            "native-api-direct-token.runtime-secret",
            if status == "pass" {
                "Direct native API runtime bearer token file exists, satisfies the local strength contract, and is not group/world accessible."
                    .to_string()
            } else {
                "Direct native API runtime bearer token file is missing, weak, or group/world accessible."
                    .to_string()
            },
        )
        .with_path(&path.display().to_string())
        .with_details(json!({
            "exists": exists,
            "acceptable": acceptable,
            "secret_path": path.display().to_string(),
            "mode": file.get("mode").cloned().unwrap_or(Value::Null),
            "permission_ok": permission_ok,
            "group_or_world_accessible": file.get("group_or_world_accessible").and_then(Value::as_bool).unwrap_or(false),
            "token_value_reported": false,
        })),
    );
    if rotate {
        let bindings = current_published_bindings(repo_root, runner);
        findings.push(
            Finding::new(
                if bindings.is_empty() { "pass" } else { "warn" },
                "native-api-direct-token.running-listener-reload",
                if bindings.is_empty() {
                    "No running direct native API listener publication was detected; no live direct listener needs token reload."
                        .to_string()
                } else {
                    "A running direct native API listener is currently published and may still require turbovas-api restart or runtime-native-api-direct-smoke before it accepts the rotated token."
                        .to_string()
                },
            )
            .with_details(json!({
                "published_bindings": bindings,
                "token_value_reported": false,
            })),
        );
        findings.push(Finding::new(
            "pass",
            "native-api-direct-token.reload-required",
            "Restart turbovas-api or rerun runtime-native-api-direct-smoke before expecting any running direct listener to accept the rotated token."
                .to_string(),
        ));
    }
    make_result(
        metadata(repo_root, "runtime-native-api-direct-token", runner),
        if rotate {
            "Direct native API runtime bearer token rotated.".to_string()
        } else {
            "Direct native API runtime bearer token inspected.".to_string()
        },
        findings,
    )
}

fn secret_file_metadata(path: &Path) -> Value {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return json!({
            "exists": false,
            "mode": null,
            "permission_ok": false,
            "group_or_world_accessible": false,
            "regular_file": false,
            "symlink": false,
        });
    };
    let mode = metadata.permissions().mode() & 0o7777;
    let regular_file = metadata.file_type().is_file();
    let symlink = metadata.file_type().is_symlink();
    let group_or_world_accessible = mode & 0o077 != 0;
    json!({
        "exists": true,
        "mode": format!("{mode:04o}"),
        "permission_ok": regular_file && !group_or_world_accessible,
        "group_or_world_accessible": group_or_world_accessible,
        "regular_file": regular_file,
        "symlink": symlink,
    })
}

fn bearer_token_is_acceptable(token: &str) -> bool {
    (32..=1024).contains(&token.chars().count())
        && token.chars().all(|character| {
            character.is_ascii() && !character.is_whitespace() && ('!'..='~').contains(&character)
        })
}

fn current_published_bindings(repo_root: &Path, runner: &dyn CommandRunner) -> Vec<Value> {
    let environment = runtime_environment(repo_root);
    let compose = compose_command(
        repo_root,
        &[
            "ps".to_string(),
            "-q".to_string(),
            "turbovas-api".to_string(),
        ],
    );
    let compose_args = compose.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(container) = runner
        .run_with(
            "docker",
            &compose_args,
            Some(repo_root),
            Some(&environment),
            None,
        )
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .map(str::to_string)
        })
        .filter(|container| !container.is_empty())
    else {
        return Vec::new();
    };
    let Some(output) = runner
        .run_with(
            "docker",
            &[
                "inspect",
                "-f",
                "{{json .NetworkSettings.Ports}}",
                &container,
            ],
            Some(repo_root),
            Some(&environment),
            None,
        )
        .filter(|output| output.success && !output.stdout.trim().is_empty())
    else {
        return Vec::new();
    };
    let Ok(payload) = serde_json::from_str::<Value>(&output.stdout) else {
        return Vec::new();
    };
    let Some(bindings) = payload
        .get(format!("{CONTAINER_PORT}/tcp"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut published = Vec::new();
    for binding in bindings {
        let Some(binding) = binding.as_object() else {
            continue;
        };
        let host = binding
            .get("HostIp")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0")
            .trim();
        let host = if host.is_empty() { "0.0.0.0" } else { host };
        let port = binding
            .get("HostPort")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        if port.is_empty() || !seen.insert((host.to_string(), port.to_string())) {
            continue;
        }
        published.push(json!({
            "host": host,
            "host_port": port,
            "container_port": CONTAINER_PORT,
        }));
    }
    published
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_contract_rejects_whitespace_and_short_values() {
        assert!(bearer_token_is_acceptable(&"a".repeat(32)));
        assert!(!bearer_token_is_acceptable("short"));
        assert!(!bearer_token_is_acceptable(&format!("{} ", "a".repeat(32))));
    }
}
