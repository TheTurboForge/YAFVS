// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::compose::{compose_command, runtime_environment};
use crate::process::CommandRunner;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(crate) const DIRECT_CONTAINER_PORT: &str = "9081";

pub(crate) fn secret_file_metadata(path: &Path) -> Value {
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

pub(crate) fn bearer_token_is_acceptable(token: &str) -> bool {
    (32..=1024).contains(&token.chars().count())
        && token.chars().all(|character| {
            character.is_ascii() && !character.is_whitespace() && ('!'..='~').contains(&character)
        })
}

pub(crate) fn current_published_bindings(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> Vec<Value> {
    let environment = runtime_environment(repo_root);
    let compose = compose_command(
        repo_root,
        &["ps".to_string(), "-q".to_string(), "yafvs-api".to_string()],
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
        .get(format!("{DIRECT_CONTAINER_PORT}/tcp"))
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
            "container_port": DIRECT_CONTAINER_PORT,
        }));
    }
    published
}
