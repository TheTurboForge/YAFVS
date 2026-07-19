// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::expand_home;
use super::direct_api::{
    BEARER_TOKEN_CONTAINER_FILE, BEARER_TOKEN_ENV, BEARER_TOKEN_FILE_ENV, BEARER_TOKEN_SECRET,
    DIRECT_BIND_ENV, DIRECT_ENV, DIRECT_HOST_ENV, DIRECT_PORT_ENV, DIRECT_WRITE_CONTROL_ENV,
    OPERATOR_NAME_ENV, OPERATOR_UUID_ENV, bearer_token_is_acceptable, current_published_bindings,
    direct_config_errors, direct_config_shape_finding, direct_host, direct_port,
    direct_port_binding, direct_requested, environment_value, host_is_loopback, host_is_wildcard,
    running_service_environment, secret_file_metadata,
};
use super::secret::{read_existing_runtime_secret, runtime_secret_path};
use crate::process::CommandRunner;
use crate::result::Finding;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
#[cfg(test)]
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) const TOKEN_MINIMUM_LENGTH: usize = 32;
pub(crate) const TOKEN_MAXIMUM_LENGTH: usize = 1024;

#[derive(Debug)]
pub(crate) struct TokenFileMetadata {
    pub(crate) source: String,
    pub(crate) configured_value: Option<String>,
    pub(crate) host_path: Option<PathBuf>,
    pub(crate) host_metadata_available: bool,
    pub(crate) mode: Value,
    pub(crate) permission_ok: Option<bool>,
    pub(crate) group_or_world_accessible: Option<bool>,
}

fn metadata_boolean(metadata: &Value, name: &str) -> Option<bool> {
    metadata.get(name).and_then(Value::as_bool)
}

fn token_file_metadata_for_path(
    source: &str,
    configured_value: Option<String>,
    host_path: PathBuf,
) -> TokenFileMetadata {
    let metadata = secret_file_metadata(&host_path);
    TokenFileMetadata {
        source: source.to_string(),
        configured_value,
        host_path: Some(host_path),
        host_metadata_available: true,
        mode: metadata.get("mode").cloned().unwrap_or(Value::Null),
        permission_ok: metadata_boolean(&metadata, "permission_ok"),
        group_or_world_accessible: metadata_boolean(&metadata, "group_or_world_accessible"),
    }
}

fn host_token_file_path(repo_root: &Path, token_file: &str) -> PathBuf {
    if token_file == BEARER_TOKEN_CONTAINER_FILE {
        runtime_secret_path(repo_root, BEARER_TOKEN_SECRET)
    } else {
        expand_home(PathBuf::from(token_file))
    }
}

pub(crate) fn token_file_metadata(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    running_environment: &BTreeMap<String, String>,
) -> TokenFileMetadata {
    let configured_token_file = environment_value(environment, BEARER_TOKEN_FILE_ENV)
        .unwrap_or_default()
        .trim()
        .to_string();
    if !configured_token_file.is_empty() {
        let host_path = host_token_file_path(repo_root, &configured_token_file);
        let source = if configured_token_file == BEARER_TOKEN_CONTAINER_FILE {
            "runtime-secret-file"
        } else {
            "configured-token-file"
        };
        return token_file_metadata_for_path(source, Some(configured_token_file), host_path);
    }

    if let Some(running_token_file) = running_environment
        .get(BEARER_TOKEN_FILE_ENV)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if running_token_file == BEARER_TOKEN_CONTAINER_FILE {
            return token_file_metadata_for_path(
                "running-container-token-file",
                Some(running_token_file.to_string()),
                runtime_secret_path(repo_root, BEARER_TOKEN_SECRET),
            );
        }
        return TokenFileMetadata {
            source: "running-container-token-file".to_string(),
            configured_value: Some(running_token_file.to_string()),
            host_path: None,
            host_metadata_available: false,
            mode: Value::Null,
            permission_ok: None,
            group_or_world_accessible: None,
        };
    }

    token_file_metadata_for_path(
        "runtime-secret-default",
        None,
        runtime_secret_path(repo_root, BEARER_TOKEN_SECRET),
    )
}

fn token_sources(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    running_environment: &BTreeMap<String, String>,
) -> (Vec<String>, PathBuf, bool) {
    let mut sources = Vec::new();
    if environment_value(environment, BEARER_TOKEN_ENV).is_some_and(|value| !value.is_empty()) {
        sources.push("environment".to_string());
    }
    if environment_value(environment, BEARER_TOKEN_FILE_ENV).is_some_and(|value| !value.is_empty())
    {
        sources.push("configured-token-file".to_string());
    }
    if running_environment
        .get(BEARER_TOKEN_ENV)
        .is_some_and(|value| !value.trim().is_empty())
    {
        sources.push("running-container-env".to_string());
    }
    if running_environment
        .get(BEARER_TOKEN_FILE_ENV)
        .is_some_and(|value| !value.trim().is_empty())
    {
        sources.push("running-container-token-file".to_string());
    }
    let secret_path = runtime_secret_path(repo_root, BEARER_TOKEN_SECRET);
    let secret_present = read_existing_runtime_secret(repo_root, BEARER_TOKEN_SECRET)
        .ok()
        .flatten()
        .is_some_and(|secret| !secret.trim().is_empty());
    (sources, secret_path, secret_present)
}

pub(crate) fn direct_posture_findings(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> Vec<Finding> {
    direct_posture_findings_with_runtime(
        repo_root,
        environment,
        current_published_bindings(repo_root, runner),
        running_service_environment(repo_root, runner),
    )
}

fn direct_posture_findings_with_runtime(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    running_bindings: Vec<Value>,
    running_environment: BTreeMap<String, String>,
) -> Vec<Finding> {
    let configured = direct_requested(environment);
    let configured_environment = [
        DIRECT_ENV,
        DIRECT_HOST_ENV,
        DIRECT_PORT_ENV,
        DIRECT_BIND_ENV,
        OPERATOR_UUID_ENV,
        OPERATOR_NAME_ENV,
        DIRECT_WRITE_CONTROL_ENV,
    ]
    .into_iter()
    .filter(|name| environment_value(environment, name).is_some_and(|value| !value.is_empty()))
    .collect::<Vec<_>>();
    let mut findings = Vec::new();
    if configured {
        findings.push(direct_config_shape_finding(
            environment,
            "production.native-api-direct.config-shape",
        ));
    }

    if configured {
        let config_errors = direct_config_errors(environment);
        let host = direct_host(environment);
        let (status, message) = if !config_errors.is_empty() {
            (
                "fail",
                "Direct native API host publication has malformed host, port, or bind settings.",
            )
        } else if host_is_wildcard(&host) {
            (
                "fail",
                "Direct native API host publication is configured for a broad wildcard binding.",
            )
        } else if !host_is_loopback(&host) {
            (
                "fail",
                "Direct native API host publication is configured for explicit non-loopback access before production TLS/bootstrap/host-binding hardening is complete.",
            )
        } else {
            (
                "pass",
                "Direct native API host publication is configured for loopback access.",
            )
        };
        findings.push(
            Finding::new(
                status,
                "production.native-api-direct.configured-binding",
                message.to_string(),
            )
            .with_details(json!({
                "enabled": true,
                "host": host,
                "host_port": direct_port(environment),
                "host_binding": direct_port_binding(environment),
                "container_bind": environment_value(environment, DIRECT_BIND_ENV),
                "configured_env": configured_environment,
            })),
        );
    } else {
        findings.push(
            Finding::new(
                "pass",
                "production.native-api-direct.configured-binding",
                "Direct native API host publication is not configured; internal-only native API remains the default."
                    .to_string(),
            )
            .with_details(json!({
                "enabled": false,
                "configured_env": configured_environment,
            })),
        );
    }

    let mut broad_running = false;
    let mut external_running = false;
    for binding in &running_bindings {
        let host = binding
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or_default();
        broad_running |= host_is_wildcard(host);
        external_running |= !host_is_wildcard(host) && !host_is_loopback(host);
    }
    let (running_status, running_message) = if broad_running {
        (
            "fail",
            "A running direct native API listener is published on a broad wildcard host binding.",
        )
    } else if external_running {
        (
            "fail",
            "A running direct native API listener is published on explicit non-loopback host binding before production TLS/bootstrap/host-binding hardening is complete.",
        )
    } else if running_bindings.is_empty() {
        (
            "pass",
            "No running direct native API host publication was detected.",
        )
    } else {
        (
            "pass",
            "Any running direct native API listener is published only on loopback host binding.",
        )
    };
    findings.push(
        Finding::new(
            running_status,
            "production.native-api-direct.running-binding",
            running_message.to_string(),
        )
        .with_details(json!({"published_bindings": running_bindings})),
    );

    let (sources, secret_path, secret_present) =
        token_sources(repo_root, environment, &running_environment);
    let configured_token = environment_value(environment, BEARER_TOKEN_ENV).unwrap_or_default();
    let configured_token_ok = if configured_token.is_empty() {
        None
    } else {
        Some(bearer_token_is_acceptable(&configured_token))
    };
    let metadata = token_file_metadata(repo_root, environment, &running_environment);
    let source_set = sources.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let secret_file_used = source_set.contains("configured-token-file")
        || source_set.contains("running-container-token-file");
    let environment_token_used =
        source_set.contains("environment") || source_set.contains("running-container-env");
    let exposure_enabled = configured || !running_bindings.is_empty();
    let auth_details = json!({
        "exposure_enabled": exposure_enabled,
        "token_sources": sources,
        "environment_token_used": environment_token_used,
        "secret_file_used": secret_file_used,
        "bearer_token_env": BEARER_TOKEN_ENV,
        "bearer_token_file_env": BEARER_TOKEN_FILE_ENV,
        "minimum_token_length": TOKEN_MINIMUM_LENGTH,
        "maximum_token_length": TOKEN_MAXIMUM_LENGTH,
        "configured_environment_token_ok": configured_token_ok,
        "runtime_secret": secret_path.display().to_string(),
        "runtime_secret_present": secret_present,
        "token_file_source": metadata.source,
        "token_file_configured_value": metadata.configured_value,
        "token_file_host_path": metadata.host_path.as_ref().map(|path| path.display().to_string()),
        "token_file_host_metadata_available": metadata.host_metadata_available,
        "runtime_secret_mode": metadata.mode,
        "runtime_secret_permission_ok": metadata.permission_ok,
        "runtime_secret_group_or_world_accessible": metadata.group_or_world_accessible,
    });
    let (auth_status, auth_message) = if !exposure_enabled {
        (
            "pass",
            "Direct native API host exposure is disabled; no direct bearer boundary is needed for the internal-only default.",
        )
    } else if configured_token_ok == Some(false) {
        (
            "fail",
            "Direct native API exposure is configured with a bearer token that is too short or contains unsafe characters.",
        )
    } else if environment_token_used {
        (
            "fail",
            "Direct native API exposure uses a bearer token from environment variables; use the ignored runtime secret file boundary instead of publishing auth material through process/container environment.",
        )
    } else if secret_file_used
        && metadata.host_metadata_available
        && metadata.permission_ok != Some(true)
    {
        (
            "fail",
            "Direct native API exposure uses a bearer-token file that is missing or group/world accessible on the host.",
        )
    } else if secret_file_used && !metadata.host_metadata_available {
        (
            "warn",
            "Direct native API exposure uses a running container bearer-token file path that the host posture helper cannot inspect.",
        )
    } else if !source_set.is_empty() {
        (
            "pass",
            "Direct native API exposure has an explicit bearer-token auth boundary configured.",
        )
    } else {
        (
            "fail",
            "Direct native API exposure appears enabled without a bearer-token environment value or token-file boundary in the requested environment or running container; do not expose /api/v1 without the explicit B-130 auth boundary.",
        )
    };
    findings.push(
        Finding::new(
            auth_status,
            "production.native-api-direct.auth-boundary",
            auth_message.to_string(),
        )
        .with_details(auth_details),
    );
    findings
}

pub(crate) fn read_configured_token(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<String> {
    if let Some(token) =
        environment_value(environment, BEARER_TOKEN_ENV).filter(|value| !value.is_empty())
    {
        return Ok(token);
    }
    let configured = environment_value(environment, BEARER_TOKEN_FILE_ENV)
        .unwrap_or_default()
        .trim()
        .to_string();
    let path = if configured.is_empty() {
        runtime_secret_path(repo_root, BEARER_TOKEN_SECRET)
    } else {
        host_token_file_path(repo_root, &configured)
    };
    read_owner_private_token(&path)
}

fn read_owner_private_token(path: &Path) -> io::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !before.file_type().is_file()
        || before.uid() != euid
        || before.nlink() != 1
        || before.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Bearer-token file is unsafe: {}", path.display()),
        ));
    }
    if before.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("Bearer-token file is too large: {}", path.display()),
        ));
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("Bearer-token file is too large: {}", path.display()),
        ));
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mode() != after.mode()
    {
        return Err(io::Error::other(format!(
            "Bearer-token file changed while reading: {}",
            path.display()
        )));
    }
    Ok(text.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::direct_api::DIRECT_CONTAINER_PORT;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-direct-posture-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let repo = root.join("YAFVS");
            fs::create_dir_all(&repo).unwrap();
            Self { root, repo }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn environment(values: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn finding<'a>(findings: &'a [Finding], check: &str) -> &'a Finding {
        findings
            .iter()
            .find(|finding| finding.check == check)
            .unwrap()
    }

    #[test]
    fn internal_default_has_no_direct_exposure_requirement() {
        let fixture = Fixture::new();
        let findings = direct_posture_findings_with_runtime(
            &fixture.repo,
            &environment(&[]),
            Vec::new(),
            BTreeMap::new(),
        );
        for check in [
            "production.native-api-direct.configured-binding",
            "production.native-api-direct.running-binding",
            "production.native-api-direct.auth-boundary",
        ] {
            assert_eq!(finding(&findings, check).status, "pass", "{check}");
        }
    }

    #[test]
    fn configured_environment_token_is_classified_without_being_reported() {
        let fixture = Fixture::new();
        let token = "super-secret-token-0123456789abcdef";
        let configured = environment(&[(DIRECT_ENV, "1"), (BEARER_TOKEN_ENV, token)]);
        let findings = direct_posture_findings_with_runtime(
            &fixture.repo,
            &configured,
            Vec::new(),
            BTreeMap::new(),
        );
        let auth = finding(&findings, "production.native-api-direct.auth-boundary");
        assert_eq!(auth.status, "fail");
        assert_eq!(
            auth.details.as_ref().unwrap()["environment_token_used"],
            true
        );
        assert!(!serde_json::to_string(&findings).unwrap().contains(token));
    }

    #[test]
    fn secure_file_is_accepted_and_broad_permissions_fail() {
        let fixture = Fixture::new();
        let token_file = fixture.root.join("custom-token");
        fs::write(&token_file, "0123456789abcdef0123456789abcdef").unwrap();
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
        let configured = environment(&[
            (DIRECT_ENV, "1"),
            (BEARER_TOKEN_FILE_ENV, token_file.to_str().unwrap()),
        ]);
        let findings = direct_posture_findings_with_runtime(
            &fixture.repo,
            &configured,
            Vec::new(),
            BTreeMap::new(),
        );
        assert_eq!(
            finding(&findings, "production.native-api-direct.auth-boundary").status,
            "pass"
        );
        assert_eq!(
            read_configured_token(&fixture.repo, &configured).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );

        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o664)).unwrap();
        let findings = direct_posture_findings_with_runtime(
            &fixture.repo,
            &configured,
            Vec::new(),
            BTreeMap::new(),
        );
        assert_eq!(
            finding(&findings, "production.native-api-direct.auth-boundary").status,
            "fail"
        );
        assert!(read_configured_token(&fixture.repo, &configured).is_err());
    }

    #[test]
    fn running_external_binding_and_uninspectable_file_are_preserved() {
        let fixture = Fixture::new();
        let mut running_environment = BTreeMap::new();
        running_environment.insert(
            BEARER_TOKEN_FILE_ENV.to_string(),
            "/container-only/custom-token".to_string(),
        );
        let findings = direct_posture_findings_with_runtime(
            &fixture.repo,
            &environment(&[]),
            vec![json!({
                "host": "192.0.2.10",
                "host_port": "19080",
                "container_port": DIRECT_CONTAINER_PORT,
            })],
            running_environment,
        );
        assert_eq!(
            finding(&findings, "production.native-api-direct.running-binding").status,
            "fail"
        );
        let auth = finding(&findings, "production.native-api-direct.auth-boundary");
        assert_eq!(auth.status, "warn");
        assert_eq!(
            auth.details.as_ref().unwrap()["token_file_host_metadata_available"],
            false
        );
    }
}
