// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::compose::runtime_environment;
use super::direct_api::{
    BEARER_TOKEN_CONTAINER_FILE, BEARER_TOKEN_ENV, BEARER_TOKEN_FILE_ENV, BEARER_TOKEN_SECRET,
    DIRECT_BIND_ENV, DIRECT_CONTAINER_PORT, DIRECT_DEFAULT_HOST, DIRECT_DEFAULT_PORT, DIRECT_ENV,
    DIRECT_HOST_ENV, DIRECT_PORT_ENV, direct_base_url, direct_config_errors,
    direct_config_shape_finding, direct_host, direct_port, direct_port_binding,
    direct_runtime_environment, ensure_direct_environment_defaults, environment_value,
    host_is_loopback, host_is_wildcard, running_service_environment,
};
use super::direct_posture::{
    TOKEN_MINIMUM_LENGTH, direct_posture_findings, read_configured_token, token_file_metadata,
};
use super::secret::runtime_secret_path;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

const COMMAND: &str = "runtime-native-api-direct-bootstrap";

pub fn command_runtime_native_api_direct_bootstrap(
    repo_root: &Path,
    status_only: bool,
) -> ResultEnvelope {
    command_runtime_native_api_direct_bootstrap_with_runner(
        repo_root,
        status_only,
        &SystemCommandRunner,
    )
}

fn command_runtime_native_api_direct_bootstrap_with_runner(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let environment = direct_runtime_environment(repo_root, runner)
        .unwrap_or_else(|_| runtime_environment(repo_root));
    bootstrap_with_environment(repo_root, environment, status_only, runner)
}

fn bootstrap_with_environment(
    repo_root: &Path,
    mut environment: BTreeMap<OsString, OsString>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    if ensure_direct_environment_defaults(repo_root, &mut environment).is_err() {
        environment.insert(OsString::from(DIRECT_ENV), OsString::from("1"));
        let direct_bind = format!("0.0.0.0:{DIRECT_CONTAINER_PORT}");
        for (name, value) in [
            (DIRECT_HOST_ENV, DIRECT_DEFAULT_HOST),
            (DIRECT_PORT_ENV, DIRECT_DEFAULT_PORT),
            (DIRECT_BIND_ENV, direct_bind.as_str()),
        ] {
            environment
                .entry(OsString::from(name))
                .or_insert_with(|| OsString::from(value));
        }
        if environment_value(&environment, BEARER_TOKEN_ENV).is_none_or(|value| value.is_empty())
            && environment_value(&environment, BEARER_TOKEN_FILE_ENV)
                .is_none_or(|value| value.is_empty())
        {
            environment.insert(
                OsString::from(BEARER_TOKEN_FILE_ENV),
                OsString::from(BEARER_TOKEN_CONTAINER_FILE),
            );
        }
    }

    let running_environment = running_service_environment(repo_root, runner);
    let token = read_configured_token(repo_root, &environment).unwrap_or_default();
    let file_metadata = token_file_metadata(repo_root, &environment, &running_environment);
    let token_source = if environment_value(&environment, BEARER_TOKEN_ENV)
        .is_some_and(|value| !value.is_empty())
    {
        "environment".to_string()
    } else {
        file_metadata.source.clone()
    };
    let secret_path = runtime_secret_path(repo_root, BEARER_TOKEN_SECRET);

    let mut findings = vec![direct_config_shape_finding(
        &environment,
        "native-api-direct-bootstrap.config-shape",
    )];
    let config_errors = direct_config_errors(&environment);
    let host = direct_host(&environment);
    let (host_status, host_message) = if !config_errors.is_empty() {
        (
            "fail",
            "Direct native API bootstrap refuses malformed host, port, or bind settings.",
        )
    } else if host_is_wildcard(&host) {
        (
            "fail",
            "Direct native API bootstrap refuses wildcard host publication.",
        )
    } else if !host_is_loopback(&host) {
        (
            "fail",
            "Direct native API bootstrap refuses non-loopback publication until production TLS/bootstrap/host-binding hardening exists.",
        )
    } else {
        ("pass", "Direct native API bootstrap is loopback-bounded.")
    };
    findings.push(
        Finding::new(
            host_status,
            "native-api-direct-bootstrap.host-binding",
            host_message.to_string(),
        )
        .with_details(json!({
            "host": host,
            "host_port": direct_port(&environment),
            "host_binding": direct_port_binding(&environment),
            "container_bind": environment_value(&environment, DIRECT_BIND_ENV),
        })),
    );

    let token_ok = super::direct_api::bearer_token_is_acceptable(&token);
    let token_permission_ok = token_source == "environment"
        || !file_metadata.host_metadata_available
        || file_metadata.permission_ok == Some(true);
    let token_status = if token_ok && token_permission_ok {
        "pass"
    } else {
        "fail"
    };
    let mut token_finding = Finding::new(
        token_status,
        "native-api-direct-bootstrap.token",
        if token_status == "pass" {
            "Direct native API bootstrap has a bearer token that satisfies the local strength contract and is not group/world accessible."
                .to_string()
        } else {
            "Direct native API bootstrap bearer token is missing, weak, or group/world accessible."
                .to_string()
        },
    );
    if token_source != "environment"
        && let Some(path) = &file_metadata.host_path
    {
        token_finding = token_finding.with_path(&path.display().to_string());
    }
    token_finding = token_finding.with_details(json!({
        "token_source": token_source,
        "minimum_token_length": TOKEN_MINIMUM_LENGTH,
        "runtime_secret": secret_path.display().to_string(),
        "token_file_configured_value": file_metadata.configured_value,
        "token_file_host_path": file_metadata.host_path.as_ref().map(|path| path.display().to_string()),
        "token_file_host_metadata_available": file_metadata.host_metadata_available,
        "runtime_secret_mode": file_metadata.mode,
        "runtime_secret_permission_ok": file_metadata.permission_ok,
        "runtime_secret_group_or_world_accessible": file_metadata.group_or_world_accessible,
        "token_value_reported": false,
    }));
    findings.push(token_finding);
    findings.extend(direct_posture_findings(repo_root, &environment, runner));

    let mut result = make_result(
        metadata(repo_root, COMMAND, runner),
        "Direct native API bootstrap guardrails checked.".to_string(),
        findings,
    )
    .with_details(json!({
        "base_url": direct_base_url(&environment),
        "direct_enabled": environment_value(&environment, DIRECT_ENV).as_deref() == Some("1"),
        "token_source": token_source,
        "token_value_reported": false,
    }));
    if status_only {
        compact_status_only(&mut result);
    }
    result
}

fn compact_status_only(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let statuses = result
        .findings
        .iter()
        .map(|finding| (finding.check.clone(), finding.status.clone()))
        .collect::<BTreeMap<_, _>>();
    let important = [
        "native-api-direct-bootstrap.config-shape",
        "native-api-direct-bootstrap.host-binding",
        "native-api-direct-bootstrap.token",
        "production.native-api-direct.config-shape",
        "production.native-api-direct.configured-binding",
        "production.native-api-direct.running-binding",
        "production.native-api-direct.auth-boundary",
    ]
    .into_iter()
    .filter_map(|check| {
        statuses
            .get(check)
            .map(|status| (check.to_string(), status.clone()))
    })
    .collect::<BTreeMap<_, _>>();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let non_pass_count = non_pass.len();
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "runtime-native-api-direct-bootstrap.status-only",
            "Direct native API bootstrap checks passed; no non-pass findings.".to_string(),
        ));
    }
    let details = result.details.as_ref();
    result.details = Some(json!({
        "direct_enabled": details.and_then(|details| details.get("direct_enabled")).cloned(),
        "token_source": details.and_then(|details| details.get("token_source")).cloned(),
        "token_value_reported": false,
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
        "important_checks": important,
    }));
    result.findings = non_pass;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: std::path::PathBuf,
        repo: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-direct-bootstrap-{}-{}",
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

    struct NoopRunner;

    impl CommandRunner for NoopRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }
    }

    fn environment(values: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn finding<'a>(result: &'a ResultEnvelope, check: &str) -> &'a Finding {
        result
            .findings
            .iter()
            .find(|finding| finding.check == check)
            .unwrap()
    }

    #[test]
    fn creates_private_default_token_without_reporting_it() {
        let fixture = Fixture::new();
        let result =
            bootstrap_with_environment(&fixture.repo, environment(&[]), false, &NoopRunner);
        let path = runtime_secret_path(&fixture.repo, BEARER_TOKEN_SECRET);
        let token = fs::read_to_string(path).unwrap().trim().to_string();
        assert_eq!(result.status, "pass");
        assert!(super::super::direct_api::bearer_token_is_acceptable(&token));
        assert!(!serde_json::to_string(&result).unwrap().contains(&token));
        let token_finding = finding(&result, "native-api-direct-bootstrap.token");
        assert_eq!(token_finding.status, "pass");
        assert_eq!(
            token_finding.details.as_ref().unwrap()["runtime_secret_mode"],
            "0600"
        );
        assert_eq!(
            finding(&result, "production.native-api-direct.auth-boundary").status,
            "pass"
        );
    }

    #[test]
    fn status_only_is_compact_and_keeps_failures() {
        let fixture = Fixture::new();
        let full = bootstrap_with_environment(&fixture.repo, environment(&[]), false, &NoopRunner);
        let compact =
            bootstrap_with_environment(&fixture.repo, environment(&[]), true, &NoopRunner);
        assert_eq!(compact.status, "pass");
        assert_eq!(compact.details.as_ref().unwrap()["non_pass_count"], 0);
        assert_eq!(
            compact.details.as_ref().unwrap()["finding_count"],
            full.findings.len()
        );
        assert_eq!(
            compact.findings[0].check,
            "runtime-native-api-direct-bootstrap.status-only"
        );

        let token_path = runtime_secret_path(&fixture.repo, BEARER_TOKEN_SECRET);
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644)).unwrap();
        let compact =
            bootstrap_with_environment(&fixture.repo, environment(&[]), true, &NoopRunner);
        assert_eq!(compact.status, "fail");
        assert_eq!(compact.details.as_ref().unwrap()["non_pass_count"], 2);
        assert_eq!(
            compact.details.as_ref().unwrap()["important_checks"]["native-api-direct-bootstrap.token"],
            "fail"
        );
    }

    #[test]
    fn malformed_or_external_bindings_fail_before_runtime_start() {
        let fixture = Fixture::new();
        let token = "A".repeat(TOKEN_MINIMUM_LENGTH);
        for (name, value) in [
            (DIRECT_BIND_ENV, "0.0.0.0:9999"),
            (DIRECT_HOST_ENV, "192.0.2.10"),
        ] {
            let result = bootstrap_with_environment(
                &fixture.repo,
                environment(&[(name, value), (BEARER_TOKEN_ENV, token.as_str())]),
                false,
                &NoopRunner,
            );
            assert_eq!(result.status, "fail");
            assert_eq!(
                finding(&result, "native-api-direct-bootstrap.host-binding").status,
                "fail"
            );
            assert!(!serde_json::to_string(&result).unwrap().contains(&token));
        }
    }

    #[test]
    fn environment_token_passes_strength_but_fails_production_posture() {
        let fixture = Fixture::new();
        let token = "A".repeat(TOKEN_MINIMUM_LENGTH);
        let result = bootstrap_with_environment(
            &fixture.repo,
            environment(&[(BEARER_TOKEN_ENV, token.as_str())]),
            false,
            &NoopRunner,
        );
        assert_eq!(
            finding(&result, "native-api-direct-bootstrap.token").status,
            "pass"
        );
        assert_eq!(
            finding(&result, "production.native-api-direct.auth-boundary").status,
            "fail"
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(&token));
    }
}
