// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::compose::{compose_command, runtime_app_environment, runtime_environment};
use super::secret::read_or_create_runtime_secret;
use crate::process::CommandRunner;
use crate::result::Finding;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::OnceLock;

pub(crate) const DIRECT_CONTAINER_PORT: &str = "9081";
pub(crate) const DIRECT_DEFAULT_HOST: &str = "127.0.0.1";
pub(crate) const DIRECT_DEFAULT_PORT: &str = "19080";
pub(crate) const DIRECT_ENV: &str = "YAFVS_API_DIRECT";
pub(crate) const DIRECT_HOST_ENV: &str = "YAFVS_API_DIRECT_HOST";
pub(crate) const DIRECT_PORT_ENV: &str = "YAFVS_API_DIRECT_PORT";
pub(crate) const DIRECT_BIND_ENV: &str = "YAFVS_API_DIRECT_BIND";
pub(crate) const OPERATOR_UUID_ENV: &str = "YAFVS_API_OPERATOR_UUID";
pub(crate) const OPERATOR_NAME_ENV: &str = "YAFVS_API_OPERATOR_NAME";
pub(crate) const DIRECT_WRITE_CONTROL_ENV: &str = "YAFVS_API_DIRECT_WRITE_CONTROL";
pub(crate) const BEARER_TOKEN_ENV: &str = "YAFVS_API_BEARER_TOKEN";
pub(crate) const BEARER_TOKEN_FILE_ENV: &str = "YAFVS_API_BEARER_TOKEN_FILE";
pub(crate) const BEARER_TOKEN_CONTAINER_FILE: &str = "/runtime/secrets/native-api-bearer-token";
pub(crate) const BEARER_TOKEN_SECRET: &str = "native-api-bearer-token";

pub(crate) fn environment_value(
    environment: &BTreeMap<OsString, OsString>,
    name: &str,
) -> Option<String> {
    environment
        .get(OsStr::new(name))
        .map(|value| value.to_string_lossy().into_owned())
}

fn environment_truthy(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

pub(crate) fn direct_requested(environment: &BTreeMap<OsString, OsString>) -> bool {
    let direct = environment_value(environment, DIRECT_ENV);
    environment_truthy(direct.as_deref())
        || [DIRECT_HOST_ENV, DIRECT_PORT_ENV, DIRECT_BIND_ENV]
            .iter()
            .any(|name| environment_value(environment, name).is_some_and(|value| !value.is_empty()))
}

pub(crate) fn direct_host(environment: &BTreeMap<OsString, OsString>) -> String {
    environment_value(environment, DIRECT_HOST_ENV)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DIRECT_DEFAULT_HOST.to_string())
}

pub(crate) fn direct_port(environment: &BTreeMap<OsString, OsString>) -> String {
    environment_value(environment, DIRECT_PORT_ENV)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DIRECT_DEFAULT_PORT.to_string())
}

fn bracketed_ipv6_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^\[[0-9A-Fa-f:.]+\]$").expect("static IPv6 regex"))
}

fn host_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9.-]*$").expect("static host regex"))
}

fn uuid_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
            .expect("static UUID regex")
    })
}

pub(crate) fn validate_direct_host(value: &str, environment_name: &str) -> Result<String, String> {
    let host = value.trim();
    if host.is_empty() {
        return Err(format!("{environment_name} must not be empty"));
    }
    if host
        .chars()
        .any(|character| (character as u32) < 33 || character.is_whitespace())
    {
        return Err(format!(
            "{environment_name} must not contain whitespace or control characters"
        ));
    }
    if host.chars().any(|character| "/\\?#@,".contains(character)) {
        return Err(format!(
            "{environment_name} must be a host name or address, not a URL or host list"
        ));
    }
    if host.starts_with('[') {
        if !bracketed_ipv6_regex().is_match(host) {
            return Err(format!(
                "{environment_name} must contain a bracketed IPv6 address like [::1]"
            ));
        }
    } else if host.contains(':') {
        return Err(format!(
            "{environment_name} must bracket IPv6 addresses, for example [::1]"
        ));
    } else if !host_regex().is_match(host) {
        return Err(format!(
            "{environment_name} must contain only host-safe ASCII characters"
        ));
    }
    Ok(host.to_string())
}

pub(crate) fn validate_direct_port(value: &str, environment_name: &str) -> Result<String, String> {
    let port = value.trim();
    if port.is_empty() {
        return Err(format!("{environment_name} must not be empty"));
    }
    if !port.chars().all(|character| character.is_ascii_digit()) {
        return Err(format!("{environment_name} must be a decimal TCP port"));
    }
    let Ok(number) = port.parse::<u32>() else {
        return Err(format!("{environment_name} must be between 1 and 65535"));
    };
    if !(1..=65_535).contains(&number) {
        return Err(format!("{environment_name} must be between 1 and 65535"));
    }
    Ok(number.to_string())
}

pub(crate) fn validate_direct_bind(value: &str, environment_name: &str) -> Result<String, String> {
    let bind = value.trim();
    if bind.is_empty() {
        return Err(format!("{environment_name} must not be empty"));
    }
    let (host, port) = if bind.starts_with('[') {
        let Some(host_end) = bind.find(']') else {
            return Err(format!(
                "{environment_name} must be host:port or [ipv6]:port"
            ));
        };
        if bind.as_bytes().get(host_end + 1) != Some(&b':') || bind.len() <= host_end + 2 {
            return Err(format!(
                "{environment_name} must be host:port or [ipv6]:port"
            ));
        }
        (&bind[..=host_end], &bind[host_end + 2..])
    } else {
        if bind.matches(':').count() != 1 {
            return Err(format!(
                "{environment_name} must be host:port or [ipv6]:port"
            ));
        }
        bind.rsplit_once(':').expect("one colon verified")
    };
    let normalized_port = validate_direct_port(port, environment_name)?;
    if normalized_port != DIRECT_CONTAINER_PORT {
        return Err(format!(
            "{environment_name} must use container port {DIRECT_CONTAINER_PORT} when managed by yafvsctl"
        ));
    }
    Ok(format!(
        "{}:{normalized_port}",
        validate_direct_host(host, environment_name)?
    ))
}

pub(crate) fn validate_operator_uuid(
    value: &str,
    environment_name: &str,
) -> Result<String, String> {
    if !uuid_regex().is_match(value) {
        return Err(format!("{environment_name} must be a UUID"));
    }
    Ok(value.to_ascii_lowercase())
}

pub(crate) fn validate_operator_name(
    value: &str,
    environment_name: &str,
) -> Result<String, String> {
    let name = value.trim();
    if name.is_empty()
        || name.chars().count() > 256
        || value.chars().any(|character| (character as u32) < 32)
    {
        return Err(format!(
            "{environment_name} must be a non-empty printable operator name up to 256 characters"
        ));
    }
    Ok(name.to_string())
}

pub(crate) fn validate_direct_write_control(
    value: &str,
    environment_name: &str,
) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "1" | "true" | "yes" | "on" | "0" | "false" | "no" | "off"
    ) {
        Ok(normalized)
    } else {
        Err(format!(
            "{environment_name} must be a boolean value such as 1/0 or true/false"
        ))
    }
}

pub(crate) fn direct_config_errors(environment: &BTreeMap<OsString, OsString>) -> Vec<String> {
    let mut errors = Vec::new();
    for result in [
        validate_direct_host(&direct_host(environment), DIRECT_HOST_ENV),
        validate_direct_port(&direct_port(environment), DIRECT_PORT_ENV),
    ] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if let Some(direct_bind) =
        environment_value(environment, DIRECT_BIND_ENV).filter(|value| !value.is_empty())
        && let Err(error) = validate_direct_bind(&direct_bind, DIRECT_BIND_ENV)
    {
        errors.push(error);
    }
    let operator_uuid = environment_value(environment, OPERATOR_UUID_ENV)
        .unwrap_or_default()
        .trim()
        .to_string();
    let operator_name = environment_value(environment, OPERATOR_NAME_ENV).unwrap_or_default();
    if operator_uuid.is_empty() {
        if !operator_name.trim().is_empty() {
            errors.push(format!("{OPERATOR_NAME_ENV} requires {OPERATOR_UUID_ENV}"));
        }
    } else if let Err(error) = validate_operator_uuid(&operator_uuid, OPERATOR_UUID_ENV) {
        errors.push(error);
    }
    if !operator_name.trim().is_empty()
        && let Err(error) = validate_operator_name(&operator_name, OPERATOR_NAME_ENV)
    {
        errors.push(error);
    }
    let write_control =
        environment_value(environment, DIRECT_WRITE_CONTROL_ENV).unwrap_or_default();
    if !write_control.trim().is_empty() {
        match validate_direct_write_control(&write_control, DIRECT_WRITE_CONTROL_ENV) {
            Ok(normalized) => {
                if environment_truthy(Some(&normalized)) && operator_uuid.is_empty() {
                    errors.push(format!(
                        "{DIRECT_WRITE_CONTROL_ENV} requires {OPERATOR_UUID_ENV}"
                    ));
                }
            }
            Err(error) => errors.push(error),
        }
    }
    errors
}

pub(crate) fn direct_config_shape_finding(
    environment: &BTreeMap<OsString, OsString>,
    check: &str,
) -> Finding {
    let errors = direct_config_errors(environment);
    Finding::new(
        if errors.is_empty() { "pass" } else { "fail" },
        check,
        if errors.is_empty() {
            "Direct native API host, port, and bind settings have a valid local shape.".to_string()
        } else {
            "Direct native API host, port, or bind settings are malformed.".to_string()
        },
    )
    .with_details(json!({
        "host_env": DIRECT_HOST_ENV,
        "host": direct_host(environment),
        "port_env": DIRECT_PORT_ENV,
        "port": direct_port(environment),
        "bind_env": DIRECT_BIND_ENV,
        "bind": environment_value(environment, DIRECT_BIND_ENV),
        "write_control_env": DIRECT_WRITE_CONTROL_ENV,
        "write_control": environment_value(environment, DIRECT_WRITE_CONTROL_ENV),
        "errors": errors,
    }))
}

pub(crate) fn direct_port_binding(environment: &BTreeMap<OsString, OsString>) -> String {
    format!(
        "{}:{}:{DIRECT_CONTAINER_PORT}",
        direct_host(environment),
        direct_port(environment)
    )
}

pub(crate) fn host_is_wildcard(host: &str) -> bool {
    matches!(
        host.trim()
            .to_ascii_lowercase()
            .trim_matches(['[', ']'])
            .to_string()
            .as_str(),
        "0.0.0.0" | "::"
    )
}

pub(crate) fn host_is_loopback(host: &str) -> bool {
    let normalized = host
        .trim()
        .to_ascii_lowercase()
        .trim_matches(['[', ']'])
        .to_string();
    normalized == "localhost" || normalized == "::1" || normalized.starts_with("127.")
}

fn insert_default(environment: &mut BTreeMap<OsString, OsString>, name: &str, value: &str) {
    environment
        .entry(OsString::from(name))
        .or_insert_with(|| OsString::from(value));
}

pub(crate) fn ensure_direct_environment_defaults(
    repo_root: &Path,
    environment: &mut BTreeMap<OsString, OsString>,
) -> std::io::Result<()> {
    environment.insert(OsString::from(DIRECT_ENV), OsString::from("1"));
    insert_default(environment, DIRECT_HOST_ENV, DIRECT_DEFAULT_HOST);
    insert_default(environment, DIRECT_PORT_ENV, DIRECT_DEFAULT_PORT);
    insert_default(
        environment,
        DIRECT_BIND_ENV,
        &format!("0.0.0.0:{DIRECT_CONTAINER_PORT}"),
    );
    let environment_token =
        environment_value(environment, BEARER_TOKEN_ENV).is_some_and(|value| !value.is_empty());
    let token_file = environment_value(environment, BEARER_TOKEN_FILE_ENV)
        .is_some_and(|value| !value.is_empty());
    if !environment_token && !token_file {
        read_or_create_runtime_secret(repo_root, BEARER_TOKEN_SECRET)?;
        environment.insert(
            OsString::from(BEARER_TOKEN_FILE_ENV),
            OsString::from(BEARER_TOKEN_CONTAINER_FILE),
        );
    }
    Ok(())
}

pub(crate) fn direct_runtime_environment(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> std::io::Result<BTreeMap<OsString, OsString>> {
    let mut environment = runtime_app_environment(repo_root)?;
    let explicit_direct_shape = [
        DIRECT_ENV,
        DIRECT_HOST_ENV,
        DIRECT_PORT_ENV,
        DIRECT_BIND_ENV,
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some());
    let bindings = if explicit_direct_shape {
        Vec::new()
    } else {
        current_published_bindings(repo_root, runner)
    };
    apply_running_binding_defaults(
        repo_root,
        &mut environment,
        explicit_direct_shape,
        &bindings,
    )?;
    ensure_direct_environment_defaults(repo_root, &mut environment)?;
    Ok(environment)
}

fn apply_running_binding_defaults(
    repo_root: &Path,
    environment: &mut BTreeMap<OsString, OsString>,
    explicit_direct_shape: bool,
    bindings: &[Value],
) -> std::io::Result<()> {
    if explicit_direct_shape {
        return Ok(());
    }
    let [binding] = bindings else {
        return Ok(());
    };
    ensure_direct_environment_defaults(repo_root, environment)?;
    if let Some(host) = binding.get("host").and_then(Value::as_str) {
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        environment.insert(OsString::from(DIRECT_HOST_ENV), OsString::from(host));
    }
    if let Some(port) = binding.get("host_port").and_then(Value::as_str) {
        environment.insert(OsString::from(DIRECT_PORT_ENV), OsString::from(port));
    }
    Ok(())
}

pub(crate) fn direct_base_url(environment: &BTreeMap<OsString, OsString>) -> String {
    format!(
        "http://{}:{}",
        direct_host(environment),
        direct_port(environment)
    )
}

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

pub(crate) fn running_service_environment(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> BTreeMap<String, String> {
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
        return BTreeMap::new();
    };
    let Some(output) = runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{json .Config.Env}}", &container],
            Some(repo_root),
            Some(&environment),
            None,
        )
        .filter(|output| output.success && !output.stdout.trim().is_empty())
    else {
        return BTreeMap::new();
    };
    let Ok(values) = serde_json::from_str::<Vec<String>>(&output.stdout) else {
        return BTreeMap::new();
    };
    values
        .into_iter()
        .filter_map(|value| {
            let (name, value) = value.split_once('=')?;
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn environment(values: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        values
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    #[test]
    fn direct_request_contract_matches_explicit_enablement_and_shape_settings() {
        assert!(!direct_requested(&environment(&[])));
        assert!(direct_requested(&environment(&[(DIRECT_ENV, " yes ")])));
        assert!(!direct_requested(&environment(&[(DIRECT_ENV, "0")])));
        assert!(direct_requested(&environment(&[(DIRECT_HOST_ENV, " ")])));
        assert!(!direct_requested(&environment(&[(
            OPERATOR_UUID_ENV,
            "uuid"
        )])));
    }

    #[test]
    fn host_contract_accepts_names_and_bracketed_ipv6_only() {
        for host in ["127.0.0.1", "localhost", "api.example.test", "[::1]"] {
            assert_eq!(validate_direct_host(host, DIRECT_HOST_ENV).unwrap(), host);
        }
        for host in [
            "",
            "api host",
            "http://localhost",
            "::1",
            "[localhost]",
            "é",
        ] {
            assert!(
                validate_direct_host(host, DIRECT_HOST_ENV).is_err(),
                "{host:?} unexpectedly passed"
            );
        }
    }

    #[test]
    fn port_and_bind_contract_normalizes_values_and_requires_container_port() {
        assert_eq!(
            validate_direct_port("019080", DIRECT_PORT_ENV).unwrap(),
            "19080"
        );
        for port in ["", "abc", "0", "65536"] {
            assert!(validate_direct_port(port, DIRECT_PORT_ENV).is_err());
        }
        assert_eq!(
            validate_direct_bind("[::1]:09081", DIRECT_BIND_ENV).unwrap(),
            "[::1]:9081"
        );
        assert!(validate_direct_bind("127.0.0.1:19080", DIRECT_BIND_ENV).is_err());
        assert!(validate_direct_bind("::1:9081", DIRECT_BIND_ENV).is_err());
    }

    #[test]
    fn operator_contract_requires_uuid_for_names_and_enabled_write_control() {
        let uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
        assert_eq!(
            validate_operator_uuid(uuid, OPERATOR_UUID_ENV).unwrap(),
            uuid.to_ascii_lowercase()
        );
        assert!(validate_operator_uuid("not-a-uuid", OPERATOR_UUID_ENV).is_err());
        assert_eq!(
            validate_operator_name(" operator ", OPERATOR_NAME_ENV).unwrap(),
            "operator"
        );
        assert!(validate_operator_name("\toperator", OPERATOR_NAME_ENV).is_err());
        assert_eq!(
            validate_direct_write_control(" YES ", DIRECT_WRITE_CONTROL_ENV).unwrap(),
            "yes"
        );

        assert_eq!(
            direct_config_errors(&environment(&[(OPERATOR_NAME_ENV, "operator")])),
            vec![format!("{OPERATOR_NAME_ENV} requires {OPERATOR_UUID_ENV}")]
        );
        assert_eq!(
            direct_config_errors(&environment(&[(DIRECT_WRITE_CONTROL_ENV, "true")])),
            vec![format!(
                "{DIRECT_WRITE_CONTROL_ENV} requires {OPERATOR_UUID_ENV}"
            )]
        );
        assert!(
            direct_config_errors(&environment(&[
                (OPERATOR_UUID_ENV, uuid),
                (OPERATOR_NAME_ENV, "operator"),
                (DIRECT_WRITE_CONTROL_ENV, "true"),
            ]))
            .is_empty()
        );
    }

    #[test]
    fn configuration_finding_preserves_values_without_secret_material() {
        let configured = environment(&[
            (DIRECT_HOST_ENV, "[::1]"),
            (DIRECT_PORT_ENV, "19080"),
            (DIRECT_BIND_ENV, "0.0.0.0:9081"),
            (DIRECT_WRITE_CONTROL_ENV, "false"),
        ]);
        let finding = direct_config_shape_finding(&configured, "test.direct-config");
        assert_eq!(finding.status, "pass");
        assert_eq!(finding.check, "test.direct-config");
        assert_eq!(finding.details.as_ref().unwrap()["bind"], "0.0.0.0:9081");
        assert_eq!(direct_port_binding(&configured), "[::1]:19080:9081");
        assert_eq!(direct_base_url(&configured), "http://[::1]:19080");

        let invalid = direct_config_shape_finding(
            &environment(&[(DIRECT_BIND_ENV, "0.0.0.0:19080")]),
            "test.direct-config",
        );
        assert_eq!(invalid.status, "fail");
        assert_eq!(
            invalid.details.as_ref().unwrap()["errors"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn host_scope_contract_classifies_only_explicit_local_values_as_loopback() {
        for host in ["127.0.0.1", "127.10.20.30", "localhost", "[::1]"] {
            assert!(host_is_loopback(host), "{host}");
            assert!(!host_is_wildcard(host), "{host}");
        }
        for host in ["0.0.0.0", "::", "[::]"] {
            assert!(host_is_wildcard(host), "{host}");
            assert!(!host_is_loopback(host), "{host}");
        }
        assert!(!host_is_loopback("192.0.2.10"));
        assert!(!host_is_wildcard("192.0.2.10"));
    }

    #[test]
    fn one_running_binding_is_inherited_only_without_explicit_direct_shape() {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-direct-api-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        let bindings = vec![json!({
            "host": "::1",
            "host_port": "19081",
            "container_port": DIRECT_CONTAINER_PORT,
        })];
        let mut inherited = environment(&[]);
        apply_running_binding_defaults(&repo, &mut inherited, false, &bindings).unwrap();
        assert_eq!(direct_host(&inherited), "[::1]");
        assert_eq!(direct_port(&inherited), "19081");
        assert_eq!(
            environment_value(&inherited, DIRECT_BIND_ENV).as_deref(),
            Some("0.0.0.0:9081")
        );

        let mut explicit = environment(&[(DIRECT_HOST_ENV, "127.0.0.2")]);
        apply_running_binding_defaults(&repo, &mut explicit, true, &bindings).unwrap();
        assert_eq!(direct_host(&explicit), "127.0.0.2");
        assert!(environment_value(&explicit, DIRECT_PORT_ENV).is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
