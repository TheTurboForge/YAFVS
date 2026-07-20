// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::write_secure_artifact;
use super::common::{build_env, runtime_dir};
use super::direct_api::{
    BEARER_TOKEN_CONTAINER_FILE, BEARER_TOKEN_ENV, BEARER_TOKEN_FILE_ENV, BEARER_TOKEN_SECRET,
    direct_config_errors, direct_port_binding, direct_requested, environment_value,
};
use super::secret::{read_or_create_runtime_secret, runtime_secret_path};
use serde_json::to_string;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

const MQTT_PASSWORD_ENVIRONMENTS: [&str; 4] = [
    "YAFVS_MQTT_OPENVAS_PASSWORD",
    "YAFVS_MQTT_NOTUS_PASSWORD",
    "YAFVS_MQTT_OSPD_PASSWORD",
    "YAFVS_MQTT_HEALTH_PASSWORD",
];
const MQTT_RUNTIME_SECRETS: [&str; 4] = [
    "mqtt-openvas-password",
    "mqtt-notus-password",
    "mqtt-ospd-password",
    "mqtt-health-password",
];
const BROWSER_PROXY_SECRET_ENV: &str = "YAFVS_API_BROWSER_PROXY_SECRET";
const BROWSER_PROXY_SECRET: &str = "native-api-browser-proxy-secret";
const GVMD_CONTROL_SECRET_ENV: &str = "YAFVS_GVMD_CONTROL_SECRET";
const GVMD_CONTROL_SECRET: &str = "gvmd-control-secret";

pub(crate) fn runtime_environment(repo_root: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = build_env(repo_root);
    insert_default(&mut environment, "COMPOSE_PROJECT_NAME", "yafvs");
    insert_default(
        &mut environment,
        "YAFVS_RUNTIME_DIR",
        &runtime_dir(repo_root).display().to_string(),
    );
    insert_default(
        &mut environment,
        "YAFVS_REPO_MOUNT_PATH",
        &repo_root.display().to_string(),
    );
    // SAFETY: getuid/getgid have no preconditions and do not dereference memory.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    insert_default(&mut environment, "YAFVS_UID", &uid.to_string());
    insert_default(&mut environment, "YAFVS_GID", &gid.to_string());
    insert_default(&mut environment, "POSTGRES_USER", "yafvs");
    insert_default(&mut environment, "POSTGRES_PASSWORD", "yafvs-dev");
    insert_default(&mut environment, "POSTGRES_DB", "yafvs");
    insert_default(
        &mut environment,
        "OPENVAS_CONFIG",
        &runtime_dir(repo_root)
            .join("state/ospd/openvas.conf")
            .display()
            .to_string(),
    );
    insert_default(&mut environment, "YAFVS_GSAD_HOST", "127.0.0.1");
    for name in MQTT_PASSWORD_ENVIRONMENTS {
        environment.remove(&OsString::from(name));
    }
    environment
}

pub(crate) fn runtime_app_environment(
    repo_root: &Path,
) -> io::Result<BTreeMap<OsString, OsString>> {
    let mut environment = runtime_lifecycle_environment(repo_root)?;
    for (environment_name, secret_name) in [
        (BROWSER_PROXY_SECRET_ENV, BROWSER_PROXY_SECRET),
        (GVMD_CONTROL_SECRET_ENV, GVMD_CONTROL_SECRET),
    ] {
        let key = OsString::from(environment_name);
        if environment.get(&key).is_none_or(|value| value.is_empty()) {
            let (secret, _created) = read_or_create_runtime_secret(repo_root, secret_name)?;
            environment.insert(key, OsString::from(secret));
        }
    }
    Ok(environment)
}

pub(crate) fn runtime_lifecycle_environment(
    repo_root: &Path,
) -> io::Result<BTreeMap<OsString, OsString>> {
    let environment = runtime_environment(repo_root);
    for secret_name in MQTT_RUNTIME_SECRETS {
        read_or_create_runtime_secret(repo_root, secret_name)?;
    }
    Ok(environment)
}

pub(crate) fn compose_command(repo_root: &Path, arguments: &[String]) -> Vec<String> {
    compose_command_with_files(repo_root, &[], arguments)
}

pub(crate) fn compose_command_with_files(
    repo_root: &Path,
    extra_files: &[&Path],
    arguments: &[String],
) -> Vec<String> {
    let mut command = vec![
        "compose".to_string(),
        "-f".to_string(),
        repo_root.join("compose/dev.yaml").display().to_string(),
    ];
    for path in extra_files {
        command.push("-f".to_string());
        command.push(path.display().to_string());
    }
    command.extend_from_slice(arguments);
    command
}

pub(crate) fn compose_command_with_environment_and_files(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    extra_files: &[&Path],
    arguments: &[String],
) -> io::Result<Vec<String>> {
    let runtime_files = ensure_runtime_override_files(repo_root, environment)?;
    let all_files = runtime_files
        .iter()
        .map(PathBuf::as_path)
        .chain(extra_files.iter().copied())
        .collect::<Vec<_>>();
    Ok(compose_command_with_files(repo_root, &all_files, arguments))
}

fn ensure_runtime_override_files(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let hosts = gsad_hosts(environment);
    let plural_requested = environment
        .get(&OsString::from("YAFVS_GSAD_HOSTS"))
        .is_some_and(|value| !value.is_empty());
    if hosts.len() > 1 || plural_requested {
        let bindings = hosts
            .iter()
            .map(|host| to_string(&format!("{host}:19392:9392")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?
            .into_iter()
            .map(|binding| format!("      - {binding}"))
            .collect::<Vec<_>>()
            .join("\n");
        let path = repo_root.join("build/compose/gsad-ports.override.yaml");
        write_override(
            &path,
            &format!("services:\n  gsad:\n    ports: !override\n{bindings}\n"),
        )?;
        files.push(path);
    }
    if direct_requested(environment) {
        let errors = direct_config_errors(environment);
        if !errors.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "direct native API runtime override is invalid: {}",
                    errors.join("; ")
                ),
            ));
        }
        let environment_token =
            environment_value(environment, BEARER_TOKEN_ENV).is_some_and(|value| !value.is_empty());
        let configured_file =
            environment_value(environment, BEARER_TOKEN_FILE_ENV).filter(|value| !value.is_empty());
        let token_file = if environment_token {
            None
        } else if let Some(path) = configured_file {
            Some(path)
        } else {
            read_or_create_runtime_secret(repo_root, BEARER_TOKEN_SECRET)?;
            Some(BEARER_TOKEN_CONTAINER_FILE.to_owned())
        };
        let token_file_config = token_file.map_or_else(String::new, |token_file| {
            format!(
                "    environment:\n      YAFVS_API_BEARER_TOKEN_FILE: {}\n    volumes:\n      - type: bind\n        source: {}\n        target: {}\n        read_only: true\n",
                to_string(&token_file).expect("string JSON encoding cannot fail"),
                to_string(
                    &runtime_secret_path(repo_root, BEARER_TOKEN_SECRET)
                        .display()
                        .to_string()
                )
                .expect("string JSON encoding cannot fail"),
                to_string(BEARER_TOKEN_CONTAINER_FILE)
                    .expect("string JSON encoding cannot fail"),
            )
        });
        let path = repo_root.join("build/compose/yafvs-api-direct.override.yaml");
        write_override(
            &path,
            &format!(
                "services:\n  yafvs-api:\n    ports:\n      - {}\n{token_file_config}",
                to_string(&direct_port_binding(environment)).map_err(io::Error::other)?
            ),
        )?;
        files.push(path);
    }
    Ok(files)
}

fn write_override(path: &Path, content: &str) -> io::Result<()> {
    write_secure_artifact(path, content.as_bytes()).map_err(io::Error::other)
}

fn gsad_hosts(environment: &BTreeMap<OsString, OsString>) -> Vec<String> {
    for name in ["YAFVS_GSAD_HOSTS", "YAFVS_GSAD_HOST"] {
        let mut seen = std::collections::BTreeSet::new();
        let hosts = environment
            .get(&OsString::from(name))
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .filter(|host| seen.insert((*host).to_owned()))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !hosts.is_empty() {
            return hosts;
        }
    }
    vec!["127.0.0.1".into()]
}

fn insert_default(environment: &mut BTreeMap<OsString, OsString>, name: &str, value: &str) {
    environment
        .entry(OsString::from(name))
        .or_insert_with(|| OsString::from(value));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::secret::runtime_secret_path;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn fixture_repo() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-compose-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    #[test]
    fn environment_compose_command_adds_plural_gsad_override() {
        let (root, repo) = fixture_repo();
        let environment = BTreeMap::from([(
            OsString::from("YAFVS_GSAD_HOSTS"),
            OsString::from("127.0.0.1,192.0.2.10"),
        )]);
        let command = compose_command_with_environment_and_files(
            &repo,
            &environment,
            &[],
            &["config".into(), "--quiet".into()],
        )
        .unwrap();
        let path = repo.join("build/compose/gsad-ports.override.yaml");
        assert!(
            command
                .windows(2)
                .any(|items| items == ["-f", &path.display().to_string()])
        );
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("\"127.0.0.1:19392:9392\""));
        assert!(content.contains("\"192.0.2.10:19392:9392\""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn environment_compose_command_adds_guarded_direct_api_override() {
        let (root, repo) = fixture_repo();
        let environment =
            BTreeMap::from([(OsString::from("YAFVS_API_DIRECT"), OsString::from("1"))]);
        let command = compose_command_with_environment_and_files(
            &repo,
            &environment,
            &[],
            &["config".into(), "--quiet".into()],
        )
        .unwrap();
        let path = repo.join("build/compose/yafvs-api-direct.override.yaml");
        assert!(
            command
                .windows(2)
                .any(|items| items == ["-f", path.to_str().unwrap()])
        );
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("\"127.0.0.1:19080:9081\""));
        assert!(content.contains("YAFVS_API_BEARER_TOKEN_FILE"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compose_command_uses_the_repository_compose_file() {
        assert_eq!(
            compose_command(
                Path::new("/srv/YAFVS"),
                &["logs".to_string(), "--tail".to_string(), "12".to_string()]
            ),
            vec![
                "compose",
                "-f",
                "/srv/YAFVS/compose/dev.yaml",
                "logs",
                "--tail",
                "12",
            ]
        );
    }

    #[test]
    fn compose_command_places_extra_files_before_the_operation() {
        assert_eq!(
            compose_command_with_files(
                Path::new("/srv/YAFVS"),
                &[Path::new("/runtime/app-images.json")],
                &["config".to_string(), "--quiet".to_string()],
            ),
            vec![
                "compose",
                "-f",
                "/srv/YAFVS/compose/dev.yaml",
                "-f",
                "/runtime/app-images.json",
                "config",
                "--quiet",
            ]
        );
    }

    #[test]
    fn app_environment_creates_mqtt_secrets_without_exporting_them() {
        let (root, repo) = fixture_repo();
        let environment = runtime_app_environment(&repo).unwrap();
        for (environment_name, secret_name) in
            MQTT_PASSWORD_ENVIRONMENTS.iter().zip(MQTT_RUNTIME_SECRETS)
        {
            assert!(!environment.contains_key(&OsString::from(environment_name)));
            let path = runtime_secret_path(&repo, secret_name);
            let secret = fs::read_to_string(&path).unwrap();
            assert!(!secret.trim().is_empty());
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert!(
                !environment
                    .values()
                    .any(|value| value == &OsString::from(secret.trim()))
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
