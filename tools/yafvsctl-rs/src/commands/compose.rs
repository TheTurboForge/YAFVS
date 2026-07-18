// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{build_env, runtime_dir};
use super::secret::read_or_create_runtime_secret;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::Path;

const MQTT_PASSWORD_ENVIRONMENTS: [&str; 4] = [
    "TURBOVAS_MQTT_OPENVAS_PASSWORD",
    "TURBOVAS_MQTT_NOTUS_PASSWORD",
    "TURBOVAS_MQTT_OSPD_PASSWORD",
    "TURBOVAS_MQTT_HEALTH_PASSWORD",
];
const MQTT_RUNTIME_SECRETS: [&str; 4] = [
    "mqtt-openvas-password",
    "mqtt-notus-password",
    "mqtt-ospd-password",
    "mqtt-health-password",
];
const BROWSER_PROXY_SECRET_ENV: &str = "TURBOVAS_API_BROWSER_PROXY_SECRET";
const BROWSER_PROXY_SECRET: &str = "native-api-browser-proxy-secret";
const GVMD_CONTROL_SECRET_ENV: &str = "TURBOVAS_GVMD_CONTROL_SECRET";
const GVMD_CONTROL_SECRET: &str = "gvmd-control-secret";

pub(crate) fn runtime_environment(repo_root: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = build_env(repo_root);
    insert_default(&mut environment, "COMPOSE_PROJECT_NAME", "turbovas");
    insert_default(
        &mut environment,
        "TURBOVAS_RUNTIME_DIR",
        &runtime_dir(repo_root).display().to_string(),
    );
    insert_default(
        &mut environment,
        "TURBOVAS_REPO_MOUNT_PATH",
        &repo_root.display().to_string(),
    );
    // SAFETY: getuid/getgid have no preconditions and do not dereference memory.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    insert_default(&mut environment, "TURBOVAS_UID", &uid.to_string());
    insert_default(&mut environment, "TURBOVAS_GID", &gid.to_string());
    insert_default(&mut environment, "POSTGRES_USER", "turbovas");
    insert_default(&mut environment, "POSTGRES_PASSWORD", "turbovas-dev");
    insert_default(&mut environment, "POSTGRES_DB", "turbovas");
    insert_default(
        &mut environment,
        "OPENVAS_CONFIG",
        &runtime_dir(repo_root)
            .join("state/ospd/openvas.conf")
            .display()
            .to_string(),
    );
    insert_default(&mut environment, "TURBOVAS_GSAD_HOST", "127.0.0.1");
    for name in MQTT_PASSWORD_ENVIRONMENTS {
        environment.remove(&OsString::from(name));
    }
    environment
}

pub(crate) fn runtime_app_environment(
    repo_root: &Path,
) -> io::Result<BTreeMap<OsString, OsString>> {
    let mut environment = runtime_environment(repo_root);
    for secret_name in MQTT_RUNTIME_SECRETS {
        read_or_create_runtime_secret(repo_root, secret_name)?;
    }
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
        let repo = root.join("TurboVAS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    #[test]
    fn compose_command_uses_the_repository_compose_file() {
        assert_eq!(
            compose_command(
                Path::new("/srv/TurboVAS"),
                &["logs".to_string(), "--tail".to_string(), "12".to_string()]
            ),
            vec![
                "compose",
                "-f",
                "/srv/TurboVAS/compose/dev.yaml",
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
                Path::new("/srv/TurboVAS"),
                &[Path::new("/runtime/app-images.json")],
                &["config".to_string(), "--quiet".to_string()],
            ),
            vec![
                "compose",
                "-f",
                "/srv/TurboVAS/compose/dev.yaml",
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
