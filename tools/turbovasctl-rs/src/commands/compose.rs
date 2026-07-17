// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{build_env, runtime_dir};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

const MQTT_PASSWORD_ENVIRONMENTS: [&str; 4] = [
    "TURBOVAS_MQTT_OPENVAS_PASSWORD",
    "TURBOVAS_MQTT_NOTUS_PASSWORD",
    "TURBOVAS_MQTT_OSPD_PASSWORD",
    "TURBOVAS_MQTT_HEALTH_PASSWORD",
];

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

pub(crate) fn compose_command(repo_root: &Path, arguments: &[String]) -> Vec<String> {
    let mut command = vec![
        "compose".to_string(),
        "-f".to_string(),
        repo_root.join("compose/dev.yaml").display().to_string(),
    ];
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
}
