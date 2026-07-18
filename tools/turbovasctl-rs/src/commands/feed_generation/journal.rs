// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only validation for the private feed activation journal.

use super::{absolute_dir, identity, is_reg, mode, open_at, stat, stat_at};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const APP_SERVICES: [&str; 5] = [
    "gvmd",
    "ospd-openvas",
    "notus-scanner",
    "gsad",
    "turbovas-api",
];
const ARTIFACT_ROOTS: [&str; 9] = [
    "build/prefix",
    "build/venvs/ospd-openvas",
    "build/venvs/notus-scanner",
    "build/openvas-scanner/nasl",
    "build/openvas-scanner/misc",
    "components/ospd-openvas/ospd",
    "components/ospd-openvas/ospd_openvas",
    "components/notus-scanner/notus/scanner",
    "build/openvas-scanner/src/openvas",
];

pub(super) fn activation_state_path(runtime: &Path) -> PathBuf {
    runtime.join("state/feed-generation/activation.json")
}

fn euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

fn digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn absent(value: Option<&Value>) -> bool {
    value.is_none_or(Value::is_null)
}

fn validate_image_ids(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("feed activation app image identities are incomplete")?;
    if object.len() != APP_SERVICES.len()
        || !APP_SERVICES
            .iter()
            .all(|service| object.contains_key(*service))
    {
        return Err("feed activation app image identities are incomplete".into());
    }
    for service in APP_SERVICES {
        let valid = object
            .get(service)
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("sha256:"))
            .is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if !valid {
            return Err(format!(
                "feed activation app image identity is invalid for {service}"
            ));
        }
    }
    Ok(())
}

fn validate_artifacts(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("feed activation runtime artifact identity is invalid")?;
    let keys = [
        "schema_version",
        "algorithm",
        "digest",
        "entry_count",
        "byte_count",
        "roots",
    ];
    let roots = object
        .get("roots")
        .and_then(Value::as_array)
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>());
    if object.len() != keys.len()
        || !keys.iter().all(|key| object.contains_key(*key))
        || object.get("schema_version") != Some(&Value::from(1))
        || object.get("algorithm").and_then(Value::as_str) != Some("sha256")
        || !digest(object.get("digest"))
        || object
            .get("entry_count")
            .and_then(Value::as_u64)
            .is_none_or(|count| count < 1)
        || object.get("byte_count").and_then(Value::as_u64).is_none()
        || roots.as_deref() != Some(ARTIFACT_ROOTS.as_slice())
    {
        return Err("feed activation runtime artifact identity is invalid".into());
    }
    Ok(())
}

fn validate_compose(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("application Compose execution contract is invalid")?;
    let keys = ["schema_version", "algorithm", "digest", "services"];
    let services = object
        .get("services")
        .and_then(Value::as_array)
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>());
    if object.len() != keys.len()
        || !keys.iter().all(|key| object.contains_key(*key))
        || object.get("schema_version") != Some(&Value::from(1))
        || object.get("algorithm").and_then(Value::as_str) != Some("sha256")
        || !digest(object.get("digest"))
        || services.as_deref() != Some(APP_SERVICES.as_slice())
    {
        return Err("application Compose execution contract is invalid".into());
    }
    Ok(())
}

fn validate(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("feed activation state schema is invalid")?;
    if object.get("schema_version") != Some(&Value::from(1)) {
        return Err("feed activation state schema is invalid".into());
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or("feed activation state status is invalid")?;
    if !matches!(status, "active" | "transitioning") {
        return Err("feed activation state status is invalid".into());
    }
    if status == "active" {
        if !digest(object.get("current_generation_id"))
            || !absent(object.get("target_generation_id"))
            || !absent(object.get("previous_generation_id"))
        {
            return Err("active feed activation state identifiers are invalid".into());
        }
    } else {
        if !matches!(
            object.get("action").and_then(Value::as_str),
            Some("activate" | "rollback")
        ) || !digest(object.get("target_generation_id"))
        {
            return Err("transitioning feed activation state is invalid".into());
        }
        if !absent(object.get("current_generation_id")) {
            return Err(
                "transitioning feed activation state must not claim an active generation".into(),
            );
        }
    }
    for (name, field) in [
        (
            "previous_generation_id",
            object.get("previous_generation_id"),
        ),
        (
            "rollback_generation_id",
            object.get("rollback_generation_id"),
        ),
    ] {
        if !absent(field) && !digest(field) {
            return Err(format!("feed activation state {name} is invalid"));
        }
    }
    if let Some(hosts) = object
        .get("restore_gsad_hosts")
        .filter(|value| !value.is_null())
    {
        let hosts = hosts
            .as_array()
            .filter(|hosts| !hosts.is_empty() && hosts.len() <= 16)
            .ok_or("feed activation state restore_gsad_hosts is invalid")?;
        let mut seen = BTreeSet::new();
        for host in hosts {
            let host = host
                .as_str()
                .ok_or("feed activation state restore_gsad_hosts is invalid")?;
            let parsed = host
                .parse::<IpAddr>()
                .map_err(|_| "feed activation state restore_gsad_hosts is invalid")?;
            if parsed.to_string() != host || !seen.insert(host) {
                return Err("feed activation state restore_gsad_hosts is invalid".into());
            }
        }
    }
    let image_ids = object.get("app_image_ids").filter(|value| !value.is_null());
    let artifacts = object
        .get("app_runtime_artifacts")
        .filter(|value| !value.is_null());
    let compose = object
        .get("app_compose_contract")
        .filter(|value| !value.is_null());
    if status == "transitioning"
        && (image_ids.is_none() || artifacts.is_none() || compose.is_none())
    {
        return Err("transitioning feed activation state lacks deployment identity".into());
    }
    if let Some(value) = image_ids {
        validate_image_ids(value)?;
    }
    if let Some(value) = artifacts {
        validate_artifacts(value)?;
    }
    if let Some(value) = compose {
        validate_compose(value)?;
    }
    Ok(())
}

fn read_private_text(path: &Path) -> Result<String, String> {
    let parent_path = path
        .parent()
        .ok_or_else(|| format!("private path has no parent: {}", path.display()))?;
    let parent = absolute_dir(parent_path)?;
    let parent_stat = stat(parent.as_raw_fd())?;
    if parent_stat.st_uid != euid() || mode(&parent_stat) != 0o700 {
        return Err(format!(
            "Private directory is not owner-only: {}",
            parent_path.display()
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("private path name is invalid: {}", path.display()))?;
    let fd = open_at(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let opened = stat(fd.as_raw_fd())?;
    if !is_reg(&opened) {
        return Err(format!("Private path is not a file: {}", path.display()));
    }
    if opened.st_uid != euid() {
        return Err(format!(
            "Private file is not owned by the current user: {}",
            path.display()
        ));
    }
    if mode(&opened) & 0o077 != 0 {
        return Err(format!(
            "Private file is accessible outside its owner: {}",
            path.display()
        ));
    }
    if opened.st_size < 0 || opened.st_size as u64 > MAX_JOURNAL_BYTES {
        return Err(format!("Private file is too large: {}", path.display()));
    }
    let mut file = File::from(fd);
    let mut content = Vec::new();
    file.by_ref()
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("could not read private file {}: {error}", path.display()))?;
    if content.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(format!("Private file is too large: {}", path.display()));
    }
    let final_stat = stat(file.as_raw_fd())?;
    let final_entry = stat_at(parent.as_raw_fd(), name)?;
    if identity(&opened) != identity(&final_stat)
        || opened.st_size != final_stat.st_size
        || opened.st_mtime != final_stat.st_mtime
        || opened.st_mtime_nsec != final_stat.st_mtime_nsec
        || opened.st_ctime != final_stat.st_ctime
        || opened.st_ctime_nsec != final_stat.st_ctime_nsec
        || identity(&opened) != identity(&final_entry)
    {
        return Err(format!(
            "Private file changed while reading: {}",
            path.display()
        ));
    }
    String::from_utf8(content).map_err(|error| format!("private file is not valid UTF-8: {error}"))
}

pub(super) fn read_activation_state(runtime: &Path) -> Result<Option<Value>, String> {
    let path = activation_state_path(runtime);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect {}: {error}", path.display())),
        Ok(_) => {}
    }
    let content = read_private_text(&path)?;
    let value: Value = serde_json::from_str(&content)
        .map_err(|error| format!("feed activation state is not valid JSON: {error}"))?;
    validate(&value)?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "turbovas-feed-journal-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn write(runtime: &Path, value: &Value) -> PathBuf {
        let path = activation_state_path(runtime);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn missing_journal_is_read_only() {
        let runtime = fixture("missing");
        assert_eq!(read_activation_state(&runtime).unwrap(), None);
        assert_eq!(fs::read_dir(&runtime).unwrap().count(), 0);
        fs::remove_dir(runtime).unwrap();
    }

    #[test]
    fn active_journal_accepts_optional_rollback_and_rejects_bad_ids() {
        let runtime = fixture("active");
        let id = "a".repeat(64);
        let rollback = "b".repeat(64);
        let path = write(
            &runtime,
            &json!({"schema_version":1,"status":"active","current_generation_id":id,"rollback_generation_id":rollback}),
        );
        assert_eq!(
            read_activation_state(&runtime).unwrap().unwrap()["status"],
            "active"
        );
        fs::write(
            &path,
            br#"{"schema_version":1,"status":"active","current_generation_id":"bad"}"#,
        )
        .unwrap();
        assert!(read_activation_state(&runtime).is_err());
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn transitioning_journal_requires_complete_deployment_identity() {
        let runtime = fixture("transitioning");
        let target = "a".repeat(64);
        let incomplete = json!({"schema_version":1,"status":"transitioning","action":"activate","target_generation_id":target});
        write(&runtime, &incomplete);
        assert_eq!(
            read_activation_state(&runtime).unwrap_err(),
            "transitioning feed activation state lacks deployment identity"
        );
        let digest = "b".repeat(64);
        let images = APP_SERVICES
            .iter()
            .map(|service| ((*service).to_string(), json!(format!("sha256:{digest}"))))
            .collect::<serde_json::Map<_, _>>();
        let complete = json!({
            "schema_version":1,
            "status":"transitioning",
            "action":"activate",
            "target_generation_id":"a".repeat(64),
            "restore_gsad_hosts":["127.0.0.1","::1"],
            "app_image_ids":images,
            "app_runtime_artifacts":{"schema_version":1,"algorithm":"sha256","digest":digest,"entry_count":1,"byte_count":0,"roots":ARTIFACT_ROOTS},
            "app_compose_contract":{"schema_version":1,"algorithm":"sha256","digest":"c".repeat(64),"services":APP_SERVICES},
        });
        write(&runtime, &complete);
        assert!(read_activation_state(&runtime).is_ok());
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn accessible_or_oversized_journal_fails_closed() {
        let runtime = fixture("unsafe");
        let path = write(
            &runtime,
            &json!({"schema_version":1,"status":"active","current_generation_id":"a".repeat(64)}),
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_activation_state(&runtime).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, vec![b'x'; MAX_JOURNAL_BYTES as usize + 1]).unwrap();
        assert!(read_activation_state(&runtime).is_err());
        fs::remove_dir_all(runtime).unwrap();
    }
}
