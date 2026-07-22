// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deployment identity validation and private receipt reads for feed transitions.
//!
//! This module deliberately contains no Compose or Docker execution.  Its callers
//! supply those observations after the receipt has been parsed and structurally
//! validated.

use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path};

const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const RECEIPT_DIR: &str = "state";
const RECEIPT_NAME: &str = "app-deployment.json";
pub(super) const APP_SERVICES: [&str; 5] =
    ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];
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

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
        || ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .iter()
            .all(|range| bytes[range.clone()].iter().all(u8::is_ascii_digit))
        || !valid_date(bytes)
        || number(bytes, 11, 2) >= 24
        || number(bytes, 14, 2) >= 60
        || number(bytes, 17, 2) >= 60
    {
        return false;
    }
    let timezone = bytes[19..]
        .iter()
        .position(|byte| matches!(*byte, b'Z' | b'+' | b'-'))
        .map(|index| index + 19);
    let Some(timezone) = timezone else {
        return false;
    };
    if timezone > 19
        && (bytes[19] != b'.'
            || !bytes[20..timezone].iter().all(u8::is_ascii_digit)
            || timezone == 20)
    {
        return false;
    }
    (bytes.len() == timezone + 1 && bytes[timezone] == b'Z')
        || (bytes.len() == timezone + 6
            && matches!(bytes[timezone], b'+' | b'-')
            && bytes[timezone + 3] == b':'
            && bytes[timezone + 1..timezone + 3]
                .iter()
                .all(u8::is_ascii_digit)
            && bytes[timezone + 4..timezone + 6]
                .iter()
                .all(u8::is_ascii_digit)
            && number(bytes, timezone + 1, 2) < 24
            && number(bytes, timezone + 4, 2) < 60)
}

fn valid_date(bytes: &[u8]) -> bool {
    let year = number(bytes, 0, 4);
    let month = number(bytes, 5, 2);
    let day = number(bytes, 8, 2);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    };
    year != 0 && (1..=days).contains(&day)
}

fn number(bytes: &[u8], start: usize, width: usize) -> u32 {
    bytes[start..start + width]
        .iter()
        .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
}

/// Validates and normalizes the full pinned application image identity set.
pub(super) fn validate_app_service_image_ids(
    value: &Value,
) -> Result<BTreeMap<String, String>, String> {
    let Some(object) = value.as_object() else {
        return Err("feed activation app image identities are incomplete".into());
    };
    if !exact_keys(object, &APP_SERVICES) {
        return Err("feed activation app image identities are incomplete".into());
    }
    APP_SERVICES
        .iter()
        .map(|service| {
            let image = object.get(*service).and_then(Value::as_str);
            match image.filter(|image| {
                image.len() == 71 && image.starts_with("sha256:") && digest(&image[7..])
            }) {
                Some(image) => Ok(((*service).to_string(), image.to_string())),
                None => Err(format!(
                    "feed activation app image identity is invalid for {service}"
                )),
            }
        })
        .collect()
}

/// Validates the digest of bind-mounted application runtime artifacts.
pub(super) fn validate_app_runtime_artifact_manifest(value: &Value) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Err("feed activation runtime artifact identity is invalid".into());
    };
    if !exact_keys(
        object,
        &[
            "schema_version",
            "algorithm",
            "digest",
            "entry_count",
            "byte_count",
            "roots",
        ],
    ) {
        return Err("feed activation runtime artifact identity is invalid".into());
    }
    let expected_roots = ARTIFACT_ROOTS.map(Value::from);
    if object.get("schema_version") != Some(&Value::from(1))
        || object.get("algorithm") != Some(&Value::from("sha256"))
        || !object
            .get("digest")
            .and_then(Value::as_str)
            .is_some_and(digest)
        || object
            .get("entry_count")
            .and_then(Value::as_u64)
            .is_none_or(|count| count < 1)
        || object.get("byte_count").and_then(Value::as_u64).is_none()
        || object.get("roots") != Some(&Value::Array(expected_roots.to_vec()))
    {
        return Err("feed activation runtime artifact identity is invalid".into());
    }
    Ok(())
}

/// Validates the stable identity for the rendered application Compose contract.
pub(super) fn validate_app_compose_contract(value: &Value) -> Result<(), String> {
    let Some(object) = value.as_object() else {
        return Err("application Compose execution contract is invalid".into());
    };
    if !exact_keys(
        object,
        &["schema_version", "algorithm", "digest", "services"],
    ) || object.get("schema_version") != Some(&Value::from(1))
        || object.get("algorithm") != Some(&Value::from("sha256"))
        || !object
            .get("digest")
            .and_then(Value::as_str)
            .is_some_and(digest)
        || object.get("services") != Some(&Value::Array(APP_SERVICES.map(Value::from).to_vec()))
    {
        return Err("application Compose execution contract is invalid".into());
    }
    Ok(())
}

/// Validates a deployment receipt without dropping any of its attested fields.
pub(super) fn validate_app_deployment_receipt(value: &Value) -> Result<Value, String> {
    let Some(object) = value.as_object() else {
        return Err("application deployment receipt is invalid".into());
    };
    if !exact_keys(
        object,
        &[
            "schema_version",
            "image_ids",
            "runtime_artifacts",
            "compose_contract",
            "prepared_at",
        ],
    ) {
        return Err("application deployment receipt is invalid".into());
    }
    if object.get("schema_version") != Some(&Value::from(1)) {
        return Err("application deployment receipt schema is invalid".into());
    }
    validate_app_service_image_ids(
        object
            .get("image_ids")
            .ok_or("application deployment receipt is invalid")?,
    )?;
    validate_app_runtime_artifact_manifest(
        object
            .get("runtime_artifacts")
            .ok_or("application deployment receipt is invalid")?,
    )?;
    validate_app_compose_contract(
        object
            .get("compose_contract")
            .ok_or("application deployment receipt is invalid")?,
    )?;
    let prepared_at = object
        .get("prepared_at")
        .and_then(Value::as_str)
        .ok_or("application deployment receipt timestamp is invalid")?;
    if !timestamp(prepared_at) {
        return Err("application deployment receipt timestamp is invalid".into());
    }
    Ok(value.clone())
}

fn c(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("unsafe deployment receipt path component: {value:?}"))
}

fn stat(fd: i32) -> Result<libc::stat, String> {
    let mut metadata = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is an open descriptor and `metadata` is a writable output buffer.
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        Err(format!(
            "could not stat deployment receipt: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(metadata)
    }
}

fn same_identity(before: &libc::stat, after: &libc::stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
        && before.st_mode == after.st_mode
}

fn private_directory(path: &Path) -> Result<OwnedFd, String> {
    if !path.is_absolute() {
        return Err(format!(
            "private deployment receipt directory is unsafe: {}",
            path.display()
        ));
    }
    let root = c("/")?;
    // SAFETY: `root` is NUL terminated and successful descriptors are immediately owned.
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(format!(
            "could not open private deployment receipt directory: {}",
            io::Error::last_os_error()
        ));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    let normal_components = path
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let mut normal_index = 0;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(format!(
                "private deployment receipt directory is unsafe: {}",
                path.display()
            ));
        };
        let name = name.to_str().ok_or_else(|| {
            format!(
                "private deployment receipt directory is unsafe: {}",
                path.display()
            )
        })?;
        let name = c(name)?;
        normal_index += 1;
        let mut before = unsafe { std::mem::zeroed() };
        // SAFETY: descriptor, name, and output buffer are valid for this call.
        if unsafe {
            libc::fstatat(
                current.as_raw_fd(),
                name.as_ptr(),
                &mut before,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(format!(
                "could not inspect private deployment receipt directory: {}",
                io::Error::last_os_error()
            ));
        }
        let final_directory = normal_index == normal_components;
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let unsafe_directory = before.st_mode & libc::S_IFMT != libc::S_IFDIR
            || if final_directory {
                before.st_uid != euid || before.st_mode & 0o077 != 0
            } else {
                !matches!(before.st_uid, 0) && before.st_uid != euid
                    || before.st_mode & 0o002 != 0
                    || before.st_mode & 0o020 != 0
                        && (before.st_uid != euid || before.st_gid != egid)
            };
        if unsafe_directory {
            return Err("private deployment receipt directory is unsafe".into());
        }
        // SAFETY: descriptor and name are valid; successful descriptor is immediately owned.
        let raw = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(format!(
                "could not open private deployment receipt directory: {}",
                io::Error::last_os_error()
            ));
        }
        let opened = unsafe { OwnedFd::from_raw_fd(raw) };
        let after = stat(opened.as_raw_fd())?;
        if !same_identity(&before, &after) {
            return Err("private deployment receipt directory changed while opening".into());
        }
        current = opened;
    }
    Ok(current)
}

/// Reads the owner-private receipt under `runtime/state`, refusing links, broad
/// permissions, replacement races, invalid UTF-8, and content over 16 KiB.
pub(super) fn read_app_deployment_receipt(runtime: &Path) -> Result<Option<Value>, String> {
    let receipt_dir = runtime.join(RECEIPT_DIR);
    if matches!(fs::symlink_metadata(&receipt_dir), Err(error) if error.kind() == io::ErrorKind::NotFound)
    {
        return Ok(None);
    }
    let parent = private_directory(&receipt_dir)?;
    let name = c(RECEIPT_NAME)?;
    // SAFETY: descriptor and name are valid; successful descriptor is immediately owned.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(format!(
                "could not read application deployment receipt: {error}"
            ))
        };
    }
    let file = unsafe { OwnedFd::from_raw_fd(raw) };
    let before = stat(file.as_raw_fd())?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("private deployment receipt path is not a file".into());
    }
    if before.st_uid != unsafe { libc::geteuid() } || before.st_mode & 0o077 != 0 {
        return Err("private deployment receipt is unsafe".into());
    }
    if before.st_size < 0 || before.st_size as usize > MAX_RECEIPT_BYTES {
        return Err("private deployment receipt is too large".into());
    }
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    while bytes.len() < before.st_size as usize {
        let mut buffer = [0_u8; 4096];
        let wanted = (before.st_size as usize - bytes.len()).min(buffer.len());
        // SAFETY: `buffer` is writable for `wanted` bytes and `file` remains open.
        let count = unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr().cast(), wanted) };
        if count < 0 {
            return Err(format!(
                "could not read application deployment receipt: {}",
                io::Error::last_os_error()
            ));
        }
        if count == 0 {
            return Err("application deployment receipt was truncated while reading".into());
        }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
    let mut extra = [0_u8; 1];
    // SAFETY: `extra` is writable and `file` remains open.
    let extra_count = unsafe { libc::read(file.as_raw_fd(), extra.as_mut_ptr().cast(), 1) };
    if extra_count < 0 {
        return Err(format!(
            "could not read application deployment receipt: {}",
            io::Error::last_os_error()
        ));
    }
    if extra_count != 0 {
        return Err("private deployment receipt is too large".into());
    }
    let after = stat(file.as_raw_fd())?;
    if !same_identity(&before, &after) {
        return Err("application deployment receipt changed while reading".into());
    }
    let payload = serde_json::from_slice(&bytes)
        .map_err(|error| format!("application deployment receipt is not valid JSON: {error}"))?;
    validate_app_deployment_receipt(&payload).map(Some)
}

/// Returns the receipt or the public missing/invalid receipt error used by the
/// transition adapter before it performs image, artifact, and Compose checks.
pub(super) fn require_app_deployment_receipt(runtime: &Path) -> Result<Value, String> {
    match read_app_deployment_receipt(runtime) {
        Ok(Some(receipt)) => Ok(receipt),
        Ok(None) => Err(
            "Prepared application deployment receipt is missing; run runtime-app-build first"
                .into(),
        ),
        Err(error) => Err(format!(
            "Prepared application deployment receipt is invalid: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn receipt() -> Value {
        json!({
            "schema_version": 1,
            "image_ids": {"gvmd": format!("sha256:{}", "a".repeat(64)), "ospd-openvas": format!("sha256:{}", "b".repeat(64)), "notus-scanner": format!("sha256:{}", "c".repeat(64)), "gsad": format!("sha256:{}", "d".repeat(64)), "yafvs-api": format!("sha256:{}", "e".repeat(64))},
            "runtime_artifacts": {"schema_version": 1, "algorithm": "sha256", "digest": "f".repeat(64), "entry_count": 1, "byte_count": 0, "roots": ARTIFACT_ROOTS},
            "compose_contract": {"schema_version": 1, "algorithm": "sha256", "digest": "1".repeat(64), "services": APP_SERVICES},
            "prepared_at": "2026-07-18T12:00:00+00:00"
        })
    }

    fn runtime_fixture() -> std::path::PathBuf {
        let runtime = std::env::current_dir().unwrap().join(format!(
            ".yafvsctl-deployment-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let state = runtime.join(RECEIPT_DIR);
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        runtime
    }

    fn write_receipt(runtime: &Path, value: &Value) {
        let path = runtime.join(RECEIPT_DIR).join(RECEIPT_NAME);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn accepts_complete_deployment_receipt() {
        assert_eq!(
            validate_app_deployment_receipt(&receipt()).unwrap(),
            receipt()
        );
    }

    #[test]
    fn rejects_identity_drift_and_extra_fields() {
        let mut candidate = receipt();
        candidate["image_ids"]["gvmd"] = Value::from("sha256:upper-case-is-not-an-image-id");
        assert_eq!(
            validate_app_deployment_receipt(&candidate).unwrap_err(),
            "feed activation app image identity is invalid for gvmd"
        );
        let mut candidate = receipt();
        candidate
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::Null);
        assert_eq!(
            validate_app_deployment_receipt(&candidate).unwrap_err(),
            "application deployment receipt is invalid"
        );
    }

    #[test]
    fn rejects_artifact_and_compose_shape_drift() {
        let mut candidate = receipt();
        candidate["runtime_artifacts"]["roots"] = json!(["build/prefix"]);
        assert_eq!(
            validate_app_deployment_receipt(&candidate).unwrap_err(),
            "feed activation runtime artifact identity is invalid"
        );
        let mut candidate = receipt();
        candidate["compose_contract"]["services"] = json!(["gvmd"]);
        assert_eq!(
            validate_app_deployment_receipt(&candidate).unwrap_err(),
            "application Compose execution contract is invalid"
        );
    }

    #[test]
    fn rejects_invalid_calendar_time_and_timezone_ranges() {
        for prepared_at in [
            "2026-02-29T12:00:00+00:00",
            "2026-07-18T24:00:00+00:00",
            "2026-07-18T12:60:00+00:00",
            "2026-07-18T12:00:00+24:00",
            "2026-07-18T12:00:00",
        ] {
            let mut candidate = receipt();
            candidate["prepared_at"] = Value::from(prepared_at);
            assert_eq!(
                validate_app_deployment_receipt(&candidate).unwrap_err(),
                "application deployment receipt timestamp is invalid"
            );
        }
        let mut leap_day = receipt();
        leap_day["prepared_at"] = Value::from("2028-02-29T12:00:00.1Z");
        assert!(validate_app_deployment_receipt(&leap_day).is_ok());
    }

    #[test]
    fn reads_only_owner_private_bounded_receipts() {
        let runtime = runtime_fixture();
        write_receipt(&runtime, &receipt());
        assert_eq!(
            read_app_deployment_receipt(&runtime).unwrap(),
            Some(receipt())
        );

        let path = runtime.join(RECEIPT_DIR).join(RECEIPT_NAME);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_app_deployment_receipt(&runtime).unwrap_err(),
            "private deployment receipt is unsafe"
        );

        fs::remove_file(&path).unwrap();
        fs::write(&path, vec![b'x'; MAX_RECEIPT_BYTES + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_app_deployment_receipt(&runtime).unwrap_err(),
            "private deployment receipt is too large"
        );
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn refuses_receipt_and_directory_symlinks() {
        let runtime = runtime_fixture();
        let state = runtime.join(RECEIPT_DIR);
        let target = runtime.join("target.json");
        fs::write(&target, serde_json::to_vec(&receipt()).unwrap()).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, state.join(RECEIPT_NAME)).unwrap();
        assert!(read_app_deployment_receipt(&runtime).is_err());
        fs::remove_dir_all(&runtime).unwrap();

        let runtime = runtime_fixture();
        let state = runtime.join(RECEIPT_DIR);
        fs::remove_dir(&state).unwrap();
        let replacement = runtime.join("replacement");
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&replacement, &state).unwrap();
        assert_eq!(
            read_app_deployment_receipt(&runtime).unwrap_err(),
            "private deployment receipt directory is unsafe"
        );
        fs::remove_dir_all(runtime).unwrap();
    }
}
