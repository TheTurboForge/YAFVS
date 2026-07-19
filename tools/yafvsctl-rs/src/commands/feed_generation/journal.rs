// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Descriptor-anchored validation and durable writes for the private feed
//! activation journal.

use super::{absolute_dir, identity, is_dir, is_lnk, is_reg, mode, open_at, stat, stat_at};
use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const JOURNAL_NAME: &str = "activation.json";
const JOURNAL_DIRS: [&str; 2] = ["state", "feed-generation"];
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn c(name: &str) -> Result<CString, String> {
    CString::new(name).map_err(|_| format!("unsafe journal path component: {name:?}"))
}

fn fsync_directory(fd: i32, context: &str) -> Result<(), String> {
    // SAFETY: `fd` is an owned directory descriptor for the duration of this call.
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(format!(
            "could not sync {context}: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn mkdir_at(parent: i32, name: &str) -> Result<bool, String> {
    let name = c(name)?;
    // SAFETY: `parent` is an open directory descriptor and `name` is NUL terminated.
    if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        Ok(false)
    } else {
        Err(format!(
            "could not create private journal directory: {error}"
        ))
    }
}

fn open_private_child(parent: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    let created = mkdir_at(parent.as_raw_fd(), name)?;
    if created {
        fsync_directory(parent.as_raw_fd(), "private journal directory parent")?;
    }
    let before = stat_at(parent.as_raw_fd(), name)?;
    if is_lnk(&before) || !is_dir(&before) {
        return Err(format!(
            "feed activation state path component is not a real directory: {name}"
        ));
    }
    let child = open_at(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let opened = stat(child.as_raw_fd())?;
    if identity(&before) != identity(&opened) {
        return Err(format!(
            "feed activation state directory changed while opening: {name}"
        ));
    }
    if opened.st_uid != euid() {
        return Err(format!(
            "feed activation state directory is not owner-owned: {name}"
        ));
    }
    // SAFETY: `child` is an owned descriptor for a verified directory.
    if unsafe { libc::fchmod(child.as_raw_fd(), 0o700) } != 0 {
        return Err(format!(
            "could not normalize private journal directory {name}: {}",
            io::Error::last_os_error()
        ));
    }
    fsync_directory(child.as_raw_fd(), "private journal directory")?;
    Ok(child)
}

fn open_runtime_root(runtime: &Path) -> Result<OwnedFd, String> {
    let parent_path = runtime
        .parent()
        .ok_or_else(|| format!("runtime path has no parent: {}", runtime.display()))?;
    let runtime_name = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("runtime path name is invalid: {}", runtime.display()))?;
    let parent = absolute_dir(parent_path)?;
    let created = mkdir_at(parent.as_raw_fd(), runtime_name)?;
    if created {
        fsync_directory(parent.as_raw_fd(), "runtime directory parent")?;
    }
    let before = stat_at(parent.as_raw_fd(), runtime_name)?;
    if is_lnk(&before) || !is_dir(&before) {
        return Err("runtime path is not a real directory".into());
    }
    let runtime_fd = open_at(
        parent.as_raw_fd(),
        runtime_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let opened = stat(runtime_fd.as_raw_fd())?;
    if identity(&before) != identity(&opened) {
        return Err("runtime directory changed while opening".into());
    }
    if opened.st_uid != euid() {
        return Err(format!(
            "Runtime directory is not owner-owned: {}",
            runtime.display()
        ));
    }
    Ok(runtime_fd)
}

fn ensure_activation_state_directory(runtime: &Path) -> Result<OwnedFd, String> {
    let mut current = open_runtime_root(runtime)?;
    for name in JOURNAL_DIRS {
        current = open_private_child(&current, name)?;
    }
    Ok(current)
}

#[derive(Clone)]
struct TempEntry {
    name: String,
    identity: (u64, u64),
}

fn create_temp_file(parent: &OwnedFd) -> Result<(File, TempEntry), String> {
    for _ in 0..32 {
        let name = format!(
            ".{JOURNAL_NAME}.tmp-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let encoded = c(&name)?;
        // SAFETY: `parent` is an owned directory descriptor and `encoded` is NUL terminated.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                encoded.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(format!(
                "could not create private journal temporary file: {error}"
            ));
        }
        // SAFETY: `raw` came from a successful `openat` and is immediately owned.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
        let initial = stat(file.as_raw_fd())?;
        let entry = TempEntry {
            name,
            identity: identity(&initial),
        };
        if !is_reg(&initial) || initial.st_uid != euid() || initial.st_nlink != 1 {
            return match cleanup_temp(parent, &entry) {
                Ok(()) => Err("private journal temporary file is unsafe".into()),
                Err(cleanup) => Err(format!(
                    "private journal temporary file is unsafe; temporary journal cleanup failed: {cleanup}"
                )),
            };
        }
        // SAFETY: `file` owns a regular file descriptor created above.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            let error = format!(
                "could not normalize private journal temporary file: {}",
                io::Error::last_os_error()
            );
            return match cleanup_temp(parent, &entry) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; temporary journal cleanup failed: {cleanup}"
                )),
            };
        }
        let metadata = match stat(file.as_raw_fd()) {
            Ok(metadata) => metadata,
            Err(error) => {
                return match cleanup_temp(parent, &entry) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(format!(
                        "{error}; temporary journal cleanup failed: {cleanup}"
                    )),
                };
            }
        };
        if !is_reg(&metadata)
            || metadata.st_uid != euid()
            || mode(&metadata) != 0o600
            || metadata.st_nlink != 1
        {
            return match cleanup_temp(parent, &entry) {
                Ok(()) => Err("private journal temporary file is unsafe".into()),
                Err(cleanup) => Err(format!(
                    "private journal temporary file is unsafe; temporary journal cleanup failed: {cleanup}"
                )),
            };
        }
        return Ok((file, entry));
    }
    Err("could not allocate a unique private journal temporary file".into())
}

fn temp_metadata(parent: &OwnedFd, name: &str) -> Result<Option<libc::stat>, String> {
    let name = c(name)?;
    let mut metadata = unsafe { std::mem::zeroed() };
    // SAFETY: `parent` is an owned directory descriptor, `name` is NUL terminated, and
    // `metadata` is writable for the syscall.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        Ok(Some(metadata))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(format!(
                "could not inspect private journal temporary file: {error}"
            ))
        }
    }
}

fn cleanup_temp(parent: &OwnedFd, temp: &TempEntry) -> Result<(), String> {
    let Some(metadata) = temp_metadata(parent, &temp.name)? else {
        return Ok(());
    };
    if identity(&metadata) != temp.identity {
        return Err("private journal temporary file was replaced before cleanup".into());
    }
    let name = c(&temp.name)?;
    // SAFETY: `parent` is an owned directory descriptor and `name` is NUL terminated.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(format!(
            "could not remove private journal temporary file: {}",
            io::Error::last_os_error()
        ));
    }
    fsync_directory(
        parent.as_raw_fd(),
        "private journal directory after cleanup",
    )
}

fn rename_temp(parent: &OwnedFd, temp: &TempEntry, file: &File) -> Result<(), String> {
    let opened = stat(file.as_raw_fd())?;
    let metadata = temp_metadata(parent, &temp.name)?
        .ok_or("private journal temporary file disappeared before replacement")?;
    if identity(&opened) != temp.identity
        || identity(&metadata) != temp.identity
        || !is_reg(&opened)
        || !is_reg(&metadata)
        || opened.st_uid != euid()
        || metadata.st_uid != euid()
        || mode(&opened) != 0o600
        || mode(&metadata) != 0o600
        || opened.st_nlink != 1
        || metadata.st_nlink != 1
    {
        return Err("private journal temporary file changed before replacement".into());
    }
    let source = c(&temp.name)?;
    let target = c(JOURNAL_NAME)?;
    // SAFETY: both names are NUL terminated and both operands are anchored to `parent`.
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "could not atomically replace private activation journal: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
type JournalHook = (PathBuf, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static BEFORE_RENAME_HOOK: std::sync::Mutex<Vec<JournalHook>> = std::sync::Mutex::new(Vec::new());
#[cfg(test)]
static FINAL_SYNC_HOOK: std::sync::Mutex<Vec<JournalHook>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn take_hook(hook: &std::sync::Mutex<Vec<JournalHook>>, path: &Path) -> Option<JournalHook> {
    let mut pending = hook.lock().unwrap();
    let position = pending.iter().position(|(target, _)| target == path)?;
    Some(pending.remove(position))
}

#[cfg(test)]
fn run_hook(hook: &std::sync::Mutex<Vec<JournalHook>>, path: &Path) {
    let action = take_hook(hook, path);
    if let Some((_, action)) = action {
        action();
    }
}

#[cfg(test)]
fn before_rename_hook(path: &Path) {
    run_hook(&BEFORE_RENAME_HOOK, path);
}
#[cfg(not(test))]
fn before_rename_hook(_: &Path) {}

fn final_parent_sync(parent: &OwnedFd, _path: &Path) -> Result<(), String> {
    #[cfg(test)]
    {
        let action = take_hook(&FINAL_SYNC_HOOK, _path);
        if action.is_some() {
            return Err("injected private journal durability failure".into());
        }
    }
    fsync_directory(
        parent.as_raw_fd(),
        "private journal directory after replacement",
    )
}
const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];
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

pub(super) fn validate(value: &Value) -> Result<(), String> {
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

pub(super) fn write_activation_state(runtime: &Path, payload: Value) -> Result<(), String> {
    let mut candidate = payload;
    if let Some(object) = candidate.as_object_mut() {
        object
            .entry("schema_version".to_string())
            .or_insert_with(|| Value::from(1));
    }
    validate(&candidate)?;
    candidate.sort_all_objects();
    let text = serde_json::to_string_pretty(&candidate)
        .map_err(|error| format!("could not serialize feed activation state: {error}"))?
        + "\n";
    if text.len() as u64 > MAX_JOURNAL_BYTES {
        return Err("feed activation state exceeds size limit".into());
    }
    let parent = ensure_activation_state_directory(runtime)?;
    let parent_path = activation_state_path(runtime)
        .parent()
        .ok_or_else(|| "private activation journal path has no parent".to_string())?
        .to_path_buf();
    let mut temporary = None;
    let result = (|| {
        let (mut file, entry) = create_temp_file(&parent)?;
        temporary = Some(entry);
        file.write_all(text.as_bytes())
            .map_err(|error| format!("could not write private activation journal: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not sync private activation journal: {error}"))?;
        before_rename_hook(&parent_path);
        rename_temp(
            &parent,
            temporary
                .as_ref()
                .expect("temporary journal entry is present"),
            &file,
        )?;
        drop(file);
        temporary = None;
        final_parent_sync(&parent, &parent_path)?;
        let path = activation_state_path(runtime);
        let readback =
            decode_activation_state(&read_private_text_at(&parent, &parent_path, &path)?)?;
        if readback == candidate {
            Ok(())
        } else {
            Err("private activation journal readback does not match the candidate".into())
        }
    })();
    if let Err(error) = result {
        if let Some(temp) = temporary {
            return match cleanup_temp(&parent, &temp) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; temporary journal cleanup failed: {cleanup}"
                )),
            };
        }
        return Err(error);
    }
    Ok(())
}

fn read_private_text(path: &Path) -> Result<String, String> {
    let parent_path = path
        .parent()
        .ok_or_else(|| format!("private path has no parent: {}", path.display()))?;
    let parent = absolute_dir(parent_path)?;
    read_private_text_at(&parent, parent_path, path)
}

fn read_private_text_at(
    parent: &OwnedFd,
    parent_path: &Path,
    path: &Path,
) -> Result<String, String> {
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
    Read::by_ref(&mut file)
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

fn decode_activation_state(content: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(content)
        .map_err(|error| format!("feed activation state is not valid JSON: {error}"))?;
    validate(&value)?;
    Ok(value)
}

pub(super) fn read_activation_state(runtime: &Path) -> Result<Option<Value>, String> {
    let path = activation_state_path(runtime);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect {}: {error}", path.display())),
        Ok(_) => {}
    }
    read_private_text(&path)
        .and_then(|content| decode_activation_state(&content))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "yafvs-feed-journal-{name}-{}",
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

    fn transitioning_payload() -> Value {
        let image_digest = "b".repeat(64);
        let images = APP_SERVICES
            .iter()
            .map(|service| {
                (
                    (*service).to_string(),
                    json!(format!("sha256:{image_digest}")),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        json!({
            "target_generation_id":"a".repeat(64),
            "status":"transitioning",
            "app_image_ids":images,
            "action":"activate",
            "app_runtime_artifacts":{"roots":ARTIFACT_ROOTS,"byte_count":0,"entry_count":1,"digest":"c".repeat(64),"algorithm":"sha256","schema_version":1},
            "app_compose_contract":{"services":APP_SERVICES,"digest":"d".repeat(64),"schema_version":1,"algorithm":"sha256"},
        })
    }

    fn journal_directory(runtime: &Path) -> PathBuf {
        activation_state_path(runtime)
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn assert_in_order(text: &str, fragments: &[&str]) {
        let mut cursor = 0;
        for fragment in fragments {
            let offset = text[cursor..]
                .find(fragment)
                .unwrap_or_else(|| panic!("missing canonical fragment: {fragment}"));
            cursor += offset + fragment.len();
        }
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

    #[test]
    fn write_round_trips_active_and_transitioning_with_private_canonical_state() {
        let runtime = fixture("write-round-trip");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o775)).unwrap();
        write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"a".repeat(64)}),
        )
        .unwrap();
        let path = activation_state_path(&runtime);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!(
                "{{\n  \"current_generation_id\": \"{}\",\n  \"schema_version\": 1,\n  \"status\": \"active\"\n}}\n",
                "a".repeat(64)
            )
        );
        assert_eq!(
            fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
            0o775
        );
        for directory in [runtime.join("state"), journal_directory(&runtime)] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let payload = transitioning_payload();
        write_activation_state(&runtime, payload.clone()).unwrap();
        let mut expected = payload;
        expected["schema_version"] = Value::from(1);
        assert_eq!(read_activation_state(&runtime).unwrap(), Some(expected));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"));
        assert_in_order(
            &text,
            &[
                "\"action\"",
                "\"app_compose_contract\"",
                "\"app_image_ids\"",
                "\"app_runtime_artifacts\"",
                "\"schema_version\"",
                "\"status\"",
                "\"target_generation_id\"",
            ],
        );
        assert_in_order(
            &text,
            &[
                "\"app_compose_contract\": {\n    \"algorithm\"",
                "\"digest\"",
                "\"schema_version\"",
                "\"services\"",
            ],
        );
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn write_rejects_symlinked_intermediate_directory() {
        let runtime = fixture("symlink-intermediate");
        let outside = fixture("symlink-outside");
        symlink(&outside, runtime.join("state")).unwrap();
        let error = write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"a".repeat(64)}),
        )
        .unwrap_err();
        assert!(error.contains("not a real directory"));
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        fs::remove_file(runtime.join("state")).unwrap();
        fs::remove_dir(runtime).unwrap();
        fs::remove_dir(outside).unwrap();
    }

    #[test]
    fn write_replaces_an_unsafe_target_without_following_it_and_validation_preserves_prior() {
        let runtime = fixture("unsafe-target");
        write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"a".repeat(64)}),
        )
        .unwrap();
        let path = activation_state_path(&runtime);
        let original = fs::read_to_string(&path).unwrap();
        assert!(
            write_activation_state(
                &runtime,
                json!({"status":"active","current_generation_id":"../escape"}),
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let victim = runtime.join("victim");
        fs::write(&victim, "unchanged").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&victim, &path).unwrap();
        write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"b".repeat(64)}),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert_eq!(
            read_activation_state(&runtime).unwrap().unwrap()["current_generation_id"],
            "b".repeat(64)
        );
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn write_surfaces_durability_and_temp_cleanup_failures() {
        let runtime = fixture("write-hooks");
        write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"a".repeat(64)}),
        )
        .unwrap();
        let parent = journal_directory(&runtime);
        FINAL_SYNC_HOOK
            .lock()
            .unwrap()
            .push((parent.clone(), Box::new(|| {})));
        let durability = write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"b".repeat(64)}),
        )
        .unwrap_err();
        assert!(durability.contains("injected private journal durability failure"));
        assert_eq!(
            read_activation_state(&runtime).unwrap().unwrap()["current_generation_id"],
            "b".repeat(64)
        );
        let hook_parent = parent.clone();
        BEFORE_RENAME_HOOK.lock().unwrap().push((
            parent.clone(),
            Box::new(move || {
                fs::set_permissions(&hook_parent, fs::Permissions::from_mode(0o500)).unwrap();
            }),
        ));
        let cleanup = write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"c".repeat(64)}),
        )
        .unwrap_err();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(cleanup.contains("temporary journal cleanup failed"));
        assert_eq!(
            read_activation_state(&runtime).unwrap().unwrap()["current_generation_id"],
            "b".repeat(64)
        );
        let leftovers = fs::read_dir(&parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".activation.json.tmp-")
            })
            .collect::<Vec<_>>();
        assert_eq!(leftovers.len(), 1);
        fs::remove_file(&leftovers[0]).unwrap();
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn write_rejects_replaced_temporary_entry_without_touching_prior_state() {
        let runtime = fixture("write-temp-replaced");
        write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"a".repeat(64)}),
        )
        .unwrap();
        let parent = journal_directory(&runtime);
        let hook_parent = parent.clone();
        BEFORE_RENAME_HOOK.lock().unwrap().push((
            parent.clone(),
            Box::new(move || {
                let temp = fs::read_dir(&hook_parent)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".activation.json.tmp-")
                    })
                    .unwrap();
                fs::remove_file(&temp).unwrap();
                fs::write(&temp, b"attacker replacement").unwrap();
                fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).unwrap();
            }),
        ));

        let error = write_activation_state(
            &runtime,
            json!({"status":"active","current_generation_id":"b".repeat(64)}),
        )
        .unwrap_err();

        assert!(
            error.contains("temporary file changed before replacement"),
            "{error}"
        );
        assert!(
            error.contains("temporary journal cleanup failed"),
            "{error}"
        );
        assert_eq!(
            read_activation_state(&runtime).unwrap().unwrap()["current_generation_id"],
            "a".repeat(64)
        );
        for entry in fs::read_dir(&parent).unwrap().flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".activation.json.tmp-")
            {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn oversized_candidate_fails_before_creating_journal_state() {
        let runtime = fixture("write-oversized");
        let error = write_activation_state(
            &runtime,
            json!({
                "status":"active",
                "current_generation_id":"a".repeat(64),
                "padding":"x".repeat(MAX_JOURNAL_BYTES as usize),
            }),
        )
        .unwrap_err();

        assert_eq!(error, "feed activation state exceeds size limit");
        assert_eq!(fs::read_dir(&runtime).unwrap().count(), 0);
        fs::remove_dir(runtime).unwrap();
    }
}
