// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process-level serialization for runtime lifecycle operations.

use super::common::{iso_system_time, runtime_dir};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

pub(crate) const FEED_ACTIVATION_LOCK: &str = "feed-generation-activation";
pub(crate) const DEFAULT_RUNTIME_LOCK_TIMEOUT: Duration = Duration::from_secs(1800);

#[derive(Debug)]
pub(crate) enum RuntimeLockError {
    Timeout {
        name: String,
        operation: String,
        holder: Value,
    },
    Setup(String),
}

fn validate_user_directory(path: &Path, label: &str) -> Result<(), RuntimeLockError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeLockError::Setup(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::getuid() } {
        return Err(RuntimeLockError::Setup(format!(
            "{label} is not a real, current-user-owned directory"
        )));
    }
    Ok(())
}

fn prepare_lock_directory(repo_root: &Path) -> Result<(), RuntimeLockError> {
    let runtime = runtime_dir(repo_root);
    fs::create_dir_all(&runtime).map_err(|error| {
        RuntimeLockError::Setup(format!("could not create runtime lock directory: {error}"))
    })?;
    validate_user_directory(&runtime, "runtime root")?;
    let run = runtime.join("run");
    let locks = run.join("locks");
    for (directory, label) in [
        (&run, "runtime run directory"),
        (&locks, "runtime lock directory"),
    ] {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(RuntimeLockError::Setup(format!(
                    "could not create {label}: {error}"
                )));
            }
        }
        validate_user_directory(directory, label)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|error| {
            RuntimeLockError::Setup(format!("could not secure {label}: {error}"))
        })?;
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct RuntimeOperationLock {
    lock: File,
    metadata_path: PathBuf,
    metadata_identity: (u64, u64),
}

fn safe_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut previous_dash = false;
    for character in name.chars() {
        let safe = character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-');
        if safe {
            output.push(character);
            previous_dash = false;
        } else if !previous_dash {
            output.push('-');
            previous_dash = true;
        }
    }
    let trimmed = output.trim_matches(['.', '-']);
    if trimmed.is_empty() {
        "runtime".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn runtime_lock_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("run/locks")
}

fn lock_paths(repo_root: &Path, name: &str) -> (PathBuf, PathBuf) {
    let directory = runtime_lock_dir(repo_root);
    let name = safe_name(name);
    (
        directory.join(format!("{name}.lock")),
        directory.join(format!("{name}.json")),
    )
}

fn read_holder(path: &Path) -> Value {
    let mut payload = String::new();
    let parsed = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|mut file| file.read_to_string(&mut payload))
        .ok()
        .and_then(|_| serde_json::from_str::<Value>(&payload).ok());
    parsed.filter(Value::is_object).unwrap_or_else(|| json!({}))
}

fn private_regular_file(file: &File, label: &str) -> Result<(u64, u64), RuntimeLockError> {
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeLockError::Setup(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.nlink() != 1
    {
        return Err(RuntimeLockError::Setup(format!(
            "{label} is not a regular, single-link, current-user-owned file"
        )));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| RuntimeLockError::Setup(format!("could not secure {label}: {error}")))?;
    Ok((metadata.dev(), metadata.ino()))
}

impl RuntimeOperationLock {
    pub(crate) fn acquire(
        repo_root: &Path,
        name: &str,
        operation: &str,
        timeout: Duration,
    ) -> Result<Self, RuntimeLockError> {
        let (lock_path, metadata_path) = lock_paths(repo_root, name);
        prepare_lock_directory(repo_root)?;
        let lock = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| {
                RuntimeLockError::Setup(format!("could not open runtime lock: {error}"))
            })?;
        private_regular_file(&lock, "runtime lock")?;

        let deadline = Instant::now() + timeout;
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(RuntimeLockError::Setup(format!(
                    "could not acquire runtime lock: {error}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(RuntimeLockError::Timeout {
                    name: name.to_string(),
                    operation: operation.to_string(),
                    holder: read_holder(&metadata_path),
                });
            }
            thread::sleep(
                Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }

        (|| {
            let mut metadata = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&metadata_path)
                .map_err(|error| {
                    RuntimeLockError::Setup(format!(
                        "could not open runtime lock metadata: {error}"
                    ))
                })?;
            let identity = private_regular_file(&metadata, "runtime lock metadata")?;
            let payload = serde_json::to_vec_pretty(&json!({
                "name": name,
                "operation": operation,
                "pid": std::process::id(),
                "started_at": iso_system_time(SystemTime::now())
                    .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_string()),
            }))
            .map_err(|error| {
                RuntimeLockError::Setup(format!("could not encode runtime lock metadata: {error}"))
            })?;
            metadata
                .seek(SeekFrom::Start(0))
                .and_then(|_| metadata.set_len(0))
                .and_then(|_| metadata.write_all(&payload))
                .and_then(|_| metadata.write_all(b"\n"))
                .and_then(|_| metadata.sync_data())
                .map_err(|error| {
                    RuntimeLockError::Setup(format!(
                        "could not write runtime lock metadata: {error}"
                    ))
                })?;
            Ok(Self {
                lock,
                metadata_path,
                metadata_identity: identity,
            })
        })()
    }
}

impl Drop for RuntimeOperationLock {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.metadata_path)
            && (metadata.dev(), metadata.ino()) == self.metadata_identity
        {
            let _ = fs::remove_file(&self.metadata_path);
        }
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "turbovas-runtime-lock-{name}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("TurboVAS");
        fs::create_dir_all(&repo).unwrap();
        repo
    }

    #[test]
    fn lock_metadata_reports_holder_and_is_removed_on_release() {
        let repo = fixture("holder");
        let lock = RuntimeOperationLock::acquire(
            &repo,
            FEED_ACTIVATION_LOCK,
            "feed-generation-stage",
            Duration::ZERO,
        )
        .unwrap();
        let (_, metadata_path) = lock_paths(&repo, FEED_ACTIVATION_LOCK);
        let metadata = read_holder(&metadata_path);
        assert_eq!(metadata["operation"], "feed-generation-stage");

        let timeout =
            RuntimeOperationLock::acquire(&repo, FEED_ACTIVATION_LOCK, "contender", Duration::ZERO)
                .unwrap_err();
        match timeout {
            RuntimeLockError::Timeout {
                name,
                operation,
                holder,
            } => {
                assert_eq!(name, FEED_ACTIVATION_LOCK);
                assert_eq!(operation, "contender");
                assert_eq!(holder["operation"], "feed-generation-stage");
            }
            RuntimeLockError::Setup(error) => panic!("unexpected setup error: {error}"),
        }
        drop(lock);
        assert!(!metadata_path.exists());
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn unsafe_lock_symlink_is_rejected() {
        let repo = fixture("symlink");
        let (lock_path, _) = lock_paths(&repo, FEED_ACTIVATION_LOCK);
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        let target = repo.parent().unwrap().join("target");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &lock_path).unwrap();
        assert!(matches!(
            RuntimeOperationLock::acquire(&repo, FEED_ACTIVATION_LOCK, "stage", Duration::ZERO,),
            Err(RuntimeLockError::Setup(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"target");
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn symlinked_intermediate_lock_directory_is_rejected() {
        let repo = fixture("intermediate-symlink");
        let runtime = runtime_dir(&repo);
        fs::create_dir_all(&runtime).unwrap();
        let target = repo.parent().unwrap().join("outside-run");
        fs::create_dir(&target).unwrap();
        symlink(&target, runtime.join("run")).unwrap();

        assert!(matches!(
            RuntimeOperationLock::acquire(&repo, FEED_ACTIVATION_LOCK, "stage", Duration::ZERO,),
            Err(RuntimeLockError::Setup(_))
        ));
        assert!(target.read_dir().unwrap().next().is_none());
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }
}
