// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fail-closed, atomic migration of the local runtime directory identity.

use super::common::metadata;
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

const MAX_ENTRIES: u64 = 1_000_000;
const COMPOSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ready,
    AlreadyMigrated,
    Ambiguous,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    device: u64,
    inode: u64,
    files: u64,
    directories: u64,
    symlinks: u64,
    bytes: u64,
}

impl Snapshot {
    fn details(&self) -> serde_json::Value {
        json!({
            "device": self.device,
            "inode": self.inode,
            "files": self.files,
            "directories": self.directories,
            "symlinks": self.symlinks,
            "regular_file_bytes": self.bytes,
        })
    }
}

pub fn command_runtime_identity_migrate(repo_root: &Path, apply: bool) -> ResultEnvelope {
    command_with(repo_root, apply, &SystemCommandRunner, &NoopHook)
}

fn command_with(
    repo_root: &Path,
    apply: bool,
    runner: &dyn CommandRunner,
    hook: &dyn PostRenameHook,
) -> ResultEnvelope {
    let parent = match repo_root.parent() {
        Some(parent) => parent,
        None => {
            return failure(
                repo_root,
                "runtime-identity-migrate",
                "repository root has no parent",
            );
        }
    };
    let old = parent.join("TurboVAS-runtime");
    let new = parent.join("YAFVS-runtime");
    let state = match roots_state(&old, &new) {
        Ok(state) => state,
        Err(error) => return failure_paths(repo_root, &old, &new, error),
    };
    match state {
        State::Missing => {
            return result(
                repo_root,
                "warn",
                "neither runtime directory exists; no action",
                &old,
                &new,
                None,
            );
        }
        State::AlreadyMigrated => {
            return result(
                repo_root,
                "pass",
                "runtime identity is already migrated",
                &old,
                &new,
                None,
            );
        }
        State::Ambiguous => {
            return failure_paths(
                repo_root,
                &old,
                &new,
                "both runtime directories exist; refusing ambiguous migration",
            );
        }
        State::Ready => {}
    }
    let before = match snapshot(&old) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return failure_paths(
                repo_root,
                &old,
                &new,
                format!("source snapshot failed: {error}"),
            );
        }
    };
    if let Err(error) = inspect_locks(&old) {
        return failure_paths(
            repo_root,
            &old,
            &new,
            format!("runtime lock inspection failed: {error}"),
        );
    }
    if !apply {
        return result(
            repo_root,
            "pass",
            "runtime identity migration planned; pass --apply to rename",
            &old,
            &new,
            Some(before),
        );
    }
    if let Err(error) = ensure_compose_stopped(repo_root, runner) {
        return failure_paths(
            repo_root,
            &old,
            &new,
            format!("Docker Compose safety check failed: {error}"),
        );
    }
    if let Err(error) = fs::rename(&old, &new) {
        return failure_paths(
            repo_root,
            &old,
            &new,
            format!("atomic rename failed: {error}"),
        );
    }
    let verification = (|| -> Result<(), String> {
        fsync_parent(parent).map_err(|error| format!("parent fsync failed: {error}"))?;
        hook.after_rename(&new)?;
        if fs::symlink_metadata(&old).is_ok() {
            return Err("old runtime directory remains after rename".to_string());
        }
        let after =
            snapshot(&new).map_err(|error| format!("destination snapshot failed: {error}"))?;
        if after.device != before.device || after.inode != before.inode {
            return Err("destination device/inode differs from source".to_string());
        }
        if after != before {
            return Err("destination snapshot differs from source".to_string());
        }
        Ok(())
    })();
    if let Err(error) = verification {
        let rollback = rollback(&old, &new);
        return failure_paths(
            repo_root,
            &old,
            &new,
            format!("post-rename verification failed: {error}; rollback {rollback}"),
        );
    }
    result(
        repo_root,
        "pass",
        "runtime identity migrated atomically",
        &old,
        &new,
        Some(before),
    )
}

fn roots_state(old: &Path, new: &Path) -> Result<State, String> {
    let old_exists = root_is_valid(old)?;
    let new_exists = root_is_valid(new)?;
    Ok(match (old_exists, new_exists) {
        (true, false) => State::Ready,
        (false, true) => State::AlreadyMigrated,
        (true, true) => State::Ambiguous,
        (false, false) => State::Missing,
    })
}

fn root_is_valid(path: &Path) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{} must be a real directory, never a symlink",
            path.display()
        ));
    }
    // SAFETY: getuid has no preconditions and does not dereference memory.
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err(format!(
            "{} is not owned by the current user",
            path.display()
        ));
    }
    Ok(true)
}

fn snapshot(root: &Path) -> Result<Snapshot, String> {
    let root_meta = fs::symlink_metadata(root).map_err(|error| error.to_string())?;
    // SAFETY: getuid has no preconditions and does not dereference memory.
    if root_meta.file_type().is_symlink()
        || !root_meta.is_dir()
        || root_meta.uid() != unsafe { libc::getuid() }
    {
        return Err(format!(
            "{} must remain a current-user-owned real directory",
            root.display()
        ));
    }
    let mut snapshot = Snapshot {
        device: root_meta.dev(),
        inode: root_meta.ino(),
        files: 0,
        directories: 1,
        symlinks: 0,
        bytes: 0,
    };
    snapshot_walk(root, &mut snapshot)?;
    Ok(snapshot)
}

fn snapshot_walk(directory: &Path, snapshot: &mut Snapshot) -> Result<(), String> {
    for entry in
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            increment(&mut snapshot.symlinks)?;
        } else if metadata.is_dir() {
            increment(&mut snapshot.directories)?;
            snapshot_walk(&path, snapshot)?;
        } else if metadata.is_file() {
            increment(&mut snapshot.files)?;
            snapshot.bytes = snapshot
                .bytes
                .checked_add(metadata.len())
                .ok_or("regular-file byte count overflow")?;
        } else {
            return Err(format!("{} has unsupported file type", path.display()));
        }
    }
    Ok(())
}

fn increment(value: &mut u64) -> Result<(), String> {
    *value = value.checked_add(1).ok_or("entry count overflow")?;
    if *value > MAX_ENTRIES {
        return Err(format!(
            "entry count exceeds bounded limit of {MAX_ENTRIES}"
        ));
    }
    Ok(())
}

fn inspect_locks(root: &Path) -> Result<(), String> {
    let locks = root.join("run/locks");
    let entries = match fs::read_dir(&locks) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", locks.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "lock")
        {
            inspect_lock(&path)?;
        }
    }
    Ok(())
}

fn inspect_lock(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    // SAFETY: getuid has no preconditions and does not dereference memory.
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.nlink() != 1
    {
        return Err(format!(
            "{} is malformed (must be current-user-owned, regular, and singly linked)",
            path.display()
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if !opened.is_file()
        || opened.uid() != metadata.uid()
        || opened.nlink() != 1
        || opened.ino() != metadata.ino()
        || opened.dev() != metadata.dev()
    {
        return Err(format!("{} changed during lock inspection", path.display()));
    }
    // SAFETY: flock receives a valid file descriptor and constant operation bits.
    let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if status != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(format!("{} is active", path.display()));
        }
        return Err(format!("{} flock check failed: {error}", path.display()));
    }
    // SAFETY: see flock call above; unlock is best effort before closing the file.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
        return Err(format!(
            "{} could not be unlocked: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn ensure_compose_stopped(repo_root: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    let command = compose_command(repo_root, &["ps".into(), "-q".into()]);
    let arguments: Vec<&str> = command.iter().map(String::as_str).collect();
    let output = runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(COMPOSE_TIMEOUT),
        )
        .ok_or("could not start bounded docker compose ps -q check")?;
    if !output.success {
        return Err("bounded docker compose ps -q check did not complete successfully".to_string());
    }
    if !output.stdout.trim().is_empty() {
        return Err("one or more Compose containers are running".to_string());
    }
    Ok(())
}

fn fsync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

fn rollback(old: &Path, new: &Path) -> String {
    match (fs::symlink_metadata(old), fs::symlink_metadata(new)) {
        (Err(error), Ok(metadata))
            if error.kind() == io::ErrorKind::NotFound
                && metadata.is_dir()
                && !metadata.file_type().is_symlink() =>
        {
            match fs::rename(new, old) {
                Ok(()) => "succeeded".to_string(),
                Err(error) => format!("failed: {error}"),
            }
        }
        _ => "not attempted because paths were ambiguous".to_string(),
    }
}

trait PostRenameHook {
    fn after_rename(&self, new: &Path) -> Result<(), String>;
}
struct NoopHook;
impl PostRenameHook for NoopHook {
    fn after_rename(&self, _: &Path) -> Result<(), String> {
        Ok(())
    }
}

fn result(
    repo_root: &Path,
    status: &str,
    summary: &str,
    old: &Path,
    new: &Path,
    snapshot: Option<Snapshot>,
) -> ResultEnvelope {
    let finding = Finding::new(status, "runtime_identity_migrate", summary.to_string())
        .with_details(json!({
            "source_path": old, "destination_path": new,
            "snapshot": snapshot.map(|snapshot| snapshot.details()),
        }));
    make_result(
        metadata(repo_root, "runtime-identity-migrate", &SystemCommandRunner),
        summary.to_string(),
        vec![finding],
    )
}

fn failure(repo_root: &Path, command: &str, message: &str) -> ResultEnvelope {
    make_result(
        metadata(repo_root, command, &SystemCommandRunner),
        message.to_string(),
        vec![Finding::new("fail", command, message.to_string())],
    )
}

fn failure_paths(
    repo_root: &Path,
    old: &Path,
    new: &Path,
    message: impl Into<String>,
) -> ResultEnvelope {
    result(repo_root, "fail", &message.into(), old, new, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    struct FakeRunner {
        output: Option<ProcessOutput>,
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, _: &str, _: &[&str]) -> Option<ProcessOutput> {
            self.output.clone()
        }
    }
    fn runner(success: bool, stdout: &str) -> FakeRunner {
        FakeRunner {
            output: Some(ProcessOutput {
                success,
                exit_code: Some(if success { 0 } else { 1 }),
                stdout: stdout.into(),
                stderr: String::new(),
            }),
        }
    }
    fn fixture() -> (PathBuf, PathBuf, PathBuf) {
        let parent = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-identity-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = parent.join("TurboVAS");
        let old = parent.join("TurboVAS-runtime");
        fs::create_dir_all(repo.join("compose")).unwrap();
        fs::create_dir_all(old.join("run/locks")).unwrap();
        fs::write(old.join("data"), b"data").unwrap();
        (parent, repo, old)
    }
    fn cleanup(parent: PathBuf) {
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn parses_and_names_command() {
        assert_eq!(
            crate::parse_cli(["runtime-identity-migrate", "--apply"])
                .unwrap()
                .command
                .name(),
            "runtime-identity-migrate"
        );
    }
    #[test]
    fn dry_run_is_read_only() {
        let (parent, repo, old) = fixture();
        let result = command_with(&repo, false, &runner(true, ""), &NoopHook);
        assert_eq!(result.status, "pass");
        assert!(old.exists());
        assert!(!parent.join("YAFVS-runtime").exists());
        cleanup(parent);
    }
    #[test]
    fn missing_warns_and_already_migrated_passes() {
        let (parent, repo, old) = fixture();
        fs::remove_dir_all(&old).unwrap();
        assert_eq!(
            command_with(&repo, false, &runner(true, ""), &NoopHook).status,
            "warn"
        );
        fs::create_dir(parent.join("YAFVS-runtime")).unwrap();
        assert_eq!(
            command_with(&repo, false, &runner(true, ""), &NoopHook).status,
            "pass"
        );
        cleanup(parent);
    }
    #[test]
    fn both_and_symlink_are_refused() {
        let (parent, repo, old) = fixture();
        fs::create_dir(parent.join("YAFVS-runtime")).unwrap();
        assert_eq!(
            command_with(&repo, false, &runner(true, ""), &NoopHook).status,
            "fail"
        );
        fs::remove_dir_all(parent.join("YAFVS-runtime")).unwrap();
        fs::remove_dir_all(&old).unwrap();
        std::os::unix::fs::symlink("elsewhere", &old).unwrap();
        assert_eq!(
            command_with(&repo, false, &runner(true, ""), &NoopHook).status,
            "fail"
        );
        cleanup(parent);
    }
    #[test]
    fn docker_and_lock_refusals() {
        let (parent, repo, old) = fixture();
        assert_eq!(
            command_with(&repo, true, &runner(true, "container"), &NoopHook).status,
            "fail"
        );
        assert_eq!(
            command_with(&repo, true, &runner(false, ""), &NoopHook).status,
            "fail"
        );
        fs::write(old.join("run/locks/a.lock"), b"").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(old.join("run/locks/a.lock"))
            .unwrap();
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(
            command_with(&repo, false, &runner(true, ""), &NoopHook).status,
            "fail"
        );
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        fs::remove_file(old.join("run/locks/a.lock")).unwrap();
        std::os::unix::fs::symlink("x", old.join("run/locks/b.lock")).unwrap();
        assert_eq!(
            command_with(&repo, false, &runner(true, ""), &NoopHook).status,
            "fail"
        );
        cleanup(parent);
    }
    #[test]
    fn apply_preserves_identity_and_snapshot() {
        let (parent, repo, old) = fixture();
        let before = snapshot(&old).unwrap();
        let result = command_with(&repo, true, &runner(true, ""), &NoopHook);
        let new = parent.join("YAFVS-runtime");
        assert_eq!(result.status, "pass");
        assert!(!old.exists());
        assert_eq!(snapshot(&new).unwrap(), before);
        cleanup(parent);
    }
    struct CorruptHook;
    impl PostRenameHook for CorruptHook {
        fn after_rename(&self, new: &Path) -> Result<(), String> {
            fs::write(new.join("extra"), b"x").map_err(|error| error.to_string())
        }
    }
    #[test]
    fn verification_failure_rolls_back_when_unambiguous() {
        let (parent, repo, old) = fixture();
        let result = command_with(&repo, true, &runner(true, ""), &CorruptHook);
        assert_eq!(result.status, "fail");
        assert!(old.exists());
        assert!(!parent.join("YAFVS-runtime").exists());
        cleanup(parent);
    }
}
