// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Secure, mutating preparation for the persistent development runtime.
//!
//! Runtime inspection deliberately does not call this module.  Lifecycle
//! commands use it to create the directory layout without following
//! attacker-controlled links and to make the first gvmd state installation a
//! no-clobber transaction.

use super::common::runtime_dir;
use super::compose::{compose_command, runtime_environment};
use crate::process::CommandRunner;
use crate::result::Finding;
use serde_json::json;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const RUNTIME_DIRS: [&str; 45] = [
    "postgres",
    "mosquitto",
    "mosquitto/secrets",
    "feeds",
    "run",
    "logs",
    "artifacts",
    "certs/CA",
    "certs/private/CA",
    "secrets",
    "state",
    "state/gvmd-bind-files",
    "state/ospd",
    "state/ospd/result-spool",
    "state/feed-gnupg",
    "redis-openvas",
    "run/gvmd-gmp",
    "run/gvmd-control",
    "run/gvmd",
    "run/gsad",
    "run/ospd",
    "run/notus",
    "run/redis-openvas",
    "logs/gvmd",
    "logs/ospd",
    "logs/notus",
    "logs/gsad",
    "logs/yafvs-api",
    "logs/redis-openvas",
    "logs/feed-sync",
    "logs/quality-gate",
    "artifacts/log-review",
    "artifacts/data-state",
    "artifacts/quality-gate",
    "artifacts/performance",
    "artifacts/reports",
    "artifacts/credential-smoke",
    "artifacts/native-api",
    "feed-cache/community/22.04/var-lib",
    "feeds/openvas/plugins",
    "feeds/notus/advisories",
    "feeds/notus/products",
    "feeds/gvm/scap-data",
    "feeds/gvm/cert-data",
    "feeds/gvm/data-objects/gvmd/22.04",
];

const PRIVATE_RUNTIME_DIRS: [&str; 6] = [
    "mosquitto/secrets",
    "certs/private/CA",
    "secrets",
    "state/ospd",
    "state/ospd/result-spool",
    "state/feed-gnupg",
];
const BUILD_RUNTIME_DIRS: [&str; 4] = [
    "build/var/lib/gvm",
    "build/run/gvmd",
    "build/run/gsad",
    "build/logs",
];
const FEED_LOCKS: [&str; 2] = ["run/feed-update.lock", "run/ospd/feed-update.lock"];
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// Creates and probes the complete Python-compatible lifecycle layout.
pub(crate) fn ensure_runtime_setup(repo_root: &Path, runner: &dyn CommandRunner) -> Vec<Finding> {
    let root = runtime_dir(repo_root);
    let mut findings = Vec::new();
    let runtime_fd = match secure_runtime_root(repo_root, &root) {
        Ok(fd) => fd,
        Err(error) => {
            for relative in RUNTIME_DIRS {
                let path = root.join(relative);
                findings.push(runtime_directory_failure(&path, &error));
            }
            findings.push(seed_failure(&root.join("state/gvmd"), &error));
            for relative in FEED_LOCKS {
                findings.push(lock_failure(&root.join(relative), &error));
            }
            findings.extend(ensure_build_runtime_dirs(repo_root));
            return findings;
        }
    };

    for relative in RUNTIME_DIRS {
        let path = root.join(relative);
        let private = PRIVATE_RUNTIME_DIRS.contains(&relative);
        let result = ensure_relative_directory(&runtime_fd, relative, private).and_then(|fd| {
            probe_directory(&fd)?;
            Ok(())
        });
        findings.push(match result {
            Ok(()) => Finding::new(
                "pass",
                "runtime.dir",
                format!("Runtime directory is writable: {}", path.display()),
            )
            .with_path(&path.display().to_string()),
            Err(error) => runtime_directory_failure(&path, &error),
        });
    }

    findings.push(seed_gvmd_runtime_state(
        repo_root,
        &root,
        &runtime_fd,
        runner,
    ));
    for relative in FEED_LOCKS {
        let path = root.join(relative);
        findings.push(
            match open_or_create_regular_at(&runtime_fd, relative, 0o600) {
                Ok(file) => {
                    drop(file);
                    Finding::new(
                        "pass",
                        "runtime.feed-lock",
                        format!("Runtime feed lock file exists: {}", path.display()),
                    )
                    .with_path(&path.display().to_string())
                }
                Err(error) => lock_failure(&path, &error),
            },
        );
    }
    findings.extend(ensure_build_runtime_dirs(repo_root));
    findings
}

fn ensure_build_runtime_dirs(repo_root: &Path) -> Vec<Finding> {
    BUILD_RUNTIME_DIRS
        .iter()
        .map(|relative| {
            let path = repo_root.join(relative);
            let result = secure_existing_or_new_directory(&path, false).and_then(|fd| {
                probe_directory(&fd)?;
                Ok(())
            });
            match result {
                Ok(()) => Finding::new(
                    "pass",
                    "build-runtime.dir",
                    format!(
                        "Inherited build runtime directory is writable: {}",
                        path.display()
                    ),
                )
                .with_path(relative),
                Err(error) => Finding::new(
                    "fail",
                    "build-runtime.dir",
                    format!(
                        "Inherited build runtime directory is not writable: {}: {error}",
                        path.display()
                    ),
                )
                .with_path(&path.display().to_string()),
            }
        })
        .collect()
}

fn secure_runtime_root(repo_root: &Path, root: &Path) -> io::Result<OwnedFd> {
    let canonical_repo = repo_root.canonicalize()?;
    if root.starts_with(&canonical_repo) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory must be outside the repository",
        ));
    }
    let runtime = secure_existing_or_new_directory(root, false)?;
    let canonical_runtime = root.canonicalize()?;
    if canonical_runtime.starts_with(&canonical_repo) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory must be outside the repository",
        ));
    }
    Ok(runtime)
}

fn runtime_directory_failure(path: &Path, error: &io::Error) -> Finding {
    Finding::new(
        "fail",
        "runtime.dir",
        format!(
            "Runtime directory is not writable: {}: {error}",
            path.display()
        ),
    )
    .with_path(&path.display().to_string())
}

fn lock_failure(path: &Path, error: &io::Error) -> Finding {
    Finding::new(
        "fail",
        "runtime.feed-lock",
        format!(
            "Runtime feed lock file is not usable: {}: {error}",
            path.display()
        ),
    )
    .with_path(&path.display().to_string())
}

fn seed_failure(path: &Path, error: &io::Error) -> Finding {
    Finding::new(
        "fail",
        "runtime.gvmd-state-seed",
        format!("gvmd runtime state could not be prepared: {error}"),
    )
    .with_path(&path.display().to_string())
}

fn secure_existing_or_new_directory(path: &Path, private: bool) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime directory path must be absolute",
        ));
    }
    let root = CString::new("/").expect("static path");
    // SAFETY: root is a valid NUL-terminated absolute directory path.
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a unique owned descriptor.
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => current = open_child_directory(&current, name, 0o755)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime directory contains an unsafe path component",
                ));
            }
        }
    }
    if private {
        validate_private_directory(&current)?;
    }
    Ok(current)
}

fn ensure_relative_directory(root: &OwnedFd, relative: &str, private: bool) -> io::Result<OwnedFd> {
    let mut current = duplicate_fd(root)?;
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime directory contains an unsafe path component",
            ));
        };
        current = open_child_directory(&current, name, 0o755)?;
    }
    if private {
        validate_private_directory(&current)?;
    }
    Ok(current)
}

fn duplicate_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl duplicates the supplied open descriptor.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn open_child_directory(parent: &OwnedFd, name: &OsStr, mode: u32) -> io::Result<OwnedFd> {
    let name = cstring(name)?;
    if entry_stat(parent, &name).is_err_and(|error| error.kind() == io::ErrorKind::NotFound) {
        // SAFETY: mkdirat is constrained to the held parent and static mode.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
    }
    open_existing_child_directory_cstr(parent, &name)
}

fn open_existing_child_directory(parent: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    let name = cstring(name)?;
    open_existing_child_directory_cstr(parent, &name)
}

fn open_existing_child_directory_cstr(parent: &OwnedFd, name: &CString) -> io::Result<OwnedFd> {
    let before = entry_stat(parent, name)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path is not a real directory",
        ));
    }
    // SAFETY: parent and name are valid; O_NOFOLLOW rejects links atomically.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let directory = unsafe { OwnedFd::from_raw_fd(raw) };
    let after = descriptor_stat(&directory)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || after.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(io::Error::other("runtime directory changed while opening"));
    }
    Ok(directory)
}

fn entry_stat(parent: &OwnedFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent/name/stat are valid and AT_SYMLINK_NOFOLLOW observes the entry itself.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized stat.
    Ok(unsafe { stat.assume_init() })
}

fn validate_private_directory(directory: &OwnedFd) -> io::Result<()> {
    // SAFETY: fchmod applies only to the held directory descriptor.
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = descriptor_stat(directory)?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != euid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private directory is not current-user-owned and owner-private",
        ));
    }
    Ok(())
}

fn descriptor_stat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to valid writable storage and fd is open.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized all fields.
    Ok(unsafe { stat.assume_init() })
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn probe_directory(directory: &OwnedFd) -> io::Result<()> {
    for sequence in 0..100_u64 {
        let name = CString::new(format!(
            ".yafvs-write-test-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed) + sequence
        ))
        .expect("generated name has no NUL");
        // SAFETY: exact name is relative to the held directory and O_EXCL avoids replacement.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: openat returned a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(raw) };
        let result = (|| {
            file.write_all(b"ok\n")?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);
        // SAFETY: unlinkat is confined to the held directory and exact temporary name.
        let unlink_result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if unlink_result != 0 && result.is_ok() {
            return Err(io::Error::last_os_error());
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique runtime write probe",
    ))
}

fn open_or_create_regular_at(parent: &OwnedFd, relative: &str, mode: u32) -> io::Result<File> {
    let path = Path::new(relative);
    let parent_relative = path.parent().unwrap_or_else(|| Path::new(""));
    let mut directory = duplicate_fd(parent)?;
    for component in parent_relative.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        directory = open_child_directory(&directory, name, 0o755)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing runtime file name"))?;
    let name = cstring(name)?;
    // SAFETY: exact name is relative to a verified parent; O_NOFOLLOW rejects links.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(raw) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file() || metadata.uid() != euid || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime file is not a current-user-owned single-link regular file",
        ));
    }
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    // SAFETY: fsync is constrained to the held parent descriptor.
    if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn seed_gvmd_runtime_state(
    repo_root: &Path,
    root: &Path,
    runtime_fd: &OwnedFd,
    runner: &dyn CommandRunner,
) -> Finding {
    let destination = root.join("state/gvmd");
    let result = (|| {
        let state = ensure_relative_directory(runtime_fd, "state", true)?;
        let bind_parent = ensure_relative_directory(runtime_fd, "state/gvmd-bind-files", true)?;
        let semaphore = open_or_create_regular_at(&bind_parent, "gvmd.sem", 0o600)?;
        drop(semaphore);

        match directory_entry_kind(&state, "gvmd")? {
            Some(EntryKind::Directory) => {
                return Ok(SeedOutcome::Existing);
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gvmd runtime-state destination is a symlink or special file",
                ));
            }
            None => {}
        }

        let source = repo_root.join("build/var/lib/gvm/gvmd");
        if !source.exists() {
            return Ok(SeedOutcome::Unavailable);
        }
        let source_fd = secure_existing_directory(&source)?;
        if container_running(repo_root, "gvmd", runner) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "gvmd must be stopped before initial runtime-state seeding",
            ));
        }

        let temporary = format!(
            ".gvmd-seed-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        );
        let temporary_name = CString::new(temporary.as_bytes()).expect("generated name has no NUL");
        // SAFETY: mkdirat is confined to the verified private state directory.
        if unsafe { libc::mkdirat(state.as_raw_fd(), temporary_name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let temporary_path = root.join("state").join(&temporary);
        let temporary_fd = open_existing_child_directory(&state, OsStr::new(temporary.as_str()))?;
        let copied = copy_gvmd_state_tree(&source_fd, &temporary_fd, Path::new(""));
        let copied = match copied {
            Ok(copied) => copied,
            Err(error) => {
                let _ = fs::remove_dir_all(&temporary_path);
                return Err(error);
            }
        };
        // SAFETY: fsync is constrained to the held private temporary directory.
        if unsafe { libc::fsync(temporary_fd.as_raw_fd()) } != 0 {
            let error = io::Error::last_os_error();
            let _ = fs::remove_dir_all(&temporary_path);
            return Err(error);
        }
        let destination_name = CString::new("gvmd").expect("static name");
        // SAFETY: both names are held entries under the same verified state directory;
        // RENAME_NOREPLACE gives the seed its atomic no-clobber boundary.
        let renamed = unsafe {
            libc::renameat2(
                state.as_raw_fd(),
                temporary_name.as_ptr(),
                state.as_raw_fd(),
                destination_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                let _ = fs::remove_dir_all(&temporary_path);
                return match directory_entry_kind(&state, "gvmd")? {
                    Some(EntryKind::Directory) => Ok(SeedOutcome::Existing),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "concurrent gvmd runtime-state destination is unsafe",
                    )),
                };
            }
            let _ = fs::remove_dir_all(&temporary_path);
            return Err(error);
        }
        // SAFETY: fsync is constrained to the held private state directory.
        if unsafe { libc::fsync(state.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SeedOutcome::Installed {
            copied: copied.0,
            skipped: copied.1,
            semaphore: root.join("state/gvmd-bind-files/gvmd.sem"),
        })
    })();

    match result {
        Ok(SeedOutcome::Existing) => Finding::new(
            "pass",
            "runtime.gvmd-state-seed",
            "Existing gvmd runtime state was left unchanged.".to_string(),
        )
        .with_path(&destination.display().to_string()),
        Ok(SeedOutcome::Unavailable) => Finding::new(
            "pass",
            "runtime.gvmd-state-seed",
            "Built gvmd state is not available yet; no runtime-state seed was needed.".to_string(),
        )
        .with_path(&destination.display().to_string()),
        Ok(SeedOutcome::Installed {
            copied,
            skipped,
            semaphore,
        }) => Finding::new(
            "pass",
            "runtime.gvmd-state-seed",
            "gvmd persistent state was installed atomically outside the build tree.".to_string(),
        )
        .with_path(&destination.display().to_string())
        .with_details(json!({
            "copied": copied,
            "skipped_transient": skipped,
            "semaphore_bind_file": semaphore.display().to_string(),
        })),
        Err(error) => seed_failure(&destination, &error),
    }
}

enum SeedOutcome {
    Existing,
    Unavailable,
    Installed {
        copied: Vec<String>,
        skipped: Vec<String>,
        semaphore: PathBuf,
    },
}

enum EntryKind {
    Directory,
    Other,
}

fn directory_entry_kind(parent: &OwnedFd, name: &str) -> io::Result<Option<EntryKind>> {
    let name = CString::new(name).expect("static name");
    let stat = match entry_stat(parent, &name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
        Ok(Some(EntryKind::Directory))
    } else {
        Ok(Some(EntryKind::Other))
    }
}

fn secure_existing_directory(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source path must be absolute",
        ));
    }
    let root = CString::new("/").expect("static path");
    // SAFETY: root is a valid absolute directory path.
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned an owned descriptor.
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = cstring(name)?;
                // SAFETY: O_NOFOLLOW makes every source path component a real directory.
                let raw = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: openat returned an owned descriptor.
                current = unsafe { OwnedFd::from_raw_fd(raw) };
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "source path contains an unsafe component",
                ));
            }
        }
    }
    Ok(current)
}

fn copy_gvmd_state_tree(
    source: &OwnedFd,
    destination: &OwnedFd,
    relative: &Path,
) -> io::Result<(Vec<String>, Vec<String>)> {
    let mut copied = Vec::new();
    let mut skipped = Vec::new();
    copy_gvmd_state_tree_at(source, destination, relative, &mut copied, &mut skipped)?;
    Ok((copied, skipped))
}

fn copy_gvmd_state_tree_at(
    source: &OwnedFd,
    destination: &OwnedFd,
    relative: &Path,
    copied: &mut Vec<String>,
    skipped: &mut Vec<String>,
) -> io::Result<()> {
    for name in directory_names(source)? {
        let entry_relative = relative.join(&name);
        let display = entry_relative.display().to_string();
        let name_c = cstring(&name)?;
        let metadata = entry_stat(source, &name_c)?;
        let kind = metadata.st_mode & libc::S_IFMT;
        if kind != libc::S_IFREG && kind != libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("gvmd seed source contains a symlink or special file: {display}"),
            ));
        }
        if kind == libc::S_IFREG
            && (name.as_bytes().starts_with(b"gvm-")
                || name.as_bytes().starts_with(b"yafvs-task-control-"))
        {
            skipped.push(display);
            continue;
        }
        let mode = metadata.st_mode & 0o7777;
        if kind == libc::S_IFREG {
            copy_regular_file_at(source, destination, &name, mode)?;
            copied.push(display);
        } else {
            // SAFETY: destination/name are verified and the target is a private new tree.
            if unsafe {
                libc::mkdirat(
                    destination.as_raw_fd(),
                    name_c.as_ptr(),
                    if mode == 0 { 0o700 } else { mode },
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let source_child = open_existing_child_directory(source, &name)?;
            let destination_child = open_existing_child_directory(destination, &name)?;
            copy_gvmd_state_tree_at(
                &source_child,
                &destination_child,
                &entry_relative,
                copied,
                skipped,
            )?;
            // SAFETY: fsync is constrained to the held destination child directory.
            if unsafe { libc::fsync(destination_child.as_raw_fd()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn directory_names(directory: &OwnedFd) -> io::Result<Vec<OsString>> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

fn copy_regular_file_at(
    source: &OwnedFd,
    destination: &OwnedFd,
    name: &OsStr,
    mode: u32,
) -> io::Result<()> {
    let name = cstring(name)?;
    let before = entry_stat(source, &name)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gvmd seed source file is not regular",
        ));
    }
    // SAFETY: source/name are verified and O_NOFOLLOW rejects replacement links.
    let input_raw = unsafe {
        libc::openat(
            source.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if input_raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut input = unsafe { File::from_raw_fd(input_raw) };
    let opened = input.metadata()?;
    if before.st_dev != opened.dev()
        || before.st_ino != opened.ino()
        || !opened.file_type().is_file()
    {
        return Err(io::Error::other(
            "gvmd seed source file changed while opening",
        ));
    }
    // SAFETY: destination/name are verified and O_EXCL/O_NOFOLLOW prevent replacement.
    let output_raw = unsafe {
        libc::openat(
            destination.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            if mode == 0 { 0o600 } else { mode },
        )
    };
    if output_raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut output = unsafe { File::from_raw_fd(output_raw) };
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    let after = input.metadata()?;
    if opened.dev() != after.dev() || opened.ino() != after.ino() || !after.file_type().is_file() {
        return Err(io::Error::other(
            "gvmd seed source file changed while copying",
        ));
    }
    Ok(())
}

fn container_running(repo_root: &Path, service: &str, runner: &dyn CommandRunner) -> bool {
    let arguments = compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]);
    let args = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(identifier) = runner
        .run_with(
            "docker",
            &args,
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            None,
        )
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
        })
    else {
        return false;
    };
    if identifier.len() < 12
        || identifier.len() > 64
        || !identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &identifier],
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            None,
        )
        .is_some_and(|output| output.success && output.stdout.trim() == "true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Mutex;

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }
    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-runtime-setup-{name}-{}-{}",
                std::process::id(),
                NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
            ));
            let repo = root.join("YAFVS");
            fs::create_dir_all(&repo).unwrap();
            Self { root, repo }
        }
        fn runtime(&self) -> PathBuf {
            self.root.join("YAFVS-runtime")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct Runner {
        responses: Mutex<Vec<ProcessOutput>>,
    }
    impl Runner {
        fn new(responses: Vec<ProcessOutput>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }
    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }
        fn run_with(
            &self,
            program: &str,
            _: &[&str],
            _: Option<&Path>,
            _: Option<&std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            if program != "docker" {
                return self.run(program, &[]);
            }
            self.responses.lock().unwrap().pop()
        }
    }
    fn success(text: &str) -> ProcessOutput {
        ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: text.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn creates_exact_layout_private_directories_and_locks() {
        let fixture = Fixture::new("layout");
        let findings = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));
        assert!(findings.iter().all(|finding| finding.status == "pass"));
        for relative in RUNTIME_DIRS {
            assert!(fixture.runtime().join(relative).is_dir());
        }
        for relative in PRIVATE_RUNTIME_DIRS {
            let metadata = fs::metadata(fixture.runtime().join(relative)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        }
        for relative in FEED_LOCKS {
            assert!(fixture.runtime().join(relative).is_file());
        }
        assert!(
            fixture
                .runtime()
                .join("state/gvmd-bind-files/gvmd.sem")
                .is_file()
        );
    }

    #[test]
    fn private_runtime_symlink_is_rejected_without_traversal() {
        let fixture = Fixture::new("private-link");
        let runtime = fixture.runtime();
        fs::create_dir_all(&runtime).unwrap();
        let victim = fixture.root.join("victim");
        fs::create_dir(&victim).unwrap();
        symlink(&victim, runtime.join("secrets")).unwrap();
        let findings = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));
        assert!(findings.iter().any(|finding| finding.path.as_deref()
            == Some(&runtime.join("secrets").display().to_string())
            && finding.status == "fail"));
        assert!(victim.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn feed_lock_hardlink_is_rejected_without_touching_the_other_name() {
        let fixture = Fixture::new("feed-lock-hardlink");
        let run = fixture.runtime().join("run");
        fs::create_dir_all(&run).unwrap();
        let victim = fixture.root.join("victim");
        fs::write(&victim, "unchanged\n").unwrap();
        fs::hard_link(&victim, run.join("feed-update.lock")).unwrap();

        let findings = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));

        assert!(findings.iter().any(|finding| {
            finding.path.as_deref()
                == Some(
                    &fixture
                        .runtime()
                        .join("run/feed-update.lock")
                        .display()
                        .to_string(),
                )
                && finding.status == "fail"
        }));
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged\n");
    }

    #[test]
    fn rejects_repository_nested_runtime() {
        let fixture = Fixture::new("nested");
        let error = secure_runtime_root(&fixture.repo, &fixture.repo.join("runtime")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!fixture.repo.join("runtime").exists());
    }

    #[test]
    fn gvmd_seed_copies_persistent_data_and_skips_transient_files_atomically() {
        let fixture = Fixture::new("seed");
        let source = fixture.repo.join("build/var/lib/gvm/gvmd/nested");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("persistent"), "kept").unwrap();
        fs::write(source.join("gvm-lock"), "skip").unwrap();
        fs::write(source.join("yafvs-task-control-1"), "skip").unwrap();
        let findings = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![success("")]));
        let seed = findings
            .iter()
            .find(|finding| finding.check == "runtime.gvmd-state-seed")
            .unwrap();
        assert_eq!(seed.status, "pass");
        assert!(
            fixture
                .runtime()
                .join("state/gvmd/nested/persistent")
                .is_file()
        );
        assert!(
            !fixture
                .runtime()
                .join("state/gvmd/nested/gvm-lock")
                .exists()
        );
        assert!(
            !fixture
                .runtime()
                .join("state/gvmd/nested/yafvs-task-control-1")
                .exists()
        );
        assert!(
            seed.details.as_ref().unwrap()["skipped_transient"]
                .as_array()
                .unwrap()
                .len()
                == 2
        );
    }

    #[test]
    fn gvmd_seed_rejects_a_link_in_the_source_tree() {
        let fixture = Fixture::new("seed-source-link");
        let source = fixture.repo.join("build/var/lib/gvm/gvmd");
        fs::create_dir_all(&source).unwrap();
        let victim = fixture.root.join("victim");
        fs::write(&victim, "outside\n").unwrap();
        symlink(&victim, source.join("linked")).unwrap();

        let findings = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));
        let seed = findings
            .iter()
            .find(|finding| finding.check == "runtime.gvmd-state-seed")
            .unwrap();

        assert_eq!(seed.status, "fail");
        assert!(seed.message.contains("symlink or special file"));
        assert!(!fixture.runtime().join("state/gvmd").exists());
        assert_eq!(fs::read_to_string(victim).unwrap(), "outside\n");
    }

    #[test]
    fn gvmd_seed_noops_for_existing_destination_and_refuses_unsafe_destination() {
        let fixture = Fixture::new("seed-existing");
        let runtime = fixture.runtime();
        fs::create_dir_all(runtime.join("state/gvmd")).unwrap();
        fs::write(runtime.join("state/gvmd/keep"), "unchanged").unwrap();
        let existing = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));
        assert_eq!(
            existing
                .iter()
                .find(|finding| finding.check == "runtime.gvmd-state-seed")
                .unwrap()
                .status,
            "pass"
        );
        assert_eq!(
            fs::read_to_string(runtime.join("state/gvmd/keep")).unwrap(),
            "unchanged"
        );
        fs::remove_dir_all(runtime.join("state/gvmd")).unwrap();
        fs::write(runtime.join("state/gvmd"), "unsafe").unwrap();
        let unsafe_destination = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));
        assert_eq!(
            unsafe_destination
                .iter()
                .find(|finding| finding.check == "runtime.gvmd-state-seed")
                .unwrap()
                .status,
            "fail"
        );
    }

    #[test]
    fn gvmd_seed_refuses_when_gvmd_is_running() {
        let fixture = Fixture::new("seed-running");
        fs::create_dir_all(fixture.repo.join("build/var/lib/gvm/gvmd")).unwrap();
        let findings = ensure_runtime_setup(
            &fixture.repo,
            &Runner::new(vec![
                success("true\n"),
                success(&format!("{}\n", "a".repeat(64))),
            ]),
        );
        let seed = findings
            .iter()
            .find(|finding| finding.check == "runtime.gvmd-state-seed")
            .unwrap();
        assert_eq!(seed.status, "fail");
        assert!(seed.message.contains("must be stopped"));
        assert!(!fixture.runtime().join("state/gvmd").exists());
    }
}
