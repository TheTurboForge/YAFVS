// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

pub(crate) fn write_secure_json_artifact<T: Serialize>(
    path: &Path,
    payload: &T,
) -> Result<(), String> {
    let text = serde_json::to_string_pretty(payload)
        .map(|text| format!("{text}\n"))
        .map_err(|error| error.to_string())?;
    write_secure_artifact(path, text.as_bytes())
}

pub(crate) fn write_secure_artifact(path: &Path, contents: &[u8]) -> Result<(), String> {
    let (parent, target_name) = open_artifact_parent(path)?;
    validate_secure_artifact_target(&parent, &target_name)?;
    write_atomic(&parent, &target_name, contents)
}

pub(crate) fn prepare_secure_artifact_parent(path: &Path) -> Result<(), String> {
    let (parent, target_name) = open_artifact_parent(path)?;
    validate_secure_artifact_target(&parent, &target_name)
}

fn open_artifact_parent(path: &Path) -> Result<(OwnedFd, CString), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("artifact working directory is unavailable: {error}"))?
            .join(path)
    };
    let mut parts = Vec::<OsString>::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => parts.clear(),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(part) => parts.push(part.to_os_string()),
            Component::Prefix(_) => return Err("artifact path prefix is unsupported".into()),
        }
    }
    let target = parts
        .pop()
        .ok_or_else(|| "artifact has no file name".to_string())?;
    let target_name = CString::new(target.as_bytes())
        .map_err(|_| "artifact name contains an invalid byte".to_string())?;
    let root_name = CString::new("/").expect("static root path");
    // SAFETY: root_name is a valid C string; the returned descriptor is owned
    // on success and O_NOFOLLOW prevents substitution of a final symlink.
    let root = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(format!(
            "artifact filesystem root could not be opened safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: open returned a new owned descriptor.
    let mut parent = unsafe { OwnedFd::from_raw_fd(root) };
    for part in parts {
        parent = open_or_create_directory(&parent, &part)?;
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is open and stat points to writable storage.
    if unsafe { libc::fstat(parent.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "artifact directory identity could not be read: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful fstat initialized stat.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != unsafe { libc::getuid() }
        || stat.st_mode & 0o022 != 0
    {
        return Err(
            "artifact directory is not a private, real, current-user-owned directory".into(),
        );
    }
    Ok((parent, target_name))
}

fn open_or_create_directory(parent: &OwnedFd, name: &OsString) -> Result<OwnedFd, String> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| "artifact directory name contains an invalid byte".to_string())?;
    let open = || {
        // SAFETY: parent is an open directory descriptor and name is a valid C
        // string. O_NOFOLLOW rejects a symlink in every traversed component.
        unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }
    };
    let mut descriptor = open();
    if descriptor < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        // SAFETY: mkdirat is constrained to the held parent descriptor and
        // creates only this exact child component.
        let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(format!(
                "artifact directory could not be created safely: {}",
                std::io::Error::last_os_error()
            ));
        }
        descriptor = open();
    }
    if descriptor < 0 {
        return Err(format!(
            "artifact directory component could not be opened safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn validate_secure_artifact_target(parent: &OwnedFd, name: &CString) -> Result<(), String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent and name are valid; AT_SYMLINK_NOFOLLOW inspects rather
    // than follows the destination entry.
    let status = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        // SAFETY: successful fstatat initialized stat.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_uid != unsafe { libc::getuid() }
            || stat.st_nlink != 1
        {
            return Err("artifact target is not a private regular file".into());
        }
    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(format!(
            "artifact target could not be inspected safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn write_atomic(parent: &OwnedFd, name: &CString, contents: &[u8]) -> Result<(), String> {
    for counter in 0..100_u32 {
        let mut temporary_bytes = Vec::with_capacity(name.as_bytes().len() + 48);
        temporary_bytes.push(b'.');
        temporary_bytes.extend_from_slice(name.as_bytes());
        temporary_bytes.extend_from_slice(
            format!(
                ".tmp-{}-{}-{counter}",
                std::process::id(),
                NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        let temporary = CString::new(temporary_bytes)
            .map_err(|_| "temporary artifact name is invalid".to_string())?;
        // SAFETY: parent and temporary are valid; O_EXCL/O_NOFOLLOW make the
        // new file private to this exact directory entry.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(format!(
                "private temporary artifact could not be created: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned a new descriptor transferred to File.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let result = (|| -> Result<(), String> {
            file.write_all(contents)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("temporary artifact could not be persisted: {error}"))?;
            drop(file);
            validate_secure_artifact_target(parent, name)?;
            // SAFETY: both names are relative to the same held directory, so
            // renameat atomically replaces only the validated target entry.
            if unsafe {
                libc::renameat(
                    parent.as_raw_fd(),
                    temporary.as_ptr(),
                    parent.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(format!(
                    "artifact could not be atomically installed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: fsync accepts the held directory descriptor.
            if unsafe { libc::fsync(parent.as_raw_fd()) } != 0 {
                return Err(format!(
                    "artifact was installed but its directory durability could not be confirmed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            // SAFETY: unlinkat is constrained to the held directory and exact
            // generated temporary name. ENOENT is expected after a successful rename.
            if unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) } != 0 {
                let cleanup_error = std::io::Error::last_os_error();
                if cleanup_error.raw_os_error() != Some(libc::ENOENT) {
                    return Err(format!(
                        "{error}; temporary artifact cleanup also failed: {cleanup_error}"
                    ));
                }
            }
            return Err(error);
        }
        return Ok(());
    }
    Err("could not allocate a private temporary artifact".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temporary_root(label: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "yafvsctl-artifact-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn writes_private_json_atomically() {
        let root = temporary_root("json");
        let path = root.join("report.json");
        write_secure_json_artifact(&path, &serde_json::json!({"status": "pass"})).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{\n  \"status\": \"pass\"\n}\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_symlink_and_hard_link_targets() {
        let root = temporary_root("links");
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        fs::write(&source, "unchanged").unwrap();
        let link = root.join("link");
        symlink(&source, &link).unwrap();
        assert!(write_secure_artifact(&link, b"changed").is_err());
        assert_eq!(fs::read_to_string(&source).unwrap(), "unchanged");

        let hard_link = root.join("hard-link");
        fs::hard_link(&source, &hard_link).unwrap();
        assert!(write_secure_artifact(&hard_link, b"changed").is_err());
        assert_eq!(fs::read_to_string(&source).unwrap(), "unchanged");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn creates_nested_directories_without_following_ancestor_symlinks() {
        let root = temporary_root("ancestors");
        let victim = temporary_root("ancestor-victim");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("report.json"), "unchanged").unwrap();
        symlink(&victim, root.join("linked")).unwrap();
        assert!(write_secure_artifact(&root.join("linked/report.json"), b"changed").is_err());
        assert_eq!(
            fs::read_to_string(victim.join("report.json")).unwrap(),
            "unchanged"
        );

        let nested = root.join("new/parent/report.json");
        write_secure_artifact(&nested, b"created").unwrap();
        assert_eq!(fs::read_to_string(nested).unwrap(), "created");
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(victim);
    }

    #[test]
    fn refuses_a_group_writable_final_parent() {
        let root = temporary_root("writable-parent");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(write_secure_artifact(&root.join("report.json"), b"unsafe").is_err());
        assert!(!root.join("report.json").exists());
        let _ = fs::remove_dir_all(root);
    }
}
