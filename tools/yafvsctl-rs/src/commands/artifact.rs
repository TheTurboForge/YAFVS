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

pub(crate) struct SecureArtifactTransaction {
    parent: OwnedFd,
    target: CString,
    temporary: CString,
    file: Option<File>,
    overwrite: bool,
    committed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ArtifactCommit {
    Durable,
    InstalledDurabilityUnknown(String),
}

impl SecureArtifactTransaction {
    pub(crate) fn file(&self) -> &File {
        self.file.as_ref().expect("transaction file remains open")
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("transaction file remains open")
    }

    pub(crate) fn commit(self) -> Result<ArtifactCommit, String> {
        self.commit_with_directory_sync(|directory_fd| {
            // SAFETY: fsync accepts the held directory descriptor.
            if unsafe { libc::fsync(directory_fd) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }

    fn commit_with_directory_sync(
        mut self,
        sync_directory: impl FnOnce(i32) -> std::io::Result<()>,
    ) -> Result<ArtifactCommit, String> {
        self.file()
            .sync_all()
            .map_err(|error| format!("temporary artifact could not be persisted: {error}"))?;
        validate_temporary_identity(&self.parent, &self.temporary, self.file())?;
        if self.overwrite {
            validate_secure_artifact_target(&self.parent, &self.target)?;
            // SAFETY: both names are relative to the same held directory. The
            // source identity was just matched to the still-open descriptor.
            if unsafe {
                libc::renameat(
                    self.parent.as_raw_fd(),
                    self.temporary.as_ptr(),
                    self.parent.as_raw_fd(),
                    self.target.as_ptr(),
                )
            } != 0
            {
                return Err(format!(
                    "artifact could not be atomically installed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        } else {
            // SAFETY: renameat2 is constrained to the held directory and
            // RENAME_NOREPLACE fails atomically with EEXIST if another process
            // won the target name.
            if unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    self.temporary.as_ptr(),
                    self.parent.as_raw_fd(),
                    self.target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(format!(
                    "artifact target already exists or could not be installed without replacement: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        self.committed = true;
        self.file.take();
        match sync_directory(self.parent.as_raw_fd()) {
            Ok(()) => Ok(ArtifactCommit::Durable),
            Err(error) => Ok(ArtifactCommit::InstalledDurabilityUnknown(format!(
                "artifact was installed but its directory durability could not be confirmed: {error}"
            ))),
        }
    }
}

impl Drop for SecureArtifactTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.file.as_ref().is_some_and(|file| {
            validate_temporary_identity(&self.parent, &self.temporary, file).is_ok()
        }) {
            // SAFETY: cleanup is constrained to the held parent and the path
            // identity was just matched to the still-open descriptor.
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.temporary.as_ptr(), 0);
            }
        }
        self.file.take();
    }
}

pub(crate) fn begin_secure_artifact_transaction(
    path: &Path,
    overwrite: bool,
) -> Result<SecureArtifactTransaction, String> {
    let (parent, target) = open_existing_artifact_parent(path)?;
    let target_exists = secure_artifact_target_exists(&parent, &target)?;
    if target_exists && !overwrite {
        return Err("artifact target already exists; enable overwrite to replace it".into());
    }
    for counter in 0..100_u32 {
        let temporary = temporary_name(&target, counter)?;
        // SAFETY: parent and temporary are valid. O_EXCL/O_NOFOLLOW create a
        // private exact entry in the already validated output directory.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        return Ok(SecureArtifactTransaction {
            parent,
            target,
            temporary,
            file: Some(file),
            overwrite,
            committed: false,
        });
    }
    Err("could not allocate a private temporary artifact".into())
}

fn open_artifact_parent(path: &Path) -> Result<(OwnedFd, CString), String> {
    open_artifact_parent_with(path, true)
}

fn open_existing_artifact_parent(path: &Path) -> Result<(OwnedFd, CString), String> {
    open_artifact_parent_with(path, false)
}

fn open_artifact_parent_with(
    path: &Path,
    create_directories: bool,
) -> Result<(OwnedFd, CString), String> {
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
        parent = open_directory(&parent, &part, create_directories)?;
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
        || stat.st_mode & 0o002 != 0
    {
        return Err(
            "artifact directory is not a real, current-user-owned, non-world-writable directory"
                .into(),
        );
    }
    Ok((parent, target_name))
}

fn open_directory(parent: &OwnedFd, name: &OsString, create: bool) -> Result<OwnedFd, String> {
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
    if create
        && descriptor < 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
    {
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
    secure_artifact_target_exists(parent, name).map(|_| ())
}

fn secure_artifact_target_exists(parent: &OwnedFd, name: &CString) -> Result<bool, String> {
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
        return Ok(true);
    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(format!(
            "artifact target could not be inspected safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(false)
}

fn temporary_name(target: &CString, counter: u32) -> Result<CString, String> {
    let mut entropy = 0_u64;
    // SAFETY: entropy is valid writable storage for its full length and
    // GRND_NONBLOCK avoids waiting during artifact preparation.
    let entropy_bytes = unsafe {
        libc::getrandom(
            std::ptr::from_mut(&mut entropy).cast(),
            std::mem::size_of::<u64>(),
            libc::GRND_NONBLOCK,
        )
    };
    if entropy_bytes != std::mem::size_of::<u64>() as isize {
        return Err(format!(
            "temporary artifact entropy is unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut temporary_bytes = Vec::with_capacity(target.as_bytes().len() + 48);
    temporary_bytes.push(b'.');
    temporary_bytes.extend_from_slice(target.as_bytes());
    temporary_bytes.extend_from_slice(
        format!(
            ".tmp-{}-{}-{counter}-{entropy:016x}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        )
        .as_bytes(),
    );
    CString::new(temporary_bytes).map_err(|_| "temporary artifact name is invalid".to_string())
}

fn validate_temporary_identity(
    parent: &OwnedFd,
    name: &CString,
    file: &File,
) -> Result<(), String> {
    let mut descriptor_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file is open and the stat storage is writable.
    if unsafe { libc::fstat(file.as_raw_fd(), descriptor_stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "temporary artifact descriptor could not be inspected: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut path_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent/name are valid and AT_SYMLINK_NOFOLLOW refuses a link.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            path_stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(format!(
            "temporary artifact path could not be inspected: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful fstat/fstatat initialized both values.
    let descriptor_stat = unsafe { descriptor_stat.assume_init() };
    let path_stat = unsafe { path_stat.assume_init() };
    if descriptor_stat.st_dev != path_stat.st_dev
        || descriptor_stat.st_ino != path_stat.st_ino
        || path_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || path_stat.st_uid != unsafe { libc::getuid() }
        || path_stat.st_nlink != 1
    {
        return Err("temporary artifact path identity changed before installation".into());
    }
    Ok(())
}

fn write_atomic(parent: &OwnedFd, name: &CString, contents: &[u8]) -> Result<(), String> {
    for counter in 0..100_u32 {
        let temporary = temporary_name(name, counter)?;
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
    fn streaming_transaction_preserves_no_clobber_and_allows_explicit_overwrite() {
        let root = temporary_root("transaction");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("report.pdf");
        let mut first = begin_secure_artifact_transaction(&path, false).unwrap();
        first.file_mut().write_all(b"first").unwrap();
        first.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        assert!(begin_secure_artifact_transaction(&path, false).is_err());

        let mut second = begin_secure_artifact_transaction(&path, true).unwrap();
        second.file_mut().write_all(b"second").unwrap();
        second.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streaming_transaction_distinguishes_post_install_durability_failure() {
        let root = temporary_root("transaction-durability");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("report.pdf");
        let mut transaction = begin_secure_artifact_transaction(&path, false).unwrap();
        transaction.file_mut().write_all(b"installed").unwrap();
        let outcome = transaction
            .commit_with_directory_sync(|_| Err(std::io::Error::other("sync denied")))
            .unwrap();
        assert!(matches!(
            outcome,
            ArtifactCommit::InstalledDurabilityUnknown(ref message)
                if message.contains("sync denied")
        ));
        assert_eq!(fs::read(&path).unwrap(), b"installed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streaming_transaction_drop_does_not_unlink_a_replaced_temporary_path() {
        let root = temporary_root("transaction-drop-race");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("report.pdf");
        let transaction = begin_secure_artifact_transaction(&target, false).unwrap();
        let temporary = root.join(transaction.temporary.to_str().unwrap());
        fs::remove_file(&temporary).unwrap();
        fs::write(&temporary, b"replacement").unwrap();
        drop(transaction);
        assert_eq!(fs::read(&temporary).unwrap(), b"replacement");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streaming_transaction_refuses_target_and_temporary_name_races() {
        let root = temporary_root("transaction-race");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("report.pdf");
        let mut raced_target = begin_secure_artifact_transaction(&target, false).unwrap();
        raced_target.file_mut().write_all(b"candidate").unwrap();
        fs::write(&target, b"raced").unwrap();
        assert!(raced_target.commit().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"raced");

        fs::remove_file(&target).unwrap();
        let mut raced_temporary = begin_secure_artifact_transaction(&target, false).unwrap();
        raced_temporary.file_mut().write_all(b"candidate").unwrap();
        let temporary = root.join(raced_temporary.temporary.to_str().unwrap());
        fs::remove_file(&temporary).unwrap();
        fs::write(&temporary, b"replacement").unwrap();
        assert!(raced_temporary.commit().is_err());
        assert!(!target.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn streaming_transaction_requires_an_existing_safe_parent() {
        let root = temporary_root("transaction-parent");
        let path = root.join("missing/report.pdf");
        assert!(begin_secure_artifact_transaction(&path, false).is_err());
        assert!(!root.exists());
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
    fn accepts_the_existing_group_writable_owner_parent_contract() {
        let root = temporary_root("group-writable-parent");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
        write_secure_artifact(&root.join("report.json"), b"expected").unwrap();
        assert_eq!(
            fs::read_to_string(root.join("report.json")).unwrap(),
            "expected"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_a_world_writable_final_parent() {
        let root = temporary_root("world-writable-parent");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_secure_artifact(&root.join("report.json"), b"unsafe").is_err());
        assert!(!root.join("report.json").exists());
        let _ = fs::remove_dir_all(root);
    }
}
