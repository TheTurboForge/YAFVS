// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::runtime_dir;
use std::ffi::CString;
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) fn runtime_secret_path(repo_root: &Path, name: &str) -> PathBuf {
    runtime_dir(repo_root).join("secrets").join(name)
}

pub(crate) fn read_or_create_runtime_secret(
    repo_root: &Path,
    name: &str,
) -> io::Result<(String, bool)> {
    let path = runtime_secret_path(repo_root, name);
    match read_private_text(&path, 4096) {
        Ok(secret) => Ok((validate_single_line_secret(&path, secret)?, false)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let secret = random_urlsafe_token(24)?;
            write_private_text(&path, &format!("{secret}\n"))?;
            Ok((secret, true))
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn read_existing_runtime_secret(
    repo_root: &Path,
    name: &str,
) -> io::Result<Option<String>> {
    let path = runtime_secret_path(repo_root, name);
    match read_private_text(&path, 4096) {
        Ok(secret) => validate_single_line_secret(&path, secret).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_single_line_secret(path: &Path, mut secret: String) -> io::Result<String> {
    if secret.ends_with('\n') {
        secret.pop();
    }
    if secret.is_empty()
        || secret
            .as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b'\0' | b'\n' | b'\r'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Runtime secret must contain one line with an optional terminal LF: {}",
                path.display()
            ),
        ));
    }
    Ok(secret)
}

fn read_private_text(path: &Path, max_bytes: usize) -> io::Result<String> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private path has no parent"))?;
    let directory = open_private_directory(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "private path has no file name")
    })?;
    let name = CString::new(file_name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private file name"))?;
    // SAFETY: the directory descriptor and C string are valid. O_NOFOLLOW
    // refuses a link in place of the secret file.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(raw) };
    let before = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !before.file_type().is_file()
        || before.uid() != euid
        || before.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Private file is unsafe: {}", path.display()),
        ));
    }
    if before.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("Private file is too large: {}", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("Private file is too large: {}", path.display()),
        ));
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mode() != after.mode()
    {
        return Err(io::Error::other(format!(
            "Private file changed while reading: {}",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Private file is not UTF-8: {}", path.display()),
        )
    })
}

pub(crate) fn rotate_runtime_secret(repo_root: &Path, name: &str) -> io::Result<PathBuf> {
    let path = runtime_secret_path(repo_root, name);
    let token = random_urlsafe_token(32)?;
    write_private_text(&path, &format!("{token}\n"))?;
    Ok(path)
}

pub(crate) fn write_private_text(path: &Path, text: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private path has no parent"))?;
    let directory = open_private_directory(parent)?;
    let lock_name = CString::new(".yafvs-private.lock").expect("static lock name");
    // SAFETY: directory is a valid open directory descriptor, lock_name is
    // NUL-terminated, and the flags/mode are valid for openat.
    let lock_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            lock_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if lock_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let lock = unsafe { OwnedFd::from_raw_fd(lock_fd) };
    validate_private_file_descriptor(&lock, parent.join(".yafvs-private.lock"))?;
    // SAFETY: lock is a valid file descriptor and LOCK_EX is a valid operation.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "private path has no file name")
    })?;
    let random = random_bytes(8)?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = format!(
        ".{}.tmp-{}-{suffix}",
        file_name.to_string_lossy(),
        std::process::id()
    );
    let temporary_name = CString::new(temporary.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid temporary name"))?;
    let destination_name = CString::new(file_name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid private file name"))?;
    // SAFETY: descriptors and C strings are valid; O_EXCL/O_NOFOLLOW prevent
    // replacing or following an attacker-controlled temporary path.
    let temporary_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if temporary_fd < 0 {
        // SAFETY: lock remains a valid descriptor until this function returns.
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor which is transferred to File.
    let mut temporary_file = unsafe { File::from_raw_fd(temporary_fd) };
    let write_result = (|| {
        temporary_file.write_all(text.as_bytes())?;
        temporary_file.sync_all()?;
        drop(temporary_file);
        // SAFETY: both names are valid C strings relative to the same verified
        // directory descriptor; renameat atomically replaces the destination.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                destination_name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fsync accepts the verified directory descriptor.
        if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if write_result.is_err() {
        // SAFETY: unlinkat is constrained to the verified directory and exact
        // temporary name; failure merely means cleanup is unnecessary/failed.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    // SAFETY: lock remains a valid descriptor and unlocking has no preconditions.
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
    write_result
}

fn open_private_directory(path: &Path) -> io::Result<OwnedFd> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Private path is not a real directory: {}", path.display()),
        ));
    }
    if metadata.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Private directory is not owned by the current user: {}",
                path.display()
            ),
        ));
    }
    fs::set_permissions(path, Permissions::from_mode(0o700))?;
    let path_c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid private directory path",
        )
    })?;
    // SAFETY: path_c is a valid C string and flags are valid for open.
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new owned descriptor.
    let directory = unsafe { OwnedFd::from_raw_fd(fd) };
    let stat = descriptor_stat(&directory)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != euid
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Private directory validation failed: {}", path.display()),
        ));
    }
    Ok(directory)
}

fn validate_private_file_descriptor(descriptor: &OwnedFd, path: PathBuf) -> io::Result<()> {
    let stat = descriptor_stat(descriptor)?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != euid
        || stat.st_mode & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Private directory lock is not owner-only: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn descriptor_stat(descriptor: &OwnedFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to valid writable storage and descriptor is open.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized the full structure.
    Ok(unsafe { stat.assume_init() })
}

fn random_urlsafe_token(byte_count: usize) -> io::Result<String> {
    Ok(base64_url_no_pad(&random_bytes(byte_count)?))
}

fn random_bytes(byte_count: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; byte_count];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        output.push(ALPHABET[(first >> 2) as usize] as char);
        let second_index = ((first & 0x03) << 4) | chunk.get(1).copied().unwrap_or(0) >> 4;
        output.push(ALPHABET[second_index as usize] as char);
        if let Some(second) = chunk.get(1) {
            let third_index = ((second & 0x0f) << 2) | chunk.get(2).copied().unwrap_or(0) >> 6;
            output.push(ALPHABET[third_index as usize] as char);
        }
        if let Some(third) = chunk.get(2) {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn fixture() -> PathBuf {
        std::env::temp_dir().join(format!(
            "yafvsctl-private-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn atomic_private_write_is_owner_only() {
        let root = fixture();
        let path = root.join("secrets/token");
        write_private_text(&path, "secret\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_token_matches_python_token_urlsafe_shape() {
        let token = random_urlsafe_token(32).unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
    }

    #[test]
    fn private_write_refuses_a_symlinked_directory() {
        let root = fixture();
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        symlink(&target, root.join("secrets")).unwrap();
        let error = write_private_text(&root.join("secrets/token"), "secret\n").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_secret_is_created_once_and_read_back() {
        let root = fixture();
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        let (created, was_created) = read_or_create_runtime_secret(&repo, "browser-proxy").unwrap();
        assert!(was_created);
        assert!(!created.is_empty());
        let (observed, was_created) =
            read_or_create_runtime_secret(&repo, "browser-proxy").unwrap();
        assert!(!was_created);
        assert_eq!(observed, created);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_secret_rejects_links_and_multiple_lines() {
        let root = fixture();
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        let path = runtime_secret_path(&repo, "browser-proxy");
        write_private_text(&path, "first\nsecond\n").unwrap();
        assert_eq!(
            read_or_create_runtime_secret(&repo, "browser-proxy")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(&path).unwrap();
        let target = root.join("target");
        fs::write(&target, "secret\n").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_or_create_runtime_secret(&repo, "browser-proxy").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
