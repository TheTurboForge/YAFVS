// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deterministic, descriptor-anchored identity for bind-mounted application artifacts.

use super::canonical_json::to_ascii_compact;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

const ROOTS: [&str; 8] = [
    "build/prefix",
    "build/venvs/ospd-openvas",
    "build/venvs/notus-scanner",
    "build/openvas-scanner/nasl",
    "build/openvas-scanner/misc",
    "components/ospd-openvas/ospd",
    "components/ospd-openvas/ospd_openvas",
    "components/notus-scanner/notus/scanner",
];
const FILES: [&str; 1] = ["build/openvas-scanner/src/openvas"];
const IGNORED_PATHS: [&str; 3] = [
    "build/prefix/include/cgreen",
    "build/prefix/lib/libcgreen.so",
    "build/prefix/lib/libcgreen.so.1",
];
const IGNORED_DIRS: [&str; 1] = [".pytest_cache"];
const IGNORED_SUFFIXES: [&str; 0] = [];
const CHUNK: usize = 1024 * 1024;

type Result<T> = std::result::Result<T, String>;

/// Produces the Python-compatible runtime artifact manifest or fails closed.
pub(super) fn app_runtime_artifact_manifest(repo_root: &Path) -> Result<Value> {
    let repo = absolute_directory(repo_root)?;
    let repo_path = lexical_absolute(repo_root)?;
    let mut state = State {
        digest: Sha256::new(),
        entry_count: 0,
        byte_count: 0,
    };
    for root in ROOTS {
        let directory = open_relative_directory(repo.as_raw_fd(), root)?;
        walk(&directory, root, &repo_path, &mut state)?;
    }
    for file in FILES {
        let (parent, name) = split_parent(file)?;
        let directory = open_relative_directory(repo.as_raw_fd(), parent)?;
        hash_entry(&directory, name, file, &repo_path, &mut state)?;
    }
    Ok(serde_json::json!({
        "schema_version": 1,
        "algorithm": "sha256",
        "digest": format!("{:x}", state.digest.finalize()),
        "entry_count": state.entry_count,
        "byte_count": state.byte_count,
        "roots": ROOTS.into_iter().chain(FILES).collect::<Vec<_>>(),
    }))
}

struct State {
    digest: Sha256,
    entry_count: u64,
    byte_count: u64,
}

fn error(context: &str) -> String {
    format!("{context}: {}", io::Error::last_os_error())
}
fn c(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| "unsafe runtime artifact path".into())
}
fn stat_fd(fd: i32) -> Result<libc::stat> {
    let mut value = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        Err(error("could not inspect runtime artifact"))
    } else {
        Ok(value)
    }
}
fn stat_at(fd: i32, name: &str) -> Result<libc::stat> {
    let mut value = unsafe { std::mem::zeroed() };
    let name = c(name)?;
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(error("could not inspect runtime artifact"))
    } else {
        Ok(value)
    }
}
fn same_identity(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_mode == b.st_mode
}
fn is_dir(value: &libc::stat) -> bool {
    value.st_mode & libc::S_IFMT == libc::S_IFDIR
}
fn is_file(value: &libc::stat) -> bool {
    value.st_mode & libc::S_IFMT == libc::S_IFREG
}
fn is_link(value: &libc::stat) -> bool {
    value.st_mode & libc::S_IFMT == libc::S_IFLNK
}
fn mode(value: &libc::stat) -> u32 {
    value.st_mode & 0o7777
}

fn open_at(fd: i32, name: &str, flags: i32) -> Result<OwnedFd> {
    let name = c(name)?;
    let raw = unsafe { libc::openat(fd, name.as_ptr(), flags, 0) };
    if raw < 0 {
        Err(error("could not open runtime artifact"))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn open_checked_directory(fd: i32, name: &str) -> Result<OwnedFd> {
    let before = stat_at(fd, name)?;
    if !is_dir(&before) || is_link(&before) {
        return Err(format!(
            "required runtime artifact directory is unavailable: {name}"
        ));
    }
    let child = open_at(
        fd,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    if !same_identity(&before, &stat_fd(child.as_raw_fd())?) {
        return Err(format!(
            "runtime artifact directory changed while opening: {name}"
        ));
    }
    Ok(child)
}
fn absolute_directory(path: &Path) -> Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(format!(
            "runtime artifact repository root is unsafe: {}",
            path.display()
        ));
    }
    let mut current = open_at(
        libc::AT_FDCWD,
        "/",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                current = open_checked_directory(
                    current.as_raw_fd(),
                    name.to_str().ok_or("runtime artifact path is not UTF-8")?,
                )?
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!(
                    "runtime artifact repository root is unsafe: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(current)
}
fn open_relative_directory(fd: i32, path: &str) -> Result<OwnedFd> {
    let raw = unsafe { libc::dup(fd) };
    if raw < 0 {
        return Err(error("could not duplicate runtime artifact directory"));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    for component in safe_components(path)? {
        current = open_checked_directory(current.as_raw_fd(), component)?;
    }
    Ok(current)
}
fn safe_components(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() || path.starts_with('/') {
        return Err("unsafe runtime artifact path".into());
    }
    let components: Vec<_> = path.split('/').collect();
    if components
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == ".." || part.contains('\0'))
    {
        Err("unsafe runtime artifact path".into())
    } else {
        Ok(components)
    }
}
fn split_parent(path: &str) -> Result<(&str, &str)> {
    let (parent, name) = path
        .rsplit_once('/')
        .ok_or("unsafe runtime artifact path")?;
    safe_components(parent)?;
    safe_components(name)?;
    Ok((parent, name))
}

struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn names(fd: i32) -> Result<Vec<String>> {
    let raw = unsafe { libc::dup(fd) };
    if raw < 0 {
        return Err(error("could not duplicate runtime artifact directory"));
    }
    if unsafe { libc::lseek(raw, 0, libc::SEEK_SET) } < 0 {
        unsafe {
            libc::close(raw);
        }
        return Err(error("could not enumerate runtime artifact directory"));
    }
    let raw_directory = unsafe { libc::fdopendir(raw) };
    if raw_directory.is_null() {
        unsafe {
            libc::close(raw);
        }
        return Err(error("could not enumerate runtime artifact directory"));
    }
    let directory = Directory(raw_directory);
    let mut output = Vec::new();
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let code = unsafe { *libc::__errno_location() };
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code).to_string());
            }
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        output.push(
            std::str::from_utf8(bytes)
                .map_err(|_| "runtime artifact entry is not UTF-8")?
                .to_string(),
        );
    }
    output.sort();
    Ok(output)
}
fn walk(directory: &OwnedFd, relative: &str, repo: &Path, state: &mut State) -> Result<()> {
    for name in names(directory.as_raw_fd())? {
        let path = format!("{relative}/{name}");
        if IGNORED_PATHS.contains(&path.as_str()) {
            continue;
        }
        let metadata = stat_at(directory.as_raw_fd(), &name)?;
        if is_dir(&metadata) {
            if IGNORED_DIRS.contains(&name.as_str())
                || IGNORED_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
            {
                continue;
            }
            let child = open_checked_directory(directory.as_raw_fd(), &name)?;
            walk(&child, &path, repo, state)?;
        } else {
            hash_entry(directory, &name, &path, repo, state)?;
        }
    }
    Ok(())
}
fn hash_entry(
    parent: &OwnedFd,
    name: &str,
    relative: &str,
    repo: &Path,
    state: &mut State,
) -> Result<()> {
    let before = stat_at(parent.as_raw_fd(), name)?;
    let (kind, byte_count, entry_digest) = if is_link(&before) {
        let target = read_link(parent.as_raw_fd(), name)?;
        validate_link_target(relative, &target, repo)?;
        if !same_identity(&before, &stat_at(parent.as_raw_fd(), name)?) {
            return Err(format!(
                "runtime artifact changed while hashing: {relative}"
            ));
        }
        ("symlink", target.len() as u64, Sha256::digest(&target))
    } else if is_file(&before) {
        let file = open_at(
            parent.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )?;
        if !same_identity(&before, &stat_fd(file.as_raw_fd())?) {
            return Err(format!(
                "runtime artifact changed while hashing: {relative}"
            ));
        }
        let mut digest = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = vec![0_u8; CHUNK];
        loop {
            let amount =
                unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if amount < 0 {
                return Err(error("could not read runtime artifact"));
            }
            if amount == 0 {
                break;
            }
            let amount = amount as usize;
            digest.update(&buffer[..amount]);
            count += amount as u64;
        }
        if !same_identity(&before, &stat_fd(file.as_raw_fd())?)
            || !same_identity(&before, &stat_at(parent.as_raw_fd(), name)?)
        {
            return Err(format!(
                "runtime artifact changed while hashing: {relative}"
            ));
        }
        ("file", count, digest.finalize())
    } else {
        return Err(format!("unsupported runtime artifact type: {relative}"));
    };
    let mut record = to_ascii_compact(&json!([
        relative,
        kind,
        mode(&before),
        byte_count,
        format!("{entry_digest:x}"),
    ]))?;
    record.push(b'\n');
    state.digest.update(&record);
    state.entry_count += 1;
    state.byte_count += byte_count;
    Ok(())
}
fn read_link(fd: i32, name: &str) -> Result<Vec<u8>> {
    let name = c(name)?;
    let mut size = 256_usize;
    loop {
        let mut output = vec![0_u8; size];
        let read = unsafe {
            libc::readlinkat(fd, name.as_ptr(), output.as_mut_ptr().cast(), output.len())
        };
        if read < 0 {
            return Err(error("could not read runtime artifact symlink"));
        }
        let read = read as usize;
        if read < output.len() {
            output.truncate(read);
            return Ok(output);
        }
        if size >= 65536 {
            return Err("runtime artifact symlink target is too long".into());
        }
        size *= 2;
    }
}
fn validate_link_target(relative: &str, target: &[u8], repo: &Path) -> Result<()> {
    let target = std::str::from_utf8(target).map_err(|_| {
        format!("runtime artifact symlink escapes the attested deployment roots: {relative}")
    })?;
    if target.starts_with("/workspace/") {
        return Err(format!(
            "runtime artifact symlink escapes the attested deployment roots: {relative}"
        ));
    }
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        let normalized = lexical_absolute(target_path)?;
        let owned = ["/bin", "/lib", "/lib64", "/usr"].iter().any(|prefix| {
            normalized == Path::new(prefix) || normalized.starts_with(Path::new(prefix))
        });
        if !owned {
            return Err(format!(
                "runtime artifact symlink escapes the attested deployment roots: {relative}"
            ));
        }
    } else {
        let resolved = lexical_normalize(
            &repo
                .join(Path::new(relative).parent().unwrap_or(Path::new("")))
                .join(target_path),
        );
        let allowed = ROOTS.iter().any(|root| {
            let root = repo.join(root);
            resolved == root || resolved.starts_with(root)
        }) || FILES.iter().any(|file| resolved == repo.join(file));
        if !allowed {
            return Err(format!(
                "runtime artifact symlink escapes the attested deployment roots: {relative}"
            ));
        }
    }
    Ok(())
}
fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        Err("runtime artifact path is unsafe".into())
    } else {
        Ok(lexical_normalize(path))
    }
}
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => output.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(part) => output.push(part),
            Component::Prefix(_) => {}
        }
    }
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture(name: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "yafvs-artifact-{name}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        for path in ROOTS {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        let executable = root.join(FILES[0]);
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"openvas\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        Fixture(root)
    }
    #[test]
    fn deterministic_record_digest_and_exact_manifest_shape() {
        let fixture = fixture("deterministic");
        for (name, content) in [("z", b"z".as_slice()), ("a", b"a".as_slice())] {
            let path = fixture.0.join("build/prefix").join(name);
            fs::write(&path, content).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let first = app_runtime_artifact_manifest(&fixture.0).unwrap();
        let second = app_runtime_artifact_manifest(&fixture.0).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["schema_version"], 1);
        assert_eq!(first["algorithm"], "sha256");
        assert_eq!(first["entry_count"], 3);
        assert_eq!(first["byte_count"], 10);
        assert_eq!(
            first["digest"],
            "d1bd5469a0b756fb319704fe830726c79204e459f1f7842cbf6468f67d56e568"
        );
        assert_eq!(
            first["roots"],
            serde_json::json!([
                "build/prefix",
                "build/venvs/ospd-openvas",
                "build/venvs/notus-scanner",
                "build/openvas-scanner/nasl",
                "build/openvas-scanner/misc",
                "components/ospd-openvas/ospd",
                "components/ospd-openvas/ospd_openvas",
                "components/notus-scanner/notus/scanner",
                "build/openvas-scanner/src/openvas",
            ])
        );
        assert_eq!(first.as_object().unwrap().len(), 6);
        let record = "[\"build/prefix/a\",\"file\",420,1,\"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\"]\n";
        assert_eq!(
            format!("{:x}", Sha256::digest(record.as_bytes())),
            "0b16888fa9b108e5a58fc396055e6ae9794191e0cdc06401f5779c057e7d84e1"
        );
    }
    #[test]
    fn ignores_exact_paths_and_pytest_cache() {
        let fixture = fixture("ignored");
        fs::create_dir_all(fixture.0.join("build/prefix/.pytest_cache")).unwrap();
        fs::write(fixture.0.join("build/prefix/.pytest_cache/no"), b"no").unwrap();
        fs::create_dir_all(fixture.0.join("build/prefix/include")).unwrap();
        fs::write(fixture.0.join("build/prefix/include/cgreen"), b"no").unwrap();
        let manifest = app_runtime_artifact_manifest(&fixture.0).unwrap();
        assert_eq!(manifest["entry_count"], 1);
        assert_eq!(manifest["byte_count"], 8);
    }
    #[test]
    fn hashes_file_and_symlink_identity_types() {
        let fixture = fixture("types");
        fs::write(fixture.0.join("build/prefix/file"), b"data").unwrap();
        symlink("file", fixture.0.join("build/prefix/link")).unwrap();
        let manifest = app_runtime_artifact_manifest(&fixture.0).unwrap();
        assert_eq!(manifest["entry_count"], 3);
        assert_eq!(manifest["byte_count"], 16);
    }
    #[test]
    fn rejects_relative_and_workspace_escapes() {
        let fixture = fixture("escape");
        symlink("../../outside", fixture.0.join("build/prefix/escape")).unwrap();
        assert!(
            app_runtime_artifact_manifest(&fixture.0)
                .unwrap_err()
                .contains("escapes")
        );
        fs::remove_file(fixture.0.join("build/prefix/escape")).unwrap();
        symlink("/workspace/owned", fixture.0.join("build/prefix/escape")).unwrap();
        assert!(
            app_runtime_artifact_manifest(&fixture.0)
                .unwrap_err()
                .contains("escapes")
        );
    }
    #[test]
    fn permits_image_owned_absolute_links() {
        let fixture = fixture("image");
        symlink("/usr/bin/python3", fixture.0.join("build/prefix/python")).unwrap();
        assert!(app_runtime_artifact_manifest(&fixture.0).is_ok());
    }
}
