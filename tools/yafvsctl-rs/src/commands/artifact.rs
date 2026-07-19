// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

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
    validate_secure_artifact_target(path)?;
    write_atomic(path, contents)
}

fn validate_secure_artifact_target(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "artifact has no parent directory".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.uid() != unsafe { libc::getuid() } {
        return Err("artifact directory is not a real, current-user-owned directory".into());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::getuid() }
                && metadata.nlink() == 1 => {}
        Ok(_) => return Err("artifact target is not a private regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "artifact has no parent directory".to_string())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "artifact name is invalid".to_string())?;
    for counter in 0..100_u32 {
        let temporary = parent.join(format!(".{name}.tmp-{}-{counter}", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        };
        if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        return Ok(());
    }
    Err("could not allocate a private temporary artifact".into())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
