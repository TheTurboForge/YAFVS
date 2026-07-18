// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Descriptor-anchored runtime feed compatibility mappings.

use super::transition::{StepOutcome, StepStatus};
use super::{
    absolute_dir, c, identity, is_dir, is_lnk, mode, names, open_dir_at, stat, stat_at_io, uid,
};
use crate::result::Finding;
use serde_json::json;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

const MAX_TEMP_ATTEMPTS: u32 = 32;
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

#[derive(Clone, Copy)]
struct Mapping {
    key: &'static str,
    label: &'static str,
    build_rel: &'static str,
    target: &'static str,
}

const RUNTIME_FEED_MAPPINGS: [Mapping; 4] = [
    Mapping {
        key: "nasl",
        label: "OpenVAS plugin feed",
        build_rel: "build/var/lib/openvas/plugins",
        target: "/runtime/feeds/openvas/plugins",
    },
    Mapping {
        key: "gvmd",
        label: "GVMD data objects feed",
        build_rel: "build/var/lib/gvm/data-objects/gvmd",
        target: "/runtime/feeds/gvm/data-objects/gvmd/22.04",
    },
    Mapping {
        key: "scap",
        label: "SCAP data feed",
        build_rel: "build/var/lib/gvm/scap-data",
        target: "/runtime/feeds/gvm/scap-data",
    },
    Mapping {
        key: "cert",
        label: "CERT data feed",
        build_rel: "build/var/lib/gvm/cert-data",
        target: "/runtime/feeds/gvm/cert-data",
    },
];

struct Temporary {
    name: String,
    identity: (u64, u64),
}

/// Ensures Python-compatible mappings while retaining descriptor-based safety.
pub(super) fn ensure_runtime_feed_mappings(repo_root: &Path) -> StepOutcome {
    let root = match absolute_dir(repo_root).and_then(|fd| {
        checked_dir(fd.as_raw_fd(), "repository root")?;
        Ok(fd)
    }) {
        Ok(fd) => fd,
        Err(_) => {
            return root_failure(
                "Runtime feed mappings stopped because the repository root is not a safe user-owned directory.",
            );
        }
    };
    let root_identity = match stat(root.as_raw_fd()) {
        Ok(value) => identity(&value),
        Err(_) => {
            return root_failure(
                "Runtime feed mappings stopped because the repository root could not be verified.",
            );
        }
    };
    let mut findings = Vec::with_capacity(RUNTIME_FEED_MAPPINGS.len());
    let mut failed = false;
    for mapping in RUNTIME_FEED_MAPPINGS {
        match verify_root(repo_root, root_identity)
            .and_then(|_| map_one(root.as_raw_fd(), repo_root, mapping))
        {
            Ok(message) => findings.push(
                Finding::new("pass", &format!("feed-map.{}", mapping.key), message)
                    .with_path(mapping.build_rel)
                    .with_details(json!({"target": mapping.target})),
            ),
            Err(reason) => {
                failed = true;
                findings.push(Finding::new("fail", &format!("feed-map.{}", mapping.key), format!("{} mapping was refused because its descriptor-anchored path was unsafe or changed.", mapping.label))
                    .with_path(mapping.build_rel).with_details(json!({"expected_target": mapping.target, "reason": reason})));
            }
        }
    }
    StepOutcome::with_evidence(
        if failed {
            StepStatus::Fail
        } else {
            StepStatus::Pass
        },
        findings,
        RUNTIME_FEED_MAPPINGS
            .iter()
            .map(|mapping| mapping.build_rel.to_string())
            .collect(),
    )
}

fn root_failure(message: &str) -> StepOutcome {
    StepOutcome::with_evidence(
        StepStatus::Fail,
        vec![Finding::new(
            "fail",
            "feed-map.repository-root",
            message.into(),
        )],
        Vec::new(),
    )
}

fn verify_root(repo_root: &Path, expected: (u64, u64)) -> Result<(), String> {
    let reopened = absolute_dir(repo_root)?;
    checked_dir(reopened.as_raw_fd(), "repository root")?;
    if identity(&stat(reopened.as_raw_fd())?) != expected {
        return Err("repository root changed while preparing mappings".into());
    }
    Ok(())
}

fn checked_dir(fd: i32, what: &str) -> Result<(), String> {
    let entry = stat(fd)?;
    if !trusted_directory(&entry) {
        return Err(format!(
            "{what} is not a trusted user/project-group directory"
        ));
    }
    Ok(())
}

fn trusted_directory(entry: &libc::stat) -> bool {
    // SAFETY: getegid has no preconditions.
    let effective_group = unsafe { libc::getegid() };
    is_dir(entry)
        && entry.st_uid == uid()
        && mode(entry) & 0o002 == 0
        && (mode(entry) & 0o020 == 0 || entry.st_gid == effective_group)
}

fn map_one(root: i32, repo_root: &Path, mapping: Mapping) -> Result<String, String> {
    let components: Vec<_> = mapping.build_rel.split('/').collect();
    if components.len() < 2
        || components
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == ".." || part.contains('\0'))
    {
        return Err("mapping path is invalid".into());
    }
    let parent = parent_dir(root, &components[..components.len() - 1])?;
    let final_name = components[components.len() - 1];
    match stat_at_io(parent.as_raw_fd(), final_name) {
        Ok(entry) if is_lnk(&entry) => {
            if entry.st_uid != uid() {
                return Err("existing symlink is not user-owned".into());
            }
            if read_link_at(parent.as_raw_fd(), final_name)? == mapping.target {
                Ok(format!(
                    "{} mapping already points at the active feed generation.",
                    mapping.label
                ))
            } else {
                replace_stale(
                    parent.as_raw_fd(),
                    final_name,
                    &entry,
                    mapping.key,
                    mapping.target,
                )?;
                Ok(format!(
                    "Stale {} symlink was retargeted to the active feed generation.",
                    mapping.label
                ))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            install_missing(
                parent.as_raw_fd(),
                final_name,
                mapping.key,
                mapping.target,
                || competing_final_hook(&repo_root.join(mapping.build_rel)),
            )?;
            Ok(format!("{} mapping was created.", mapping.label))
        }
        Ok(entry) if is_dir(&entry) => {
            replace_empty_dir(
                parent.as_raw_fd(),
                final_name,
                &entry,
                mapping.key,
                mapping.target,
                || competing_final_hook(&repo_root.join(mapping.build_rel)),
            )?;
            Ok(format!(
                "Empty {} directory was replaced with a runtime feed mapping.",
                mapping.label
            ))
        }
        Ok(_) => Err("final mapping entry is not an expected symlink or empty directory".into()),
        Err(_) => Err("final mapping entry could not be inspected".into()),
    }
}

fn parent_dir(root: i32, components: &[&str]) -> Result<OwnedFd, String> {
    let duplicate = unsafe { libc::dup(root) };
    if duplicate < 0 {
        return Err("repository root descriptor could not be duplicated".into());
    }
    let mut parent = unsafe { OwnedFd::from_raw_fd(duplicate) };
    for component in components {
        if component.is_empty()
            || *component == "."
            || *component == ".."
            || component.contains('\0')
        {
            return Err("mapping parent component is invalid".into());
        }
        match stat_at_io(parent.as_raw_fd(), component) {
            Ok(entry) if trusted_directory(&entry) => {}
            Ok(_) => return Err("mapping parent is not a safe user-owned directory".into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                mkdir_at(parent.as_raw_fd(), component)?
            }
            Err(_) => return Err("mapping parent could not be inspected".into()),
        }
        let child = open_dir_at(parent.as_raw_fd(), component)
            .map_err(|_| "mapping parent is not a real directory or changed".to_string())?;
        checked_dir(child.as_raw_fd(), "mapping parent")?;
        parent = child;
    }
    Ok(parent)
}

fn mkdir_at(parent: i32, name: &str) -> Result<(), String> {
    let name = c(name)?;
    if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o775) } == 0 {
        return fsync_dir(parent);
    }
    if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
        Ok(())
    } else {
        Err("mapping parent could not be created".into())
    }
}

fn replace_empty_dir(
    parent: i32,
    final_name: &str,
    expected: &libc::stat,
    key: &str,
    target: &str,
    hook: impl FnOnce(),
) -> Result<(), String> {
    if !trusted_directory(expected) {
        return Err("existing directory is not a trusted user/project-group directory".into());
    }
    let child = open_dir_at(parent, final_name)
        .map_err(|_| "existing directory changed while opening".to_string())?;
    if identity(&stat(child.as_raw_fd())?) != identity(expected)
        || !names(child.as_raw_fd())?.is_empty()
    {
        return Err("existing directory changed or is not empty".into());
    }
    let before = stat_at_io(parent, final_name)
        .map_err(|_| "existing directory could not be rechecked".to_string())?;
    if !is_dir(&before) || identity(&before) != identity(expected) {
        return Err("existing directory changed before removal".into());
    }
    let name = c(final_name)?;
    if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err("empty directory could not be removed".into());
    }
    fsync_dir(parent)?;
    install_missing(parent, final_name, key, target, hook)
}

fn install_missing(
    parent: i32,
    final_name: &str,
    key: &str,
    target: &str,
    hook: impl FnOnce(),
) -> Result<(), String> {
    let temporary = create_temp(parent, key, target)?;
    hook();
    match rename_at2(
        parent,
        &temporary.name,
        parent,
        final_name,
        RENAME_NOREPLACE,
    ) {
        Ok(()) => {
            let final_entry = stat_at_io(parent, final_name)
                .map_err(|_| "new mapping could not be verified".to_string())?;
            if identity(&final_entry) != temporary.identity
                || final_entry.st_uid != uid()
                || !is_lnk(&final_entry)
                || read_link_at(parent, final_name)? != target
            {
                if identity(&final_entry) == temporary.identity
                    && final_entry.st_uid == uid()
                    && is_lnk(&final_entry)
                {
                    let _ = cleanup_temp(
                        parent,
                        &Temporary {
                            name: final_name.to_owned(),
                            identity: temporary.identity,
                        },
                    );
                }
                return Err("new mapping changed while installing".into());
            }
            fsync_dir(parent)
        }
        Err(error) => {
            cleanup_temp(parent, &temporary)?;
            if error.kind() == io::ErrorKind::AlreadyExists {
                Err("a competing final mapping entry appeared".into())
            } else {
                Err("new mapping could not be installed atomically".into())
            }
        }
    }
}

fn replace_stale(
    parent: i32,
    final_name: &str,
    expected: &libc::stat,
    key: &str,
    target: &str,
) -> Result<(), String> {
    let temporary = create_temp(parent, key, target)?;
    let current = match stat_at_io(parent, final_name) {
        Ok(entry) => entry,
        Err(_) => {
            cleanup_temp(parent, &temporary)?;
            return Err("stale mapping disappeared before replacement".into());
        }
    };
    if !is_lnk(&current) || identity(&current) != identity(expected) {
        cleanup_temp(parent, &temporary)?;
        return Err("stale mapping changed before replacement".into());
    }
    if rename_at2(parent, &temporary.name, parent, final_name, RENAME_EXCHANGE).is_err() {
        cleanup_temp(parent, &temporary)?;
        return Err("stale mapping could not be exchanged atomically".into());
    }
    let installed = stat_at_io(parent, final_name)
        .map_err(|_| "new mapping could not be verified".to_string())?;
    let displaced = stat_at_io(parent, &temporary.name)
        .map_err(|_| "displaced stale mapping could not be verified".to_string())?;
    if identity(&installed) != temporary.identity
        || installed.st_uid != uid()
        || !is_lnk(&installed)
        || read_link_at(parent, final_name)? != target
        || identity(&displaced) != identity(expected)
        || displaced.st_uid != uid()
        || !is_lnk(&displaced)
    {
        if identity(&installed) == temporary.identity
            && identity(&displaced) == identity(expected)
            && rename_at2(parent, final_name, parent, &temporary.name, RENAME_EXCHANGE).is_ok()
        {
            let _ = fsync_dir(parent);
            let _ = cleanup_temp(
                parent,
                &Temporary {
                    name: temporary.name,
                    identity: temporary.identity,
                },
            );
        }
        return Err("mapping changed during atomic replacement".into());
    }
    fsync_dir(parent)?;
    cleanup_temp(
        parent,
        &Temporary {
            name: temporary.name,
            identity: identity(expected),
        },
    )?;
    fsync_dir(parent)
}

fn create_temp(parent: i32, key: &str, target: &str) -> Result<Temporary, String> {
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let name = format!(
            ".turbovasctl-feed-map-{key}-{}-{attempt}",
            std::process::id()
        );
        let entry_name = c(&name)?;
        let target_name = c(target)?;
        if unsafe { libc::symlinkat(target_name.as_ptr(), parent, entry_name.as_ptr()) } != 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err("temporary mapping symlink could not be created".into());
        }
        let entry = stat_at_io(parent, &name)
            .map_err(|_| "temporary mapping symlink could not be verified".to_string())?;
        let identity = identity(&entry);
        let valid = entry.st_uid == uid()
            && is_lnk(&entry)
            && read_link_at(parent, &name).is_ok_and(|observed| observed == target);
        if !valid {
            if entry.st_uid == uid() && is_lnk(&entry) {
                let _ = cleanup_temp(parent, &Temporary { name, identity });
            }
            return Err("temporary mapping symlink changed while creating".into());
        }
        return Ok(Temporary { name, identity });
    }
    Err("could not allocate a bounded unique temporary mapping name".into())
}

fn cleanup_temp(parent: i32, temporary: &Temporary) -> Result<(), String> {
    let entry = stat_at_io(parent, &temporary.name)
        .map_err(|_| "temporary mapping symlink could not be rechecked".to_string())?;
    if identity(&entry) != temporary.identity || entry.st_uid != uid() || !is_lnk(&entry) {
        return Err("temporary mapping symlink changed before cleanup".into());
    }
    let name = c(&temporary.name)?;
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        return Err("temporary mapping symlink could not be cleaned up".into());
    }
    fsync_dir(parent)
}

fn read_link_at(parent: i32, name: &str) -> Result<String, String> {
    let name = c(name)?;
    let mut buffer = [0_u8; 4096];
    let read = unsafe {
        libc::readlinkat(
            parent,
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if read < 0 || read as usize == buffer.len() {
        return Err("mapping symlink target is invalid".into());
    }
    std::str::from_utf8(&buffer[..read as usize])
        .map(str::to_owned)
        .map_err(|_| "mapping symlink target is invalid".into())
}

fn rename_at2(
    old_parent: i32,
    old_name: &str,
    new_parent: i32,
    new_name: &str,
    flags: u32,
) -> io::Result<()> {
    let old_name = c(old_name).map_err(io::Error::other)?;
    let new_name = c(new_name).map_err(io::Error::other)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fsync_dir(fd: i32) -> Result<(), String> {
    loop {
        if unsafe { libc::fsync(fd) } == 0 {
            return Ok(());
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err("mapping directory could not be synchronized".into());
        }
    }
}

#[cfg(test)]
type TestHook = (std::path::PathBuf, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static COMPETING_FINAL_HOOK: std::sync::Mutex<Option<TestHook>> = std::sync::Mutex::new(None);
#[cfg(test)]
fn competing_final_hook(path: &Path) {
    let hook = {
        let mut pending = COMPETING_FINAL_HOOK.lock().unwrap();
        pending
            .as_ref()
            .is_some_and(|(target, _)| target == path)
            .then(|| pending.take())
            .flatten()
    };
    if let Some((_, hook)) = hook {
        hook();
    }
}
#[cfg(not(test))]
fn competing_final_hook(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        root: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "turbovasctl-feed-mappings-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
            Self { root }
        }
        fn mapping(&self, mapping: Mapping) -> std::path::PathBuf {
            self.root.join(mapping.build_rel)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn failed(outcome: &StepOutcome) -> bool {
        outcome.status == StepStatus::Fail
    }

    #[test]
    fn feed_mappings_create_all_exact_runtime_targets() {
        let fixture = Fixture::new();
        assert!(!failed(&ensure_runtime_feed_mappings(&fixture.root)));
        for mapping in RUNTIME_FEED_MAPPINGS {
            assert_eq!(
                fs::read_link(fixture.mapping(mapping)).unwrap(),
                Path::new(mapping.target)
            );
        }
    }
    #[test]
    fn feed_mappings_are_idempotent() {
        let fixture = Fixture::new();
        assert!(!failed(&ensure_runtime_feed_mappings(&fixture.root)));
        let outcome = ensure_runtime_feed_mappings(&fixture.root);
        assert!(!failed(&outcome));
        assert!(
            outcome
                .findings
                .iter()
                .all(|finding| finding.status == "pass")
        );
    }
    #[test]
    fn feed_mappings_replace_stale_symlink() {
        let fixture = Fixture::new();
        let mapping = RUNTIME_FEED_MAPPINGS[0];
        let stale = fixture.mapping(mapping);
        fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/runtime/feeds/old", &stale).unwrap();
        assert!(!failed(&ensure_runtime_feed_mappings(&fixture.root)));
        assert_eq!(fs::read_link(stale).unwrap(), Path::new(mapping.target));
    }
    #[test]
    fn feed_mappings_replace_an_empty_trusted_directory() {
        let fixture = Fixture::new();
        let mapping = RUNTIME_FEED_MAPPINGS[0];
        let empty = fixture.mapping(mapping);
        fs::create_dir_all(&empty).unwrap();

        let outcome = ensure_runtime_feed_mappings(&fixture.root);

        assert!(!failed(&outcome));
        assert_eq!(fs::read_link(empty).unwrap(), Path::new(mapping.target));
    }
    #[test]
    fn feed_mappings_refuse_regular_file_and_nonempty_directory() {
        let fixture = Fixture::new();
        let regular = fixture.mapping(RUNTIME_FEED_MAPPINGS[0]);
        fs::create_dir_all(regular.parent().unwrap()).unwrap();
        fs::write(&regular, "do not replace").unwrap();
        let nonempty = fixture.mapping(RUNTIME_FEED_MAPPINGS[2]);
        fs::create_dir_all(&nonempty).unwrap();
        fs::write(nonempty.join("keep"), "do not replace").unwrap();
        assert!(failed(&ensure_runtime_feed_mappings(&fixture.root)));
        assert_eq!(fs::read_to_string(regular).unwrap(), "do not replace");
        assert!(nonempty.join("keep").exists());
    }
    #[test]
    fn feed_mappings_refuse_symlink_ancestor() {
        let fixture = Fixture::new();
        let outside = fixture.root.join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, fixture.root.join("build")).unwrap();
        assert!(failed(&ensure_runtime_feed_mappings(&fixture.root)));
        assert!(!outside.join("var").exists());
    }
    #[test]
    fn feed_mappings_refuse_a_world_writable_ancestor() {
        let fixture = Fixture::new();
        let build = fixture.root.join("build");
        fs::create_dir(&build).unwrap();
        fs::set_permissions(&build, fs::Permissions::from_mode(0o777)).unwrap();

        let outcome = ensure_runtime_feed_mappings(&fixture.root);

        assert!(failed(&outcome));
        assert!(!build.join("var").exists());
    }
    #[test]
    fn feed_mappings_do_not_overwrite_a_competing_final_entry() {
        let fixture = Fixture::new();
        let mapping = RUNTIME_FEED_MAPPINGS[0];
        let final_path = fixture.mapping(mapping);
        *COMPETING_FINAL_HOOK.lock().unwrap() = Some((
            final_path.clone(),
            Box::new({
                let final_path = final_path.clone();
                move || fs::write(final_path, "racer").unwrap()
            }),
        ));
        assert!(failed(&ensure_runtime_feed_mappings(&fixture.root)));
        assert_eq!(fs::read_to_string(final_path).unwrap(), "racer");
    }
}
