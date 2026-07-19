// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure, descriptor-anchored construction of an immutable feed generation.

use super::*;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum FaultPoint {
    SyncFilesystem,
    StagingFsync,
    Rename,
    PostInstall,
}

#[cfg(test)]
static FAULT_POINT: std::sync::Mutex<Option<FaultPoint>> = std::sync::Mutex::new(None);
#[cfg(test)]
static COPY_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn take_fault(point: FaultPoint) -> bool {
    let mut configured = FAULT_POINT
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if configured.as_ref() == Some(&point) {
        configured.take();
        true
    } else {
        false
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::MutexGuard;

    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Fixture {
        _serial: MutexGuard<'static, ()>,
        root: PathBuf,
        cache: PathBuf,
        runtime: PathBuf,
        provenance: Vec<Value>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            make_writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn make_writable(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    make_writable(&entry.path());
                }
            }
        } else {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }

    fn write(cache: &Path, relative: &str, payload: &[u8]) {
        let path = cache.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, payload).unwrap();
    }

    fn add_signed_manifest(
        cache: &Path,
        provenance: &mut Vec<Value>,
        class: &str,
        class_root: &str,
        checksums: &str,
        signature: &str,
        payloads: &[&str],
    ) {
        let manifest_parent = Path::new(checksums)
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        let mut rows = String::new();
        for payload in payloads {
            let source = manifest_parent
                .map(|parent| Path::new(class_root).join(parent).join(payload))
                .unwrap_or_else(|| Path::new(class_root).join(payload));
            rows.push_str(&format!(
                "{}  {payload}\n",
                sha(&fs::read(cache.join(source)).unwrap())
            ));
        }
        write(cache, &format!("{class_root}/{checksums}"), rows.as_bytes());
        let signature_payload = format!("fixture-signature-{class}-{checksums}\n");
        write(
            cache,
            &format!("{class_root}/{signature}"),
            signature_payload.as_bytes(),
        );
        let checksums_payload = fs::read(cache.join(class_root).join(checksums)).unwrap();
        let signature_payload = fs::read(cache.join(class_root).join(signature)).unwrap();
        provenance.push(json!({
            "class": class,
            "checksums_path": checksums,
            "signature_path": signature,
            "checksums_sha256": sha(&checksums_payload),
            "signature_sha256": sha(&signature_payload),
            "signing_key_fingerprint": FPR,
        }));
    }

    fn make_fixture(name: &str) -> Fixture {
        let serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = std::env::temp_dir().join(format!(
            "yafvs-feed-stage-{name}-{}-{}",
            std::process::id(),
            STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let cache = root.join("cache");
        let runtime = root.join("runtime");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();

        write(&cache, "openvas/plugins/plugin_feed_info.inc", b"feed\n");
        write(&cache, "openvas/plugins/LICENSE", b"license\n");
        write(&cache, "notus/advisories/advisory.json", b"{}\n");
        write(&cache, "notus/products/product.json", b"{}\n");
        for path in ["LICENSE", "LICENSE.GPLv2", "LICENSE.ODbLv1", "timestamp"] {
            write(
                &cache,
                &format!("notus/{path}"),
                format!("{path}\n").as_bytes(),
            );
        }
        write(&cache, "gvm/scap-data/COPYING", b"copying\n");
        write(&cache, "gvm/scap-data/feed.xml", b"<feed/>\n");
        write(&cache, "gvm/scap-data/timestamp", b"20260718\n");
        write(&cache, "gvm/cert-data/COPYING.CERT-BUND", b"bund\n");
        write(&cache, "gvm/cert-data/COPYING.DFN-CERT", b"dfn\n");
        write(&cache, "gvm/cert-data/feed.xml", b"<feed/>\n");
        write(&cache, "gvm/data-objects/gvmd/22.04/LICENSE", b"license\n");
        write(&cache, "gvm/data-objects/gvmd/22.04/feed.xml", b"<feed/>\n");
        write(
            &cache,
            "gvm/data-objects/gvmd/22.04/timestamp",
            b"20260718\n",
        );
        write(
            &cache,
            "gvm/data-objects/gvmd/22.04/scan-configs/config.xml",
            b"<config/>\n",
        );
        write(
            &cache,
            "gvm/data-objects/gvmd/22.04/report-formats/format.xml",
            b"<format/>\n",
        );
        write(
            &cache,
            "gvm/data-objects/gvmd/22.04/port-lists/list.xml",
            b"<list/>\n",
        );

        let mut provenance = Vec::new();
        add_signed_manifest(
            &cache,
            &mut provenance,
            "nasl",
            "openvas/plugins",
            "sha256sums",
            "sha256sums.asc",
            &["LICENSE", "plugin_feed_info.inc"],
        );
        add_signed_manifest(
            &cache,
            &mut provenance,
            "notus",
            "notus",
            "advisories/sha256sums",
            "advisories/sha256sums.asc",
            &["advisory.json"],
        );
        add_signed_manifest(
            &cache,
            &mut provenance,
            "notus",
            "notus",
            "products/sha256sums",
            "products/sha256sums.asc",
            &["product.json"],
        );
        add_signed_manifest(
            &cache,
            &mut provenance,
            "cert",
            "gvm/cert-data",
            "sha256sums",
            "sha256sums.asc",
            &["COPYING.CERT-BUND", "COPYING.DFN-CERT", "feed.xml"],
        );
        Fixture {
            _serial: serial,
            root,
            cache,
            runtime,
            provenance,
        }
    }

    fn stage(fixture: &Fixture) -> R<Value> {
        stage_generation(
            &fixture.cache,
            &fixture.runtime,
            &fixture.provenance,
            &Limits::default(),
        )
    }

    fn generation_entries(fixture: &Fixture) -> Vec<String> {
        let root = fixture.runtime.join("feed-store/generations");
        let mut entries = fs::read_dir(root)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != ".stage.lock")
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[test]
    fn stages_all_classes_without_changing_selector_and_reuses_duplicate() {
        let fixture = make_fixture("success");
        let store = fixture.runtime.join("feed-store");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        let existing = fixture.root.join("existing-current");
        fs::create_dir(&existing).unwrap();
        symlink(&existing, store.join("current")).unwrap();

        let first = stage(&fixture).unwrap();
        let second = stage(&fixture).unwrap();
        assert_eq!(
            first["generation_id"],
            "9daff8ed0a530138cf6ef069500cc92c1c8d92dc1fb2eb200b3a9ccbb86230b9"
        );
        assert_eq!(first["generation_id"], second["generation_id"]);
        assert_eq!(first["reused"], false);
        assert_eq!(second["reused"], true);
        assert_eq!(first["current_pointer_changed"], false);
        assert_eq!(fs::read_link(store.join("current")).unwrap(), existing);
        let generation = PathBuf::from(first["path"].as_str().unwrap());
        for path in [
            "openvas/plugins/plugin_feed_info.inc",
            "notus/advisories/advisory.json",
            "gvm/scap-data/feed.xml",
            "gvm/cert-data/feed.xml",
            "gvm/data-objects/gvmd/22.04/scan-configs/config.xml",
        ] {
            assert!(generation.join(path).is_file(), "missing {path}");
        }
        assert_eq!(
            fs::metadata(generation).unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert_eq!(generation_entries(&fixture).len(), 1);
    }

    #[test]
    fn payload_change_changes_generation_identifier() {
        let fixture = make_fixture("payload-change");
        let first = stage(&fixture).unwrap();
        write(&fixture.cache, "gvm/scap-data/feed.xml", b"<changed/>\n");
        let second = stage(&fixture).unwrap();
        assert_ne!(first["generation_id"], second["generation_id"]);
    }

    #[test]
    fn missing_marker_and_resource_limits_fail_without_orphans() {
        let fixture = make_fixture("missing-marker");
        fs::remove_file(fixture.cache.join("gvm/scap-data/COPYING")).unwrap();
        assert!(stage(&fixture).unwrap_err().contains("missing marker"));
        assert!(generation_entries(&fixture).is_empty());
        drop(fixture);

        let fixture = make_fixture("limits");
        let limits = Limits {
            files: 1,
            dirs: 1,
            total: 1,
            ..Limits::default()
        };
        assert!(
            stage_generation(
                &fixture.cache,
                &fixture.runtime,
                &fixture.provenance,
                &limits,
            )
            .is_err()
        );
        assert!(generation_entries(&fixture).is_empty());
    }

    #[test]
    fn signed_manifest_changed_after_preflight_provenance_fails_closed() {
        let fixture = make_fixture("stale-provenance");
        fs::write(
            fixture.cache.join("openvas/plugins/sha256sums"),
            b"changed after signature verification\n",
        )
        .unwrap();
        assert!(
            stage(&fixture)
                .unwrap_err()
                .contains("signed provenance file differs from manifest")
        );
        assert!(generation_entries(&fixture).is_empty());
    }

    #[test]
    fn symlink_fifo_and_hardlink_sources_are_rejected() {
        for case in ["symlink", "fifo", "hardlink"] {
            let fixture = make_fixture(case);
            let path = fixture.cache.join(format!("openvas/plugins/bad-{case}"));
            match case {
                "symlink" => symlink("LICENSE", &path).unwrap(),
                "fifo" => {
                    let encoded = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
                }
                "hardlink" => {
                    fs::hard_link(fixture.cache.join("openvas/plugins/LICENSE"), &path).unwrap()
                }
                _ => unreachable!(),
            }
            assert!(stage(&fixture).is_err(), "{case} was accepted");
            assert!(generation_entries(&fixture).is_empty());
            drop(fixture);
        }
    }

    #[test]
    fn depth_limit_and_source_mutation_are_rejected() {
        let fixture = make_fixture("depth");
        let mut relative = PathBuf::from("openvas/plugins");
        for index in 0..65 {
            relative.push(format!("d{index}"));
        }
        write(
            &fixture.cache,
            relative.join("file").to_str().unwrap(),
            b"data",
        );
        assert!(stage(&fixture).unwrap_err().contains("maximum depth"));
        drop(fixture);

        let fixture = make_fixture("mutation");
        let changed = fixture.cache.join("gvm/cert-data/feed.xml");
        *COPY_HOOK.lock().unwrap_or_else(|error| error.into_inner()) = Some(Box::new(move || {
            fs::write(changed, b"<changed/>\n").unwrap();
        }));
        assert!(stage(&fixture).unwrap_err().contains("changed"));
        assert!(generation_entries(&fixture).is_empty());
    }

    #[test]
    fn signed_checksum_coverage_is_exact() {
        let fixture = make_fixture("signed-coverage");
        write(
            &fixture.cache,
            "openvas/plugins/unsigned.nasl",
            b"unsigned\n",
        );
        assert!(stage(&fixture).unwrap_err().contains("exact nasl payload"));
        assert!(generation_entries(&fixture).is_empty());
    }

    fn assert_fault_cleanup(point: FaultPoint) {
        let fixture = make_fixture(match point {
            FaultPoint::SyncFilesystem => "fault-syncfs",
            FaultPoint::StagingFsync => "fault-fsync",
            FaultPoint::Rename => "fault-rename",
            FaultPoint::PostInstall => "fault-post-install",
        });
        *FAULT_POINT
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(point);
        assert!(stage(&fixture).is_err());
        assert!(generation_entries(&fixture).is_empty());
    }

    #[test]
    fn durability_rename_and_post_install_failures_clean_exact_tree() {
        for point in [
            FaultPoint::SyncFilesystem,
            FaultPoint::StagingFsync,
            FaultPoint::Rename,
            FaultPoint::PostInstall,
        ] {
            assert_fault_cleanup(point);
        }
    }

    #[test]
    fn unsafe_lock_and_replaced_cleanup_target_are_rejected() {
        let fixture = make_fixture("unsafe-lock");
        let generations = fixture.runtime.join("feed-store/generations");
        fs::create_dir_all(&generations).unwrap();
        let target = fixture.root.join("lock-target");
        fs::write(&target, b"target").unwrap();
        symlink(&target, generations.join(".stage.lock")).unwrap();
        assert!(stage(&fixture).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"target");
        drop(fixture);

        let fixture = make_fixture("identity-cleanup");
        let parent_path = fixture.root.join("cleanup-parent");
        fs::create_dir(&parent_path).unwrap();
        let parent = absolute_dir(&parent_path).unwrap();
        let first = private_dir(parent.as_raw_fd(), "captured").unwrap();
        let identity = super::identity(&stat(first.as_raw_fd()).unwrap());
        fs::create_dir(parent_path.join("replacement")).unwrap();
        drop(first);
        fs::remove_dir(parent_path.join("captured")).unwrap();
        fs::rename(
            parent_path.join("replacement"),
            parent_path.join("captured"),
        )
        .unwrap();
        assert!(remove_exact(parent.as_raw_fd(), "captured", identity).is_err());
        assert!(parent_path.join("captured").is_dir());
    }

    #[test]
    fn invalid_provenance_is_rejected_before_store_creation() {
        let fixture = make_fixture("provenance");
        let mut invalid = fixture.provenance.clone();
        invalid[0]["checksums_sha256"] = Value::String("A".repeat(64));
        assert!(
            stage_generation(
                &fixture.cache,
                &fixture.runtime,
                &invalid,
                &Limits::default(),
            )
            .unwrap_err()
            .contains("provenance is invalid")
        );
        assert!(!fixture.runtime.join("feed-store").exists());
    }
}

#[cfg(test)]
fn run_copy_hook() {
    if let Some(hook) = COPY_HOOK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
        hook();
    }
}

#[cfg(not(test))]
fn run_copy_hook() {}

fn private_dir(fd: i32, name: &str) -> R<OwnedFd> {
    match c(name).and_then(|n| {
        let r = unsafe { libc::mkdirat(fd, n.as_ptr(), 0o700) };
        if r == 0 || io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(err("could not create private directory"))
        }
    }) {
        Ok(()) => {}
        Err(e) => return Err(e),
    }
    let child = open_dir_at(fd, name)?;
    let s = stat(child.as_raw_fd())?;
    if s.st_uid != uid() {
        return Err(format!("directory is not owned by current user: {name}"));
    }
    if unsafe { libc::fchmod(child.as_raw_fd(), 0o700) } != 0 {
        return Err(err("could not secure private directory"));
    }
    Ok(child)
}

fn ensure_path(fd: i32, parts: &[&str]) -> R<OwnedFd> {
    let raw = unsafe { libc::dup(fd) };
    if raw < 0 {
        return Err(err("could not duplicate directory descriptor"));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    for part in parts {
        current = private_dir(current.as_raw_fd(), part)?;
    }
    Ok(current)
}

fn lock(generations: i32) -> R<OwnedFd> {
    let parent = stat(generations)?;
    if parent.st_uid != uid() || mode(&parent) & 0o077 != 0 {
        return Err("feed generation store must be private and user-owned".into());
    }
    let name = c(".stage.lock")?;
    let raw = unsafe {
        libc::openat(
            generations,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if raw < 0 {
        return Err(err("could not open feed generation lock"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let s = stat(fd.as_raw_fd())?;
    if !is_reg(&s) || s.st_uid != uid() || s.st_nlink != 1 {
        return Err("feed generation lock file is unsafe".into());
    }
    if unsafe { libc::fchmod(fd.as_raw_fd(), 0o600) } != 0 {
        return Err(err("could not secure feed generation lock"));
    }
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(err("could not lock feed generation store"));
    }
    Ok(fd)
}

fn class_inventory(cache: i32, spec: &Spec, limits: &Limits) -> R<Inventory> {
    let source = parts(spec.source, limits)?;
    let fd = beneath(cache, &source)?;
    let inventory = inventory(fd.as_raw_fd(), limits)?;
    if inventory.files.is_empty() {
        return Err(format!("{} feed class is empty", spec.key));
    }
    let available: BTreeSet<_> = inventory
        .files
        .iter()
        .chain(&inventory.dirs)
        .map(|x| x.path.as_str())
        .collect();
    for marker in spec.markers {
        if !available.contains(*marker) {
            return Err(format!(
                "{} feed class is missing marker: {marker}",
                spec.key
            ));
        }
    }
    Ok(inventory)
}

fn copy_file(
    cache: i32,
    staging: i32,
    source: &str,
    destination: &str,
    expected: &Snap,
    limits: &Limits,
) -> R<String> {
    let input_parts = parts(source, limits)?;
    let output_parts = parts(destination, limits)?;
    let parent = beneath(cache, &input_parts[..input_parts.len() - 1])?;
    let target = beneath(staging, &output_parts[..output_parts.len() - 1])?;
    let before = stat_at(parent.as_raw_fd(), input_parts[input_parts.len() - 1])?;
    if !is_reg(&before) || !same(expected, &snap(expected.path.clone(), true, &before)) {
        return Err(format!("source file changed before copy: {source}"));
    }
    let input = open_at(
        parent.as_raw_fd(),
        input_parts[input_parts.len() - 1],
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    if !same(
        expected,
        &snap(expected.path.clone(), true, &stat(input.as_raw_fd())?),
    ) {
        return Err(format!("source file changed while opening: {source}"));
    }
    let n = c(output_parts[output_parts.len() - 1])?;
    let raw = unsafe {
        libc::openat(
            target.as_raw_fd(),
            n.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if raw < 0 {
        return Err(err("could not create staged feed file"));
    }
    let output = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut copied = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; CHUNK];
    loop {
        let r = unsafe { libc::read(input.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if r < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err("could not read feed source"));
        }
        if r == 0 {
            break;
        }
        let chunk = &buffer[..r as usize];
        copied += chunk.len() as u64;
        if copied > expected.size {
            return Err(format!("source file grew while copying: {source}"));
        }
        digest.update(chunk);
        let mut done = 0;
        while done < chunk.len() {
            let w = unsafe {
                libc::write(
                    output.as_raw_fd(),
                    chunk[done..].as_ptr().cast(),
                    chunk.len() - done,
                )
            };
            if w <= 0 {
                return Err("short write while copying staged feed file".into());
            }
            done += w as usize;
        }
    }
    if copied != expected.size
        || !same(
            expected,
            &snap(expected.path.clone(), true, &stat(input.as_raw_fd())?),
        )
    {
        return Err(format!("source file changed while copying: {source}"));
    }
    run_copy_hook();
    Ok(format!("{:x}", digest.finalize()))
}

fn write_manifest(staging: i32, value: &Value) -> R<()> {
    let mut canonical_value = String::new();
    canonical(value, &mut canonical_value);
    canonical_value.push('\n');
    if canonical_value.len() as u64 > MAX_MANIFEST {
        return Err("generation manifest exceeds size limit".into());
    }
    let name = c(MANIFEST)?;
    let raw = unsafe {
        libc::openat(
            staging,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if raw < 0 {
        return Err(err("could not create generation manifest"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let bytes = canonical_value.as_bytes();
    let mut done = 0;
    while done < bytes.len() {
        let w = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[done..].as_ptr().cast(),
                bytes.len() - done,
            )
        };
        if w <= 0 {
            return Err("short write while writing generation manifest".into());
        }
        done += w as usize;
    }
    Ok(())
}

fn seal(fd: i32) -> R<()> {
    for name in names(fd)? {
        let before = stat_at(fd, &name)?;
        if is_lnk(&before) {
            return Err(format!("symbolic link appeared while sealing: {name}"));
        }
        if is_reg(&before) {
            let child = open_at(
                fd,
                &name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )?;
            if unsafe { libc::fchmod(child.as_raw_fd(), 0o444) } != 0 {
                return Err(err("could not seal generation file"));
            }
        } else if is_dir(&before) {
            let child = open_dir_at(fd, &name)?;
            seal(child.as_raw_fd())?;
        } else {
            return Err(format!("special file appeared while sealing: {name}"));
        }
    }
    if unsafe { libc::fchmod(fd, 0o500) } != 0 {
        return Err(err("could not seal generation directory"));
    }
    Ok(())
}

fn sync(fd: i32) -> R<()> {
    #[cfg(test)]
    if take_fault(FaultPoint::SyncFilesystem) {
        return Err("injected syncfs failure".into());
    }
    if unsafe { libc::syncfs(fd) } != 0 {
        return Err(err("could not sync staged generation filesystem"));
    }
    #[cfg(test)]
    if take_fault(FaultPoint::StagingFsync) {
        return Err("injected staging fsync failure".into());
    }
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(err("could not sync staged generation"));
    }
    Ok(())
}

fn rename_noreplace(parent: i32, source: &str, destination: &str) -> io::Result<()> {
    #[cfg(test)]
    if take_fault(FaultPoint::Rename) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    let source = c(source).map_err(io::Error::other)?;
    let destination = c(destination).map_err(io::Error::other)?;
    if unsafe {
        libc::renameat2(
            parent,
            source.as_ptr(),
            parent,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove_exact(parent: i32, name: &str, expected: (u64, u64)) -> R<()> {
    let entry = stat_at(parent, name)?;
    if !is_dir(&entry) || identity(&entry) != expected {
        return Err("refusing to remove a generation whose identity changed".into());
    }
    let fd = open_dir_at(parent, name)?;
    if identity(&stat(fd.as_raw_fd())?) != expected {
        return Err("refusing to remove a generation whose identity changed".into());
    }
    if unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
        return Err(err("could not make staged generation removable"));
    }
    for child in names(fd.as_raw_fd())? {
        let s = stat_at(fd.as_raw_fd(), &child)?;
        if is_dir(&s) {
            remove_exact(fd.as_raw_fd(), &child, identity(&s))?;
        } else {
            let c = c(&child)?;
            if unsafe { libc::unlinkat(fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
                return Err(err("could not remove staged feed file"));
            }
        }
    }
    let n = c(name)?;
    if unsafe { libc::unlinkat(parent, n.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(err("could not remove staged generation directory"));
    }
    Ok(())
}

fn create_staging(generations: i32) -> R<(String, OwnedFd, (u64, u64))> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..64 {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".staging-{}-{epoch}-{sequence}", std::process::id());
        let encoded = c(&name)?;
        if unsafe { libc::mkdirat(generations, encoded.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(format!("could not create staging directory: {error}"));
        }
        let directory = open_dir_at(generations, &name)?;
        let metadata = stat(directory.as_raw_fd())?;
        if metadata.st_uid != uid() || mode(&metadata) & 0o077 != 0 {
            return Err("new staging directory is not private and user-owned".into());
        }
        return Ok((name, directory, identity(&metadata)));
    }
    Err("could not allocate a unique staging directory".into())
}

fn cleanup_captured(
    generations: i32,
    staging_name: &str,
    generation_id: Option<&str>,
    expected: (u64, u64),
) -> R<()> {
    match stat_at_io(generations, staging_name) {
        Ok(metadata) => {
            if identity(&metadata) != expected {
                return Err("refusing to remove a replaced staging generation".into());
            }
            remove_exact(generations, staging_name, expected)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(generation_id) = generation_id {
                match stat_at_io(generations, generation_id) {
                    Ok(metadata) if identity(&metadata) == expected => {
                        remove_exact(generations, generation_id, expected)?;
                    }
                    Ok(_) | Err(_) => {}
                }
            }
        }
        Err(error) => return Err(format!("could not inspect staging cleanup target: {error}")),
    }
    if unsafe { libc::fsync(generations) } != 0 {
        return Err(err("could not durably clean staging generation"));
    }
    Ok(())
}

fn timestamp() -> String {
    let s = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        s.year(),
        u8::from(s.month()),
        s.day(),
        s.hour(),
        s.minute(),
        s.second()
    )
}

/// Builds, seals, verifies, and installs a content-addressed generation without changing `current`.
pub(super) fn stage_generation(
    cache_root: &Path,
    runtime_root: &Path,
    signature_provenance: &[Value],
    limits: &Limits,
) -> R<Value> {
    let specs = specs();
    if specs.iter().map(|x| x.key).collect::<BTreeSet<_>>().len() != specs.len() {
        return Err("feed class specification is empty or duplicated".into());
    }
    let expected: BTreeSet<_> = specs
        .iter()
        .flat_map(|s| s.signed.iter().map(move |(c, g)| (s.key, *c, *g)))
        .collect();
    let mut got = BTreeSet::new();
    for row in signature_provenance {
        let q = row
            .as_object()
            .ok_or("verified signature provenance is invalid")?;
        if !exact_keys(
            q,
            &[
                "class",
                "checksums_path",
                "signature_path",
                "checksums_sha256",
                "signature_sha256",
                "signing_key_fingerprint",
            ],
        ) || !digest(&q["checksums_sha256"])
            || !digest(&q["signature_sha256"])
        {
            return Err("verified signature provenance is invalid".into());
        }
        let pair = (
            strv(q, "class")?,
            strv(q, "checksums_path")?,
            strv(q, "signature_path")?,
        );
        if q["signing_key_fingerprint"].as_str() != Some(FPR)
            || !expected.contains(&pair)
            || !got.insert(pair)
        {
            return Err(
                "verified signature provenance differs from configured feed classes".into(),
            );
        }
    }
    if got != expected || got.len() != signature_provenance.len() {
        return Err("verified signature provenance is incomplete or duplicated".into());
    }
    let cache = absolute_dir(cache_root)?;
    let runtime = absolute_dir(runtime_root)?;
    if stat(runtime.as_raw_fd())?.st_uid != uid() {
        return Err("runtime root is not owned by the current user".into());
    }
    let store = private_dir(runtime.as_raw_fd(), "feed-store")?;
    let generations = private_dir(store.as_raw_fd(), "generations")?;
    let _lock = lock(generations.as_raw_fd())?;
    let inventories: Vec<_> = specs
        .iter()
        .map(|s| class_inventory(cache.as_raw_fd(), s, limits))
        .collect::<R<_>>()?;
    let files: usize = inventories.iter().map(|i| i.files.len()).sum();
    let dirs: usize = inventories.iter().map(|i| i.dirs.len()).sum();
    let bytes: u64 = inventories.iter().map(|i| i.total).sum();
    if files > limits.files || dirs > limits.dirs || bytes > limits.total {
        return Err("combined feed classes exceed configured limits".into());
    }
    let (staging_name, staging, staging_id) = create_staging(generations.as_raw_fd())?;
    let mut cleanup_needed = true;
    let mut generation_id: Option<String> = None;
    let result = (|| -> R<Value> {
        let mut class_rows = Vec::new();
        let mut file_rows = Vec::new();
        for (spec, inv) in specs.iter().zip(&inventories) {
            let runtime_parts = parts(spec.runtime, limits)?;
            ensure_path(staging.as_raw_fd(), &runtime_parts)?;
            for d in &inv.dirs {
                let mut p = runtime_parts.clone();
                p.extend(parts(&d.path, limits)?);
                ensure_path(staging.as_raw_fd(), &p)?;
            }
            for source in &inv.files {
                let source_path = format!("{}/{}", spec.source, source.path);
                let runtime_path = format!("{}/{}", spec.runtime, source.path);
                let hash = copy_file(
                    cache.as_raw_fd(),
                    staging.as_raw_fd(),
                    &source_path,
                    &runtime_path,
                    source,
                    limits,
                )?;
                file_rows.push(json!({"class":spec.key,"path":source.path,"runtime_path":runtime_path,"sha256":hash,"size":source.size}));
            }
            class_rows.push(json!({"key":spec.key,"source_rel":spec.source,"runtime_rel":spec.runtime,"markers":spec.markers,"signed_manifests":spec.signed.iter().map(|(checksums,signature)|json!({"checksums":checksums,"signature":signature})).collect::<Vec<_>>(),"signing_key_fingerprint":if spec.signed.is_empty(){Value::Null}else{json!(FPR)},"unsigned_metadata":spec.unsigned,"file_count":inv.files.len(),"byte_count":inv.total,"directories":inv.dirs.iter().map(|x|x.path.clone()).collect::<Vec<_>>() }));
        }
        for (spec, inv) in specs.iter().zip(&inventories) {
            let later = class_inventory(cache.as_raw_fd(), spec, limits)?;
            if later.files.len() != inv.files.len()
                || later.dirs.len() != inv.dirs.len()
                || !later.files.iter().zip(&inv.files).all(|(a, b)| same(a, b))
                || !later.dirs.iter().zip(&inv.dirs).all(|(a, b)| same(a, b))
            {
                return Err(format!("{} feed class changed while staging", spec.key));
            }
        }
        file_rows.sort_by(|a, b| {
            (a["class"].as_str(), a["path"].as_str())
                .cmp(&(b["class"].as_str(), b["path"].as_str()))
        });
        class_rows.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
        let mut provenance = signature_provenance.to_vec();
        provenance.sort_by(|a, b| {
            (a["class"].as_str(), a["checksums_path"].as_str())
                .cmp(&(b["class"].as_str(), b["checksums_path"].as_str()))
        });
        let content = json!({"schema_version":1,"feed_release":RELEASE,"classes":class_rows,"files":file_rows,"signature_provenance":provenance});
        let mut canon = String::new();
        canonical(&content, &mut canon);
        let id = sha(canon.as_bytes());
        generation_id = Some(id.clone());
        let manifest = json!({"schema_version":1,"feed_release":RELEASE,"classes":content["classes"],"files":content["files"],"signature_provenance":content["signature_provenance"],"generation_id":id,"created_at":timestamp(),"source_snapshot":{"class_count":5,"file_count":files,"byte_count":bytes}});
        write_manifest(staging.as_raw_fd(), &manifest)?;
        seal(staging.as_raw_fd())?;
        sync(staging.as_raw_fd())?;
        verify_entry(
            &runtime_root.join("feed-store/generations"),
            &id,
            &staging_name,
            limits,
        )?;
        let reused = match rename_noreplace(generations.as_raw_fd(), &staging_name, &id) {
            Ok(()) => false,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                verify(&runtime_root.join("feed-store/generations"), &id, limits)?;
                remove_exact(generations.as_raw_fd(), &staging_name, staging_id)?;
                cleanup_needed = false;
                true
            }
            Err(error) => return Err(format!("could not install staged generation: {error}")),
        };
        if unsafe { libc::fsync(generations.as_raw_fd()) } != 0 {
            return Err(err("could not sync generation store"));
        }
        #[cfg(test)]
        if take_fault(FaultPoint::PostInstall) {
            return Err("injected post-install verification failure".into());
        }
        let verified = verify(&runtime_root.join("feed-store/generations"), &id, limits)?;
        cleanup_needed = false;
        Ok(
            json!({"generation_id":verified["generation_id"],"feed_release":verified["feed_release"],"file_count":verified["file_count"],"byte_count":verified["byte_count"],"class_count":verified["class_count"],"created_at":verified["created_at"],"verified":true,"path":runtime_root.join("feed-store/generations").join(&id),"reused":reused,"current_pointer_changed":false}),
        )
    })();
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if cleanup_needed
                && let Err(cleanup) = cleanup_captured(
                    generations.as_raw_fd(),
                    &staging_name,
                    generation_id.as_deref(),
                    staging_id,
                )
            {
                return Err(format!(
                    "{error}; failed to remove incomplete staging generation {staging_name}: {cleanup}"
                ));
            }
            Err(error)
        }
    }
}
