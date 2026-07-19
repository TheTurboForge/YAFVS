// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transactional selection of fully verified immutable feed generations.

use super::{
    Limits, R, absolute_dir, digest, identity, is_dir, is_lnk, is_reg, mode, open_dir_at,
    path_is_missing, selector, stat, stat_at, uid, verify,
};
use serde_json::{Value, json};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Store {
    path: PathBuf,
    generations_path: PathBuf,
    store: OwnedFd,
    generations: OwnedFd,
}

struct TempSelector {
    name: String,
    identity: (u64, u64),
    descriptor: OwnedFd,
}

fn last_error(context: &str) -> String {
    format!("{context}: {}", io::Error::last_os_error())
}

fn validate_opened_lock(lock: i32) -> R<()> {
    let opened = stat(lock)?;
    if !is_reg(&opened) || opened.st_uid != uid() || opened.st_nlink != 1 {
        return Err("feed generation lock is not an owner-only single-link regular file".into());
    }
    Ok(())
}

fn private_user_directory(fd: i32) -> R<()> {
    let metadata = stat(fd)?;
    if !is_dir(&metadata) || metadata.st_uid != uid() || mode(&metadata) & 0o077 != 0 {
        return Err("feed generation store is not private and user-owned".into());
    }
    Ok(())
}

fn open_store(runtime_root: &Path) -> R<Store> {
    let path = runtime_root.join("feed-store");
    let store = absolute_dir(&path)?;
    private_user_directory(store.as_raw_fd())?;
    let generations = open_dir_at(store.as_raw_fd(), "generations")?;
    private_user_directory(generations.as_raw_fd())?;
    Ok(Store {
        generations_path: path.join("generations"),
        path,
        store,
        generations,
    })
}

fn validate_lock(generations: i32, lock: i32) -> R<()> {
    let opened = stat(lock)?;
    let entry = stat_at(generations, ".stage.lock")?;
    if !is_reg(&opened)
        || !is_reg(&entry)
        || opened.st_uid != uid()
        || entry.st_uid != uid()
        || mode(&opened) & 0o077 != 0
        || mode(&entry) & 0o077 != 0
        || opened.st_nlink != 1
        || entry.st_nlink != 1
        || (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino)
    {
        return Err("feed generation lock is not an owner-only single-link regular file".into());
    }
    Ok(())
}

fn lock_store(generations: i32) -> R<OwnedFd> {
    let name = CString::new(".stage.lock").unwrap();
    let raw = unsafe {
        libc::openat(
            generations,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if raw < 0 {
        return Err(last_error("could not open feed generation lock"));
    }
    let lock = unsafe { OwnedFd::from_raw_fd(raw) };
    validate_opened_lock(lock.as_raw_fd())?;
    if unsafe { libc::fchmod(lock.as_raw_fd(), 0o600) } != 0 {
        return Err(last_error("could not normalize feed generation lock"));
    }
    validate_lock(generations, lock.as_raw_fd())?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(format!("could not lock feed generation store: {error}"));
        }
    }
    validate_lock(generations, lock.as_raw_fd())?;
    Ok(lock)
}

fn fsync_directory(fd: i32) -> R<()> {
    if unsafe { libc::fsync(fd) } != 0 {
        Err(last_error("could not synchronize feed generation store"))
    } else {
        Ok(())
    }
}

fn read_link_at(fd: i32, name: &str) -> R<String> {
    let name = CString::new(name).map_err(|_| "temporary selector name is unsafe")?;
    let mut buffer = [0u8; 256];
    let length =
        unsafe { libc::readlinkat(fd, name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if length < 0 {
        return Err(last_error(
            "could not read temporary feed generation selector",
        ));
    }
    if length as usize == buffer.len() {
        return Err("temporary feed generation selector target is invalid".into());
    }
    std::str::from_utf8(&buffer[..length as usize])
        .map(str::to_owned)
        .map_err(|_| "temporary feed generation selector target is invalid".into())
}

fn unlink_at(fd: i32, name: &str) -> R<()> {
    let name = CString::new(name).map_err(|_| "selector name is unsafe")?;
    if unsafe { libc::unlinkat(fd, name.as_ptr(), 0) } != 0 {
        Err(last_error("could not remove feed generation selector"))
    } else {
        Ok(())
    }
}

fn temp_metadata(store: i32, name: &str) -> R<Option<libc::stat>> {
    let name = CString::new(name).map_err(|_| "temporary selector name is unsafe")?;
    let mut metadata = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            store,
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        Ok(Some(metadata))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(format!(
                "could not inspect temporary feed generation selector: {error}"
            ))
        }
    }
}

fn validate_temp_selector(store: i32, temporary: &TempSelector, target: &str) -> R<()> {
    let opened = stat(temporary.descriptor.as_raw_fd())?;
    let entry = temp_metadata(store, &temporary.name)?
        .ok_or_else(|| "temporary feed generation selector disappeared".to_owned())?;
    if identity(&opened) != temporary.identity
        || identity(&entry) != temporary.identity
        || !is_lnk(&opened)
        || !is_lnk(&entry)
        || opened.st_uid != uid()
        || entry.st_uid != uid()
        || read_link_at(store, &temporary.name)? != target
    {
        return Err("temporary feed generation selector is unsafe".into());
    }
    Ok(())
}

fn cleanup_temp_selector(store: i32, temporary: &TempSelector) -> R<()> {
    let Some(entry) = temp_metadata(store, &temporary.name)? else {
        return Ok(());
    };
    if identity(&entry) != temporary.identity {
        return Err("temporary feed generation selector was replaced before cleanup".into());
    }
    unlink_at(store, &temporary.name)?;
    fsync_directory(store)
}

fn create_temp_selector(store: i32, target: &str) -> R<TempSelector> {
    let target_c = CString::new(target).unwrap();
    for _ in 0..128 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".current-{}-{sequence:016x}", std::process::id());
        let encoded = CString::new(name.as_str()).unwrap();
        if unsafe { libc::symlinkat(target_c.as_ptr(), store, encoded.as_ptr()) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(format!(
                "could not create temporary feed generation selector: {error}"
            ));
        }
        let raw = unsafe {
            libc::openat(
                store,
                encoded.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(last_error(
                "could not retain temporary feed generation selector",
            ));
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let opened = stat(descriptor.as_raw_fd())?;
        let temporary = TempSelector {
            name,
            identity: identity(&opened),
            descriptor,
        };
        return match validate_temp_selector(store, &temporary, target) {
            Ok(()) => Ok(temporary),
            Err(error) => match cleanup_temp_selector(store, &temporary) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; temporary selector cleanup failed: {cleanup}"
                )),
            },
        };
    }
    Err("could not allocate temporary feed generation selector".into())
}

#[cfg(test)]
static BEFORE_RENAME_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn before_rename_hook() {
    if let Some(action) = BEFORE_RENAME_HOOK.lock().unwrap().take() {
        action();
    }
}

#[cfg(not(test))]
fn before_rename_hook() {}

fn replace_current_selector(store: i32, generation_id: &str) -> R<()> {
    let target = format!("generations/{generation_id}");
    let temporary = create_temp_selector(store, &target)?;
    let mut replaced = false;
    let result = (|| {
        before_rename_hook();
        validate_temp_selector(store, &temporary, &target)?;
        let temporary_c = CString::new(temporary.name.as_str()).unwrap();
        let current_c = CString::new("current").unwrap();
        if unsafe { libc::renameat(store, temporary_c.as_ptr(), store, current_c.as_ptr()) } != 0 {
            return Err(last_error(
                "could not replace current feed generation selector",
            ));
        }
        replaced = true;
        fsync_directory(store)
    })();
    if let Err(error) = result {
        if !replaced {
            return match cleanup_temp_selector(store, &temporary) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!(
                    "{error}; temporary selector cleanup failed: {cleanup}"
                )),
            };
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone)]
struct FaultPlan {
    store: PathBuf,
    post_replace: bool,
    restore: bool,
}

#[cfg(test)]
static FAULT_PLAN: std::sync::Mutex<Option<FaultPlan>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn injected_failure(store: &Path, restoring: bool) -> R<()> {
    let mut plan = FAULT_PLAN.lock().unwrap();
    let Some(active) = plan.as_mut().filter(|active| active.store == store) else {
        return Ok(());
    };
    let requested = if restoring {
        &mut active.restore
    } else {
        &mut active.post_replace
    };
    if !*requested {
        return Ok(());
    }
    *requested = false;
    let message = if restoring {
        "injected selector restoration failure"
    } else {
        "injected post-replace selection failure"
    };
    Err(message.into())
}

#[cfg(not(test))]
fn injected_failure(_: &Path, _: bool) -> R<()> {
    Ok(())
}

fn clear_if_expected(store: i32, expected_generation_id: &str) -> R<()> {
    if selector(store)? != Some(expected_generation_id.to_owned()) {
        return Err("current feed generation differs from the expected selector".into());
    }
    unlink_at(store, "current")?;
    fsync_directory(store)
}

fn restore_absent_selector(store: i32, selected_generation_id: &str) -> R<()> {
    match selector(store)? {
        None => Ok(()),
        Some(observed) if observed == selected_generation_id => {
            unlink_at(store, "current")?;
            fsync_directory(store)
        }
        Some(_) => Err("current feed generation changed while restoring an absent selector".into()),
    }
}

pub(super) fn read_current_generation(runtime_root: &Path, limits: &Limits) -> R<Option<Value>> {
    let store_path = runtime_root.join("feed-store");
    let store = match absolute_dir(&store_path) {
        Ok(store) => store,
        Err(_) if path_is_missing(&store_path) => return Ok(None),
        Err(error) => return Err(error),
    };
    private_user_directory(store.as_raw_fd())?;
    let Some(generation_id) = selector(store.as_raw_fd())? else {
        return Ok(None);
    };
    let generations = open_dir_at(store.as_raw_fd(), "generations")?;
    private_user_directory(generations.as_raw_fd())?;
    let generations_path = store_path.join("generations");
    let verified = verify(&generations_path, &generation_id, limits)?;
    if selector(store.as_raw_fd())? != Some(generation_id) {
        return Err("current feed generation selector changed while verifying".into());
    }
    Ok(Some(verified))
}

/// Read only the safely resolved immutable-generation reference.
///
/// This deliberately does not inventory or hash generation contents. Runtime
/// callers use it to reject a missing, unsafe, or journal-mismatched selector
/// before paying for full content verification. Starting app services still
/// requires `read_current_generation` and its complete verification pass.
pub(super) fn read_current_generation_reference(runtime_root: &Path) -> R<Option<Value>> {
    let store_path = runtime_root.join("feed-store");
    let store = match absolute_dir(&store_path) {
        Ok(store) => store,
        Err(_) if path_is_missing(&store_path) => return Ok(None),
        Err(error) => return Err(error),
    };
    private_user_directory(store.as_raw_fd())?;
    let Some(generation_id) = selector(store.as_raw_fd())? else {
        return Ok(None);
    };
    let generations = open_dir_at(store.as_raw_fd(), "generations")?;
    private_user_directory(generations.as_raw_fd())?;
    let entry = stat_at(generations.as_raw_fd(), &generation_id)?;
    let opened = open_dir_at(generations.as_raw_fd(), &generation_id)?;
    let opened_stat = stat(opened.as_raw_fd())?;
    if !is_dir(&entry)
        || !is_dir(&opened_stat)
        || identity(&entry) != identity(&opened_stat)
        || opened_stat.st_uid != uid()
        || mode(&opened_stat) & 0o222 != 0
    {
        return Err("current feed generation reference is unsafe".into());
    }
    if selector(store.as_raw_fd())? != Some(generation_id.clone()) {
        return Err("current feed generation selector changed while resolving".into());
    }
    Ok(Some(json!({
        "generation_id": generation_id,
        "verified": false,
    })))
}

pub(super) fn select_generation(
    runtime_root: &Path,
    generation_id: &str,
    limits: &Limits,
) -> R<Value> {
    if !digest(&Value::String(generation_id.to_owned())) {
        return Err("feed generation identifier is invalid".into());
    }
    let opened = open_store(runtime_root)?;
    let _lock = lock_store(opened.generations.as_raw_fd())?;
    let previous_generation_id = selector(opened.store.as_raw_fd())?;
    if let Some(previous) = previous_generation_id.as_deref() {
        verify(&opened.generations_path, previous, limits)?;
    }
    let mut verified = verify(&opened.generations_path, generation_id, limits)?;
    let selection: R<()> = (|| {
        replace_current_selector(opened.store.as_raw_fd(), generation_id)?;
        injected_failure(&opened.path, false)?;
        let selected = read_current_generation(runtime_root, limits)?.ok_or_else(|| {
            "feed generation selector did not retain the requested generation".to_owned()
        })?;
        if selected["generation_id"] != generation_id {
            return Err("feed generation selector did not retain the requested generation".into());
        }
        Ok(())
    })();
    if let Err(selection_error) = selection {
        let restoration = (|| {
            injected_failure(&opened.path, true)?;
            if let Some(previous) = previous_generation_id.as_deref() {
                replace_current_selector(opened.store.as_raw_fd(), previous)
            } else {
                restore_absent_selector(opened.store.as_raw_fd(), generation_id)
            }
        })();
        return match restoration {
            Ok(()) => Err(format!(
                "feed generation selection failed; prior selector was restored: {selection_error}"
            )),
            Err(restoration_error) => Err(format!(
                "feed generation selection failed: {selection_error}; prior selector restoration failed: {restoration_error}"
            )),
        };
    }
    let object = verified
        .as_object_mut()
        .ok_or_else(|| "verified generation result is not an object".to_owned())?;
    object.insert(
        "previous_generation_id".into(),
        previous_generation_id.map_or(Value::Null, Value::String),
    );
    object.insert(
        "current_generation_id".into(),
        Value::String(generation_id.to_owned()),
    );
    Ok(verified)
}

pub(super) fn clear_current_generation(runtime_root: &Path, expected_generation_id: &str) -> R<()> {
    if !digest(&Value::String(expected_generation_id.to_owned())) {
        return Err("expected feed generation identifier is invalid".into());
    }
    let opened = open_store(runtime_root)?;
    let _lock = lock_store(opened.generations.as_raw_fd())?;
    clear_if_expected(opened.store.as_raw_fd(), expected_generation_id)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{cleanup_tree, valid_generation};
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    fn cleanup(root: &Path) {
        cleanup_tree(root);
        fs::remove_dir_all(root).unwrap();
    }

    fn set_fault(root: &Path, restore: bool) {
        *FAULT_PLAN.lock().unwrap() = Some(FaultPlan {
            store: root.join("feed-store"),
            post_replace: true,
            restore,
        });
    }

    #[test]
    fn selection_succeeds_and_reports_previous_id() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("select-success");
        let first = select_generation(&root, &id, &Limits::default()).unwrap();
        assert_eq!(first["previous_generation_id"], Value::Null);
        assert_eq!(first["current_generation_id"], id);
        let second = select_generation(&root, &id, &Limits::default()).unwrap();
        assert_eq!(second["previous_generation_id"], id);
        assert_eq!(second["current_generation_id"], id);
        cleanup(&root);
    }

    #[test]
    fn invalid_identifiers_are_rejected() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, _) = valid_generation("invalid-id");
        assert_eq!(
            select_generation(&root, "ABC", &Limits::default()).unwrap_err(),
            "feed generation identifier is invalid"
        );
        assert_eq!(
            clear_current_generation(&root, "ABC").unwrap_err(),
            "expected feed generation identifier is invalid"
        );
        cleanup(&root);
    }

    #[test]
    fn unsafe_selector_and_non_private_store_are_rejected() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, _) = valid_generation("unsafe-selector");
        let store = root.join("feed-store");
        fs::write(store.join("current"), b"unsafe").unwrap();
        assert!(
            read_current_generation(&root, &Limits::default())
                .unwrap_err()
                .contains("not a user-owned symlink")
        );
        assert!(
            read_current_generation_reference(&root)
                .unwrap_err()
                .contains("not a user-owned symlink")
        );
        fs::remove_file(store.join("current")).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            read_current_generation(&root, &Limits::default()).unwrap_err(),
            "feed generation store is not private and user-owned"
        );
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        cleanup(&root);
    }

    #[test]
    fn current_reference_is_structural_and_full_read_still_hashes_payload() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("reference-vs-verification");
        symlink(format!("generations/{id}"), root.join("feed-store/current")).unwrap();

        let reference = read_current_generation_reference(&root).unwrap().unwrap();
        assert_eq!(reference["generation_id"], id);
        assert_eq!(reference["verified"], false);

        let payload = root
            .join("feed-store/generations")
            .join(&id)
            .join("openvas/plugins/plugin_feed_info.inc");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&payload, b"tampered-but-sealed").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o444)).unwrap();

        assert_eq!(
            read_current_generation_reference(&root).unwrap().unwrap()["generation_id"],
            id
        );
        assert!(read_current_generation(&root, &Limits::default()).is_err());
        cleanup(&root);
    }

    #[test]
    fn current_reference_rejects_a_writable_generation_root() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("writable-reference");
        symlink(format!("generations/{id}"), root.join("feed-store/current")).unwrap();
        let generation = root.join("feed-store/generations").join(&id);
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            read_current_generation_reference(&root).unwrap_err(),
            "current feed generation reference is unsafe"
        );
        cleanup(&root);
    }

    #[test]
    fn first_selection_can_be_cleared() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("select-clear");
        select_generation(&root, &id, &Limits::default()).unwrap();
        assert_eq!(
            read_current_generation(&root, &Limits::default())
                .unwrap()
                .unwrap()["generation_id"],
            id
        );
        clear_current_generation(&root, &id).unwrap();
        assert!(
            read_current_generation(&root, &Limits::default())
                .unwrap()
                .is_none()
        );
        cleanup(&root);
    }

    #[test]
    fn clear_rejects_a_selector_mismatch() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("clear-mismatch");
        select_generation(&root, &id, &Limits::default()).unwrap();
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            clear_current_generation(&root, other).unwrap_err(),
            "current feed generation differs from the expected selector"
        );
        assert_eq!(
            read_current_generation(&root, &Limits::default())
                .unwrap()
                .unwrap()["generation_id"],
            id
        );
        cleanup(&root);
    }

    #[test]
    fn post_replace_failure_restores_the_prior_selector() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("restore-prior");
        symlink(format!("generations/{id}"), root.join("feed-store/current")).unwrap();
        set_fault(&root, false);
        let error = select_generation(&root, &id, &Limits::default()).unwrap_err();
        assert!(error.contains("injected post-replace selection failure"));
        assert!(error.contains("prior selector was restored"));
        assert_eq!(
            read_current_generation(&root, &Limits::default())
                .unwrap()
                .unwrap()["generation_id"],
            id
        );
        cleanup(&root);
    }

    #[test]
    fn first_selection_failure_clears_the_selector() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("clear-failed-first");
        set_fault(&root, false);
        let error = select_generation(&root, &id, &Limits::default()).unwrap_err();
        assert!(error.contains("injected post-replace selection failure"));
        assert!(
            read_current_generation(&root, &Limits::default())
                .unwrap()
                .is_none()
        );
        cleanup(&root);
    }

    #[test]
    fn restoration_failure_preserves_both_errors() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("restore-failure");
        symlink(format!("generations/{id}"), root.join("feed-store/current")).unwrap();
        set_fault(&root, true);
        let error = select_generation(&root, &id, &Limits::default()).unwrap_err();
        assert!(error.contains("injected post-replace selection failure"));
        assert!(error.contains("injected selector restoration failure"));
        cleanup(&root);
    }

    #[test]
    fn replaced_temporary_selector_is_rejected_without_unlinking_replacement() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("temporary-replacement");
        let store = root.join("feed-store");
        let hook_store = store.clone();
        let target = format!("generations/{id}");
        *BEFORE_RENAME_HOOK.lock().unwrap() = Some(Box::new(move || {
            let temporary = fs::read_dir(&hook_store)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".current-")
                })
                .unwrap();
            fs::remove_file(&temporary).unwrap();
            symlink(&target, &temporary).unwrap();
        }));

        let error = select_generation(&root, &id, &Limits::default()).unwrap_err();
        assert!(
            error.contains("temporary feed generation selector is unsafe"),
            "{error}"
        );
        assert!(
            error.contains("temporary selector cleanup failed"),
            "{error}"
        );
        assert!(!store.join("current").exists());
        let replacement = fs::read_dir(&store)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".current-")
            })
            .unwrap();
        assert_eq!(
            fs::read_link(&replacement).unwrap(),
            Path::new(&format!("generations/{id}"))
        );
        fs::remove_file(replacement).unwrap();
        cleanup(&root);
    }

    #[test]
    fn lock_mode_is_normalized_and_hardlinks_are_rejected() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("lock-hardening");
        let lock = root.join("feed-store/generations/.stage.lock");
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        select_generation(&root, &id, &Limits::default()).unwrap();
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(&lock).unwrap();

        let outside = root.join("linked-lock");
        fs::write(&outside, b"").unwrap();
        fs::hard_link(&outside, &lock).unwrap();
        let error = select_generation(&root, &id, &Limits::default()).unwrap_err();
        assert!(
            error.contains("owner-only single-link regular file"),
            "{error}"
        );
        fs::remove_file(&lock).unwrap();
        fs::remove_file(&outside).unwrap();
        cleanup(&root);
    }

    #[test]
    fn symlinked_lock_and_path_components_are_rejected() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let (root, id) = valid_generation("symlink-rejection");
        symlink("/tmp", root.join("feed-store/generations/.stage.lock")).unwrap();
        assert!(
            select_generation(&root, &id, &Limits::default())
                .unwrap_err()
                .contains("could not open feed generation lock")
        );
        fs::remove_file(root.join("feed-store/generations/.stage.lock")).unwrap();

        let link = std::env::temp_dir().join(format!(
            "yafvs-selector-link-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        symlink(&root, &link).unwrap();
        assert!(read_current_generation(&link, &Limits::default()).is_err());
        fs::remove_file(link).unwrap();
        cleanup(&root);
    }
}
