// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Descriptor-anchored verifier for immutable feed generations, with private
//! activation-journal validation and detached-signature provenance checks.

mod activation;
mod adapter;
mod app_build;
mod app_up;
mod artifact_identity;
mod canonical_json;
mod compose_identity;
mod database;
mod deployment;
mod feed_mappings;
mod journal;
mod manager_import;
mod manager_init;
mod native_api_rebuild;
mod ospd_readiness;
mod payload;
mod provenance;
mod scanner_runtime;
mod selector;
mod service_runtime;
mod stage;
mod transition;

pub(crate) use scanner_runtime::prepare_openvas_runtime_config;

pub(crate) fn initialize_manager_with_images(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    image_ids: &BTreeMap<String, String>,
) -> (bool, Vec<Finding>, Vec<String>) {
    let runtime = service_runtime::ServiceRuntime::new(repo_root, runner, environment, image_ids);
    let outcome = manager_init::initialize_manager(repo_root, runner, &runtime);
    (
        outcome.status != transition::StepStatus::Fail,
        outcome.findings,
        outcome.artifacts,
    )
}

pub(crate) fn command_feed_generation_startup_guard_with_runner(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let runtime = runtime_dir(repo_root);
    let finding = active_feed_generation_runtime_guard_finding(
        &runtime,
        selector::read_current_generation_attested_reference(&runtime),
        journal::read_activation_state(&runtime),
        false,
        || {
            DatabaseAttestationAdapter::new(repo_root, runner)
                .read()
                .map(|attestation| attestation.map(|value| value.generation_id().to_owned()))
        },
    );
    make_result(
        metadata(repo_root, "feed-generation-startup-guard", runner),
        "Active feed generation startup guard completed.".into(),
        vec![finding],
    )
}

pub(crate) fn run_pinned_gvmd(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    image_ids: &BTreeMap<String, String>,
    command: &[&str],
) -> Result<crate::process::ProcessOutput, ()> {
    let runtime = service_runtime::ServiceRuntime::new(repo_root, runner, environment, image_ids);
    manager_init::run_gvmd(&runtime, command, std::time::Duration::from_secs(300))
}

pub use app_build::command_runtime_app_build;
pub(crate) use app_build::run_compose;
pub use app_up::command_runtime_app_up;
pub use native_api_rebuild::command_runtime_native_api_rebuild;
pub(crate) use native_api_rebuild::{
    deployed_app_environment, native_api_up_arguments, refresh_deployment,
    run_retained_native_api_smoke,
};

use super::common::{compact_finding, metadata, runtime_dir};
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use database::DatabaseAttestationAdapter;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

const RELEASE: &str = "22.04";
pub(super) const FPR: &str = "8AE4BE429B60A59B311C2E739823FAA60ED1E580";
const MANIFEST: &str = "manifest.json";
const CHUNK: usize = 1024 * 1024;
const MAX_MANIFEST: u64 = 128 * 1024 * 1024;
const MAX_STORE_ENTRIES: usize = 64;
const MAX_GENERATIONS: usize = 32;
const MAX_NAME: usize = 128;

pub(crate) fn require_current_app_deployment(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<BTreeMap<String, String>, String> {
    require_current_app_deployment_snapshot(repo_root, runner, environment)
        .map(|deployment| deployment.image_ids)
}

pub(crate) struct CurrentAppDeployment {
    pub(crate) receipt: Value,
    pub(crate) image_ids: BTreeMap<String, String>,
}

pub(crate) fn require_current_app_deployment_snapshot(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<CurrentAppDeployment, String> {
    let receipt = deployment::require_app_deployment_receipt(&runtime_dir(repo_root))?;
    let image_ids = deployment::validate_app_service_image_ids(
        receipt
            .get("image_ids")
            .ok_or("application deployment receipt is invalid")?,
    )?;
    let unavailable =
        compose_identity::unavailable_images(repo_root, runner, environment, &image_ids)?;
    if !unavailable.is_empty() {
        return Err(format!(
            "Pinned application image objects are unavailable for {}; restore those exact image objects by digest from a trusted registry or docker load before continuing",
            unavailable.join(", ")
        ));
    }

    let expected_artifacts = receipt
        .get("runtime_artifacts")
        .ok_or("application deployment receipt is invalid")?;
    let observed_artifacts =
        artifact_identity::app_runtime_artifact_manifest(repo_root).map_err(|error| {
            format!("Runtime deployment artifact identity could not be verified: {error}")
        })?;
    if observed_artifacts.get("digest") != expected_artifacts.get("digest") {
        return Err("Bind-mounted runtime artifacts changed during the feed transition.".into());
    }

    let expected_compose = receipt
        .get("compose_contract")
        .ok_or("application deployment receipt is invalid")?;
    let observed_compose =
        compose_identity::compose_contract_manifest(repo_root, runner, environment, &image_ids)
            .map_err(|error| {
                format!("Application Compose execution contract could not be verified: {error}")
            })?;
    if observed_compose.get("digest") != expected_compose.get("digest") {
        return Err(
            "Rendered application Compose execution contract changed after deployment preparation."
                .into(),
        );
    }
    Ok(CurrentAppDeployment { receipt, image_ids })
}

pub(crate) fn pinned_app_compose_command(
    repo_root: &Path,
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    image_ids: &BTreeMap<String, String>,
    arguments: &[String],
) -> Result<Vec<String>, String> {
    compose_identity::pinned_compose_command(repo_root, environment, image_ids, arguments)
}

#[derive(Clone)]
struct Spec {
    key: &'static str,
    source: &'static str,
    runtime: &'static str,
    markers: &'static [&'static str],
    signed: &'static [(&'static str, &'static str)],
    unsigned: &'static [&'static str],
}

pub fn command_feed_generation_stage(repo_root: &Path) -> ResultEnvelope {
    command_feed_generation_stage_with_timeout(repo_root, DEFAULT_RUNTIME_LOCK_TIMEOUT)
}

pub fn command_feed_generation_activate(
    repo_root: &Path,
    generation_id: &str,
    allow_first_activation: bool,
    repair_attestation: bool,
) -> ResultEnvelope {
    activation::command(
        repo_root,
        generation_id,
        false,
        allow_first_activation,
        repair_attestation,
        false,
    )
}

pub fn command_feed_generation_rollback(
    repo_root: &Path,
    generation_id: &str,
    repair_deployment: bool,
) -> ResultEnvelope {
    activation::command(
        repo_root,
        generation_id,
        true,
        false,
        false,
        repair_deployment,
    )
}

/// Verify the selected immutable feed generation against the private activation
/// journal and, unless requested otherwise, the PostgreSQL import attestation.
pub fn command_feed_generation_runtime_guard(
    repo_root: &Path,
    selector_only: bool,
) -> ResultEnvelope {
    command_feed_generation_runtime_guard_with_runner(
        repo_root,
        selector_only,
        &SystemCommandRunner,
    )
}

pub(crate) fn command_feed_generation_runtime_guard_with_runner(
    repo_root: &Path,
    selector_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let runtime = runtime_dir(repo_root);
    let selector_journal = active_feed_generation_runtime_guard_finding(
        &runtime,
        selector::read_current_generation_reference(&runtime),
        journal::read_activation_state(&runtime),
        true,
        || unreachable!("selector-only feed guard must not read PostgreSQL"),
    );
    let referenced_generation_id = selector_journal
        .details
        .as_ref()
        .and_then(|details| details["selector_generation_id"].as_str())
        .map(str::to_owned);
    let finding = if selector_only {
        selector_journal
    } else if selector_journal.status != "pass" {
        promote_selector_journal_failure(selector_journal)
    } else {
        active_feed_generation_runtime_guard_finding(
            &runtime,
            require_referenced_generation(
                referenced_generation_id.as_deref(),
                selector::read_current_generation(&runtime, &Limits::default()),
            ),
            journal::read_activation_state(&runtime),
            false,
            || {
                DatabaseAttestationAdapter::new(repo_root, runner)
                    .read()
                    .map(|attestation| attestation.map(|value| value.generation_id().to_owned()))
            },
        )
    };
    make_result(
        metadata(repo_root, "feed-generation-runtime-guard", runner),
        "Active feed generation runtime guard completed.".into(),
        vec![finding],
    )
}

fn require_referenced_generation(
    referenced_generation_id: Option<&str>,
    verified: Result<Option<Value>, String>,
) -> Result<Option<Value>, String> {
    let verified = verified?;
    let verified_generation_id = verified
        .as_ref()
        .and_then(|value| value["generation_id"].as_str());
    if referenced_generation_id.is_some() && referenced_generation_id == verified_generation_id {
        Ok(verified)
    } else {
        Err(
            "current feed generation changed between reference resolution and full verification"
                .into(),
        )
    }
}

fn promote_selector_journal_failure(selector_journal: Finding) -> Finding {
    let mut finding = Finding::new("fail", "feed-generation.current", selector_journal.message)
        .with_path(selector_journal.path.as_deref().unwrap_or_default());
    if let Some(details) = selector_journal.details {
        finding = finding.with_details(details);
    }

    finding
}

fn active_feed_generation_runtime_guard_finding<F>(
    runtime: &Path,
    selector: Result<Option<Value>, String>,
    journal_state: Result<Option<Value>, String>,
    selector_only: bool,
    read_database: F,
) -> Finding
where
    F: FnOnce() -> Result<Option<String>, String>,
{
    let selector_journal =
        active_feed_generation_selector_journal_finding(runtime, selector, journal_state);
    if selector_only {
        return selector_journal;
    }
    if selector_journal.status != "pass" {
        return promote_selector_journal_failure(selector_journal);
    }
    let mut details = selector_journal.details.unwrap_or_else(|| json!({}));
    match read_database() {
        Err(error) => Finding::new(
            "fail",
            "feed-generation.current",
            format!("Active feed generation database attestation failed closed: {error}"),
        )
        .with_path(
            &journal::activation_state_path(runtime)
                .display()
                .to_string(),
        )
        .with_details(details),
        Ok(database_generation_id) => {
            let database = database_generation_id
                .map(Value::String)
                .unwrap_or(Value::Null);
            let valid = details["selector_generation_id"] == database;
            details["database_generation_id"] = database;
            Finding::new(
                if valid { "pass" } else { "fail" },
                "feed-generation.current",
                if valid {
                    "Active feed selector, completed import journal, and database attestation agree."
                        .into()
                } else {
                    "No completed feed activation and database attestation match the current selector; recover or explicitly re-import the verified generation before starting app services."
                        .into()
                },
            )
            .with_path(&journal::activation_state_path(runtime).display().to_string())
            .with_details(details)
        }
    }
}

fn active_feed_generation_selector_journal_finding(
    runtime: &Path,
    selector: Result<Option<Value>, String>,
    journal_state: Result<Option<Value>, String>,
) -> Finding {
    let path = journal::activation_state_path(runtime)
        .display()
        .to_string();
    let (current, state) = match (selector, journal_state) {
        (Ok(current), Ok(state)) => (current, state),
        (Err(error), _) | (_, Err(error)) => {
            return Finding::new(
                "fail",
                "feed-generation.selector-journal",
                format!("Active feed selector or completed import journal failed closed: {error}"),
            )
            .with_path(&path);
        }
    };
    let selector_generation_id = current
        .as_ref()
        .and_then(|value| value.get("generation_id"))
        .cloned()
        .unwrap_or(Value::Null);
    let journal_status = state
        .as_ref()
        .and_then(|value| value.get("status"))
        .cloned()
        .unwrap_or(Value::Null);
    let journal_generation_id = if journal_status == Value::String("active".into()) {
        state
            .as_ref()
            .and_then(|value| value.get("current_generation_id"))
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let valid =
        !selector_generation_id.is_null() && selector_generation_id == journal_generation_id;
    Finding::new(
        if valid { "pass" } else { "fail" },
        "feed-generation.selector-journal",
        if valid {
            "Active feed selector and completed import journal agree.".into()
        } else {
            "No completed feed activation journal matches the current selector; recover before starting app services.".into()
        },
    )
    .with_path(&path)
    .with_details(json!({
        "selector_generation_id": selector_generation_id,
        "journal_generation_id": journal_generation_id,
        "journal_status": journal_status,
    }))
}

fn command_feed_generation_stage_with_timeout(
    repo_root: &Path,
    timeout: std::time::Duration,
) -> ResultEnvelope {
    match RuntimeOperationLock::acquire(
        repo_root,
        FEED_ACTIVATION_LOCK,
        "feed-generation-stage",
        timeout,
    ) {
        Ok(_lock) => command_feed_generation_stage_unlocked(repo_root),
        Err(RuntimeLockError::Timeout {
            name,
            operation,
            holder,
        }) => make_result(
            metadata(repo_root, "feed-generation-stage", &SystemCommandRunner),
            "Feed generation staging stopped while waiting for the feed lifecycle lock.".into(),
            vec![Finding::new(
                "fail",
                "feed-generation.activation-lock",
                format!(
                    "Timed out waiting for runtime lock '{name}'; another operation may still be running."
                ),
            )
            .with_details(json!({"operation": operation, "holder": holder}))],
        )
        .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()]),
        Err(RuntimeLockError::Setup(error)) => make_result(
            metadata(repo_root, "feed-generation-stage", &SystemCommandRunner),
            "Feed generation staging stopped because the feed lifecycle lock failed closed."
                .into(),
            vec![Finding::new(
                "fail",
                "feed-generation.activation-lock",
                format!("Feed lifecycle lock failed closed: {error}"),
            )],
        )
        .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()]),
    }
}

fn command_feed_generation_stage_unlocked(repo_root: &Path) -> ResultEnvelope {
    let runtime = runtime_dir(repo_root);
    let cache = runtime.join(format!("feed-cache/community/{RELEASE}/var-lib"));
    let (mut findings, provenance) =
        provenance::cache_signature_findings(repo_root, &cache, &SystemCommandRunner);
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "feed-generation-stage", &SystemCommandRunner),
            "Immutable feed generation staging stopped because signed feed provenance could not be verified."
                .into(),
            findings,
        )
        .with_artifacts(vec![
            cache.display().to_string(),
            runtime.join("feed-store").display().to_string(),
        ]);
    }
    match stage::stage_generation(&cache, &runtime, &provenance, &Limits::default()) {
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "feed-generation.stage",
                    format!("Immutable feed generation staging failed closed: {error}"),
                )
                .with_path(&runtime.join("feed-store/generations").display().to_string()),
            );
            make_result(
                metadata(repo_root, "feed-generation-stage", &SystemCommandRunner),
                "Immutable feed generation staging failed.".into(),
                findings,
            )
            .with_artifacts(vec![
                cache.display().to_string(),
                runtime.join("feed-store").display().to_string(),
            ])
        }
        Ok(staged) => {
            let path = staged["path"].as_str().unwrap_or_default().to_string();
            findings.push(
                Finding::new(
                    "pass",
                    "feed-generation.stage",
                    "A complete immutable feed generation was verified and staged without changing the active runtime feed."
                        .into(),
                )
                .with_path(&path)
                .with_details(staged),
            );
            make_result(
                metadata(repo_root, "feed-generation-stage", &SystemCommandRunner),
                "Immutable feed generation staging completed.".into(),
                findings,
            )
            .with_artifacts(vec![path])
        }
    }
}
fn specs() -> [Spec; 5] {
    [
        Spec {
            key: "nasl",
            source: "openvas/plugins",
            runtime: "openvas/plugins",
            markers: &["plugin_feed_info.inc", "LICENSE"],
            signed: &[("sha256sums", "sha256sums.asc")],
            unsigned: &[],
        },
        Spec {
            key: "notus",
            source: "notus",
            runtime: "notus",
            markers: &[
                "advisories/sha256sums",
                "advisories/sha256sums.asc",
                "products/sha256sums",
                "products/sha256sums.asc",
            ],
            signed: &[
                ("advisories/sha256sums", "advisories/sha256sums.asc"),
                ("products/sha256sums", "products/sha256sums.asc"),
            ],
            unsigned: &["LICENSE", "LICENSE.GPLv2", "LICENSE.ODbLv1", "timestamp"],
        },
        Spec {
            key: "scap",
            source: "gvm/scap-data",
            runtime: "gvm/scap-data",
            markers: &["COPYING", "feed.xml", "timestamp"],
            signed: &[],
            unsigned: &[],
        },
        Spec {
            key: "cert",
            source: "gvm/cert-data",
            runtime: "gvm/cert-data",
            markers: &["COPYING.CERT-BUND", "COPYING.DFN-CERT", "feed.xml"],
            signed: &[("sha256sums", "sha256sums.asc")],
            unsigned: &[],
        },
        Spec {
            key: "gvmd",
            source: "gvm/data-objects/gvmd/22.04",
            runtime: "gvm/data-objects/gvmd/22.04",
            markers: &[
                "LICENSE",
                "feed.xml",
                "timestamp",
                "scan-configs",
                "report-formats",
                "port-lists",
            ],
            signed: &[],
            unsigned: &[],
        },
    ]
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    files: usize,
    dirs: usize,
    total: u64,
    file: u64,
    path: usize,
    depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            files: 250_000,
            dirs: 250_000,
            total: 32 * 1024 * 1024 * 1024,
            file: 8 * 1024 * 1024 * 1024,
            path: 4096,
            depth: 64,
        }
    }
}
#[derive(Clone, Eq, PartialEq)]
struct Snap {
    path: String,
    kind: bool,
    size: u64,
    mode: u32,
    dev: u64,
    ino: u64,
    mt: i64,
    mn: i64,
    ct: i64,
    cn: i64,
    links: u64,
}
#[derive(Clone, Eq, PartialEq)]
struct Inventory {
    files: Vec<Snap>,
    dirs: Vec<Snap>,
    total: u64,
}
#[derive(Clone)]
pub(super) struct VerificationWitness {
    generation_id: String,
    entry: String,
    store_identity: (u64, u64),
    generation_identity: (u64, u64),
    inventory: Inventory,
    manifest: Value,
}
pub(super) struct VerifiedGeneration {
    details: Value,
    witness: VerificationWitness,
}
impl VerifiedGeneration {
    pub(super) fn into_parts(self) -> (Value, VerificationWitness) {
        (self.details, self.witness)
    }
}
impl VerificationWitness {
    pub(super) fn generation_id(&self) -> &str {
        &self.generation_id
    }

    pub(super) fn manifest(&self) -> &Value {
        &self.manifest
    }

    fn relocated(mut self, entry: &str) -> R<Self> {
        if entry != self.generation_id {
            return Err("verified generation relocation does not match its identifier".into());
        }
        self.entry = entry.to_owned();
        Ok(self)
    }
}
type R<T> = Result<T, String>;

#[cfg(test)]
type TestHook = (std::path::PathBuf, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static VERIFY_FINAL_HOOK: std::sync::Mutex<Option<TestHook>> = std::sync::Mutex::new(None);
#[cfg(test)]
static SELECTOR_RECHECK_HOOK: std::sync::Mutex<Option<TestHook>> = std::sync::Mutex::new(None);
#[cfg(test)]
fn verify_final_hook(path: &Path) {
    let hook = {
        let mut pending = VERIFY_FINAL_HOOK.lock().unwrap();
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
fn verify_final_hook(_: &Path) {}
#[cfg(test)]
fn selector_recheck_hook(path: &Path) {
    let hook = {
        let mut pending = SELECTOR_RECHECK_HOOK.lock().unwrap();
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
fn selector_recheck_hook(_: &Path) {}

fn err(context: &str) -> String {
    format!("{context}: {}", io::Error::last_os_error())
}
fn c(name: &str) -> R<CString> {
    CString::new(name).map_err(|_| format!("unsafe path component: {name:?}"))
}
fn stat(fd: i32) -> R<libc::stat> {
    let mut s = unsafe { std::mem::zeroed() }; /* SAFETY: valid output pointer; fd is owned/open. */
    if unsafe { libc::fstat(fd, &mut s) } != 0 {
        Err(err("could not stat descriptor"))
    } else {
        Ok(s)
    }
}
fn stat_at(fd: i32, name: &str) -> R<libc::stat> {
    stat_at_io(fd, name).map_err(|e| format!("could not inspect directory entry: {e}"))
}
fn stat_at_io(fd: i32, name: &str) -> io::Result<libc::stat> {
    let mut s = unsafe { std::mem::zeroed() };
    let n = c(name).map_err(io::Error::other)?; /* SAFETY: `n` is NUL terminated and `s` is writable. */
    if unsafe { libc::fstatat(fd, n.as_ptr(), &mut s, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(s)
    }
}
fn is_dir(s: &libc::stat) -> bool {
    s.st_mode & libc::S_IFMT == libc::S_IFDIR
}
fn is_reg(s: &libc::stat) -> bool {
    s.st_mode & libc::S_IFMT == libc::S_IFREG
}
fn is_lnk(s: &libc::stat) -> bool {
    s.st_mode & libc::S_IFMT == libc::S_IFLNK
}
fn mode(s: &libc::stat) -> u32 {
    s.st_mode & 0o7777
}
fn identity(s: &libc::stat) -> (u64, u64) {
    (s.st_dev, s.st_ino)
}
fn uid() -> u32 {
    unsafe { libc::getuid() }
}
fn open_at(fd: i32, name: &str, flags: i32) -> R<OwnedFd> {
    let n = c(name)?; /* SAFETY: descriptor and C name are valid; successful fd is immediately owned. */
    let raw = unsafe { libc::openat(fd, n.as_ptr(), flags, 0) };
    if raw < 0 {
        Err(err("could not open directory entry"))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn open_dir_at(fd: i32, name: &str) -> R<OwnedFd> {
    let before = stat_at(fd, name)?;
    if is_lnk(&before) || !is_dir(&before) {
        return Err(format!("path component is not a real directory: {name}"));
    };
    let child = open_at(
        fd,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    if identity(&before) != identity(&stat(child.as_raw_fd())?) {
        return Err(format!("directory changed while opening: {name}"));
    }
    Ok(child)
}
fn absolute_dir(path: &Path) -> R<OwnedFd> {
    if !path.is_absolute() {
        return Err(format!("directory path is unsafe: {}", path.display()));
    };
    let mut fd = open_at(
        libc::AT_FDCWD,
        "/",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    for p in path.components() {
        match p {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(x) => {
                let n = x.to_str().ok_or_else(|| {
                    format!("directory path is not valid UTF-8: {}", path.display())
                })?;
                let child = open_dir_at(fd.as_raw_fd(), n).map_err(|_| {
                    format!("directory path component is unsafe: {}", path.display())
                })?;
                fd = child;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("directory path is unsafe: {}", path.display()));
            }
        }
    }
    Ok(fd)
}
fn parts<'a>(value: &'a str, l: &Limits) -> R<Vec<&'a str>> {
    if value.is_empty() || value.starts_with('/') || value.len() > l.path {
        return Err(format!("unsafe relative path: {value:?}"));
    }
    let p: Vec<_> = value.split('/').collect();
    if p.len() > l.depth {
        return Err(format!("path exceeds maximum depth {}: {value}", l.depth));
    };
    if p.iter()
        .any(|x| x.is_empty() || *x == "." || *x == ".." || x.contains('\0'))
    {
        return Err(format!("unsafe relative path: {value:?}"));
    };
    Ok(p)
}
fn beneath(fd: i32, p: &[&str]) -> R<OwnedFd> {
    let raw = unsafe { libc::dup(fd) };
    if raw < 0 {
        return Err(err("could not duplicate directory descriptor"));
    };
    let mut out = unsafe { OwnedFd::from_raw_fd(raw) };
    for x in p {
        out = open_dir_at(out.as_raw_fd(), x)?;
    }
    Ok(out)
}
fn snap(path: String, kind: bool, s: &libc::stat) -> Snap {
    Snap {
        path,
        kind,
        size: s.st_size as u64,
        mode: mode(s),
        dev: s.st_dev,
        ino: s.st_ino,
        mt: s.st_mtime,
        mn: s.st_mtime_nsec,
        ct: s.st_ctime,
        cn: s.st_ctime_nsec,
        links: s.st_nlink,
    }
}
fn same(a: &Snap, b: &Snap) -> bool {
    (
        a.path.as_str(),
        a.kind,
        a.size,
        a.dev,
        a.ino,
        a.mt,
        a.mn,
        a.ct,
        a.cn,
        a.links,
    ) == (
        b.path.as_str(),
        b.kind,
        b.size,
        b.dev,
        b.ino,
        b.mt,
        b.mn,
        b.ct,
        b.cn,
        b.links,
    )
}
struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        /* SAFETY: `Directory` is only constructed from a successful `fdopendir`,
        which transfers ownership of its duplicated descriptor to `closedir`. */
        unsafe { libc::closedir(self.0) };
    }
}
fn names(fd: i32) -> R<Vec<String>> {
    let raw = unsafe { libc::dup(fd) };
    if raw < 0 {
        return Err(err("could not duplicate directory descriptor"));
    }; /* SAFETY: fdopendir owns only the duplicated descriptor and closedir releases it. */
    if unsafe { libc::lseek(raw, 0, libc::SEEK_SET) } < 0 {
        unsafe { libc::close(raw) };
        return Err(err("could not rewind directory descriptor"));
    }
    let raw_dir = unsafe { libc::fdopendir(raw) };
    if raw_dir.is_null() {
        unsafe { libc::close(raw) };
        return Err(err("could not enumerate directory"));
    };
    let d = Directory(raw_dir);
    let mut result = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 }; /* SAFETY: `d` remains valid until closed below. */
        let e = unsafe { libc::readdir(d.0) };
        if e.is_null() {
            let e = unsafe { *libc::__errno_location() };
            if e != 0 {
                return Err(io::Error::from_raw_os_error(e).to_string());
            };
            break;
        };
        let b = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_bytes();
        if b == b"." || b == b".." {
            continue;
        };
        let text = std::str::from_utf8(b)
            .map_err(|_| {
                format!(
                    "directory entry is not valid UTF-8: {:?}",
                    OsStr::from_bytes(b)
                )
            })?
            .to_string();
        result.push(text);
    }
    Ok(result)
}
fn inventory(root: i32, l: &Limits) -> R<Inventory> {
    fn walk(fd: i32, prefix: &str, l: &Limits, out: &mut Inventory) -> R<()> {
        let mut ns = names(fd)?;
        if ns.len() > l.files + l.dirs {
            return Err("feed directory contains too many entries".into());
        };
        ns.sort();
        for n in ns {
            if n.contains('/') || n.contains('\0') {
                return Err(format!("unsafe directory entry: {n:?}"));
            };
            let path = if prefix.is_empty() {
                n.clone()
            } else {
                format!("{prefix}/{n}")
            };
            parts(&path, l)?;
            let before = stat_at(fd, &n)?;
            if is_lnk(&before) {
                return Err(format!("feed tree contains a symbolic link: {path}"));
            };
            if is_reg(&before) {
                if before.st_nlink != 1 {
                    return Err(format!("feed tree contains a multiply linked file: {path}"));
                };
                if before.st_size as u64 > l.file {
                    return Err(format!("feed file exceeds size limit: {path}"));
                };
                out.total += before.st_size as u64;
                if out.total > l.total {
                    return Err("feed tree exceeds total-byte limit".into());
                };
                out.files.push(snap(path, true, &before));
                if out.files.len() > l.files {
                    return Err("feed tree exceeds file-count limit".into());
                }
            } else if is_dir(&before) {
                let child = open_dir_at(fd, &n)?;
                let got = stat(child.as_raw_fd())?;
                out.dirs.push(snap(path.clone(), false, &got));
                if out.dirs.len() > l.dirs {
                    return Err("feed tree exceeds directory-count limit".into());
                };
                walk(child.as_raw_fd(), &path, l, out)?
            } else {
                return Err(format!("feed tree contains a special file: {path}"));
            }
        }
        Ok(())
    }
    let mut out = Inventory {
        files: vec![],
        dirs: vec![],
        total: 0,
    };
    walk(root, "", l, &mut out)?;
    Ok(out)
}
fn stable_read(
    root: i32,
    path: &str,
    size: u64,
    manifest: bool,
    allow_writable: bool,
) -> R<Vec<u8>> {
    if size > MAX_MANIFEST {
        return Err(if manifest {
            "generation manifest exceeds size limit".into()
        } else {
            format!("signed checksum manifest exceeds size limit: {path}")
        });
    }
    let l = Limits::default();
    let p = parts(path, &l)?;
    let parent = beneath(root, &p[..p.len() - 1])?;
    let before = stat_at(parent.as_raw_fd(), p[p.len() - 1])?;
    if is_lnk(&before)
        || !is_reg(&before)
        || before.st_nlink != 1
        || before.st_size as u64 != size
        || (!allow_writable && mode(&before) & 0o222 != 0)
    {
        return Err(if manifest {
            "generation manifest is unsafe".into()
        } else {
            format!("generation file metadata is invalid: {path}")
        });
    };
    let fd = open_at(
        parent.as_raw_fd(),
        p[p.len() - 1],
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let opened = stat(fd.as_raw_fd())?;
    if identity(&before) != identity(&opened) {
        return Err(if manifest {
            "generation manifest changed while opening".into()
        } else {
            format!("generation file changed while opening: {path}")
        });
    };
    let mut out = Vec::with_capacity(size as usize);
    let mut buf = [0u8; CHUNK];
    while out.len() < size as usize {
        let want = (size as usize - out.len()).min(CHUNK);
        let r = loop {
            let r = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), want) };
            if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break r;
        };
        if r < 0 {
            return Err(format!(
                "could not read generation file {path}: {}",
                io::Error::last_os_error()
            ));
        }
        if r == 0 {
            return Err(format!(
                "generation file was truncated while reading: {path}"
            ));
        };
        out.extend_from_slice(&buf[..r as usize]);
    }
    let r = loop {
        let r = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break r;
    };
    if r < 0 {
        return Err(format!(
            "could not read generation file {path}: {}",
            io::Error::last_os_error()
        ));
    }
    if r != 0 {
        return Err(format!("generation file grew while reading: {path}"));
    };
    let final_s = stat(fd.as_raw_fd())?;
    if opened.st_size != final_s.st_size
        || opened.st_mtime != final_s.st_mtime
        || opened.st_mtime_nsec != final_s.st_mtime_nsec
        || opened.st_ctime != final_s.st_ctime
        || opened.st_ctime_nsec != final_s.st_ctime_nsec
    {
        return Err(format!("generation file changed while reading: {path}"));
    };
    Ok(out)
}
fn manifest(fd: i32) -> R<Value> {
    let s = stat_at(fd, MANIFEST)?;
    if s.st_size as u64 > MAX_MANIFEST {
        return Err("generation manifest exceeds size limit".into());
    };
    let b = stable_read(fd, MANIFEST, s.st_size as u64, true, false)?;
    serde_json::from_slice::<Value>(&b)
        .map_err(|_| "generation manifest is not valid JSON".into())
        .and_then(|v| {
            if v.is_object() {
                Ok(v)
            } else {
                Err("generation manifest root is not an object".into())
            }
        })
}
fn digest(v: &Value) -> bool {
    v.as_str().is_some_and(|x| {
        x.len() == 64
            && x.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c if c.is_ascii() => out.push(c),
                    c => {
                        let mut units = [0; 2];
                        for u in c.encode_utf16(&mut units) {
                            out.push_str(&format!("\\u{u:04x}"));
                        }
                    }
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(&Value::String(k.clone()), out);
                out.push(':');
                canonical(x, out);
            }
            out.push('}');
        }
    }
}
fn exact_keys(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))
}
fn strv<'a>(o: &'a Map<String, Value>, k: &str) -> R<&'a str> {
    o.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| "generation manifest classes or files are invalid".into())
}
fn u64v(o: &Map<String, Value>, k: &str) -> Option<u64> {
    o.get(k).and_then(Value::as_u64)
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn stream_sha(root: i32, path: &str, size: u64) -> R<String> {
    let l = Limits::default();
    let p = parts(path, &l)?;
    let parent = beneath(root, &p[..p.len() - 1])?;
    let before = stat_at(parent.as_raw_fd(), p[p.len() - 1])?;
    if is_lnk(&before)
        || !is_reg(&before)
        || before.st_nlink != 1
        || before.st_size as u64 != size
        || mode(&before) & 0o222 != 0
    {
        return Err(format!("generation file metadata is invalid: {path}"));
    }
    let fd = open_at(
        parent.as_raw_fd(),
        p[p.len() - 1],
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let opened = stat(fd.as_raw_fd())?;
    if identity(&before) != identity(&opened) {
        return Err(format!("generation file changed while opening: {path}"));
    }
    let mut hashed = 0u64;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; CHUNK];
    while hashed < size {
        let want = (size - hashed).min(CHUNK as u64) as usize;
        let read = loop {
            let read = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), want) };
            if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break read;
        };
        if read < 0 {
            return Err(format!(
                "could not hash generation file {path}: {}",
                io::Error::last_os_error()
            ));
        }
        if read == 0 {
            return Err(format!(
                "generation file was truncated while hashing: {path}"
            ));
        }
        hasher.update(&buf[..read as usize]);
        hashed += read as u64;
    }
    let extra = loop {
        let read = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break read;
    };
    if extra < 0 {
        return Err(format!(
            "could not hash generation file {path}: {}",
            io::Error::last_os_error()
        ));
    }
    if extra != 0 {
        return Err(format!("generation file grew while hashing: {path}"));
    }
    let final_s = stat(fd.as_raw_fd())?;
    if opened.st_size != final_s.st_size
        || opened.st_mtime != final_s.st_mtime
        || opened.st_mtime_nsec != final_s.st_mtime_nsec
        || opened.st_ctime != final_s.st_ctime
        || opened.st_ctime_nsec != final_s.st_ctime_nsec
    {
        return Err(format!("generation file changed while hashing: {path}"));
    }
    Ok(format!("{:x}", hasher.finalize()))
}
fn verify_payload_hashes(root: i32, expected: &BTreeMap<String, (u64, String, String)>) -> R<()> {
    let jobs = expected
        .iter()
        .map(|(path, (size, digest, _))| (path.as_str(), *size, digest.as_str()))
        .collect::<Vec<_>>();
    let worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(8)
        .min(jobs.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let errors = std::sync::Mutex::new(Vec::<(usize, String)>::new());
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((path, size, digest)) = jobs.get(index).copied() else {
                        break;
                    };
                    let result = stream_sha(root, path, size).and_then(|actual| {
                        if actual == digest {
                            Ok(())
                        } else {
                            Err(format!(
                                "generation file digest differs from manifest: {path}"
                            ))
                        }
                    });
                    if let Err(error) = result {
                        errors.lock().unwrap().push((index, error));
                    }
                }
            });
        }
    });
    let mut errors = errors
        .into_inner()
        .map_err(|_| "parallel generation verification state was poisoned".to_owned())?;
    errors.sort_by_key(|(index, _)| *index);
    match errors.into_iter().next() {
        Some((_, error)) => Err(error),
        None => Ok(()),
    }
}
fn parse_sums(b: &[u8], mp: &str, l: &Limits) -> R<BTreeMap<String, String>> {
    let t = std::str::from_utf8(b)
        .map_err(|_| format!("signed checksum manifest is not UTF-8: {mp}"))?;
    let mut r = BTreeMap::new();
    let parent = mp.rsplit_once('/').map_or("", |x| x.0);
    for (n, line) in t.lines().enumerate() {
        if line.is_empty() {
            continue;
        };
        let Some((d, tail)) = line.split_once(' ') else {
            return Err(format!("invalid signed checksum row in {mp}:{}", n + 1));
        };
        let p = tail
            .strip_prefix(' ')
            .or_else(|| tail.strip_prefix('*'))
            .ok_or_else(|| format!("invalid signed checksum row in {mp}:{}", n + 1))?;
        if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) || p.starts_with('\\') {
            return Err(format!("invalid signed checksum row in {mp}:{}", n + 1));
        };
        parts(p, l)?;
        let path = if parent.is_empty() {
            p.to_string()
        } else {
            format!("{parent}/{p}")
        };
        parts(&path, l)?;
        if r.insert(path, d.to_ascii_lowercase()).is_some() {
            return Err(format!("duplicate signed checksum path in {mp}: {p}"));
        };
        if r.len() > l.files {
            return Err(format!(
                "signed checksum manifest exceeds file-count limit: {mp}"
            ));
        }
    }
    if r.is_empty() {
        Err(format!("signed checksum manifest is empty: {mp}"))
    } else {
        Ok(r)
    }
}
fn verify(root: &Path, id: &str, l: &Limits) -> R<Value> {
    verify_with_witness(root, id, l).map(|verified| verified.details)
}
pub(super) fn verify_with_witness(root: &Path, id: &str, l: &Limits) -> R<VerifiedGeneration> {
    verify_entry_with_witness(root, id, id, l)
}
fn verify_entry_with_witness(
    root: &Path,
    id: &str,
    entry: &str,
    l: &Limits,
) -> R<VerifiedGeneration> {
    if !digest(&Value::String(id.into())) {
        return Err(format!("invalid generation identifier: {id:?}"));
    };
    let store = absolute_dir(root)?;
    let ss = stat(store.as_raw_fd())?;
    if ss.st_uid != uid() || mode(&ss) & 0o077 != 0 {
        return Err("feed generation store is not private and user-owned".into());
    };
    let generation_fd = open_dir_at(store.as_raw_fd(), entry)?;
    let gs = stat(generation_fd.as_raw_fd())?;
    if gs.st_uid != uid() || mode(&gs) & 0o222 != 0 {
        return Err("generation root is writable".into());
    };
    let first = inventory(generation_fd.as_raw_fd(), l)?;
    let m = manifest(generation_fd.as_raw_fd())?;
    let o = m.as_object().unwrap();
    if !exact_keys(
        o,
        &[
            "schema_version",
            "feed_release",
            "classes",
            "files",
            "signature_provenance",
            "generation_id",
            "created_at",
            "source_snapshot",
        ],
    ) {
        return Err("generation manifest has unexpected or missing fields".into());
    };
    if o.get("schema_version") != Some(&json!(1)) {
        return Err("unsupported generation manifest schema".into());
    };
    if strv(o, "feed_release")? != RELEASE {
        return Err("generation feed release differs from the configured release".into());
    };
    if strv(o, "generation_id")? != id {
        return Err("generation directory and manifest identifiers differ".into());
    };
    if o.get("created_at").and_then(Value::as_str).is_none() {
        return Err("generation manifest classes or files are invalid".into());
    };
    let content = json!({"schema_version":o["schema_version"],"feed_release":o["feed_release"],"classes":o["classes"],"files":o["files"],"signature_provenance":o["signature_provenance"]});
    let mut canon = String::new();
    canonical(&content, &mut canon);
    if sha(canon.as_bytes()) != id {
        return Err("generation manifest content identifier is invalid".into());
    };
    let classes = o
        .get("classes")
        .and_then(Value::as_array)
        .ok_or("generation manifest classes or files are invalid")?;
    let files = o
        .get("files")
        .and_then(Value::as_array)
        .ok_or("generation manifest classes or files are invalid")?;
    let prov = o
        .get("signature_provenance")
        .and_then(Value::as_array)
        .ok_or("generation manifest classes or files are invalid")?;
    let source = o
        .get("source_snapshot")
        .and_then(Value::as_object)
        .ok_or("generation manifest classes or files are invalid")?;
    if !exact_keys(source, &["class_count", "file_count", "byte_count"])
        || classes.len() != 5
        || files.len() > l.files
        || prov.len() != 4
    {
        return Err(
            "generation manifest class or file count exceeds the configured contract".into(),
        );
    };
    let specs = specs();
    let mut class_root = BTreeMap::new();
    let mut summaries = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    let mut markers = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for row in classes {
        let r = row
            .as_object()
            .ok_or("generation manifest has invalid class row")?;
        if !exact_keys(
            r,
            &[
                "key",
                "source_rel",
                "runtime_rel",
                "markers",
                "signed_manifests",
                "signing_key_fingerprint",
                "unsigned_metadata",
                "file_count",
                "byte_count",
                "directories",
            ],
        ) {
            return Err("generation manifest has invalid class row".into());
        };
        let k = strv(r, "key")?;
        let sp = specs
            .iter()
            .find(|s| s.key == k)
            .ok_or_else(|| format!("generation contains unexpected feed class: {k}"))?;
        if !keys.insert(k) {
            return Err("generation manifest class metadata is invalid".into());
        };
        let marker = r["markers"]
            .as_array()
            .ok_or("generation manifest class metadata is invalid")?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or("generation manifest class metadata is invalid")?;
        let unsigned = r["unsigned_metadata"]
            .as_array()
            .ok_or("generation manifest class metadata is invalid")?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or("generation manifest class metadata is invalid")?;
        let signed = r["signed_manifests"]
            .as_array()
            .ok_or("generation manifest class metadata is invalid")?;
        let pairs = signed
            .iter()
            .map(|x| {
                x.as_object()
                    .filter(|q| exact_keys(q, &["checksums", "signature"]))
                    .and_then(|q| {
                        Some((q.get("checksums")?.as_str()?, q.get("signature")?.as_str()?))
                    })
                    .ok_or_else(|| {
                        "generation feed class contract differs from configuration".to_string()
                    })
            })
            .collect::<R<Vec<_>>>()?;
        if strv(r, "source_rel")? != sp.source
            || strv(r, "runtime_rel")? != sp.runtime
            || marker != sp.markers
            || unsigned != sp.unsigned
            || pairs.as_slice() != sp.signed
            || if sp.signed.is_empty() {
                r.get("signing_key_fingerprint") != Some(&Value::Null)
            } else {
                r.get("signing_key_fingerprint").and_then(Value::as_str) != Some(FPR)
            }
        {
            return Err(format!(
                "generation feed class contract differs from configuration: {k}"
            ));
        };
        let rp = parts(sp.runtime, l)?;
        class_root.insert(k, rp.join("/"));
        for i in 1..=rp.len() {
            dirs.insert(rp[..i].join("/"));
        }
        for x in sp.markers {
            markers.insert(format!("{}/{x}", sp.runtime));
        }
        let ds = r["directories"]
            .as_array()
            .ok_or("generation manifest class metadata is invalid")?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or("generation manifest class directory is invalid")?;
        if ds.len() > l.dirs || !ds.windows(2).all(|w| w[0] < w[1]) {
            return Err("generation manifest class directories are not unique and sorted".into());
        };
        for d in ds {
            let p = parts(d, l)?;
            for i in 1..=p.len() {
                dirs.insert(format!("{}/{}", sp.runtime, p[..i].join("/")));
            }
        }
        let fc = u64v(r, "file_count").ok_or("generation manifest class summary is invalid")?;
        let bc = u64v(r, "byte_count").ok_or("generation manifest class summary is invalid")?;
        summaries.insert(k, (fc, bc));
    }
    if keys.len() != 5
        || classes
            .iter()
            .map(|x| x["key"].as_str())
            .collect::<Option<Vec<_>>>()
            != Some(vec!["cert", "gvmd", "nasl", "notus", "scap"])
    {
        return Err("generation manifest classes are not sorted".into());
    };
    let mut expected = BTreeMap::new();
    let mut actual: BTreeMap<&str, (u64, u64)> = keys.iter().map(|k| (*k, (0, 0))).collect();
    for f in files {
        let q = f
            .as_object()
            .ok_or("generation manifest has invalid file row")?;
        if !exact_keys(q, &["class", "path", "runtime_path", "sha256", "size"]) {
            return Err("generation manifest has invalid file row".into());
        };
        let k = strv(q, "class")?;
        let path = strv(q, "path")?;
        let run = strv(q, "runtime_path")?;
        let d = q
            .get("sha256")
            .filter(|v| digest(v))
            .and_then(Value::as_str)
            .ok_or("generation manifest file metadata is invalid")?;
        let sz = u64v(q, "size").ok_or("generation manifest file metadata is invalid")?;
        if !keys.contains(k)
            || sz > l.file
            || run != format!("{}/{}", class_root[k], path)
            || expected
                .insert(run.to_string(), (sz, d.to_string(), k.to_string()))
                .is_some()
        {
            return Err(format!(
                "generation manifest repeats or exceeds file limit: {run}"
            ));
        };
        parts(path, l)?;
        parts(run, l)?;
        let x = actual.get_mut(k).unwrap();
        x.0 += 1;
        x.1 += sz;
        let pp = parts(run, l)?;
        for i in 1..pp.len() {
            dirs.insert(pp[..i].join("/"));
        }
    }
    if files.windows(2).any(|w| {
        (w[0]["class"].as_str(), w[0]["path"].as_str())
            > (w[1]["class"].as_str(), w[1]["path"].as_str())
    }) {
        return Err("generation manifest files are not sorted".into());
    };
    let total: u64 = expected.values().map(|x| x.0).sum();
    if total > l.total
        || source.get("class_count").and_then(Value::as_u64) != Some(5)
        || source.get("file_count").and_then(Value::as_u64) != Some(expected.len() as u64)
        || source.get("byte_count").and_then(Value::as_u64) != Some(total)
    {
        return Err("generation source snapshot differs from manifest content".into());
    };
    for (k, (fc, bc)) in summaries {
        if actual[k] != (fc, bc) {
            return Err("generation class summaries differ from file rows".into());
        }
    }
    // Provenance metadata and checksum coverage are data integrity checks; the GPG
    // subprocess that establishes provenance remains deliberately outside this packet.
    let mut by_class: BTreeMap<String, BTreeMap<String, (String, String, u64)>> = BTreeMap::new();
    for (run, (sz, d, k)) in &expected {
        let rel = run
            .strip_prefix(&(class_root[k.as_str()].clone() + "/"))
            .unwrap()
            .to_string();
        by_class
            .entry(k.clone())
            .or_default()
            .insert(rel, (run.clone(), d.clone(), *sz));
    }
    let mut got = BTreeSet::new();
    for p in prov {
        let q = p
            .as_object()
            .ok_or("generation signature provenance row is invalid")?;
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
        ) {
            return Err("generation signature provenance row is invalid".into());
        };
        let k = strv(q, "class")?;
        let cp = strv(q, "checksums_path")?;
        let sp = strv(q, "signature_path")?;
        if !digest(&q["checksums_sha256"])
            || !digest(&q["signature_sha256"])
            || q["signing_key_fingerprint"].as_str() != Some(FPR)
            || !specs
                .iter()
                .any(|s| s.key == k && s.signed.contains(&(cp, sp)))
            || !got.insert((k, cp, sp))
        {
            return Err("generation signature provenance metadata is invalid".into());
        };
        let cf = by_class
            .get(k)
            .and_then(|x| x.get(cp))
            .ok_or_else(|| format!("signed provenance file differs from manifest: {k}/{cp}"))?;
        let sf = by_class
            .get(k)
            .and_then(|x| x.get(sp))
            .ok_or_else(|| format!("signed provenance file differs from manifest: {k}/{sp}"))?;
        if cf.1 != q["checksums_sha256"] || sf.1 != q["signature_sha256"] {
            return Err(format!(
                "signed provenance file differs from manifest: {k}/{cp}"
            ));
        };
    }
    if !prov.windows(2).all(|w| {
        (w[0]["class"].as_str(), w[0]["checksums_path"].as_str())
            <= (w[1]["class"].as_str(), w[1]["checksums_path"].as_str())
    }) {
        return Err("generation signature provenance is not sorted".into());
    }
    for s in &specs {
        let b = by_class.get(s.key).cloned().unwrap_or_default();
        let mut signed = BTreeSet::new();
        let mut meta = BTreeSet::new();
        for (cp, sp) in s.signed {
            let x = b.get(*cp).ok_or_else(|| {
                format!(
                    "signed provenance file differs from manifest: {}/{}",
                    s.key, cp
                )
            })?;
            meta.insert((*cp).to_string());
            meta.insert((*sp).to_string());
            for (p, d) in parse_sums(
                &stable_read(generation_fd.as_raw_fd(), &x.0, x.2, false, false)?,
                cp,
                l,
            )? {
                if b.get(&p).is_none_or(|z| z.1 != d) {
                    return Err(format!(
                        "signed checksum does not match generation content: {}/{}",
                        s.key, p
                    ));
                };
                signed.insert(p);
            }
        }
        if !s.unsigned.iter().all(|x| b.contains_key(*x)) {
            return Err(format!("configured unsigned {} metadata is missing", s.key));
        };
        if !s.signed.is_empty()
            && b.keys()
                .filter(|x| !meta.contains(*x) && !s.unsigned.contains(&x.as_str()))
                .collect::<BTreeSet<_>>()
                != signed.iter().collect()
        {
            return Err(format!(
                "signed checksum manifests do not cover the exact {} payload",
                s.key
            ));
        }
    }
    let payload: Vec<_> = first.files.iter().filter(|x| x.path != MANIFEST).collect();
    if payload
        .iter()
        .map(|x| x.path.clone())
        .collect::<BTreeSet<_>>()
        != expected.keys().cloned().collect()
    {
        return Err("generation payload files differ from manifest".into());
    };
    if first
        .dirs
        .iter()
        .map(|x| x.path.clone())
        .collect::<BTreeSet<_>>()
        != dirs
    {
        return Err("generation payload directories differ from manifest".into());
    };
    if !markers
        .iter()
        .all(|m| expected.contains_key(m) || dirs.contains(m))
    {
        return Err("generation payload is missing a required class marker".into());
    };
    if first.dirs.iter().any(|x| x.mode & 0o222 != 0) {
        return Err("generation contains a writable directory".into());
    };
    verify_payload_hashes(generation_fd.as_raw_fd(), &expected)?;
    verify_final_hook(root);
    let last = inventory(generation_fd.as_raw_fd(), l)?;
    let final_manifest = manifest(generation_fd.as_raw_fd())?;
    let unchanged = final_manifest == m
        && first.files.len() == last.files.len()
        && first.dirs.len() == last.dirs.len()
        && first.files.iter().zip(&last.files).all(|(a, b)| same(a, b))
        && first.dirs.iter().zip(&last.dirs).all(|(a, b)| same(a, b));
    if !unchanged {
        return Err("generation changed while it was being verified".into());
    };
    if last.dirs.iter().any(|x| x.mode & 0o222 != 0) {
        return Err("generation contains a writable directory".into());
    }
    if last.files.iter().any(|x| x.mode & 0o222 != 0) {
        return Err("generation contains a writable file".into());
    }
    let finalg = stat(generation_fd.as_raw_fd())?;
    if identity(&finalg) != identity(&gs) || finalg.st_uid != uid() || mode(&finalg) & 0o222 != 0 {
        return Err("generation permissions changed while verifying".into());
    };
    let reopened_store = absolute_dir(root)?;
    let reopened_store_stat = stat(reopened_store.as_raw_fd())?;
    if identity(&reopened_store_stat) != identity(&ss)
        || reopened_store_stat.st_uid != uid()
        || mode(&reopened_store_stat) & 0o077 != 0
    {
        return Err("feed generation store path changed while verifying".into());
    }
    let parent_entry = stat_at(store.as_raw_fd(), entry)?;
    let reopened_generation = open_dir_at(store.as_raw_fd(), entry)?;
    let reopened_generation_stat = stat(reopened_generation.as_raw_fd())?;
    if !is_dir(&parent_entry)
        || identity(&parent_entry) != identity(&gs)
        || identity(&reopened_generation_stat) != identity(&gs)
        || reopened_generation_stat.st_uid != uid()
        || mode(&reopened_generation_stat) & 0o222 != 0
    {
        return Err("generation directory changed while it was being verified".into());
    }
    Ok(VerifiedGeneration {
        details: json!({"generation_id":id,"feed_release":RELEASE,"file_count":expected.len(),"byte_count":total,"class_count":5,"created_at":o["created_at"],"verified":true}),
        witness: VerificationWitness {
            generation_id: id.to_owned(),
            entry: entry.to_owned(),
            store_identity: identity(&ss),
            generation_identity: identity(&gs),
            inventory: last,
            manifest: final_manifest,
        },
    })
}

pub(super) fn recheck_verified_generation(
    root: &Path,
    witness: &VerificationWitness,
    l: &Limits,
) -> R<Value> {
    if !digest(&Value::String(witness.generation_id.clone())) {
        return Err("verified generation witness has an invalid identifier".into());
    }
    let store = absolute_dir(root)?;
    let store_stat = stat(store.as_raw_fd())?;
    if identity(&store_stat) != witness.store_identity
        || store_stat.st_uid != uid()
        || mode(&store_stat) & 0o077 != 0
    {
        return Err("feed generation store changed after verification".into());
    }
    let parent_entry = stat_at(store.as_raw_fd(), &witness.entry)?;
    let generation = open_dir_at(store.as_raw_fd(), &witness.entry)?;
    let generation_stat = stat(generation.as_raw_fd())?;
    if !is_dir(&parent_entry)
        || identity(&parent_entry) != witness.generation_identity
        || identity(&generation_stat) != witness.generation_identity
        || generation_stat.st_uid != uid()
        || mode(&generation_stat) & 0o222 != 0
    {
        return Err("generation directory changed after verification".into());
    }
    let current = inventory(generation.as_raw_fd(), l)?;
    if current != witness.inventory {
        return Err("generation tree changed after verification".into());
    }
    if manifest(generation.as_raw_fd())? != witness.manifest {
        return Err("generation manifest changed after verification".into());
    }
    let final_generation = stat(generation.as_raw_fd())?;
    let reopened_store = absolute_dir(root)?;
    let reopened_store_stat = stat(reopened_store.as_raw_fd())?;
    if identity(&final_generation) != witness.generation_identity
        || final_generation.st_uid != uid()
        || mode(&final_generation) & 0o222 != 0
        || identity(&reopened_store_stat) != witness.store_identity
        || reopened_store_stat.st_uid != uid()
        || mode(&reopened_store_stat) & 0o077 != 0
    {
        return Err("verified generation path changed while rechecking".into());
    }
    Ok(json!({
        "generation_id": witness.generation_id,
        "verified": true,
        "verification_reused": true,
    }))
}

fn selector(store: i32) -> R<Option<String>> {
    match stat_at_io(store, "current") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("could not inspect directory entry: {e}")),
        Ok(s) => {
            if !is_lnk(&s) || s.st_uid != uid() {
                return Err("current feed generation selector is not a user-owned symlink".into());
            };
            let n = c("current")?;
            let mut b = vec![0u8; 256]; /* SAFETY: valid descriptor, C name and writable buffer. */
            let r = unsafe { libc::readlinkat(store, n.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
            if r < 0 {
                return Err(err("could not read current feed generation selector"));
            };
            if r as usize == b.len() {
                return Err("current feed generation selector target is invalid".into());
            };
            let t = std::str::from_utf8(&b[..r as usize])
                .map_err(|_| "current feed generation selector target is invalid")?;
            let p: Vec<_> = t.split('/').collect();
            if t.starts_with('/')
                || p.len() != 2
                || p[0] != "generations"
                || !digest(&Value::String(p[1].into()))
            {
                return Err("current feed generation selector target is invalid".into());
            };
            Ok(Some(p[1].into()))
        }
    }
}
fn selector_is_symlink(store: i32) -> R<bool> {
    match stat_at_io(store, "current") {
        Ok(s) => Ok(is_lnk(&s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("could not inspect directory entry: {e}")),
    }
}
fn path_is_missing(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == io::ErrorKind::NotFound)
}
fn state(runtime: &Path, l: &Limits) -> R<Value> {
    let store_path = runtime.join("feed-store");
    let root = store_path.join("generations");
    let store = match absolute_dir(&store_path) {
        Ok(x) => x,
        Err(_e) if path_is_missing(&store_path) => {
            return Ok(
                json!({"generations_root":root,"store_exists":false,"generations":[],"generation_count":0,"orphan_staging":[],"invalid_entries":[],"current_pointer_exists":false,"current_generation_id":Value::Null,"current_error":Value::Null}),
            );
        }
        Err(e) => return Err(e),
    };
    let ss = stat(store.as_raw_fd())?;
    if ss.st_uid != uid() || mode(&ss) & 0o077 != 0 {
        return Err("feed generation store is not private and user-owned".into());
    };
    let current_pointer_exists = selector_is_symlink(store.as_raw_fd())?;
    let (current_id, current_error) = match selector(store.as_raw_fd()) {
        Ok(Some(id)) => match verify(&root, &id, l) {
            Ok(_) => {
                selector_recheck_hook(&store_path);
                match selector(store.as_raw_fd()) {
                    Ok(Some(rechecked)) if rechecked == id => (Value::String(id), Value::Null),
                    _ => (
                        Value::Null,
                        Value::String(
                            "current feed generation selector changed while verifying".into(),
                        ),
                    ),
                }
            }
            Err(e) => (Value::Null, Value::String(e)),
        },
        Ok(None) => (Value::Null, Value::Null),
        Err(e) => (Value::Null, Value::String(e)),
    };
    let gens = match absolute_dir(&root) {
        Ok(x) => x,
        Err(_e) if path_is_missing(&root) => {
            return Ok(
                json!({"generations_root":root,"store_exists":false,"generations":[],"generation_count":0,"orphan_staging":[],"invalid_entries":[],"current_pointer_exists":current_pointer_exists,"current_generation_id":current_id,"current_error":current_error}),
            );
        }
        Err(e) => return Err(e),
    };
    let gs = stat(gens.as_raw_fd())?;
    if gs.st_uid != uid() || mode(&gs) & 0o077 != 0 {
        return Err("feed generation store is not private and user-owned".into());
    };
    let ns = names(gens.as_raw_fd())?;
    if ns.len() > MAX_STORE_ENTRIES {
        return Err("feed generation store contains too many entries".into());
    };
    if ns.iter().any(|x| x.len() > MAX_NAME) {
        return Err("feed generation store contains an overlong entry name".into());
    };
    if ns
        .iter()
        .filter(|x| digest(&Value::String((*x).clone())))
        .count()
        > MAX_GENERATIONS
    {
        return Err("feed generation store contains too many generations".into());
    };
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let mut orphan = Vec::new();
    for n in ns.into_iter().collect::<BTreeSet<_>>() {
        if n == ".stage.lock" {
            continue;
        }
        if n.starts_with(".staging-") {
            orphan.push(n);
            continue;
        }
        if !digest(&Value::String(n.clone())) {
            invalid.push(json!({"name":n,"error":"unexpected generation-store entry"}));
            continue;
        }
        match verify(&root, &n, l) {
            Ok(v) => valid.push(v),
            Err(e) => invalid.push(json!({"name":n,"error":e})),
        }
    }
    Ok(
        json!({"generations_root":root,"store_exists":true,"generations":valid,"generation_count":valid.len(),"orphan_staging":orphan,"invalid_entries":invalid,"current_pointer_exists":current_pointer_exists,"current_generation_id":current_id,"current_error":current_error}),
    )
}
fn activation_consistency_finding<F>(
    current_id: Option<&str>,
    activation: Result<Option<Value>, String>,
    load_database: F,
    journal_path: &Path,
) -> Finding
where
    F: FnOnce() -> Result<Option<database::DatabaseAttestation>, String>,
{
    let activation = match activation {
        Ok(activation) => activation,
        Err(error) => {
            return Finding::new(
                "fail",
                "feed-generation.journal",
                format!("Feed activation journal is invalid: {error}"),
            )
            .with_path(&journal_path.display().to_string());
        }
    };
    match (current_id, activation) {
        (None, None) => Finding::new(
            "warn",
            "feed-generation.journal",
            "No feed activation has completed yet.".into(),
        )
        .with_path(&journal_path.display().to_string()),
        (Some(current_id), Some(activation))
            if activation["status"] == "active"
                && activation["current_generation_id"] == current_id =>
        {
            let database = match load_database() {
                Ok(database) => database,
                Err(error) => {
                    return Finding::new(
                        "fail",
                        "feed-generation.journal",
                        format!(
                            "Active feed generation database attestation failed closed: {error}"
                        ),
                    )
                    .with_path(&journal_path.display().to_string())
                    .with_details(json!({
                        "selector_generation_id": current_id,
                        "journal_generation_id": activation["current_generation_id"],
                        "journal_status": activation["status"],
                    }));
                }
            };
            let database_id = database
                .as_ref()
                .map(database::DatabaseAttestation::generation_id);
            let valid = database_id == Some(current_id);
            Finding::new(
                if valid { "pass" } else { "fail" },
                "feed-generation.journal",
                if valid {
                    "Active feed selector, completed import journal, and database attestation agree."
                        .into()
                } else {
                    "No completed feed activation and database attestation match the current selector; recover or explicitly re-import the verified generation before starting app services."
                        .into()
                },
            )
            .with_path(&journal_path.display().to_string())
            .with_details(json!({
                "selector_generation_id": current_id,
                "journal_generation_id": activation["current_generation_id"],
                "journal_status": activation["status"],
                "database_generation_id": database_id,
                "rollback_generation_id": activation
                    .get("rollback_generation_id")
                    .unwrap_or(&Value::Null),
            }))
        }
        (current_id, activation) => Finding::new(
            "fail",
            "feed-generation.journal",
            "Feed activation is interrupted or its journal does not match the selector; app startup is blocked."
                .into(),
        )
        .with_path(&journal_path.display().to_string())
        .with_details(json!({
            "selector_generation_id": current_id,
            "journal_generation_id": activation
                .as_ref()
                .and_then(|state| state.get("current_generation_id")),
            "journal_status": activation
                .as_ref()
                .and_then(|state| state.get("status")),
        })),
    }
}

pub fn command_feed_generation_state(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    let runtime = runtime_dir(repo_root);
    command_feed_generation_state_at(repo_root, &runtime, status_only)
}

fn command_feed_generation_state_at(
    repo_root: &Path,
    runtime: &Path,
    status_only: bool,
) -> ResultEnvelope {
    let root = runtime.join("feed-store/generations");
    let mut findings = Vec::new();
    match state(runtime, &Limits::default()) {
        Err(e) => findings.push(
            Finding::new(
                "fail",
                "feed-generation.state",
                format!("Feed generation store verification failed closed: {e}"),
            )
            .with_path(&root.display().to_string()),
        ),
        Ok(s) => {
            let inv = s["invalid_entries"].as_array().unwrap();
            if !inv.is_empty() {
                findings.push(
                    Finding::new(
                        "fail",
                        "feed-generation.integrity",
                        "One or more immutable feed generations failed verification.".into(),
                    )
                    .with_path(&root.display().to_string())
                    .with_details(json!({"invalid_entries":inv})),
                )
            } else if s["generation_count"] == 0 {
                findings.push(
                    Finding::new(
                        "warn",
                        "feed-generation.integrity",
                        "No immutable feed generation has been staged yet.".into(),
                    )
                    .with_path(&root.display().to_string())
                    .with_details(json!({"store_exists":s["store_exists"]})),
                )
            } else {
                findings.push(
                    Finding::new(
                        "pass",
                        "feed-generation.integrity",
                        format!(
                            "Verified {} immutable feed generation(s).",
                            s["generation_count"]
                        ),
                    )
                    .with_path(&root.display().to_string())
                    .with_details(json!({"generations":s["generations"]})),
                )
            }
            let o = s["orphan_staging"].as_array().unwrap();
            if o.is_empty() {
                findings.push(
                    Finding::new(
                        "pass",
                        "feed-generation.orphan-staging",
                        "No orphan feed-generation staging directories were found.".into(),
                    )
                    .with_path(&root.display().to_string()),
                )
            } else {
                findings.push(
                    Finding::new(
                        "warn",
                        "feed-generation.orphan-staging",
                        "Orphan feed-generation staging directories require review.".into(),
                    )
                    .with_path(&root.display().to_string())
                    .with_details(json!({"orphan_staging":o})),
                )
            }
            let cur = runtime.join("feed-store/current");
            if let Some(e) = s["current_error"].as_str() {
                findings.push(
                    Finding::new(
                        "fail",
                        "feed-generation.current",
                        format!("Active feed generation selector is invalid: {e}"),
                    )
                    .with_path(&cur.display().to_string()),
                )
            } else if let Some(id) = s["current_generation_id"].as_str() {
                findings.push(
                    Finding::new(
                        "pass",
                        "feed-generation.current",
                        "Active feed generation selector resolves to a fully verified generation."
                            .into(),
                    )
                    .with_path(&cur.display().to_string())
                    .with_details(json!({"current_generation_id":id})),
                )
            } else {
                findings.push(
                    Finding::new(
                        "warn",
                        "feed-generation.current",
                        "No feed generation is active.".into(),
                    )
                    .with_path(&cur.display().to_string()),
                )
            }
            let journal_path = journal::activation_state_path(runtime);
            findings.push(activation_consistency_finding(
                s["current_generation_id"].as_str(),
                journal::read_activation_state(runtime),
                || {
                    database::DatabaseAttestationAdapter::new(repo_root, &SystemCommandRunner)
                        .read()
                },
                &journal_path,
            ));
            findings.push(Finding::new("pass","feed-generation.activation-boundary","Generation state verification did not change the active runtime feed selector.".into()).with_path(&cur.display().to_string()).with_details(json!({"current_pointer_exists":s["current_pointer_exists"],"current_generation_id":s["current_generation_id"]})));
            for generation in s["generations"].as_array().unwrap() {
                if let Some(id) = generation["generation_id"].as_str() {
                    findings.extend(
                        provenance::signature_findings(
                            repo_root,
                            &root.join(id),
                            &SystemCommandRunner,
                        )
                        .0,
                    );
                }
            }
        }
    }
    let mut result = make_result(
        metadata(repo_root, "feed-generation-state", &SystemCommandRunner),
        "Immutable feed generation state verified.".into(),
        findings,
    )
    .with_artifacts(vec![root.display().to_string()]);
    if status_only {
        result.findings = result
            .findings
            .iter()
            .filter(|x| x.status != "pass")
            .map(compact_finding)
            .collect();
        if result.findings.is_empty() {
            result.findings.push(Finding::new(
                "pass",
                "feed-generation-state.status-only",
                "Feed generation state passed without non-pass findings.".into(),
            ))
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yafvs-feed-generation-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn selected_generation(generation_id: &str) -> Value {
        json!({"generation_id": generation_id, "verified": true})
    }

    fn active_journal(generation_id: &str) -> Value {
        json!({
            "schema_version": 1,
            "status": "active",
            "current_generation_id": generation_id,
            "target_generation_id": null,
            "previous_generation_id": null,
            "rollback_generation_id": null,
        })
    }

    #[test]
    fn runtime_guard_selector_only_skips_database() {
        let runtime = fixture("runtime-guard-selector-only");
        let generation_id = "a".repeat(64);
        let finding = active_feed_generation_runtime_guard_finding(
            &runtime,
            Ok(Some(selected_generation(&generation_id))),
            Ok(Some(active_journal(&generation_id))),
            true,
            || panic!("selector-only guard must not read PostgreSQL"),
        );

        assert_eq!(finding.status, "pass");
        assert_eq!(finding.check, "feed-generation.selector-journal");
        assert_eq!(
            finding.details.unwrap()["selector_generation_id"],
            generation_id
        );
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn runtime_guard_binds_full_verification_to_the_preliminary_reference() {
        let generation_id = "a".repeat(64);
        let other_generation_id = "b".repeat(64);
        assert!(
            require_referenced_generation(
                Some(&generation_id),
                Ok(Some(selected_generation(&generation_id))),
            )
            .is_ok()
        );
        assert_eq!(
            require_referenced_generation(
                Some(&generation_id),
                Ok(Some(selected_generation(&other_generation_id))),
            )
            .unwrap_err(),
            "current feed generation changed between reference resolution and full verification"
        );
        assert!(require_referenced_generation(None, Ok(None)).is_err());
    }

    #[test]
    fn runtime_guard_rejects_interrupted_journal() {
        let runtime = fixture("runtime-guard-transitioning");
        let generation_id = "a".repeat(64);
        let finding = active_feed_generation_runtime_guard_finding(
            &runtime,
            Ok(Some(selected_generation(&generation_id))),
            Ok(Some(json!({
                "status": "transitioning",
                "current_generation_id": null,
                "target_generation_id": generation_id,
            }))),
            true,
            || panic!("selector-only guard must not read PostgreSQL"),
        );

        assert_eq!(finding.status, "fail");
        assert_eq!(finding.check, "feed-generation.selector-journal");
        assert!(
            finding
                .message
                .contains("No completed feed activation journal")
        );
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn runtime_guard_propagates_selector_failure_without_database_read() {
        let runtime = fixture("runtime-guard-selector-failure");
        let finding = active_feed_generation_runtime_guard_finding(
            &runtime,
            Err("selector changed while verifying".into()),
            Ok(None),
            false,
            || panic!("failed selector/journal guard must not read PostgreSQL"),
        );

        assert_eq!(finding.status, "fail");
        assert_eq!(finding.check, "feed-generation.current");
        assert!(finding.message.contains("failed closed"));
        assert!(finding.message.contains("selector changed while verifying"));
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn runtime_guard_requires_matching_database_attestation() {
        let runtime = fixture("runtime-guard-database");
        let generation_id = "a".repeat(64);
        let invoke = |database_generation_id: Option<String>| {
            active_feed_generation_runtime_guard_finding(
                &runtime,
                Ok(Some(selected_generation(&generation_id))),
                Ok(Some(active_journal(&generation_id))),
                false,
                || Ok(database_generation_id),
            )
        };

        assert_eq!(invoke(None).status, "fail");
        assert_eq!(invoke(Some("b".repeat(64))).status, "fail");
        let matching = invoke(Some(generation_id.clone()));
        assert_eq!(matching.status, "pass");
        assert_eq!(matching.check, "feed-generation.current");
        assert_eq!(
            matching.details.unwrap()["database_generation_id"],
            generation_id
        );
        fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn runtime_guard_fails_closed_when_database_is_unavailable() {
        let runtime = fixture("runtime-guard-database-error");
        let generation_id = "a".repeat(64);
        let finding = active_feed_generation_runtime_guard_finding(
            &runtime,
            Ok(Some(selected_generation(&generation_id))),
            Ok(Some(active_journal(&generation_id))),
            false,
            || Err("malformed attestation".into()),
        );

        assert_eq!(finding.status, "fail");
        assert_eq!(finding.check, "feed-generation.current");
        assert!(
            finding
                .message
                .contains("database attestation failed closed")
        );
        assert!(finding.message.contains("malformed attestation"));
        fs::remove_dir_all(runtime).unwrap();
    }
    fn private(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn readonly(path: &Path, directory: bool) {
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o555 } else { 0o444 }),
        )
        .unwrap();
    }
    fn put(root: &Path, path: &str, bytes: &[u8]) {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    fn seal_tree(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                seal_tree(&entry.path());
                readonly(&entry.path(), true);
            } else {
                readonly(&entry.path(), false);
            }
        }
        readonly(path, true);
    }
    pub(super) fn cleanup_tree(path: &Path) {
        if fs::symlink_metadata(path).unwrap().file_type().is_symlink() {
            return;
        }
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                cleanup_tree(&entry.unwrap().path());
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn manifest_id(manifest: &Value) -> String {
        let content = json!({
            "schema_version": manifest["schema_version"],
            "feed_release": manifest["feed_release"],
            "classes": manifest["classes"],
            "files": manifest["files"],
            "signature_provenance": manifest["signature_provenance"],
        });
        let mut output = String::new();
        canonical(&content, &mut output);
        sha(output.as_bytes())
    }
    fn rewrite_manifest(root: &Path, old_id: &str, mut manifest: Value) -> String {
        let new_id = manifest_id(&manifest);
        manifest["generation_id"] = json!(new_id);
        let old = root.join("feed-store/generations").join(old_id);
        let new = root.join("feed-store/generations").join(&new_id);
        fs::set_permissions(&old, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(old.join(MANIFEST), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(old.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::rename(old, new).unwrap();
        seal_tree(&root.join("feed-store/generations").join(&new_id));
        new_id
    }
    pub(super) fn valid_generation(name: &str) -> (std::path::PathBuf, String) {
        let root = fixture(name);
        let store = root.join("feed-store");
        let generations = store.join("generations");
        fs::create_dir(&store).unwrap();
        private(&store);
        fs::create_dir(&generations).unwrap();
        private(&generations);
        let stage = generations.join("stage");
        fs::create_dir(&stage).unwrap();
        let mut files: BTreeMap<&str, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        files.insert(
            "nasl",
            vec![
                ("plugin_feed_info.inc".into(), b"nasl-info".to_vec()),
                ("LICENSE".into(), b"nasl-license".to_vec()),
            ],
        );
        files.insert(
            "notus",
            vec![
                ("advisories/data".into(), b"advisory".to_vec()),
                ("products/data".into(), b"product".to_vec()),
                ("LICENSE".into(), b"license".to_vec()),
                ("LICENSE.GPLv2".into(), b"gpl".to_vec()),
                ("LICENSE.ODbLv1".into(), b"odbl".to_vec()),
                ("timestamp".into(), b"time".to_vec()),
            ],
        );
        files.insert(
            "scap",
            vec![
                ("COPYING".into(), b"copy".to_vec()),
                ("feed.xml".into(), b"feed".to_vec()),
                ("timestamp".into(), b"time".to_vec()),
            ],
        );
        files.insert(
            "cert",
            vec![
                ("COPYING.CERT-BUND".into(), b"bund".to_vec()),
                ("COPYING.DFN-CERT".into(), b"dfn".to_vec()),
                ("feed.xml".into(), b"feed".to_vec()),
            ],
        );
        files.insert(
            "gvmd",
            vec![
                ("LICENSE".into(), b"license".to_vec()),
                ("feed.xml".into(), b"feed".to_vec()),
                ("timestamp".into(), b"time".to_vec()),
                ("scan-configs/item".into(), b"scan".to_vec()),
                ("report-formats/item".into(), b"report".to_vec()),
                ("port-lists/item".into(), b"port".to_vec()),
            ],
        );
        for key in ["nasl", "notus", "cert"] {
            let spec = specs().into_iter().find(|spec| spec.key == key).unwrap();
            for (checksums, _) in spec.signed {
                let parent = checksums.rsplit_once('/').map_or("", |v| v.0);
                let rows = files[key]
                    .iter()
                    .filter(|(path, _)| path.rsplit_once('/').map_or("", |v| v.0) == parent)
                    .map(|(path, bytes)| {
                        let listed = path.rsplit_once('/').map_or(path.as_str(), |v| v.1);
                        format!("{}  {listed}\n", sha(bytes))
                    })
                    .collect::<String>();
                files
                    .get_mut(key)
                    .unwrap()
                    .push(((*checksums).into(), rows.into_bytes()));
                let signature = spec
                    .signed
                    .iter()
                    .find(|(sum, _)| sum == checksums)
                    .unwrap()
                    .1;
                files
                    .get_mut(key)
                    .unwrap()
                    .push((signature.into(), b"signature".to_vec()));
            }
        }
        let mut class_rows = Vec::new();
        let mut file_rows = Vec::new();
        let mut provenance = Vec::new();
        for key in ["cert", "gvmd", "nasl", "notus", "scap"] {
            let spec = specs().into_iter().find(|spec| spec.key == key).unwrap();
            let mut dirs = BTreeSet::new();
            let mut byte_count = 0u64;
            let mut entries = files[key].clone();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (path, bytes) in &entries {
                byte_count += bytes.len() as u64;
                let runtime_path = format!("{}/{}", spec.runtime, path);
                file_rows.push(json!({"class":key,"path":path,"runtime_path":runtime_path,"sha256":sha(bytes),"size":bytes.len()}));
                if let Some((parent, _)) = path.rsplit_once('/') {
                    dirs.insert(parent.to_string());
                }
            }
            class_rows.push(json!({
                "key": key, "source_rel": spec.source, "runtime_rel": spec.runtime,
                "markers": spec.markers, "signed_manifests": spec.signed.iter().map(|(checksums, signature)| json!({"checksums":checksums,"signature":signature})).collect::<Vec<_>>(),
                "signing_key_fingerprint": if spec.signed.is_empty() { Value::Null } else { json!(FPR) },
                "unsigned_metadata": spec.unsigned, "file_count": entries.len(), "byte_count": byte_count,
                "directories": dirs.into_iter().collect::<Vec<_>>(),
            }));
            for (checksums, signature) in spec.signed {
                let sum = entries
                    .iter()
                    .find(|(path, _)| path == checksums)
                    .unwrap()
                    .1
                    .clone();
                let sig = entries
                    .iter()
                    .find(|(path, _)| path == signature)
                    .unwrap()
                    .1
                    .clone();
                provenance.push(json!({"class":key,"checksums_path":checksums,"signature_path":signature,"checksums_sha256":sha(&sum),"signature_sha256":sha(&sig),"signing_key_fingerprint":FPR}));
            }
        }
        file_rows.sort_by(|a, b| {
            (a["class"].as_str(), a["path"].as_str())
                .cmp(&(b["class"].as_str(), b["path"].as_str()))
        });
        let total = file_rows
            .iter()
            .map(|row| row["size"].as_u64().unwrap())
            .sum::<u64>();
        let mut manifest = json!({"schema_version":1,"feed_release":RELEASE,"classes":class_rows,"files":file_rows,"signature_provenance":provenance,"generation_id":"","created_at":"2026-01-01T00:00:00+00:00","source_snapshot":{"class_count":5,"file_count":file_rows.len(),"byte_count":total}});
        let id = manifest_id(&manifest);
        manifest["generation_id"] = json!(id);
        for (key, entries) in &files {
            let spec = specs().into_iter().find(|spec| spec.key == *key).unwrap();
            for (path, bytes) in entries {
                put(&stage, &format!("{}/{}", spec.runtime, path), bytes);
            }
        }
        put(&stage, MANIFEST, &serde_json::to_vec(&manifest).unwrap());
        let final_path = generations.join(&id);
        fs::rename(stage, &final_path).unwrap();
        seal_tree(&final_path);
        (root, id)
    }

    #[test]
    fn missing_store_is_read_only() {
        let root = fixture("missing");
        let before = fs::read_dir(&root).unwrap().count();
        let result = state(&root, &Limits::default()).unwrap();
        assert_eq!(result["store_exists"], false);
        assert_eq!(before, fs::read_dir(&root).unwrap().count());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn active_state_requires_matching_database_attestation() {
        let current = "a".repeat(64);
        let other = "b".repeat(64);
        let activation = || {
            Ok(Some(json!({
                "status": "active",
                "current_generation_id": current,
                "rollback_generation_id": Value::Null,
            })))
        };
        let path = Path::new("/runtime/state/feed-generation/activation.json");

        let missing =
            activation_consistency_finding(Some(&current), activation(), || Ok(None), path);
        assert_eq!(missing.status, "fail");

        let mismatched = activation_consistency_finding(
            Some(&current),
            activation(),
            || database::DatabaseAttestation::new(&other, "2026-07-18T12:00:00Z").map(Some),
            path,
        );
        assert_eq!(mismatched.status, "fail");

        let invalid = activation_consistency_finding(
            Some(&current),
            activation(),
            || Err("invalid database attestation".into()),
            path,
        );
        assert_eq!(invalid.status, "fail");

        let matching = activation_consistency_finding(
            Some(&current),
            activation(),
            || database::DatabaseAttestation::new(&current, "2026-07-18T12:00:00Z").map(Some),
            path,
        );
        assert_eq!(matching.status, "pass");
    }

    #[test]
    fn empty_state_command_and_status_only_have_exact_contract() {
        let root = fixture("state-command-empty");
        let repo = root.join("YAFVS");
        let runtime = root.join("runtime");
        fs::create_dir(&repo).unwrap();

        let result = command_feed_generation_state_at(&repo, &runtime, false);
        let compact = command_feed_generation_state_at(&repo, &runtime, true);
        let generations = runtime.join("feed-store/generations");

        assert_eq!(result.status, "warn");
        assert_eq!(result.summary, "Immutable feed generation state verified.");
        assert_eq!(result.artifacts, vec![generations.display().to_string()]);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| (finding.check.as_str(), finding.status.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("feed-generation.integrity", "warn"),
                ("feed-generation.orphan-staging", "pass"),
                ("feed-generation.current", "warn"),
                ("feed-generation.journal", "warn"),
                ("feed-generation.activation-boundary", "pass"),
            ]
        );
        assert_eq!(compact.status, "warn");
        assert_eq!(
            compact
                .findings
                .iter()
                .map(|finding| (finding.check.as_str(), finding.status.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("feed-generation.integrity", "warn"),
                ("feed-generation.current", "warn"),
                ("feed-generation.journal", "warn"),
            ]
        );
        assert_eq!(compact.artifacts, result.artifacts);
        assert_eq!(compact.metadata.command, "feed-generation-state");

        fs::remove_dir(repo).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn interrupted_or_mismatched_activation_journal_fails_state_contract() {
        let current = "a".repeat(64);
        let other = "b".repeat(64);
        let path = Path::new("/runtime/state/feed-generation/activation.json");
        for activation in [
            json!({
                "status": "transitioning",
                "current_generation_id": Value::Null,
                "target_generation_id": current,
            }),
            json!({
                "status": "active",
                "current_generation_id": other,
                "rollback_generation_id": Value::Null,
            }),
        ] {
            let finding = activation_consistency_finding(
                Some(&current),
                Ok(Some(activation)),
                || panic!("mismatched journal must not query the database"),
                path,
            );
            assert_eq!(finding.status, "fail");
            assert_eq!(
                finding.message,
                "Feed activation is interrupted or its journal does not match the selector; app startup is blocked."
            );
            assert_eq!(
                finding.details.as_ref().unwrap()["selector_generation_id"],
                current
            );
        }
    }

    #[test]
    fn unsafe_selector_and_non_private_store_fail_closed() {
        let root = fixture("selector");
        let store = root.join("feed-store");
        fs::create_dir(&store).unwrap();
        private(&store);
        fs::create_dir(store.join("generations")).unwrap();
        private(&store.join("generations"));
        symlink("/tmp/not-a-generation", store.join("current")).unwrap();
        let result = state(&root, &Limits::default()).unwrap();
        assert_eq!(
            result["current_error"],
            "current feed generation selector target is invalid"
        );
        assert_eq!(result["current_pointer_exists"], true);
        fs::remove_file(store.join("current")).unwrap();
        fs::write(store.join("current"), b"not a selector").unwrap();
        let result = state(&root, &Limits::default()).unwrap();
        assert_eq!(result["current_pointer_exists"], false);
        assert_eq!(
            result["current_error"],
            "current feed generation selector is not a user-owned symlink"
        );
        fs::remove_file(store.join("current")).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            state(&root, &Limits::default()).unwrap_err(),
            "feed generation store is not private and user-owned"
        );
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(store.join("generations")).unwrap();
        fs::remove_dir(store).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn orphan_and_store_entry_limits_do_not_follow_entries() {
        let root = fixture("entries");
        let store = root.join("feed-store");
        let generations = store.join("generations");
        fs::create_dir(&store).unwrap();
        private(&store);
        fs::create_dir(&generations).unwrap();
        private(&generations);
        symlink(
            "/definitely/not/followed",
            generations.join(".staging-unfinished"),
        )
        .unwrap();
        let result = state(&root, &Limits::default()).unwrap();
        assert_eq!(result["orphan_staging"], json!([".staging-unfinished"]));
        for n in 0..=MAX_STORE_ENTRIES {
            fs::write(generations.join(format!("x{n}")), b"x").unwrap();
        }
        assert_eq!(
            state(&root, &Limits::default()).unwrap_err(),
            "feed generation store contains too many entries"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verification_witness_recheck_rejects_post_hash_mutation() {
        let (root, id) = valid_generation("witness-mutation");
        let generations = root.join("feed-store/generations");
        let verified = verify_with_witness(&generations, &id, &Limits::default()).unwrap();
        let (_, witness) = verified.into_parts();
        assert!(recheck_verified_generation(&generations, &witness, &Limits::default()).is_ok());

        let payload = generations.join(&id).join("gvm/scap-data/feed.xml");
        let parent = payload.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
        let mut changed = fs::read(&payload).unwrap();
        changed[0] ^= 1;
        fs::write(&payload, changed).unwrap();
        readonly(&payload, false);
        readonly(parent, true);

        assert_eq!(
            recheck_verified_generation(&generations, &witness, &Limits::default()).unwrap_err(),
            "generation tree changed after verification"
        );
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checksum_coverage_and_writable_generation_are_rejected_before_payload_trust() {
        let root = fixture("sealed");
        let store = root.join("feed-store");
        let generations = store.join("generations");
        let id = "a".repeat(64);
        fs::create_dir(&store).unwrap();
        private(&store);
        fs::create_dir(&generations).unwrap();
        private(&generations);
        fs::create_dir(generations.join(&id)).unwrap();
        fs::set_permissions(generations.join(&id), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            verify(&generations, &id, &Limits::default()).unwrap_err(),
            "generation root is writable"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sealed_generation_passes_with_exact_counts_and_uppercase_sums() {
        let (root, id) = valid_generation("valid");
        let generations = root.join("feed-store/generations");
        let verified = verify(&generations, &id, &Limits::default()).unwrap();
        assert_eq!(verified["file_count"], 28);
        assert_eq!(verified["byte_count"], 687);
        assert_eq!(verified["class_count"], 5);
        let sum = generations.join(&id).join("openvas/plugins/sha256sums");
        fs::set_permissions(sum.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&sum, fs::Permissions::from_mode(0o644)).unwrap();
        let uppercase = fs::read_to_string(&sum)
            .unwrap()
            .lines()
            .map(|line| format!("{}{}\n", line[..64].to_ascii_uppercase(), &line[64..]))
            .collect::<String>();
        fs::write(&sum, uppercase.as_bytes()).unwrap();
        readonly(&sum, false);
        readonly(sum.parent().unwrap(), true);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(generations.join(&id).join(MANIFEST)).unwrap())
                .unwrap();
        let sum_digest = sha(uppercase.as_bytes());
        for row in manifest["files"].as_array_mut().unwrap() {
            if row["runtime_path"] == "openvas/plugins/sha256sums" {
                row["sha256"] = json!(sum_digest);
            }
        }
        for row in manifest["signature_provenance"].as_array_mut().unwrap() {
            if row["class"] == "nasl" {
                row["checksums_sha256"] = json!(sum_digest);
            }
        }
        let id = rewrite_manifest(&root, &id, manifest);
        assert!(verify(&generations, &id, &Limits::default()).is_ok());
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_contract_tampering_is_rejected() {
        let (root, id) = valid_generation("contract");
        let generations = root.join("feed-store/generations");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(generations.join(&id).join(MANIFEST)).unwrap())
                .unwrap();
        manifest["created_at"] = json!(7);
        let id = rewrite_manifest(&root, &id, manifest);
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(generations.join(&id).join(MANIFEST)).unwrap())
                .unwrap();
        manifest["created_at"] = json!("2026-01-01T00:00:00+00:00");
        for row in manifest["classes"].as_array_mut().unwrap() {
            if row["key"] == "scap" {
                row["signing_key_fingerprint"] = json!(false);
            }
        }
        let id = rewrite_manifest(&root, &id, manifest);
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(generations.join(&id).join(MANIFEST)).unwrap())
                .unwrap();
        for row in manifest["classes"].as_array_mut().unwrap() {
            if row["key"] == "scap" {
                row["signing_key_fingerprint"] = Value::Null;
            }
        }
        manifest["signature_provenance"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let id = rewrite_manifest(&root, &id, manifest);
        assert_eq!(
            verify(&generations, &id, &Limits::default()).unwrap_err(),
            "generation signature provenance is not sorted"
        );
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_payload_release_and_writable_file_are_rejected() {
        let (root, id) = valid_generation("tamper");
        let generations = root.join("feed-store/generations");
        let payload = generations.join(&id).join("gvm/scap-data/feed.xml");
        fs::set_permissions(payload.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&payload, b"tampered").unwrap();
        readonly(&payload, false);
        readonly(payload.parent().unwrap(), true);
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();

        let (root, id) = valid_generation("release");
        let generations = root.join("feed-store/generations");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(generations.join(&id).join(MANIFEST)).unwrap())
                .unwrap();
        manifest["feed_release"] = json!("bad");
        let id = rewrite_manifest(&root, &id, manifest);
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selector_recheck_and_final_path_identity_fail_closed() {
        let (root, id) = valid_generation("races");
        let store = root.join("feed-store");
        symlink(format!("generations/{id}"), store.join("current")).unwrap();
        let selector = store.join("current");
        *SELECTOR_RECHECK_HOOK.lock().unwrap() = Some((
            store.clone(),
            Box::new(move || {
                fs::remove_file(&selector).unwrap();
                symlink(
                    "generations/0000000000000000000000000000000000000000000000000000000000000000",
                    selector,
                )
                .unwrap();
            }),
        ));
        let result = state(&root, &Limits::default()).unwrap();
        assert_eq!(
            result["current_error"],
            "current feed generation selector changed while verifying"
        );
        let generations = root.join("feed-store/generations");
        let original = generations.join(&id);
        let replacement = generations.join("replacement");
        *VERIFY_FINAL_HOOK.lock().unwrap() = Some((
            generations.clone(),
            Box::new(move || {
                fs::rename(&original, &replacement).unwrap();
                fs::create_dir(&original).unwrap();
                readonly(&original, true);
            }),
        ));
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();

        let (root, id) = valid_generation("root-race");
        let generations = root.join("feed-store/generations");
        let replaced = root.join("feed-store/generations-old");
        let path = generations.clone();
        *VERIFY_FINAL_HOOK.lock().unwrap() = Some((
            generations.clone(),
            Box::new(move || {
                fs::rename(&path, &replaced).unwrap();
                fs::create_dir(&path).unwrap();
                private(&path);
            }),
        ));
        assert!(verify(&generations, &id, &Limits::default()).is_err());
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_json_matches_python_escape_and_unicode_vectors() {
        let vectors = [
            (json!("\u{8}\u{c}"), "\"\\b\\f\""),
            (json!("é"), "\"\\u00e9\""),
            (json!("😀"), "\"\\ud83d\\ude00\""),
            (
                json!({"z":"\u{8}","a":"é"}),
                "{\"a\":\"\\u00e9\",\"z\":\"\\b\"}",
            ),
        ];
        for (value, expected) in vectors {
            let mut actual = String::new();
            canonical(&value, &mut actual);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn invalid_utf8_enumeration_releases_descriptor() {
        use std::os::unix::ffi::OsStringExt;
        let root = fixture("utf8");
        let store = root.join("feed-store");
        let generations = store.join("generations");
        fs::create_dir(&store).unwrap();
        private(&store);
        fs::create_dir(&generations).unwrap();
        private(&generations);
        let invalid = generations.join(std::ffi::OsString::from_vec(vec![0xff]));
        fs::write(invalid, b"x").unwrap();
        let target = absolute_dir(&generations).unwrap();
        let target_identity = identity(&stat(target.as_raw_fd()).unwrap());
        drop(target);
        let fds = || {
            fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
                .filter(|fd| stat(*fd).is_ok_and(|metadata| identity(&metadata) == target_identity))
                .count()
        };
        let before = fds();
        for _ in 0..8 {
            assert!(state(&root, &Limits::default()).is_err());
        }
        assert_eq!(fds(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stage_command_reports_exact_lifecycle_lock_timeout_contract() {
        let root = fixture("stage-lock-timeout");
        let repo = root.join("YAFVS");
        fs::create_dir(&repo).unwrap();
        let holder = RuntimeOperationLock::acquire(
            &repo,
            FEED_ACTIVATION_LOCK,
            "feed-generation-activate",
            std::time::Duration::ZERO,
        )
        .unwrap();

        let result = command_feed_generation_stage_with_timeout(&repo, std::time::Duration::ZERO);

        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Feed generation staging stopped while waiting for the feed lifecycle lock."
        );
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["operation"],
            "feed-generation-stage"
        );
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["holder"]["operation"],
            "feed-generation-activate"
        );
        assert_eq!(
            result.artifacts,
            vec![runtime_lock_dir(&repo).display().to_string()]
        );
        drop(holder);
        cleanup_tree(&root);
        fs::remove_dir_all(root).unwrap();
    }
}
