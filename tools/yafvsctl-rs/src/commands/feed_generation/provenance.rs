// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Detached-signature provenance checks for already verified feed generations.

use super::{FPR, Limits, absolute_dir, beneath, parts, specs, stable_read, stat_at};
use crate::commands::common::{executable_path, output_tail, runtime_dir};
use crate::process::{CommandRunner, ProcessOutput};
use crate::result::Finding;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_SIGNED_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum ContentLayout {
    Cache,
    Generation,
}

impl ContentLayout {
    fn class_root(self, spec: &super::Spec) -> &str {
        match self {
            Self::Cache => spec.source,
            Self::Generation => spec.runtime,
        }
    }

    fn reopen_error(self, error: &str) -> String {
        match self {
            Self::Cache => format!("Feed cache could not be reopened safely: {error}"),
            Self::Generation => {
                format!("Verified generation could not be reopened safely: {error}")
            }
        }
    }
}

struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_tree() -> Result<TempTree, String> {
    let root = std::env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..64 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            "turbovas-feed-signature-{}-{now}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
                    let _ = fs::remove_dir(&path);
                    return Err(format!("could not secure temporary directory: {error}"));
                }
                return Ok(TempTree(path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("could not create temporary directory: {error}")),
        }
    }
    Err("could not allocate a unique temporary directory".into())
}

fn fingerprint_present(output: &str) -> bool {
    output.lines().any(|line| {
        let mut fields = line.split(':');
        fields.next() == Some("fpr")
            && fields
                .nth(8)
                .is_some_and(|fingerprint| fingerprint.eq_ignore_ascii_case(FPR))
    })
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not create private temporary file: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("could not write private temporary file: {error}"))?;
    file.flush()
        .map_err(|error| format!("could not flush private temporary file: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not secure private temporary file: {error}"))
}

fn failed_output() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(127),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn stable_source(root: i32, path: &str, layout: ContentLayout) -> Result<Vec<u8>, String> {
    let limits = Limits::default();
    let components = parts(path, &limits)?;
    let parent = beneath(root, &components[..components.len() - 1])?;
    let metadata = stat_at(parent.as_raw_fd(), components[components.len() - 1])?;
    if metadata.st_size < 0 || metadata.st_size as u64 > MAX_SIGNED_SOURCE_BYTES {
        return Err(format!(
            "file is unsafe or exceeds {MAX_SIGNED_SOURCE_BYTES} bytes: {path}"
        ));
    }
    stable_read(
        root,
        path,
        metadata.st_size as u64,
        false,
        matches!(layout, ContentLayout::Cache),
    )
}

fn keyring_is_safe(home: &Path) -> bool {
    absolute_dir(home).is_ok_and(|descriptor| {
        super::stat(descriptor.as_raw_fd()).is_ok_and(|metadata| {
            metadata.st_uid == super::uid() && super::mode(&metadata) & 0o077 == 0
        })
    })
}

fn signature_provenance_with(
    repo_root: &Path,
    content_root: &Path,
    layout: ContentLayout,
    runner: &dyn CommandRunner,
    gpg: Option<&Path>,
) -> (Vec<Finding>, Vec<Value>) {
    let mut findings = Vec::new();
    let mut provenance = Vec::new();
    let home = runtime_dir(repo_root).join("state/feed-gnupg");
    let home_safe = keyring_is_safe(&home);
    findings.push(
        Finding::new(
            if home_safe { "pass" } else { "fail" },
            "feed-generation.signing-keyring",
            if home_safe {
                "Feed signature keyring is private and user-owned.".into()
            } else {
                "Feed signature keyring is missing, not private, or not user-owned; run just runtime-feed-keyring-init."
                    .into()
            },
        )
        .with_path(&home.display().to_string()),
    );
    let Some(gpg) = gpg.and_then(Path::to_str) else {
        findings.push(Finding::new(
            "fail",
            "feed-generation.gpg",
            "GPG is required to verify signed feed manifests.".into(),
        ));
        return (findings, provenance);
    };
    if !home_safe {
        return (findings, provenance);
    }
    let home_text = home.to_string_lossy().into_owned();
    let fingerprint_args = [
        "--batch",
        "--homedir",
        home_text.as_str(),
        "--with-colons",
        "--fingerprint",
        FPR,
    ];
    let fingerprint = runner
        .run_with(
            gpg,
            &fingerprint_args,
            Some(repo_root),
            None,
            Some(Duration::from_secs(60)),
        )
        .unwrap_or_else(failed_output);
    let fingerprint_ok = fingerprint.success
        && fingerprint.exit_code == Some(0)
        && fingerprint_present(&fingerprint.stdout);
    findings.push(
        Finding::new(
            if fingerprint_ok { "pass" } else { "fail" },
            "feed-generation.signing-key",
            if fingerprint_ok {
                "Configured Greenbone Community signing-key fingerprint is present.".into()
            } else {
                "Configured Greenbone Community signing-key fingerprint is missing.".into()
            },
        )
        .with_details(json!({
            "fingerprint": FPR,
            "output_tail": output_tail(&fingerprint.stdout, 40),
        })),
    );
    if !fingerprint_ok {
        return (findings, provenance);
    }

    let temporary = match temp_tree() {
        Ok(temporary) => temporary,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "feed-generation.signature-temporary",
                format!("Could not create private signature-verification workspace: {error}"),
            ));
            return (findings, provenance);
        }
    };
    let content = match absolute_dir(content_root) {
        Ok(content) => content,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "feed-generation.signature-source",
                layout.reopen_error(&error),
            ));
            return (findings, provenance);
        }
    };
    for spec in specs().into_iter().filter(|spec| !spec.signed.is_empty()) {
        let relative_root = layout.class_root(&spec);
        let class_root = content_root.join(relative_root);
        for (index, (checksums_rel, signature_rel)) in spec.signed.iter().enumerate() {
            let checksums_path = format!("{relative_root}/{checksums_rel}");
            let signature_path = format!("{relative_root}/{signature_rel}");
            let (checksums, signature) = match (
                stable_source(content.as_raw_fd(), &checksums_path, layout),
                stable_source(content.as_raw_fd(), &signature_path, layout),
            ) {
                (Ok(checksums), Ok(signature)) => (checksums, signature),
                (Err(error), _) | (_, Err(error)) => {
                    findings.push(
                        Finding::new(
                            "fail",
                            &format!("feed-generation.signature.{}.{index}", spec.key),
                            format!("Signed feed manifest files are unsafe or unreadable: {error}"),
                        )
                        .with_path(&class_root.display().to_string()),
                    );
                    continue;
                }
            };
            let temporary_checksums = temporary.0.join(format!("{}-{index}.sha256sums", spec.key));
            let temporary_signature = temporary
                .0
                .join(format!("{}-{index}.sha256sums.asc", spec.key));
            if let Err(error) = private_file(&temporary_checksums, &checksums)
                .and_then(|()| private_file(&temporary_signature, &signature))
            {
                findings.push(
                    Finding::new(
                        "fail",
                        &format!("feed-generation.signature.{}.{index}", spec.key),
                        format!("Signed feed manifest files are unsafe or unreadable: {error}"),
                    )
                    .with_path(&class_root.display().to_string()),
                );
                continue;
            }
            let signature_text = temporary_signature.to_string_lossy().into_owned();
            let checksums_text = temporary_checksums.to_string_lossy().into_owned();
            let verify_args = [
                "--batch",
                "--homedir",
                home_text.as_str(),
                "--status-fd=1",
                "--verify",
                signature_text.as_str(),
                checksums_text.as_str(),
            ];
            let verify = runner
                .run_with(
                    gpg,
                    &verify_args,
                    Some(repo_root),
                    None,
                    Some(Duration::from_secs(120)),
                )
                .unwrap_or_else(failed_output);
            let valid_signer = verify.stdout.lines().any(|line| {
                line.starts_with("[GNUPG:] VALIDSIG ")
                    && line
                        .to_ascii_uppercase()
                        .split_whitespace()
                        .any(|token| token == FPR)
            });
            let passed = verify.success && verify.exit_code == Some(0) && valid_signer;
            let exit_code = verify.exit_code.unwrap_or(-1);
            findings.push(
                Finding::new(
                    if passed { "pass" } else { "fail" },
                    &format!("feed-generation.signature.{}.{index}", spec.key),
                    format!(
                        "Verify signed {} checksum manifest exit code {exit_code}.",
                        spec.key
                    ),
                )
                .with_path(&content_root.join(&checksums_path).display().to_string())
                .with_details(json!({"output_tail": output_tail(&verify.stdout, 40)})),
            );
            if passed {
                provenance.push(json!({
                    "class": spec.key,
                    "checksums_path": checksums_rel,
                    "signature_path": signature_rel,
                    "checksums_sha256": format!("{:x}", Sha256::digest(&checksums)),
                    "signature_sha256": format!("{:x}", Sha256::digest(&signature)),
                    "signing_key_fingerprint": FPR,
                }));
            }
        }
    }
    provenance.sort_by(|left, right| {
        (left["class"].as_str(), left["checksums_path"].as_str())
            .cmp(&(right["class"].as_str(), right["checksums_path"].as_str()))
    });
    (findings, provenance)
}

pub(super) fn signature_findings(
    repo_root: &Path,
    generation_root: &Path,
    runner: &dyn CommandRunner,
) -> (Vec<Finding>, Vec<Value>) {
    let gpg = executable_path("gpg");
    signature_provenance_with(
        repo_root,
        generation_root,
        ContentLayout::Generation,
        runner,
        gpg.as_deref(),
    )
}

pub(super) fn cache_signature_findings(
    repo_root: &Path,
    cache_root: &Path,
    runner: &dyn CommandRunner,
) -> (Vec<Finding>, Vec<Value>) {
    let gpg = executable_path("gpg");
    signature_provenance_with(
        repo_root,
        cache_root,
        ContentLayout::Cache,
        runner,
        gpg.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    struct PassingGpg;

    impl CommandRunner for PassingGpg {
        fn run(&self, _program: &str, args: &[&str]) -> Option<ProcessOutput> {
            let stdout = if args.contains(&"--fingerprint") {
                format!("fpr:::::::::{FPR}:\n")
            } else {
                format!("[GNUPG:] VALIDSIG {FPR} 2026-01-01 0 4 0 1 10 00 {FPR}\n")
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    fn fixture(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "turbovas-feed-provenance-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("TurboVAS");
        fs::create_dir_all(&repo).unwrap();
        repo
    }

    fn signed_generation(root: &Path) -> PathBuf {
        let generation = root.join("generation");
        fs::create_dir(&generation).unwrap();
        for spec in specs().into_iter().filter(|spec| !spec.signed.is_empty()) {
            for (checksums, signature) in spec.signed {
                for (path, content) in [
                    (checksums, b"checksums".as_slice()),
                    (signature, b"signature".as_slice()),
                ] {
                    let path = generation.join(spec.runtime).join(path);
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::write(&path, content).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
                }
            }
        }
        generation
    }

    fn signed_cache(root: &Path) -> PathBuf {
        let cache = root.join("cache");
        fs::create_dir(&cache).unwrap();
        for spec in specs().into_iter().filter(|spec| !spec.signed.is_empty()) {
            for (checksums, signature) in spec.signed {
                for (path, content) in [
                    (checksums, b"checksums".as_slice()),
                    (signature, b"signature".as_slice()),
                ] {
                    let path = cache.join(spec.source).join(path);
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::write(&path, content).unwrap();
                }
            }
        }
        cache
    }

    #[test]
    fn missing_gpg_is_reported_after_keyring_state() {
        let repo = fixture("missing-gpg");
        let generation = signed_generation(&repo);
        let (findings, provenance) = signature_provenance_with(
            &repo,
            &generation,
            ContentLayout::Generation,
            &PassingGpg,
            None,
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            ["feed-generation.signing-keyring", "feed-generation.gpg"]
        );
        assert!(provenance.is_empty());
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn fingerprint_requires_an_exact_colon_record_field() {
        assert!(fingerprint_present(&format!("fpr:::::::::{FPR}:\n")));
        assert!(!fingerprint_present(&format!("fpr:::::::::0{FPR}:\n")));
        assert!(!fingerprint_present(&format!("uid:::::::::{FPR}:\n")));
    }

    #[test]
    fn valid_signatures_use_private_copies_and_emit_sorted_provenance() {
        let repo = fixture("valid");
        let runtime = repo.parent().unwrap().join("TurboVAS-runtime");
        let keyring = runtime.join("state/feed-gnupg");
        fs::create_dir_all(&keyring).unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
        let generation = signed_generation(&repo);
        let (findings, provenance) = signature_provenance_with(
            &repo,
            &generation,
            ContentLayout::Generation,
            &PassingGpg,
            Some(Path::new("/bin/true")),
        );
        assert!(findings.iter().all(|finding| finding.status == "pass"));
        assert_eq!(provenance.len(), 4);
        assert!(provenance.windows(2).all(|rows| {
            (
                rows[0]["class"].as_str(),
                rows[0]["checksums_path"].as_str(),
            ) <= (
                rows[1]["class"].as_str(),
                rows[1]["checksums_path"].as_str(),
            )
        }));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn cache_layout_uses_source_paths_for_staging_provenance() {
        let repo = fixture("cache-layout");
        let runtime = repo.parent().unwrap().join("TurboVAS-runtime");
        let keyring = runtime.join("state/feed-gnupg");
        fs::create_dir_all(&keyring).unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = signed_cache(&repo);

        let (findings, provenance) = signature_provenance_with(
            &repo,
            &cache,
            ContentLayout::Cache,
            &PassingGpg,
            Some(Path::new("/bin/true")),
        );

        assert!(findings.iter().all(|finding| finding.status == "pass"));
        assert_eq!(provenance.len(), 4);
        assert!(
            findings
                .iter()
                .filter_map(|finding| finding.path.as_deref())
                .all(|path| !path.contains("/generation/")
                    && (path.contains("/cache/") || path.contains("feed-gnupg")))
        );
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }
}
