// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{ArtifactCommit, begin_secure_artifact_transaction};
use super::common::{executable_path, metadata, output_tail, runtime_dir};
use super::feed_generation::FPR;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const COMMAND: &str = "runtime-feed-keyring-init";
const KEY_URL: &str = "https://www.greenbone.net/GBCommunitySigningKey.asc";
const MAX_KEY_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FINGERPRINT_OUTPUT_BYTES: usize = 64 * 1024;

pub fn command_runtime_feed_keyring_init(repo_root: &Path) -> ResultEnvelope {
    let gpg = executable_path("gpg");
    let curl = executable_path("curl");
    command_with(
        repo_root,
        &SystemCommandRunner,
        gpg.as_deref(),
        curl.as_deref(),
    )
}

/// Inspect the shared keyring without creating it or importing keys.
pub(crate) fn feed_keyring_fingerprint_finding(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> Finding {
    let gpg = executable_path("gpg");
    feed_keyring_fingerprint_finding_with(repo_root, runner, gpg.as_deref())
}

fn feed_keyring_fingerprint_finding_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    gpg: Option<&Path>,
) -> Finding {
    let home = keyring_home(repo_root);
    let safe_home = fs::symlink_metadata(&home).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && metadata.uid() == current_euid()
            && metadata.mode() & 0o077 == 0
    });
    let Some(gpg) = gpg.filter(|_| safe_home) else {
        return Finding::new(
            "fail",
            "feed-keyring.fingerprint",
            "Shared feed signature keyring is not initialized; run just runtime-feed-keyring-init."
                .into(),
        )
        .with_path(&home.display().to_string());
    };
    let home_text = home.display().to_string();
    let args = [
        "--homedir",
        home_text.as_str(),
        "--with-colons",
        "--fingerprint",
        FPR,
    ];
    let output = runner.run_with_output_limit(
        &gpg.display().to_string(),
        &args,
        Some(repo_root),
        None,
        Some(Duration::from_secs(60)),
        MAX_FINGERPRINT_OUTPUT_BYTES,
    );
    let ok = output.as_ref().is_some_and(|output| {
        output.success
            && output
                .stdout
                .replace(' ', "")
                .to_ascii_uppercase()
                .contains(FPR)
    });
    Finding::new(
        if ok { "pass" } else { "fail" },
        "feed-keyring.fingerprint",
        if ok {
            "Shared feed signature keyring contains the Greenbone Community signing key."
        } else {
            "Shared feed signature keyring is missing the Greenbone Community signing key."
        }
        .into(),
    )
    .with_path(&home_text)
    .with_details(json!({
        "fingerprint": FPR,
        "output_tail": output
            .map(|output| output_tail(&output.stdout, 60))
            .unwrap_or_default(),
    }))
}

pub(crate) fn command_runtime_feed_keyring_init_with_runner(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let gpg = executable_path("gpg");
    let curl = executable_path("curl");
    command_with(repo_root, runner, gpg.as_deref(), curl.as_deref())
}

fn command_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    gpg: Option<&Path>,
    curl: Option<&Path>,
) -> ResultEnvelope {
    let home = keyring_home(repo_root);
    let artifact_dir = key_artifact_dir(repo_root);
    let key_path = key_path(repo_root);
    let mut findings = Vec::new();
    append_directory_finding(
        &mut findings,
        &home,
        0o700,
        "feed-keyring.dir",
        "Shared feed signature keyring directory is ready.",
    );
    append_directory_finding(
        &mut findings,
        &artifact_dir,
        0o755,
        "feed-keyring.artifact-dir",
        "Feed signing-key artifact directory is ready.",
    );
    findings.push(executable_finding(
        gpg,
        "gpg.available",
        "gpg is available.",
        "gpg is missing.",
    ));
    findings.push(executable_finding(
        curl,
        "curl.available",
        "curl is available.",
        "curl is missing.",
    ));
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Feed keyring initialization stopped at prerequisites.",
            findings,
            vec![home.display().to_string()],
        );
    }
    let gpg = gpg.unwrap();
    let curl = curl.unwrap();

    match open_stable_file(&key_path, MAX_KEY_BYTES) {
        Ok(Some(_)) => findings.push(
            Finding::new(
                "pass",
                "feed-keyring.community-key",
                "Greenbone Community signing key artifact already exists with a safe identity."
                    .into(),
            )
            .with_path(&key_path.display().to_string()),
        ),
        Ok(None) => match download_key(repo_root, runner, curl, &key_path) {
            Ok(commit) => {
                findings.push(
                    Finding::new(
                        "pass",
                        "feed-keyring.community-key",
                        "Downloaded the Greenbone Community signing key into a private bounded artifact."
                            .into(),
                    )
                    .with_path(&key_path.display().to_string())
                    .with_details(json!({"url": KEY_URL})),
                );
                if let ArtifactCommit::InstalledDurabilityUnknown(message) = commit {
                    findings.push(Finding::new(
                        "warn",
                        "feed-keyring.community-key-durability",
                        message,
                    ));
                }
            }
            Err(error) => {
                findings.push(
                    Finding::new("fail", "feed-keyring.community-key", error)
                        .with_path(&key_path.display().to_string())
                        .with_details(json!({"url": KEY_URL})),
                );
                return result(
                    repo_root,
                    runner,
                    "Feed keyring initialization stopped while downloading the signing key.",
                    findings,
                    vec![home.display().to_string(), key_path.display().to_string()],
                );
            }
        },
        Err(error) => {
            findings.push(
                Finding::new("fail", "feed-keyring.community-key", error)
                    .with_path(&key_path.display().to_string()),
            );
            return result(
                repo_root,
                runner,
                "Feed keyring initialization stopped at an unsafe signing-key artifact.",
                findings,
                vec![home.display().to_string(), key_path.display().to_string()],
            );
        }
    }

    let key = match open_stable_file(&key_path, MAX_KEY_BYTES) {
        Ok(Some(file)) => file,
        Ok(None) => {
            findings.push(
                Finding::new(
                    "fail",
                    "feed-keyring.community-key",
                    "Signing-key artifact is absent after preparation.".into(),
                )
                .with_path(&key_path.display().to_string()),
            );
            return result(
                repo_root,
                runner,
                "Feed keyring initialization stopped at the signing-key artifact.",
                findings,
                vec![home.display().to_string(), key_path.display().to_string()],
            );
        }
        Err(error) => {
            findings.push(
                Finding::new("fail", "feed-keyring.community-key", error)
                    .with_path(&key_path.display().to_string()),
            );
            return result(
                repo_root,
                runner,
                "Feed keyring initialization stopped at the signing-key artifact.",
                findings,
                vec![home.display().to_string(), key_path.display().to_string()],
            );
        }
    };

    let artifact_fingerprint = gpg_with_file(
        repo_root,
        runner,
        gpg,
        &home,
        &[
            "--with-colons",
            "--show-keys",
            "--fingerprint",
            stable_fd_path(&key).as_str(),
        ],
        &key,
        Duration::from_secs(60),
    );
    let artifact_fingerprint_ok =
        artifact_fingerprint.success && fingerprint_present(&artifact_fingerprint.stdout);
    findings.push(
        Finding::new(
            if artifact_fingerprint_ok {
                "pass"
            } else {
                "fail"
            },
            "feed-keyring.artifact-fingerprint",
            if artifact_fingerprint_ok {
                "Signing-key artifact matches the pinned Greenbone Community fingerprint.".into()
            } else {
                "Signing-key artifact does not match the pinned Greenbone Community fingerprint."
                    .into()
            },
        )
        .with_details(json!({
            "fingerprint": FPR,
            "output_tail": output_tail(&artifact_fingerprint.stdout, 80),
        })),
    );
    if !artifact_fingerprint_ok {
        return result(
            repo_root,
            runner,
            "Feed keyring initialization stopped before importing an unverified key artifact.",
            findings,
            vec![home.display().to_string(), key_path.display().to_string()],
        );
    }

    let import = gpg_with_file(
        repo_root,
        runner,
        gpg,
        &home,
        &["--import", stable_fd_path(&key).as_str()],
        &key,
        Duration::from_secs(120),
    );
    findings.push(process_finding(
        &import,
        "feed-keyring.import",
        "Import Greenbone Community signing key",
    ));
    if !import.success {
        return result(
            repo_root,
            runner,
            "Feed keyring initialization stopped while importing the signing key.",
            findings,
            vec![home.display().to_string(), key_path.display().to_string()],
        );
    }

    let ownertrust_text = format!("{FPR}:6:\n");
    let ownertrust = run_gpg(
        repo_root,
        runner,
        gpg,
        &home,
        &["--import-ownertrust"],
        Some(ownertrust_text.as_bytes()),
        Duration::from_secs(60),
    );
    findings.push(
        process_finding(
            &ownertrust,
            "feed-keyring.ownertrust",
            "Set Greenbone Community signing key ownertrust",
        )
        .with_details(json!({
            "fingerprint": FPR,
            "output_tail": output_tail(&ownertrust.stdout, 80),
        })),
    );

    let fingerprint = run_gpg(
        repo_root,
        runner,
        gpg,
        &home,
        &["--with-colons", "--fingerprint", FPR],
        None,
        Duration::from_secs(60),
    );
    let fingerprint_ok = fingerprint.success && fingerprint_present(&fingerprint.stdout);
    findings.push(
        Finding::new(
            if fingerprint_ok { "pass" } else { "fail" },
            "feed-keyring.fingerprint",
            if fingerprint_ok {
                "Greenbone Community signing key fingerprint is present.".into()
            } else {
                "Greenbone Community signing key fingerprint was not found after import.".into()
            },
        )
        .with_details(json!({
            "fingerprint": FPR,
            "output_tail": output_tail(&fingerprint.stdout, 80),
        })),
    );

    for (subtree, checksums, signature) in signature_files(repo_root) {
        let checksums_file = open_stable_file(&checksums, MAX_SIGNATURE_INPUT_BYTES);
        let signature_file = open_stable_file(&signature, MAX_SIGNATURE_INPUT_BYTES);
        let files_ok =
            matches!(checksums_file, Ok(Some(_))) && matches!(signature_file, Ok(Some(_)));
        let files_check = format!("feed-keyring.notus-{subtree}-files");
        findings.push(
            Finding::new(
                if files_ok { "pass" } else { "fail" },
                &files_check,
                if files_ok {
                    format!("Notus {subtree} signature files have safe identities.")
                } else {
                    format!(
                        "Notus {subtree} signature files are missing, unsafe, empty, or oversized."
                    )
                },
            )
            .with_details(json!({
                "checksums": checksums.display().to_string(),
                "signature": signature.display().to_string(),
            })),
        );
        let (Ok(Some(checksums_file)), Ok(Some(signature_file))) = (checksums_file, signature_file)
        else {
            continue;
        };
        let verify = gpg_verify(
            repo_root,
            runner,
            gpg,
            &home,
            &signature_file,
            &checksums_file,
        );
        findings.push(process_finding(
            &verify,
            format!("feed-keyring.notus-{subtree}-signature"),
            &format!("Verify Notus {subtree} sha256sums signature"),
        ));
    }

    result(
        repo_root,
        runner,
        "Shared feed signature keyring initialization completed.",
        findings,
        vec![home.display().to_string(), key_path.display().to_string()],
    )
}

fn keyring_home(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("state/feed-gnupg")
}

fn key_artifact_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("artifacts/feed-keyring")
}

fn key_path(repo_root: &Path) -> PathBuf {
    key_artifact_dir(repo_root).join("GBCommunitySigningKey.asc")
}

fn signature_files(repo_root: &Path) -> Vec<(&'static str, PathBuf, PathBuf)> {
    let root = runtime_dir(repo_root).join("feed-store/current/notus");
    ["advisories", "products"]
        .into_iter()
        .map(|subtree| {
            (
                subtree,
                root.join(subtree).join("sha256sums"),
                root.join(subtree).join("sha256sums.asc"),
            )
        })
        .collect()
}

fn append_directory_finding(
    findings: &mut Vec<Finding>,
    path: &Path,
    mode: u32,
    check: &'static str,
    success: &'static str,
) {
    match prepare_directory(path, mode) {
        Ok(()) => findings.push(
            Finding::new("pass", check, success.into()).with_path(&path.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new("fail", check, format!("Directory is not usable: {error}"))
                .with_path(&path.display().to_string()),
        ),
    }
}

fn prepare_directory(path: &Path, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.uid() != current_euid() {
        return Err("path is not a real, current-user-owned directory".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string())
}

fn executable_finding(
    executable: Option<&Path>,
    check: &'static str,
    present: &'static str,
    absent: &'static str,
) -> Finding {
    Finding::new(
        if executable.is_some() { "pass" } else { "fail" },
        check,
        if executable.is_some() {
            present
        } else {
            absent
        }
        .into(),
    )
}

fn open_stable_file(path: &Path, maximum: u64) -> Result<Option<File>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "file could not be opened without following links: {error}"
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("file identity could not be read: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != current_euid()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "file must be nonempty, at most {maximum} bytes, regular, current-user-owned, and single-linked"
        ));
    }
    Ok(Some(file))
}

fn download_key(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    curl: &Path,
    destination: &Path,
) -> Result<ArtifactCommit, String> {
    let mut transaction = begin_secure_artifact_transaction(destination, false)?;
    let descriptor = transaction.file().as_raw_fd();
    let output_path = format!("/proc/self/fd/{descriptor}");
    let maximum = MAX_KEY_BYTES.to_string();
    let arguments = [
        "-fsSL",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--max-filesize",
        maximum.as_str(),
        "-o",
        output_path.as_str(),
        KEY_URL,
    ];
    let curl = runner
        .run_with_input_and_fds(
            &curl.display().to_string(),
            &arguments,
            Some(repo_root),
            None,
            Some(Duration::from_secs(120)),
            None,
            &[descriptor],
            Some(MAX_KEY_BYTES),
        )
        .unwrap_or_else(failed_output);
    if !curl.success {
        return Err(format!(
            "Download Greenbone Community signing key exit code {}; output: {}",
            exit_code(&curl),
            output_tail(&curl.stdout, 80).join(" | ")
        ));
    }
    let length = transaction
        .file_mut()
        .metadata()
        .map_err(|error| {
            format!("downloaded signing-key artifact could not be inspected: {error}")
        })?
        .len();
    if length == 0 || length > MAX_KEY_BYTES {
        return Err(format!(
            "downloaded signing-key artifact is empty or exceeds {MAX_KEY_BYTES} bytes"
        ));
    }
    transaction.commit()
}

fn stable_fd_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

fn base_gpg_arguments(home: &Path) -> Vec<String> {
    vec![
        "--batch".into(),
        "--no-tty".into(),
        "--homedir".into(),
        home.display().to_string(),
    ]
}

fn run_gpg(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    executable: &Path,
    home: &Path,
    arguments: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> ProcessOutput {
    let mut owned = base_gpg_arguments(home);
    owned.extend(arguments.iter().map(|argument| (*argument).to_string()));
    let borrowed = owned.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with_input(
            &executable.display().to_string(),
            &borrowed,
            Some(repo_root),
            None,
            Some(timeout),
            input,
        )
        .unwrap_or_else(failed_output)
}

fn gpg_with_file(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    executable: &Path,
    home: &Path,
    arguments: &[&str],
    file: &File,
    timeout: Duration,
) -> ProcessOutput {
    let mut owned = base_gpg_arguments(home);
    owned.extend(arguments.iter().map(|argument| (*argument).to_string()));
    let borrowed = owned.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with_input_and_fd(
            &executable.display().to_string(),
            &borrowed,
            Some(repo_root),
            None,
            Some(timeout),
            None,
            file.as_raw_fd(),
        )
        .unwrap_or_else(failed_output)
}

fn gpg_verify(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    executable: &Path,
    home: &Path,
    signature: &File,
    checksums: &File,
) -> ProcessOutput {
    let signature_path = stable_fd_path(signature);
    let checksums_path = stable_fd_path(checksums);
    let mut owned = base_gpg_arguments(home);
    owned.extend(["--verify".into(), signature_path, checksums_path]);
    let borrowed = owned.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with_input_and_fds(
            &executable.display().to_string(),
            &borrowed,
            Some(repo_root),
            None,
            Some(Duration::from_secs(120)),
            None,
            &[signature.as_raw_fd(), checksums.as_raw_fd()],
            None,
        )
        .unwrap_or_else(failed_output)
}

fn fingerprint_present(output: &str) -> bool {
    output.lines().any(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        fields.first() == Some(&"fpr")
            && fields
                .get(9)
                .is_some_and(|fingerprint| fingerprint.eq_ignore_ascii_case(FPR))
    })
}

fn process_finding(output: &ProcessOutput, check: impl Into<String>, label: &str) -> Finding {
    let check = check.into();
    Finding::new(
        if output.success { "pass" } else { "fail" },
        &check,
        format!("{label} exit code {}.", exit_code(output)),
    )
    .with_details(json!({"output_tail": output_tail(&output.stdout, 80)}))
}

fn exit_code(output: &ProcessOutput) -> String {
    output
        .exit_code
        .map_or_else(|| "unavailable".into(), |code| code.to_string())
}

fn failed_output() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(127),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    unsafe { libc::geteuid() }
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    artifacts: Vec<String>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_artifacts(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    type Invocation = (String, Vec<String>, Option<Vec<u8>>, Vec<i32>);

    #[derive(Default)]
    struct Runner {
        fingerprint: bool,
        downloaded: bool,
        calls: Mutex<Vec<Invocation>>,
    }

    impl CommandRunner for Runner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.into(),
                args.iter().map(|argument| (*argument).into()).collect(),
                None,
                Vec::new(),
            ));
            Some(self.output(args))
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _timeout: Option<Duration>,
            input: Option<&[u8]>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.into(),
                args.iter().map(|argument| (*argument).into()).collect(),
                input.map(<[u8]>::to_vec),
                Vec::new(),
            ));
            Some(self.output(args))
        }

        fn run_with_input_and_fd(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _timeout: Option<Duration>,
            input: Option<&[u8]>,
            inherited_fd: i32,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.into(),
                args.iter().map(|argument| (*argument).into()).collect(),
                input.map(<[u8]>::to_vec),
                vec![inherited_fd],
            ));
            Some(self.output(args))
        }

        fn run_with_input_and_fds(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _timeout: Option<Duration>,
            _input: Option<&[u8]>,
            inherited_fds: &[i32],
            _file_size_limit: Option<u64>,
        ) -> Option<ProcessOutput> {
            if program.ends_with("curl") && self.downloaded {
                let mut file = fs::File::options()
                    .write(true)
                    .open(format!("/proc/self/fd/{}", inherited_fds[0]))
                    .unwrap();
                file.write_all(b"community-key\n").unwrap();
            }
            self.calls.lock().unwrap().push((
                program.into(),
                args.iter().map(|argument| (*argument).into()).collect(),
                None,
                inherited_fds.to_vec(),
            ));
            Some(self.output(args))
        }
    }

    impl Runner {
        fn output(&self, args: &[&str]) -> ProcessOutput {
            let stdout = if self.fingerprint
                && (args.contains(&"--show-keys") || args.contains(&"--fingerprint"))
            {
                format!("fpr:::::::::{FPR}:\n")
            } else {
                "ok\n".into()
            };
            ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout,
                stderr: String::new(),
            }
        }
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-feed-keyring-{}-{}-{name}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn write_key(repo: &Path) {
        let path = key_path(repo);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "community-key\n").unwrap();
    }

    fn write_signatures(repo: &Path) {
        for (_, checksums, signature) in signature_files(repo) {
            fs::create_dir_all(checksums.parent().unwrap()).unwrap();
            fs::write(checksums, "sum\n").unwrap();
            fs::write(signature, "signature\n").unwrap();
        }
    }

    #[test]
    fn missing_prerequisites_stop_before_process_execution() {
        let (root, repo) = fixture("missing");
        let runner = Runner::default();
        let result = command_with(&repo, &runner, None, None);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Feed keyring initialization stopped at prerequisites."
        );
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn observational_fingerprint_requires_private_directory_and_exact_key() {
        let (root, repo) = fixture("observational");
        let runner = Runner {
            fingerprint: true,
            ..Runner::default()
        };
        let missing = feed_keyring_fingerprint_finding_with(&repo, &runner, Some(Path::new("gpg")));
        assert_eq!(missing.status, "fail");
        assert!(runner.calls.lock().unwrap().is_empty());

        let home = keyring_home(&repo);
        fs::create_dir_all(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
        let broad = feed_keyring_fingerprint_finding_with(&repo, &runner, Some(Path::new("gpg")));
        assert_eq!(broad.status, "fail");
        assert!(runner.calls.lock().unwrap().is_empty());

        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let present = feed_keyring_fingerprint_finding_with(&repo, &runner, Some(Path::new("gpg")));
        assert_eq!(present.status, "pass");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linked_existing_key_is_rejected_before_gpg() {
        let (root, repo) = fixture("linked");
        let path = key_path(&repo);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let outside = root.join("outside-key");
        fs::write(&outside, "community-key\n").unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        let runner = Runner::default();
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("gpg")),
            Some(Path::new("curl")),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Feed keyring initialization stopped at an unsafe signing-key artifact."
        );
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_downloaded_fingerprint_is_not_imported() {
        let (root, repo) = fixture("wrong-fingerprint");
        let runner = Runner {
            downloaded: true,
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("gpg")),
            Some(Path::new("curl")),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Feed keyring initialization stopped before importing an unverified key artifact."
        );
        let calls = runner.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(program, _, _, _)| program.ends_with("curl"))
        );
        assert!(
            calls
                .iter()
                .any(|(_, args, _, _)| args.iter().any(|arg| arg == "--show-keys"))
        );
        assert!(
            !calls
                .iter()
                .any(|(_, args, _, _)| args.iter().any(|arg| arg == "--import"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_key_is_downloaded_then_verified_and_imported() {
        let (root, repo) = fixture("download");
        write_signatures(&repo);
        let runner = Runner {
            fingerprint: true,
            downloaded: true,
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("gpg")),
            Some(Path::new("curl")),
        );
        assert_eq!(result.status, "pass");
        assert!(key_path(&repo).is_file());
        let calls = runner.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(program, _, _, _)| program.ends_with("curl"))
        );
        assert!(
            calls
                .iter()
                .any(|(_, args, _, _)| args.iter().any(|arg| arg == "--import"))
        );
        assert!(calls.iter().any(|(_, args, input, _)| {
            args.iter().any(|arg| arg == "--import-ownertrust")
                && input.as_deref() == Some(format!("{FPR}:6:\n").as_bytes())
        }));
        assert_eq!(
            calls
                .iter()
                .filter(|(_, args, _, _)| args.iter().any(|arg| arg == "--verify"))
                .count(),
            2
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_key_skips_download_but_revalidates_everything() {
        let (root, repo) = fixture("existing");
        write_key(&repo);
        write_signatures(&repo);
        let runner = Runner {
            fingerprint: true,
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("gpg")),
            Some(Path::new("curl")),
        );
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        assert!(
            !calls
                .iter()
                .any(|(program, _, _, _)| program.ends_with("curl"))
        );
        assert!(
            calls
                .iter()
                .any(|(_, args, _, _)| args.iter().any(|arg| arg == "--show-keys"))
        );
        assert!(
            calls
                .iter()
                .any(|(_, args, _, _)| args.iter().any(|arg| arg == "--import"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_notus_signature_input_fails_without_verify() {
        let (root, repo) = fixture("missing-signature");
        write_key(&repo);
        let runner = Runner {
            fingerprint: true,
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("gpg")),
            Some(Path::new("curl")),
        );
        assert_eq!(result.status, "fail");
        let calls = runner.calls.lock().unwrap();
        assert!(
            !calls
                .iter()
                .any(|(_, args, _, _)| args.iter().any(|arg| arg == "--verify"))
        );
        fs::remove_dir_all(root).unwrap();
    }
}
