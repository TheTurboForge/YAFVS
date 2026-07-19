// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{build_env, executable_path, metadata, output_tail, runtime_dir};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{make_result, Finding, ResultEnvelope};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::{format_description, OffsetDateTime};

const COMMAND: &str = "feed-cache-sync";
const RELEASE: &str = "22.04";
const SESSION: &str = "yafvs-feed-sync";
const RSYNC_TIMEOUT_SECONDS: &str = "900";
const COMMUNITY_BASE: &str = "rsync://feed.community.greenbone.net/community";
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn command_feed_cache_sync(repo_root: &Path) -> ResultEnvelope {
    let rsync = executable_path("rsync");
    let tmux = executable_path("tmux");
    command_with(
        repo_root,
        &SystemCommandRunner,
        rsync.as_deref(),
        tmux.as_deref(),
        &timestamp(),
    )
}

fn command_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    rsync: Option<&Path>,
    tmux: Option<&Path>,
    timestamp: &str,
) -> ResultEnvelope {
    let cache = cache_dir(repo_root);
    let logs = log_dir(repo_root);
    let binary = feed_sync_binary(repo_root);
    let mut findings = Vec::new();
    append_directory_finding(&mut findings, &cache, "feed-sync.cache-dir");
    append_directory_finding(&mut findings, &logs, "feed-sync.log-dir");
    findings.push(
        Finding::new(
            if safe_executable(&binary) {
                "pass"
            } else {
                "fail"
            },
            "feed-sync.available",
            if safe_executable(&binary) {
                "greenbone-feed-sync venv command is available with a safe identity.".into()
            } else {
                "greenbone-feed-sync venv command is missing or unsafe; run just build-python or just build-baseline."
                    .into()
            },
        )
        .with_path(&binary.display().to_string()),
    );
    findings.push(executable_finding(
        rsync,
        "rsync.available",
        "rsync is available.",
        "rsync is missing.",
    ));
    findings.push(executable_finding(
        tmux,
        "tmux.available",
        "tmux is available.",
        "tmux is missing.",
    ));
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Feed cache sync stopped at prerequisites.",
            findings,
            vec![cache.display().to_string()],
        );
    }
    let tmux = tmux.unwrap();

    let selftest_arguments = feed_sync_arguments(repo_root, true);
    let selftest = run(
        runner,
        &binary,
        &selftest_arguments,
        repo_root,
        Some(Duration::from_secs(120)),
    );
    findings.push(process_finding(
        &selftest,
        "feed-sync.selftest",
        "greenbone-feed-sync selftest",
    ));
    if !selftest.success {
        return result(
            repo_root,
            runner,
            "Feed cache sync stopped at greenbone-feed-sync selftest.",
            findings,
            vec![cache.display().to_string()],
        );
    }

    let session = runner
        .run_with(
            &tmux.display().to_string(),
            &["has-session", "-t", SESSION],
            Some(repo_root),
            None,
            Some(Duration::from_secs(15)),
        )
        .unwrap_or_else(failed_output);
    match session.exit_code {
        Some(0) if session.success => {
            findings.push(
                Finding::new(
                    "warn",
                    "feed-sync.session",
                    format!(
                        "tmux session {SESSION} is already running; not starting another sync."
                    ),
                )
                .with_details(json!({"session": SESSION})),
            );
            return result(
                repo_root,
                runner,
                "Feed cache sync is already running.",
                findings,
                vec![cache.display().to_string()],
            );
        }
        Some(1) => {}
        _ => {
            findings.push(process_finding(
                &session,
                "feed-sync.session-check",
                "Check existing tmux feed sync session",
            ));
            return result(
                repo_root,
                runner,
                "Feed cache sync stopped because tmux session state was unavailable.",
                findings,
                vec![cache.display().to_string()],
            );
        }
    }

    let log_path = logs.join(format!(
        "community-{RELEASE}-{timestamp}-{:04}.log",
        LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    if let Err(error) = prepare_log(&log_path) {
        findings.push(
            Finding::new(
                "fail",
                "feed-sync.log",
                format!("Private feed-sync log could not be prepared: {error}"),
            )
            .with_path(&log_path.display().to_string()),
        );
        return result(
            repo_root,
            runner,
            "Feed cache sync stopped before tmux session start.",
            findings,
            vec![cache.display().to_string()],
        );
    }
    findings.push(
        Finding::new(
            "pass",
            "feed-sync.log",
            "Private feed-sync log is ready.".into(),
        )
        .with_path(&log_path.display().to_string()),
    );

    let shell_command = match detached_shell_command(repo_root, &binary, &log_path, timestamp) {
        Ok(command) => command,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "feed-sync.command",
                format!("Detached feed-sync command could not be constructed: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Feed cache sync stopped before tmux session start.",
                findings,
                vec![cache.display().to_string(), log_path.display().to_string()],
            );
        }
    };
    let start = runner
        .run_with(
            &tmux.display().to_string(),
            &["new-session", "-d", "-s", SESSION, &shell_command],
            Some(repo_root),
            None,
            Some(Duration::from_secs(30)),
        )
        .unwrap_or_else(failed_output);
    findings.push(
        process_finding(
            &start,
            "feed-sync.session-start",
            "Start tmux feed sync session",
        )
        .with_details(json!({
            "session": SESSION,
            "log_path": log_path.display().to_string(),
            "output_tail": output_tail(&start.stdout, 80),
        })),
    );
    result(
        repo_root,
        runner,
        "Feed cache sync session start attempted.",
        findings,
        vec![cache.display().to_string(), log_path.display().to_string()],
    )
}

fn feed_sync_binary(repo_root: &Path) -> PathBuf {
    repo_root.join("build/venvs/greenbone-feed-sync/bin/greenbone-feed-sync")
}

fn cache_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("feed-cache/community/22.04/var-lib")
}

fn log_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("logs/feed-sync")
}

fn feed_sync_arguments(repo_root: &Path, selftest: bool) -> Vec<String> {
    let mut arguments = Vec::new();
    if selftest {
        arguments.push("--selftest".into());
    }
    arguments.extend([
        "--type".into(),
        "all".into(),
        "--feed-release".into(),
        RELEASE.into(),
        "--gvmd-data-url".into(),
        format!("{COMMUNITY_BASE}/data-feed/{RELEASE}/"),
        "--report-formats-url".into(),
        format!("{COMMUNITY_BASE}/data-feed/{RELEASE}/report-formats/"),
        "--scan-configs-url".into(),
        format!("{COMMUNITY_BASE}/data-feed/{RELEASE}/scan-configs/"),
        "--port-lists-url".into(),
        format!("{COMMUNITY_BASE}/data-feed/{RELEASE}/port-lists/"),
        "--notus-url".into(),
        format!("{COMMUNITY_BASE}/vulnerability-feed/{RELEASE}/vt-data/notus/"),
        "--nasl-url".into(),
        format!("{COMMUNITY_BASE}/vulnerability-feed/{RELEASE}/vt-data/nasl/"),
        "--scap-data-url".into(),
        format!("{COMMUNITY_BASE}/vulnerability-feed/{RELEASE}/scap-data/"),
        "--cert-data-url".into(),
        format!("{COMMUNITY_BASE}/vulnerability-feed/{RELEASE}/cert-data/"),
        "--destination-prefix".into(),
        cache_dir(repo_root).display().to_string(),
        "--fail-fast".into(),
        "--rsync-timeout".into(),
        RSYNC_TIMEOUT_SECONDS.into(),
    ]);
    arguments
}

fn detached_shell_command(
    repo_root: &Path,
    binary: &Path,
    log_path: &Path,
    timestamp: &str,
) -> Result<String, String> {
    let repo = repo_root
        .to_str()
        .ok_or_else(|| "repository path is not UTF-8".to_string())?;
    let binary = binary
        .to_str()
        .ok_or_else(|| "feed-sync path is not UTF-8".to_string())?;
    let log = log_path
        .to_str()
        .ok_or_else(|| "log path is not UTF-8".to_string())?;
    let mut words = vec![binary.to_string()];
    words.extend(feed_sync_arguments(repo_root, false));
    let sync = words
        .iter()
        .map(|word| {
            shlex::try_quote(word)
                .map(|quoted| quoted.into_owned())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    let repo = shlex::try_quote(repo)
        .map_err(|error| error.to_string())?
        .into_owned();
    let log = shlex::try_quote(log)
        .map_err(|error| error.to_string())?
        .into_owned();
    let started = shlex::try_quote(&format!("YAFVS feed cache sync started at {timestamp}"))
        .map_err(|error| error.to_string())?
        .into_owned();
    let inner = format!(
        "cd {repo} && set -o pipefail && {{ printf '%s\\n' {started}; {sync}; status=$?; printf '%s\\n' \"YAFVS feed cache sync exited with status $status\"; exit $status; }} 2>&1 | tee -a {log}"
    );
    let inner = shlex::try_quote(&inner)
        .map_err(|error| error.to_string())?
        .into_owned();
    Ok(format!("bash -lc {inner}"))
}

fn run(
    runner: &dyn CommandRunner,
    program: &Path,
    arguments: &[String],
    repo_root: &Path,
    timeout: Option<Duration>,
) -> ProcessOutput {
    let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with(
            &program.display().to_string(),
            &borrowed,
            Some(repo_root),
            Some(&build_env(repo_root)),
            timeout,
        )
        .unwrap_or_else(failed_output)
}

fn append_directory_finding(findings: &mut Vec<Finding>, path: &Path, check: &'static str) {
    match prepare_directory(path) {
        Ok(()) => findings.push(
            Finding::new("pass", check, "Runtime directory is ready.".into())
                .with_path(&path.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                check,
                format!("Runtime directory is not usable: {error}"),
            )
            .with_path(&path.display().to_string()),
        ),
    }
}

fn prepare_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.uid() != current_euid() {
        return Err("path is not a real, current-user-owned directory".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())
}

fn prepare_log(path: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.uid() != current_euid() || metadata.nlink() != 1
    {
        return Err("log is not a current-user-owned single-link regular file".into());
    }
    file.sync_all().map_err(|error| error.to_string())
}

fn safe_executable(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.uid() == current_euid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o111 != 0
    })
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

fn process_finding(output: &ProcessOutput, check: &'static str, label: &str) -> Finding {
    Finding::new(
        if output.success { "pass" } else { "fail" },
        check,
        format!(
            "{label} exit code {}.",
            output
                .exit_code
                .map_or_else(|| "unavailable".into(), |code| code.to_string())
        ),
    )
    .with_details(json!({"output_tail": output_tail(&output.stdout, 80)}))
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

fn timestamp() -> String {
    let format =
        format_description::parse_borrowed::<2>("[year][month][day]T[hour][minute][second]Z")
            .expect("static timestamp format is valid");
    OffsetDateTime::now_utc()
        .format(&format)
        .unwrap_or_else(|_| "unknown-time".into())
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Copy)]
    struct Behavior {
        selftest_success: bool,
        session_exit: i32,
        start_success: bool,
    }

    impl Default for Behavior {
        fn default() -> Self {
            Self {
                selftest_success: true,
                session_exit: 1,
                start_success: true,
            }
        }
    }

    #[derive(Default)]
    struct Runner {
        behavior: Behavior,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.run_with(program, args, None, None, None)
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
            ));
            if args.contains(&"--selftest") {
                return Some(output(
                    self.behavior.selftest_success,
                    if self.behavior.selftest_success { 0 } else { 2 },
                ));
            }
            if args.first() == Some(&"has-session") {
                return Some(output(
                    self.behavior.session_exit == 0,
                    self.behavior.session_exit,
                ));
            }
            if args.first() == Some(&"new-session") {
                return Some(output(
                    self.behavior.start_success,
                    if self.behavior.start_success { 0 } else { 3 },
                ));
            }
            Some(output(true, 0))
        }
    }

    fn output(success: bool, exit_code: i32) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(exit_code),
            stdout: "ok\n".into(),
            stderr: String::new(),
        }
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-feed-cache-sync-{}-{}-{name}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn prepare_binary(repo: &Path) {
        let binary = feed_sync_binary(repo);
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn missing_prerequisites_stop_before_selftest_or_tmux() {
        let (root, repo) = fixture("missing");
        let runner = Runner::default();
        let result = command_with(&repo, &runner, None, None, "20260719T200000Z");
        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "Feed cache sync stopped at prerequisites.");
        assert!(!runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, args)| args.contains(&"--selftest".into())));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selftest_failure_stops_before_tmux() {
        let (root, repo) = fixture("selftest");
        prepare_binary(&repo);
        let runner = Runner {
            behavior: Behavior {
                selftest_success: false,
                ..Behavior::default()
            },
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("rsync")),
            Some(Path::new("tmux")),
            "20260719T200000Z",
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Feed cache sync stopped at greenbone-feed-sync selftest."
        );
        assert!(!runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, args)| args.first() == Some(&"has-session".into())));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_session_returns_warning_without_starting_another() {
        let (root, repo) = fixture("existing");
        prepare_binary(&repo);
        let runner = Runner {
            behavior: Behavior {
                session_exit: 0,
                ..Behavior::default()
            },
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("rsync")),
            Some(Path::new("tmux")),
            "20260719T200000Z",
        );
        assert_eq!(result.status, "warn");
        assert_eq!(result.summary, "Feed cache sync is already running.");
        assert!(!runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, args)| args.first() == Some(&"new-session".into())));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unexpected_session_check_failure_stops_before_start() {
        let (root, repo) = fixture("session-error");
        prepare_binary(&repo);
        let runner = Runner {
            behavior: Behavior {
                session_exit: 2,
                ..Behavior::default()
            },
            ..Runner::default()
        };
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("rsync")),
            Some(Path::new("tmux")),
            "20260719T200000Z",
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Feed cache sync stopped because tmux session state was unavailable."
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn start_uses_exact_pinned_arguments_and_private_log() {
        let (root, repo) = fixture("quoted-'repo");
        prepare_binary(&repo);
        let runner = Runner::default();
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("rsync")),
            Some(Path::new("tmux")),
            "20260719T200000Z",
        );
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        let selftest = calls
            .iter()
            .find(|(_, args)| args.contains(&"--selftest".into()))
            .unwrap();
        assert!(selftest.1.contains(&"--type".into()));
        assert!(selftest.1.contains(&"all".into()));
        assert!(selftest.1.contains(&format!(
            "{COMMUNITY_BASE}/vulnerability-feed/{RELEASE}/vt-data/nasl/"
        )));
        let start = calls
            .iter()
            .find(|(_, args)| args.first() == Some(&"new-session".into()))
            .unwrap();
        let shell = start.1.last().unwrap();
        assert!(shell.starts_with("bash -lc "));
        assert!(shell.contains("set -o pipefail"));
        assert!(shell.contains("--destination-prefix"));
        assert!(shell.contains("tee -a"));
        let log = result
            .artifacts
            .iter()
            .find(|path| path.ends_with(".log"))
            .unwrap();
        assert_eq!(
            fs::metadata(log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linked_cache_directory_is_rejected() {
        let (root, repo) = fixture("linked-cache");
        prepare_binary(&repo);
        let cache = cache_dir(&repo);
        fs::create_dir_all(cache.parent().unwrap()).unwrap();
        let outside = root.join("outside-cache");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &cache).unwrap();
        let runner = Runner::default();
        let result = command_with(
            &repo,
            &runner,
            Some(Path::new("rsync")),
            Some(Path::new("tmux")),
            "20260719T200000Z",
        );
        assert_eq!(result.status, "fail");
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.check == "feed-sync.cache-dir" && finding.status == "fail"));
        fs::remove_dir_all(root).unwrap();
    }
}
