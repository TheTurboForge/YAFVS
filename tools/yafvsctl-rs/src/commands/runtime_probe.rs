// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rust ownership for authenticated runtime-probe orchestration.
//!
//! The narrow Python helpers remain purpose-built GMP clients. Rust owns
//! prerequisite validation, bounded execution, redaction, and result envelopes.

use super::common::{build_env, executable_path, metadata, output_tail, runtime_dir};
use super::runtime_log_review::redact_text;
use super::secret::{read_existing_runtime_secret, runtime_secret_path};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const ADMIN_SECRET: &str = "gvmd-admin-password";
const ADMIN_USER: &str = "admin";
const MAX_HELPER_OUTPUT_BYTES: usize = 1024 * 1024;

pub fn command_runtime_gmp_smoke(repo_root: &Path) -> ResultEnvelope {
    command_runtime_gmp_smoke_with(repo_root, &SystemCommandRunner)
}

pub fn command_runtime_rbac_smoke(repo_root: &Path) -> ResultEnvelope {
    command_runtime_rbac_smoke_with(repo_root, &SystemCommandRunner)
}

fn command_runtime_gmp_smoke_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    let socket_path = gvmd_socket_path(repo_root);
    let probe = repo_root.join("tools/runtime_gmp_smoke.py");
    let mut findings = vec![socket_readiness_finding(
        "gvmd.socket",
        "gvmd",
        &socket_path,
        "fail",
    )];
    let password = append_secret_prerequisite(
        repo_root,
        &secret_path,
        "Development admin secret is missing; run just runtime-manager-init.",
        &mut findings,
    );
    findings.push(file_prerequisite(
        repo_root,
        &probe,
        "gmp.probe",
        "GMP smoke probe exists.",
        "GMP smoke probe is missing.",
    ));
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "runtime-gmp-smoke", runner),
            "GMP smoke stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![runtime_dir(repo_root).display().to_string()]);
    }

    let output = run_probe(
        repo_root,
        runner,
        &probe,
        &[
            "--socket",
            &socket_path.display().to_string(),
            "--username",
            ADMIN_USER,
            "--password-file",
            &secret_path.display().to_string(),
        ],
        Duration::from_secs(60),
    );
    let redactions = password.into_iter().collect::<Vec<_>>();
    let mut parsed = parse_bounded_helper_output(&output);
    if let Some(value) = parsed.as_mut() {
        redact_json_value(value, &redactions);
    }
    let probe_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let exit_code = output.exit_code.unwrap_or(1);
    findings.push(
        Finding::new(
            if output.success && probe_status == Some("pass") {
                "pass"
            } else {
                "fail"
            },
            "gvmd.gmp",
            format!("Raw GMP socket authenticated get_version exit code {exit_code}."),
        )
        .with_details(json!({
            "probe": parsed,
            "output_tail": output_tail(&redact_text(&output.stdout, &redactions), 60),
        })),
    );
    make_result(
        metadata(repo_root, "runtime-gmp-smoke", runner),
        "Runtime GMP smoke completed.".into(),
        findings,
    )
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

fn command_runtime_rbac_smoke_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    let socket_path = gvmd_socket_path(repo_root);
    let probe = repo_root.join("tools/runtime_rbac_smoke.py");
    let artifact_dir = runtime_dir(repo_root).join("artifacts/rbac-smoke");
    let mut findings = vec![simple_socket_prerequisite(&socket_path)];
    let password = append_secret_prerequisite(
        repo_root,
        &secret_path,
        "Development admin secret is missing.",
        &mut findings,
    );
    findings.push(file_prerequisite(
        repo_root,
        &probe,
        "runtime-rbac.probe",
        "Runtime RBAC smoke helper exists.",
        "Runtime RBAC smoke helper is missing.",
    ));
    match prepare_artifact_dir(&artifact_dir) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "runtime-rbac.artifact-dir",
                "Runtime RBAC smoke artifact directory is ready.".into(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-rbac.artifact-dir",
                format!("Runtime RBAC smoke artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "runtime-rbac-smoke", runner),
            "Runtime RBAC smoke stopped at prerequisites.".into(),
            findings,
        )
        .with_artifacts(vec![artifact_dir.display().to_string()]);
    }

    let output = run_probe(
        repo_root,
        runner,
        &probe,
        &[
            "--socket",
            &socket_path.display().to_string(),
            "--username",
            ADMIN_USER,
            "--password-file",
            &secret_path.display().to_string(),
            "--artifact-dir",
            &artifact_dir.display().to_string(),
        ],
        Duration::from_secs(180),
    );
    let redactions = password.into_iter().collect::<Vec<_>>();
    let mut parsed = parse_bounded_helper_output(&output);
    if let Some(value) = parsed.as_mut() {
        redact_json_value(value, &redactions);
    }
    let helper_status = parsed
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    let finding_status = if output.success && matches!(helper_status, Some("pass" | "warn")) {
        helper_status.unwrap_or("fail")
    } else {
        "fail"
    };
    let exit_code = output.exit_code.unwrap_or(1);
    let summary = parsed
        .as_ref()
        .and_then(|value| value.get("summary"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("Runtime RBAC smoke completed with exit code {exit_code}."));
    findings.push(
        Finding::new(
            finding_status,
            "runtime-rbac.operator-account",
            summary.clone(),
        )
        .with_details(json!({
            "helper": parsed,
            "output_tail": output_tail(&redact_text(&output.stdout, &redactions), 120),
        })),
    );
    let artifacts = parsed_artifacts(parsed.as_ref())
        .unwrap_or_else(|| vec![artifact_dir.display().to_string()]);
    make_result(
        metadata(repo_root, "runtime-rbac-smoke", runner),
        summary,
        findings,
    )
    .with_artifacts(artifacts)
}

fn redact_json_value(value: &mut Value, secrets: &[String]) {
    match value {
        Value::String(text) => *text = redact_text(text, secrets),
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, secrets);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                redact_json_value(item, secrets);
            }
        }
        _ => {}
    }
}

fn gvmd_socket_path(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("run/gvmd-gmp/gvmd.sock")
}

fn append_secret_prerequisite(
    repo_root: &Path,
    path: &Path,
    missing_message: &str,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    match read_existing_runtime_secret(repo_root, ADMIN_SECRET) {
        Ok(Some(secret)) => {
            findings.push(
                Finding::new(
                    "pass",
                    "runtime.admin-secret",
                    "Development admin secret exists.".into(),
                )
                .with_path(&path.display().to_string()),
            );
            Some(secret)
        }
        Ok(None) => {
            findings.push(
                Finding::new("fail", "runtime.admin-secret", missing_message.into())
                    .with_path(&path.display().to_string()),
            );
            None
        }
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "runtime.admin-secret",
                    format!("Development admin secret is unsafe or unreadable: {error}"),
                )
                .with_path(&path.display().to_string()),
            );
            None
        }
    }
}

fn file_prerequisite(
    repo_root: &Path,
    path: &Path,
    check: &str,
    present: &str,
    missing: &str,
) -> Finding {
    let exists = path.is_file();
    let display = path
        .strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string();
    Finding::new(
        if exists { "pass" } else { "fail" },
        check,
        if exists {
            present.into()
        } else {
            missing.into()
        },
    )
    .with_path(&display)
}

fn simple_socket_prerequisite(path: &Path) -> Finding {
    let ready = fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket());
    Finding::new(
        if ready { "pass" } else { "fail" },
        "gvmd.socket",
        if ready {
            "gvmd socket is ready.".into()
        } else {
            "gvmd socket is not ready.".into()
        },
    )
    .with_path(&path.display().to_string())
}

fn socket_readiness_finding(
    check: &str,
    label: &str,
    path: &Path,
    missing_status: &str,
) -> Finding {
    let mut details = serde_json::Map::new();
    details.insert("path".into(), Value::String(path.display().to_string()));
    let (status, state, message) = match fs::metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            missing_status,
            "missing",
            format!("{label} socket is missing."),
        ),
        Err(error) => {
            append_socket_error(&mut details, &error);
            (
                "fail",
                "error",
                format!("{label} socket connection failed."),
            )
        }
        Ok(metadata) if !metadata.file_type().is_socket() => (
            "fail",
            "not-socket",
            format!("{label} path exists but is not a socket."),
        ),
        Ok(_) => match connect_unix_timeout(path, Duration::from_secs(1)) {
            Ok(()) => (
                "pass",
                "ready",
                format!("{label} socket accepts connections."),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                append_socket_error(&mut details, &error);
                (
                    "fail",
                    "stale",
                    format!("{label} socket path exists but no process is listening."),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                append_socket_error(&mut details, &error);
                (
                    "fail",
                    "timeout",
                    format!("{label} socket connection timed out."),
                )
            }
            Err(error) => {
                append_socket_error(&mut details, &error);
                (
                    "fail",
                    "error",
                    format!("{label} socket connection failed."),
                )
            }
        },
    };
    details.insert("state".into(), Value::String(state.into()));
    Finding::new(status, check, message)
        .with_path(&path.display().to_string())
        .with_details(json!({ "socket": details }))
}

fn connect_unix_timeout(path: &Path, timeout: Duration) -> io::Result<()> {
    let path_bytes = path.as_os_str().as_bytes();
    let path_capacity = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path);
    if path_bytes.is_empty()
        || path_bytes.contains(&0)
        || path_bytes.len().saturating_add(1) > path_capacity
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket path is empty, contains NUL, or is too long",
        ));
    }
    // SAFETY: socket has no pointer arguments and returns a new descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is a valid initialization for sockaddr_un before its family
    // and NUL-terminated path fields are populated.
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *destination = *source as libc::c_char;
    }
    let address_length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path_bytes.len() + 1)
        as libc::socklen_t;
    // SAFETY: address contains an initialized family and bounded,
    // NUL-terminated filesystem path; address_length covers those fields.
    let connected = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if connected == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN
    ) {
        return Err(error);
    }
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: descriptor points to one valid pollfd and timeout_ms is bounded.
    let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout_ms) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    if ready == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Unix socket connection timed out",
        ));
    }
    let mut socket_error: libc::c_int = 0;
    let mut socket_error_length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
    // SAFETY: the socket descriptor is valid and the output pointers refer to
    // correctly sized writable storage.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut socket_error).cast(),
            &raw mut socket_error_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if socket_error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(socket_error))
    }
}

fn append_socket_error(details: &mut serde_json::Map<String, Value>, error: &std::io::Error) {
    details.insert("error".into(), Value::String(python_style_error(error)));
    if let Some(errno) = error.raw_os_error() {
        details.insert("errno".into(), Value::from(errno));
    }
}

fn python_style_error(error: &std::io::Error) -> String {
    let Some(errno) = error.raw_os_error() else {
        return error.to_string();
    };
    let suffix = format!(" (os error {errno})");
    let rendered = error.to_string();
    let message = rendered
        .strip_suffix(&suffix)
        .unwrap_or(&rendered)
        .to_string();
    format!("[Errno {errno}] {message}")
}

fn prepare_artifact_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("path is not a real, current-user-owned directory".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())
}

fn run_probe(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    probe: &Path,
    arguments: &[&str],
    timeout: Duration,
) -> ProcessOutput {
    let python = executable_path("python3").unwrap_or_else(|| PathBuf::from("python3"));
    let mut owned = vec![probe.display().to_string()];
    owned.extend(arguments.iter().map(|argument| (*argument).to_string()));
    let refs = owned.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with(
            &python.display().to_string(),
            &refs,
            Some(repo_root),
            Some(&build_env(repo_root)),
            Some(timeout),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: Some(127),
            stdout: String::new(),
            stderr: String::new(),
        })
}

fn parse_bounded_helper_output(output: &ProcessOutput) -> Option<Value> {
    (output.stdout.len() <= MAX_HELPER_OUTPUT_BYTES)
        .then(|| serde_json::from_str::<Value>(&output.stdout).ok())
        .flatten()
        .filter(Value::is_object)
}

fn parsed_artifacts(parsed: Option<&Value>) -> Option<Vec<String>> {
    let artifacts = parsed?.get("artifacts")?.as_array()?;
    let artifacts = artifacts
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()?;
    Some(artifacts.into_iter().map(str::to_string).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct ProbeRunner {
        output: Option<ProcessOutput>,
    }

    impl CommandRunner for ProbeRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            _args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            let _ = program;
            self.output.clone()
        }
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-probe-{}-{}-{name}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(repo.join("tools")).unwrap();
        (root, repo)
    }

    fn prepare_secret(repo: &Path, value: &str) {
        let path = runtime_secret_path(repo, ADMIN_SECRET);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, format!("{value}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn gmp_prerequisites_fail_without_running_helper() {
        let (root, repo) = fixture("gmp-missing");
        let result = command_runtime_gmp_smoke_with(&repo, &ProbeRunner::default());
        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "GMP smoke stopped at prerequisites.");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|item| item.check.as_str())
                .collect::<Vec<_>>(),
            ["gvmd.socket", "runtime.admin-secret", "gmp.probe"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gmp_success_preserves_helper_contract_and_redacts_output() {
        let (root, repo) = fixture("gmp-success");
        let socket = gvmd_socket_path(&repo);
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        prepare_secret(&repo, "long-runtime-secret");
        fs::write(repo.join("tools/runtime_gmp_smoke.py"), "# helper\n").unwrap();
        let runner = ProbeRunner {
            output: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "{\"status\":\"pass\",\"summary\":\"ok\",\"details\":{\"echo\":\"long-runtime-secret\"}}".into(),
                stderr: String::new(),
            }),
        };
        let result = command_runtime_gmp_smoke_with(&repo, &runner);
        assert_eq!(result.status, "pass");
        assert_eq!(result.findings.last().unwrap().check, "gvmd.gmp");
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("long-runtime-secret"));
        assert!(serialized.contains("[redacted]"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rbac_helper_warn_and_artifacts_are_preserved() {
        let (root, repo) = fixture("rbac-warn");
        let socket = gvmd_socket_path(&repo);
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        prepare_secret(&repo, "admin-secret");
        fs::write(repo.join("tools/runtime_rbac_smoke.py"), "# helper\n").unwrap();
        let runner = ProbeRunner {
            output: Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "{\"status\":\"warn\",\"summary\":\"coverage partial\",\"artifacts\":[\"one.json\"]}".into(),
                stderr: String::new(),
            }),
        };
        let result = command_runtime_rbac_smoke_with(&repo, &runner);
        assert_eq!(result.status, "warn");
        assert_eq!(result.summary, "coverage partial");
        assert_eq!(result.artifacts, ["one.json"]);
        assert_eq!(
            result
                .findings
                .iter()
                .map(|item| item.check.as_str())
                .collect::<Vec<_>>(),
            [
                "gvmd.socket",
                "runtime.admin-secret",
                "runtime-rbac.probe",
                "runtime-rbac.artifact-dir",
                "runtime-rbac.operator-account",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_secret_hardlink_stops_before_helper() {
        let (root, repo) = fixture("unsafe-secret");
        let socket = gvmd_socket_path(&repo);
        fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::write(repo.join("tools/runtime_rbac_smoke.py"), "# helper\n").unwrap();
        prepare_secret(&repo, "unsafe-secret");
        let secret = runtime_secret_path(&repo, ADMIN_SECRET);
        fs::hard_link(&secret, secret.with_extension("copy")).unwrap();
        let result = command_runtime_rbac_smoke_with(&repo, &ProbeRunner::default());
        assert_eq!(result.status, "fail");
        let secret_finding = result
            .findings
            .iter()
            .find(|item| item.check == "runtime.admin-secret")
            .unwrap();
        assert!(secret_finding.message.contains("unsafe or unreadable"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_or_malformed_helper_output_fails_closed() {
        let output = ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: "x".repeat(MAX_HELPER_OUTPUT_BYTES + 1),
            stderr: String::new(),
        };
        assert!(parse_bounded_helper_output(&output).is_none());
        let output = ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: "[]".into(),
            stderr: String::new(),
        };
        assert!(parse_bounded_helper_output(&output).is_none());
    }
}
