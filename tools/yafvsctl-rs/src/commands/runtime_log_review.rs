// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::secret::read_existing_runtime_secret;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use regex::RegexBuilder;
use serde_json::{Map, Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const LOG_TAIL_LINES: usize = 300;
const MATCHED_LINES: usize = 20;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const SERVICES: [&str; 8] = [
    "postgres",
    "redis-openvas",
    "mosquitto",
    "gvmd",
    "ospd-openvas",
    "notus-scanner",
    "gsad",
    "yafvs-api",
];
const RUNTIME_SERVICES: [&str; 3] = ["postgres", "redis-openvas", "mosquitto"];

type Pattern = (&'static str, &'static str, &'static str, &'static str);
const PATTERNS: [Pattern; 8] = [
    (
        "fail",
        "nmap-root-privilege",
        r"requires root privileges|requires root|raw scans require root privileges",
        "Nmap/root-privilege warning found.",
    ),
    (
        "fail",
        "postgres-collation",
        r"collation version mismatch|database .* has a collation version mismatch",
        "Postgres collation mismatch found.",
    ),
    (
        "fail",
        "mosquitto-log-file",
        r"unable to open log file|error: unable to open log file",
        "Mosquitto file-log permission warning found.",
    ),
    (
        "fail",
        "feed-signature",
        r"bad signature|no public key|sha256sums\.asc|advisory load failed",
        "Feed signature/advisory-load problem found.",
    ),
    (
        "fail",
        "traceback",
        r"traceback \(most recent call last\)|uncaught exception|panic:|panicked at|thread .* panicked",
        "Runtime traceback or panic found.",
    ),
    (
        "fail",
        "crash",
        r"segmentation fault|core dumped|fatal error|critical",
        "Crash/critical runtime error found.",
    ),
    (
        "fail",
        "permission",
        r"permission denied|operation not permitted",
        "Permission error found.",
    ),
    (
        "warn",
        "manager-response",
        r"failure to receive response from manager daemon",
        "Manager-response failure found.",
    ),
];

fn service_patterns(service: &str) -> &'static [Pattern] {
    match service {
        "postgres" => &[(
            "fail",
            "postgres-error",
            r"\bERROR:\s|\bFATAL:\s|\bPANIC:\s",
            "Postgres ERROR/FATAL/PANIC found in recent log tail.",
        )],
        "gvmd" => &[
            (
                "fail",
                "gvmd-socket",
                r"failed to .*socket|cannot .*socket|connection refused|broken pipe",
                "Manager socket/connection failure found.",
            ),
            (
                "fail",
                "gvmd-sql",
                r"sql error|database query failed|pq:|postgres.*error",
                "Manager database error found.",
            ),
        ],
        "gsad" => &[(
            "warn",
            "gsad-manager",
            r"failure to receive response from manager daemon|manager.*unavailable|connect.*gvmd.*failed",
            "GSAD manager communication problem found.",
        )],
        "ospd-openvas" => &[
            (
                "fail",
                "ospd-scanner-crash",
                r"scan.*interrupted|ospd.*exception|openvas.*crash|scanner.*exited",
                "OSPD/OpenVAS scan or scanner failure found.",
            ),
            (
                "fail",
                "ospd-feed-signature",
                r"gpg.*error|signature.*failed|bad signature|no public key|sha256sums\.asc",
                "OSPD feed signature problem found.",
            ),
        ],
        "notus-scanner" => &[(
            "fail",
            "notus-feed",
            r"gpg.*error|signature.*failed|bad signature|no public key|advisory load.*error|failed.*advisories",
            "Notus feed signature/advisory problem found.",
        )],
        "mosquitto" => &[(
            "fail",
            "mosquitto-error",
            r"\berror:\s|\bfatal:\s",
            "Mosquitto error found in recent log tail.",
        )],
        _ => &[],
    }
}

pub fn command_runtime_log_review(repo_root: &Path) -> ResultEnvelope {
    command_runtime_log_review_with(repo_root, &SystemCommandRunner)
}

fn command_runtime_log_review_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/log-review");
    let artifact_path = artifact_dir.join("log-review.json");
    let redactions = match runtime_secret_redactions(repo_root) {
        Ok(redactions) => redactions,
        Err(error) => {
            return make_result(
                metadata(repo_root, "runtime-log-review", runner),
                "Runtime log review stopped before collecting logs.".into(),
                vec![
                    Finding::new(
                        "fail",
                        "log-review.redaction",
                        "Runtime log review could not safely load its redaction secret.".into(),
                    )
                    .with_details(json!({"error": error})),
                ],
            )
            .with_artifacts(vec![artifact_path.display().to_string()]);
        }
    };
    let mut findings = Vec::new();
    let mut services = Map::new();

    for service in SERVICES {
        let mut detail = Map::new();
        let state = container_state(repo_root, service, runner, &redactions);
        detail.insert(
            "state".into(),
            match &state {
                None => Value::Null,
                Some(Ok(value)) | Some(Err(value)) => value.clone(),
            },
        );
        match state {
            None => findings.push(Finding::new("warn", "log-review.container", format!("{service} container does not exist; logs may be unavailable.")).with_details(json!({"service": service}))),
            Some(Err(state)) => findings.push(Finding::new(if RUNTIME_SERVICES.contains(&service) { "fail" } else { "warn" }, "log-review.container", format!("{service} container is not running.")).with_details(json!({"service": service, "state": state}))),
            Some(Ok(state)) => findings.push(Finding::new("pass", "log-review.container", format!("{service} container is running.")).with_details(json!({"service": service, "state": {"Status": state.get("Status"), "Running": state.get("Running")}}))),
        }
        let arguments = compose_command(
            repo_root,
            &[
                "logs".into(),
                "--no-color".into(),
                "--tail".into(),
                LOG_TAIL_LINES.to_string(),
                service.into(),
            ],
        );
        let output = run(repo_root, runner, &arguments);
        let redacted = redact_text(&bound_text(&output.stdout), &redactions);
        let log_path = artifact_dir.join(format!("{service}.log"));
        if let Err(error) = write_private_atomic(&log_path, redacted.as_bytes()) {
            findings.push(
                Finding::new(
                    "fail",
                    "log-review.artifact",
                    "Runtime log review artifact write failed closed.".into(),
                )
                .with_details(json!({"service": service, "error": error})),
            );
        }
        detail.insert(
            "artifact".into(),
            Value::String(log_path.display().to_string()),
        );
        detail.insert("line_count".into(), Value::from(redacted.lines().count()));
        findings.push(process_finding(
            if output.success { "pass" } else { "warn" },
            "log-review.logs",
            format!(
                "Collected recent {service} Docker logs with exit code {}.",
                output.exit_code.unwrap_or(1)
            ),
            &output,
            &arguments,
            &redactions,
        ));

        let matches = log_review_matches(redacted.lines(), service);
        detail.insert("matches".into(), Value::Array(matches.clone()));
        if matches.is_empty() {
            findings.push(
                Finding::new(
                    "pass",
                    "log-review.patterns",
                    format!("{service} log tail contains no high-signal runtime patterns."),
                )
                .with_details(json!({"service": service})),
            );
        } else {
            for matched in &matches {
                findings.push(
                    Finding::new(
                        matched["status"].as_str().unwrap_or("fail"),
                        &format!(
                            "log-review.{}",
                            matched["key"].as_str().unwrap_or("unknown")
                        ),
                        format!(
                            "{service}: {}",
                            matched["message"]
                                .as_str()
                                .unwrap_or("Runtime log pattern found.")
                        ),
                    )
                    .with_details(json!({"service": service, "matches": matched["matches"]})),
                );
            }
        }
        services.insert(service.into(), Value::Object(detail));
    }

    let mut result = make_result(
        metadata(repo_root, "runtime-log-review", runner),
        "Runtime log review completed.".into(),
        findings,
    )
    .with_artifacts(vec![artifact_path.display().to_string()])
    .with_details(json!({"services": services}));
    if let Err(error) = write_private_atomic_json(&artifact_path, &result) {
        result.findings.push(
            Finding::new(
                "fail",
                "log-review.artifact",
                "Runtime log review artifact write failed closed.".into(),
            )
            .with_details(json!({"error": error})),
        );
        result.status = "fail".into();
    }
    result
}

fn run(repo_root: &Path, runner: &dyn CommandRunner, arguments: &[String]) -> ProcessOutput {
    runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        })
}

fn container_state(
    repo_root: &Path,
    service: &str,
    runner: &dyn CommandRunner,
    redactions: &[String],
) -> Option<Result<Value, Value>> {
    let ps = run(
        repo_root,
        runner,
        &compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]),
    );
    if !ps.success {
        return None;
    }
    let id = ps.stdout.lines().next()?.trim();
    if id.is_empty() {
        return None;
    }
    let inspect = runner.run_with(
        "docker",
        &["inspect", "--format", "{{json .State}}", id],
        Some(repo_root),
        Some(&runtime_environment(repo_root)),
        Some(PROCESS_TIMEOUT),
    );
    let Some(inspect) = inspect else {
        return Some(Err(json!({"container_id": id, "inspect_error": []})));
    };
    if !inspect.success {
        return Some(Err(
            json!({"container_id": id, "inspect_error": output_tail(&redact_text(&bound_text(&inspect.stdout), redactions), 40)}),
        ));
    }
    let parsed = serde_json::from_str::<Value>(inspect.stdout.trim().lines().last().unwrap_or(""));
    let mut state = parsed.unwrap_or_else(|_| json!({"inspect_output": output_tail(&redact_text(&bound_text(&inspect.stdout), redactions), 40)}));
    redact_json_value(&mut state, redactions);
    if let Some(object) = state.as_object_mut() {
        object.insert("container_id".into(), Value::String(id.to_string()));
    }
    let running = state.get("Running").and_then(Value::as_bool) == Some(true);
    Some(if running { Ok(state) } else { Err(state) })
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
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn log_review_matches<'a>(lines: impl Iterator<Item = &'a str>, service: &str) -> Vec<Value> {
    let material = lines.collect::<Vec<_>>();
    PATTERNS.iter().chain(service_patterns(service)).filter_map(|(status, key, pattern, message)| {
        let regex = RegexBuilder::new(pattern).case_insensitive(true).build().ok()?;
        let matched = material.iter().filter(|line| regex.is_match(line)).map(|line| Value::String((*line).to_string())).collect::<Vec<_>>();
        (!matched.is_empty()).then(|| json!({"status": status, "key": key, "message": message, "matches": &matched[matched.len().saturating_sub(MATCHED_LINES)..]}))
    }).collect()
}

fn runtime_secret_redactions(repo_root: &Path) -> Result<Vec<String>, String> {
    read_existing_runtime_secret(repo_root, "gvmd-admin-password")
        .map(|secret| secret.into_iter().collect())
        .map_err(|error| error.to_string())
}

fn redact_text(text: &str, secrets: &[String]) -> String {
    secrets.iter().fold(text.to_string(), |value, secret| {
        redact_secret_value(&value, secret)
    })
}
fn redact_secret_value(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    if secret.len() >= 12 {
        return text.replace(secret, "[redacted]");
    }
    let mut redacted = String::with_capacity(text.len());
    let mut offset = 0;
    while let Some(found) = text[offset..].find(secret) {
        let start = offset + found;
        let end = start + secret.len();
        let before_is_boundary = text[..start]
            .chars()
            .next_back()
            .is_some_and(is_short_secret_boundary);
        let suffix = &text[end..];
        let after_is_boundary = suffix.chars().next().is_some_and(is_short_secret_boundary);
        let quoted_key =
            suffix.starts_with(['"', '\'']) && suffix[1..].trim_start().starts_with(':');
        redacted.push_str(&text[offset..start]);
        if before_is_boundary || after_is_boundary || quoted_key {
            redacted.push_str(secret);
        } else {
            redacted.push_str("[redacted]");
        }
        offset = end;
    }
    redacted.push_str(&text[offset..]);
    redacted
}
fn is_short_secret_boundary(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '/' | '-')
}
fn bound_text(text: &str) -> String {
    if text.len() <= MAX_ARTIFACT_BYTES {
        text.to_string()
    } else {
        format!(
            "{}\n[output truncated]",
            &text[..text.floor_char_boundary(MAX_ARTIFACT_BYTES)]
        )
    }
}
fn process_finding(
    status: &str,
    check: &str,
    message: String,
    output: &ProcessOutput,
    command: &[String],
    redactions: &[String],
) -> Finding {
    Finding::new(status, check, message).with_details(json!({
        "exit_code": output.exit_code.unwrap_or(1),
        "output_tail": output_tail(&redact_text(&bound_text(&output.stdout), redactions), 100),
        "command": display_docker_command(command),
    }))
}

fn display_docker_command(command: &[String]) -> String {
    std::iter::once("docker")
        .chain(command.iter().map(String::as_str))
        .map(|argument| {
            shlex::try_quote(argument)
                .map(|quoted| quoted.into_owned())
                .unwrap_or_else(|_| "[invalid-argument]".into())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn write_private_atomic_json(path: &Path, result: &ResultEnvelope) -> Result<(), String> {
    let text = serde_json::to_string_pretty(result)
        .map(|text| format!("{text}\n"))
        .map_err(|error| error.to_string())?;
    write_private_atomic(path, text.as_bytes())
}
fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    if contents.len() > MAX_ARTIFACT_BYTES {
        return Err("artifact exceeds bounded size".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "artifact path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::getuid() } {
        return Err("artifact directory is not a private current-user directory".into());
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    if fs::symlink_metadata(path)
        .is_ok_and(|metadata| !metadata.file_type().is_file() || metadata.nlink() != 1)
    {
        return Err("artifact target is not a private regular file".into());
    }
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
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct ReviewRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ReviewRunner {
        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn output(success: bool, exit_code: i32, stdout: &str) -> ProcessOutput {
            ProcessOutput {
                success,
                exit_code: Some(exit_code),
                stdout: stdout.to_string(),
                stderr: String::new(),
            }
        }
    }

    impl CommandRunner for ReviewRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            (program == "git").then(|| Self::output(true, 0, "deadbee\n"))
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            if program != "docker" {
                return None;
            }
            if args.first() == Some(&"inspect") {
                return match args.last().copied() {
                    Some("postgres-first") => Some(Self::output(
                        true,
                        0,
                        r#"{"Running":true,"Status":"running","Health":{"Log":[{"Output":"s3cr3t"}]}}"#,
                    )),
                    Some("mosquitto-id") => Some(Self::output(
                        true,
                        0,
                        r#"{"Running":false,"Status":"exited"}"#,
                    )),
                    _ => Some(Self::output(false, 1, "unexpected inspect")),
                };
            }
            if args.contains(&"ps") {
                return match args.last().copied() {
                    Some("postgres") => {
                        Some(Self::output(true, 0, "postgres-first\nignored-second\n"))
                    }
                    Some("redis-openvas") => {
                        Some(Self::output(false, 1, "error-must-not-be-an-id\n"))
                    }
                    Some("mosquitto") => Some(Self::output(true, 0, "mosquitto-id\n")),
                    _ => Some(Self::output(true, 0, "")),
                };
            }
            if args.contains(&"logs") {
                return Some(if args.last() == Some(&"postgres") {
                    Self::output(true, 0, "before\ns3cr3t\nERROR: database failure\n")
                } else {
                    Self::output(true, 0, "clean\n")
                });
            }
            Some(Self::output(false, 1, "unexpected docker command"))
        }
    }

    fn fixture() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvs-log-review-command-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        let secret_dir = root.join("YAFVS-runtime/secrets");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&secret_dir).unwrap();
        fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let secret_path = secret_dir.join("gvmd-admin-password");
        fs::write(&secret_path, "s3cr3t\n").unwrap();
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        (root, repo)
    }

    #[test]
    fn classifies_generic_and_service_patterns() {
        let generic = log_review_matches(
            ["requires root privileges"].iter().copied(),
            "redis-openvas",
        );
        assert_eq!(generic[0]["key"], "nmap-root-privilege");
        let postgres = log_review_matches(["ERROR: bad"].iter().copied(), "postgres");
        assert!(postgres.iter().any(|item| item["key"] == "postgres-error"));
        let redis = log_review_matches(["ERROR: bad"].iter().copied(), "redis-openvas");
        assert!(!redis.iter().any(|item| item["key"] == "postgres-error"));
        let notus = log_review_matches(
            ["notus-scanner: GPG error while verifying advisories"]
                .iter()
                .copied(),
            "notus-scanner",
        );
        assert!(notus.iter().any(|item| item["key"] == "notus-feed"));
    }

    #[test]
    fn pattern_matches_retain_only_the_last_twenty_lines() {
        let lines = (0..25)
            .map(|index| format!("critical line {index}"))
            .collect::<Vec<_>>();
        let matches = log_review_matches(lines.iter().map(String::as_str), "redis-openvas");
        let crash = matches.iter().find(|item| item["key"] == "crash").unwrap();
        let retained = crash["matches"].as_array().unwrap();
        assert_eq!(retained.len(), 20);
        assert_eq!(retained.first().unwrap(), "critical line 5");
        assert_eq!(retained.last().unwrap(), "critical line 24");
    }

    #[test]
    fn redaction_preserves_short_token_boundaries() {
        let secret = "abc";
        assert_eq!(redact_secret_value(" abc ", secret), " [redacted] ");
        assert_eq!(redact_secret_value("xabcx", secret), "xabcx");
        assert_eq!(redact_secret_value("abc\":", secret), "abc\":");
        assert_eq!(
            redact_secret_value("prefix-longer-secret-suffix", "longer-secret"),
            "prefix-[redacted]-suffix"
        );
    }

    #[test]
    fn command_preserves_process_order_state_policy_and_redaction() {
        let (root, repo) = fixture();
        let runner = ReviewRunner::default();

        let result = command_runtime_log_review_with(&repo, &runner);

        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "Runtime log review completed.");
        assert_eq!(result.metadata.command, "runtime-log-review");
        assert_eq!(result.findings[0].check, "log-review.container");
        assert_eq!(result.findings[0].status, "pass");
        assert_eq!(result.findings[1].check, "log-review.logs");
        assert_eq!(result.findings[1].status, "pass");
        assert!(
            result.findings[1]
                .details
                .as_ref()
                .and_then(|details| details["command"].as_str())
                .is_some_and(|command| command.starts_with("docker compose -f "))
        );
        assert_eq!(result.findings[2].check, "log-review.postgres-error");
        assert_eq!(result.findings[2].status, "fail");
        assert_eq!(result.findings[3].check, "log-review.container");
        assert_eq!(result.findings[3].status, "warn");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "log-review.container"
                && finding.status == "fail"
                && finding.message == "mosquitto container is not running."
        }));

        let artifact_dir = root.join("YAFVS-runtime/artifacts/log-review");
        let postgres_log = fs::read_to_string(artifact_dir.join("postgres.log")).unwrap();
        assert!(!postgres_log.contains("s3cr3t"));
        assert!(postgres_log.contains("[redacted]"));
        let json_text = fs::read_to_string(artifact_dir.join("log-review.json")).unwrap();
        assert!(json_text.ends_with('\n'));
        assert!(!json_text.contains("s3cr3t"));
        let json_result: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(json_result["metadata"]["command"], "runtime-log-review");
        assert_eq!(
            json_result["details"]["services"].as_object().map(Map::len),
            Some(SERVICES.len())
        );

        let calls = runner.calls();
        assert!(calls.iter().any(|(program, args)| {
            program == "docker"
                && args.first().map(String::as_str) == Some("inspect")
                && args.last().map(String::as_str) == Some("postgres-first")
        }));
        assert!(!calls.iter().any(|(_, args)| {
            matches!(
                args.last().map(String::as_str),
                Some("ignored-second" | "error-must-not-be-an-id")
            )
        }));
        let log_services = calls
            .iter()
            .filter(|(program, args)| {
                program == "docker"
                    && args
                        .iter()
                        .map(String::as_str)
                        .any(|argument| argument == "logs")
            })
            .map(|(_, args)| {
                assert_eq!(
                    &args[args.len() - 5..args.len() - 1],
                    ["logs", "--no-color", "--tail", "300"]
                );
                args.last().cloned().unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(log_services, SERVICES);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_redaction_secret_stops_before_docker_processes() {
        let (root, repo) = fixture();
        let secret_path = root.join("YAFVS-runtime/secrets/gvmd-admin-password");
        fs::remove_file(&secret_path).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), &secret_path).unwrap();
        let runner = ReviewRunner::default();

        let result = command_runtime_log_review_with(&repo, &runner);

        assert_eq!(result.status, "fail");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check, "log-review.redaction");
        assert!(
            !runner
                .calls()
                .iter()
                .any(|(program, _)| program == "docker")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_refuses_a_preplaced_symlink() {
        let root = std::env::temp_dir().join(format!(
            "yafvs-log-review-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.join("target");
        let path = root.join("artifact");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(write_private_atomic(&path, b"x").is_err());
        assert!(!target.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn fixed_service_and_compose_argument_order_is_preserved() {
        assert_eq!(
            SERVICES,
            [
                "postgres",
                "redis-openvas",
                "mosquitto",
                "gvmd",
                "ospd-openvas",
                "notus-scanner",
                "gsad",
                "yafvs-api"
            ]
        );
        assert_eq!(
            compose_command(
                Path::new("/srv/YAFVS"),
                &[
                    "logs".into(),
                    "--no-color".into(),
                    "--tail".into(),
                    "300".into(),
                    "postgres".into()
                ]
            ),
            vec![
                "compose",
                "-f",
                "/srv/YAFVS/compose/dev.yaml",
                "logs",
                "--no-color",
                "--tail",
                "300",
                "postgres"
            ]
        );
    }
}
