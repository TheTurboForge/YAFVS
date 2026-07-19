// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{ArtifactCommit, begin_secure_artifact_transaction};
use super::common::{compact_finding, expand_home, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectBinaryDownload, guarded_direct_api_binary_download};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const COMMAND: &str = "native-export-report-pdf";
const PDF_REPORT_FORMAT_ID: &str = "c402cc3e-b531-11e1-9163-406186ea4fc5";
pub(crate) const DEFAULT_MAX_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MAX_BYTES_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

pub fn command_native_export_report_pdf(
    repo_root: &Path,
    report_id: &str,
    output: Option<&Path>,
    max_bytes: u64,
    overwrite: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        repo_root,
        report_id,
        output,
        max_bytes,
        overwrite,
        status_only,
        &SystemCommandRunner,
    )
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
}

fn argument_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    report_id: &str,
    max_bytes: u64,
    message: String,
) -> ResultEnvelope {
    result(
        repo_root,
        runner,
        "Native PDF report export rejected before runtime access.",
        vec![
            Finding::new("fail", "native-export-report-pdf.arguments", message)
                .with_details(json!({"report_id": report_id, "max_bytes": max_bytes})),
        ],
    )
    .with_details(json!({
        "report_id": report_id,
        "max_bytes": max_bytes,
        "byte_count": 0,
    }))
}

#[allow(clippy::too_many_arguments)]
fn command_with_runner(
    repo_root: &Path,
    report_id: &str,
    output: Option<&Path>,
    max_bytes: u64,
    overwrite: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let report_id = match validate_operator_uuid(report_id, "--report-id") {
        Ok(value) => value,
        Err(message) => {
            return argument_failure(repo_root, runner, report_id, max_bytes, message);
        }
    };
    if !(1..=MAX_BYTES_LIMIT).contains(&max_bytes) {
        return argument_failure(
            repo_root,
            runner,
            &report_id,
            max_bytes,
            format!("--max-bytes must be between 1 and {MAX_BYTES_LIMIT}"),
        );
    }
    let output = expand_home(
        output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(format!("{report_id}.pdf"))),
    );
    let output_text = output.display().to_string();
    let mut details = json!({
        "report_id": report_id,
        "output": output_text,
        "max_bytes": max_bytes,
        "http_status": Value::Null,
        "content_type": Value::Null,
        "byte_count": 0,
        "sha256": Value::Null,
    });
    let mut transaction = match begin_secure_artifact_transaction(&output, overwrite) {
        Ok(transaction) => transaction,
        Err(message) => {
            return finish(
                repo_root,
                runner,
                "Native PDF report export rejected before runtime access.",
                vec![
                    Finding::new("fail", "native-export-report-pdf.arguments", message)
                        .with_details(json!({"output": output_text, "overwrite": overwrite})),
                ],
                details,
                None,
                status_only,
            );
        }
    };
    let path =
        format!("/api/v1/reports/{report_id}/download?report_format_id={PDF_REPORT_FORMAT_ID}");
    let download = match guarded_direct_api_binary_download(
        repo_root,
        &path,
        max_bytes,
        transaction.file(),
        "native-export-report-pdf.direct-config-shape",
        "native-export-report-pdf.direct-token-strength",
        runner,
    ) {
        Ok(download) => download,
        Err(findings) => {
            return finish(
                repo_root,
                runner,
                "Direct native API PDF export rejected before runtime access.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let (byte_count, prefix, sha256) = match inspect_download(transaction.file_mut()) {
        Ok(identity) => identity,
        Err(error) => {
            return finish(
                repo_root,
                runner,
                "Native PDF report export could not validate its private output.",
                vec![
                    download.config,
                    Finding::new(
                        "fail",
                        "native-export-report-pdf.output",
                        format!("Private PDF output could not be inspected: {error}"),
                    )
                    .with_details(json!({"output": output_text})),
                ],
                details,
                None,
                status_only,
            );
        }
    };
    details["http_status"] = download.http_status.map_or(Value::Null, Value::from);
    details["content_type"] = download
        .content_type
        .as_deref()
        .map_or(Value::Null, Value::from);
    details["byte_count"] = Value::from(byte_count);
    let valid = valid_pdf_download(&download, byte_count, &prefix, max_bytes);
    if !valid {
        let failure_details = json!({
            "http_status": download.http_status,
            "content_type": download.content_type,
            "byte_count": byte_count,
            "reported_bytes": download.reported_bytes,
            "max_bytes": max_bytes,
            "cap_exceeded": download.cap_exceeded || byte_count > max_bytes,
            "exit_code": download.output.exit_code,
        });
        return finish(
            repo_root,
            runner,
            "Native PDF report export stopped before replacing the output.",
            vec![
                download.config,
                Finding::new(
                    "fail",
                    "native-export-report-pdf.download",
                    "Direct native API did not return a bounded PDF report; no output was replaced."
                        .into(),
                )
                .with_details(failure_details),
            ],
            details,
            None,
            status_only,
        );
    }
    let commit = match transaction.commit() {
        Ok(commit) => commit,
        Err(error) => {
            return finish(
                repo_root,
                runner,
                "Native PDF report export could not complete atomic output installation.",
                vec![
                    download.config,
                    Finding::new(
                        "fail",
                        "native-export-report-pdf.output",
                        format!("Atomic PDF output installation failed: {error}"),
                    )
                    .with_details(json!({"output": output_text})),
                ],
                details,
                None,
                status_only,
            );
        }
    };
    details["sha256"] = Value::String(sha256.clone());
    let (status, summary, message) = match commit {
        ArtifactCommit::Durable => (
            "pass",
            "Native PDF report export completed.",
            "Native PDF report was downloaded and written atomically.".to_string(),
        ),
        ArtifactCommit::InstalledDurabilityUnknown(error) => (
            "warn",
            "Native PDF report export completed with an output-durability warning.",
            error,
        ),
    };
    finish(
        repo_root,
        runner,
        summary,
        vec![
            download.config,
            Finding::new(status, "native-export-report-pdf.output", message).with_details(json!({
                "output": output_text,
                "byte_count": byte_count,
                "sha256": sha256,
            })),
        ],
        details,
        Some(output),
        status_only,
    )
}

fn valid_pdf_download(
    download: &GuardedDirectBinaryDownload,
    actual_bytes: u64,
    prefix: &[u8],
    max_bytes: u64,
) -> bool {
    download.output.success
        && download.output.exit_code == Some(0)
        && download.http_status == Some(200)
        && download.content_type.as_deref() == Some("application/pdf")
        && download.reported_bytes == Some(actual_bytes)
        && actual_bytes <= max_bytes
        && !download.cap_exceeded
        && prefix == b"%PDF-"
}

fn inspect_download(file: &mut File) -> std::io::Result<(u64, Vec<u8>, String)> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut byte_count = 0_u64;
    let mut prefix = Vec::with_capacity(5);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if prefix.len() < 5 {
            prefix.extend_from_slice(&buffer[..read.min(5 - prefix.len())]);
        }
        byte_count = byte_count
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("PDF byte count overflow"))?;
        digest.update(&buffer[..read]);
    }
    Ok((byte_count, prefix, format!("{:x}", digest.finalize())))
}

fn finish(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
    artifact: Option<PathBuf>,
    status_only: bool,
) -> ResultEnvelope {
    let mut outcome = result(repo_root, runner, summary, findings).with_details(details);
    if let Some(artifact) = artifact {
        outcome = outcome.with_artifacts(vec![artifact.display().to_string()]);
    }
    if status_only {
        outcome.findings = outcome
            .findings
            .iter()
            .filter(|finding| finding.status != "pass")
            .map(compact_finding)
            .collect();
        if outcome.findings.is_empty() {
            outcome.findings.push(Finding::new(
                "pass",
                "native-export-report-pdf.status-only",
                "Native PDF report export completed; PDF content omitted.".into(),
            ));
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    type CurlCall = (
        Vec<String>,
        BTreeMap<OsString, OsString>,
        Vec<RawFd>,
        Option<u64>,
    );

    struct Runner {
        body: Vec<u8>,
        http_status: i64,
        content_type: String,
        success: bool,
        exit_code: i32,
        reported_bytes: Option<u64>,
        raced_target: Option<PathBuf>,
        curl_calls: Mutex<Vec<CurlCall>>,
        private_header_seen: Mutex<bool>,
    }

    impl Runner {
        fn pdf(body: &[u8]) -> Self {
            Self {
                body: body.to_vec(),
                http_status: 200,
                content_type: "application/pdf".into(),
                success: true,
                exit_code: 0,
                reported_bytes: None,
                raced_target: None,
                curl_calls: Mutex::new(Vec::new()),
                private_header_seen: Mutex::new(false),
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }

        #[allow(clippy::too_many_arguments)]
        fn run_with_input_and_fds(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
            _input: Option<&[u8]>,
            inherited_fds: &[RawFd],
            file_size_limit: Option<u64>,
        ) -> Option<ProcessOutput> {
            if program != "curl" || inherited_fds.len() != 2 {
                return None;
            }
            let header =
                std::fs::read_to_string(format!("/proc/self/fd/{}", inherited_fds[0])).ok()?;
            *self.private_header_seen.lock().unwrap() = header
                .strip_prefix("Authorization: Bearer ")
                .and_then(|value| value.strip_suffix('\n'))
                .is_some_and(|token| token.len() >= 32);
            // SAFETY: dup returns a new owned descriptor or -1.
            let duplicate = unsafe { libc::dup(inherited_fds[1]) };
            if duplicate < 0 {
                return None;
            }
            // SAFETY: dup returned a new owned descriptor.
            let mut output = unsafe { File::from_raw_fd(duplicate) };
            output.write_all(&self.body).ok()?;
            output.flush().ok()?;
            if let Some(target) = &self.raced_target {
                std::fs::write(target, b"raced output").ok()?;
            }
            self.curl_calls.lock().unwrap().push((
                args.iter().map(|value| (*value).to_string()).collect(),
                env.cloned().unwrap_or_default(),
                inherited_fds.to_vec(),
                file_size_limit,
            ));
            let reported = self.reported_bytes.unwrap_or(self.body.len() as u64);
            Some(ProcessOutput {
                success: self.success,
                exit_code: Some(self.exit_code),
                stdout: format!(
                    "\nYAFVS_HTTP_STATUS:{}\nYAFVS_CONTENT_TYPE:{}\nYAFVS_SIZE_DOWNLOAD:{reported}\n",
                    self.http_status, self.content_type
                ),
                stderr: String::new(),
            })
        }
    }

    fn fixture(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-native-pdf-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        std::fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn temporary_files(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".tmp-"))
            })
            .collect()
    }

    #[test]
    fn streams_a_private_pdf_without_exposing_the_token() {
        let (root, repo) = fixture("success");
        let output = root.join("report.pdf");
        std::fs::write(&output, b"old output").unwrap();
        let pdf = b"%PDF-1.7\nminimal test PDF\n";
        let runner = Runner::pdf(pdf);
        let result = command_with_runner(
            &repo,
            "11111111-1111-4111-8111-111111111111",
            Some(&output),
            DEFAULT_MAX_BYTES,
            true,
            true,
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(std::fs::read(&output).unwrap(), pdf);
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            result.details.as_ref().unwrap()["sha256"],
            format!("{:x}", Sha256::digest(pdf))
        );
        assert!(*runner.private_header_seen.lock().unwrap());
        let calls = runner.curl_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (args, env, fds, limit) = &calls[0];
        assert_eq!(fds.len(), 2);
        assert_eq!(*limit, Some(DEFAULT_MAX_BYTES));
        assert!(!args.join(" ").contains("Bearer "));
        assert!(
            !env.keys()
                .any(|name| name.to_string_lossy().contains("TOKEN"))
        );
        assert!(!serde_json::to_string(&result).unwrap().contains("Bearer "));
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_clobber_commit_preserves_a_raced_destination() {
        let (root, repo) = fixture("race");
        let output = root.join("report.pdf");
        let mut runner = Runner::pdf(b"%PDF-1.7\ncandidate");
        runner.raced_target = Some(output.clone());
        let result = command_with_runner(
            &repo,
            "11111111-1111-4111-8111-111111111111",
            Some(&output),
            DEFAULT_MAX_BYTES,
            false,
            false,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(std::fs::read(&output).unwrap(), b"raced output");
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cap_and_non_pdf_failures_preserve_an_existing_output() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let (cap_root, cap_repo) = fixture("cap");
        let cap_output = cap_root.join("report.pdf");
        std::fs::write(&cap_output, b"old output").unwrap();
        let mut capped = Runner::pdf(b"%PDF-1.7\npartial");
        capped.success = false;
        capped.exit_code = 63;
        capped.reported_bytes = Some(19);
        let result = command_with_runner(
            &cap_repo,
            report_id,
            Some(&cap_output),
            18,
            true,
            false,
            &capped,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(std::fs::read(&cap_output).unwrap(), b"old output");
        assert!(temporary_files(&cap_root).is_empty());
        std::fs::remove_dir_all(cap_root).unwrap();

        let (json_root, json_repo) = fixture("json");
        let json_output = json_root.join("report.pdf");
        std::fs::write(&json_output, b"old output").unwrap();
        let mut json_error = Runner::pdf(br#"{"error":"missing"}"#);
        json_error.http_status = 404;
        json_error.content_type = "application/json; charset=utf-8".into();
        let result = command_with_runner(
            &json_repo,
            report_id,
            Some(&json_output),
            DEFAULT_MAX_BYTES,
            true,
            true,
            &json_error,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(std::fs::read(&json_output).unwrap(), b"old output");
        assert_eq!(
            result.details.as_ref().unwrap()["content_type"],
            "application/json"
        );
        assert!(!serde_json::to_string(&result).unwrap().contains("missing"));
        assert!(temporary_files(&json_root).is_empty());
        std::fs::remove_dir_all(json_root).unwrap();
    }

    #[test]
    fn invalid_arguments_never_reach_runtime_access() {
        let (root, repo) = fixture("arguments");
        let runner = Runner::pdf(b"%PDF-1.7");
        for result in [
            command_with_runner(
                &repo,
                "not-a-uuid",
                None,
                DEFAULT_MAX_BYTES,
                false,
                false,
                &runner,
            ),
            command_with_runner(
                &repo,
                "11111111-1111-4111-8111-111111111111",
                None,
                0,
                false,
                false,
                &runner,
            ),
        ] {
            assert_eq!(result.status, "fail");
            assert_eq!(
                result.findings[0].check,
                "native-export-report-pdf.arguments"
            );
        }
        assert!(runner.curl_calls.lock().unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
