// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{build_env, executable_path, metadata, output_tail, runtime_dir};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const COMMAND: &str = "runtime-certs-init";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct CertFile {
    name: &'static str,
    path: PathBuf,
    private: bool,
}

pub(crate) fn runtime_certificate_findings(repo_root: &Path) -> Vec<Finding> {
    cert_file_findings(&cert_files(repo_root), "warn")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertState {
    Empty,
    Partial,
    Complete,
}

pub fn command_runtime_certs_init(repo_root: &Path) -> ResultEnvelope {
    command_with(
        repo_root,
        &SystemCommandRunner,
        executable_path("certtool").is_some(),
    )
}

fn command_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    certtool_available: bool,
) -> ResultEnvelope {
    let public_dir = cert_public_dir(repo_root);
    let private_dir = cert_private_dir(repo_root);
    let files = cert_files(repo_root);
    let mut findings = Vec::new();
    append_directory_finding(
        &mut findings,
        &private_dir,
        0o700,
        "runtime.cert.private-dir",
        "Private certificate directory is ready.",
    );
    append_directory_finding(
        &mut findings,
        &public_dir,
        0o755,
        "runtime.cert.public-dir",
        "Public certificate directory is ready.",
    );

    let script = repo_root.join("build/prefix/bin/gvm-manage-certs");
    findings.push(Finding::new(
        if certtool_available { "pass" } else { "fail" },
        "certtool.available",
        if certtool_available {
            "certtool is available."
        } else {
            "certtool is missing; install gnutls-bin."
        }
        .into(),
    ));
    let script_available = safe_executable(&script);
    findings.push(
        Finding::new(
            if script_available { "pass" } else { "fail" },
            "gvm-manage-certs.available",
            if script_available {
                "gvm-manage-certs is available in build/prefix."
            } else {
                "gvm-manage-certs is missing or unsafe; build/install gvmd first."
            }
            .into(),
        )
        .with_path(&script.display().to_string()),
    );
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Certificate initialization stopped before generation.",
            findings,
            vec![runtime_dir(repo_root).display().to_string()],
        );
    }

    match cert_state(&files) {
        CertState::Partial => {
            findings.extend(cert_file_findings(&files, "warn"));
            findings.push(Finding::new(
                "fail",
                "runtime.cert.partial",
                "Partial or unsafe certificate infrastructure exists; refusing to overwrite or rotate automatically.".into(),
            ));
            return result(
                repo_root,
                runner,
                "Certificate initialization stopped at partial existing state.",
                findings,
                vec![runtime_dir(repo_root).display().to_string()],
            );
        }
        CertState::Complete => findings.push(Finding::new(
            "pass",
            "runtime.cert.exists",
            "Complete certificate infrastructure already exists; not regenerating.".into(),
        )),
        CertState::Empty => {
            let create = run_script(repo_root, runner, &script, "-a");
            findings.push(process_finding(
                &create,
                "runtime.cert.create",
                "gvm-manage-certs -a",
            ));
            if !create.success {
                return result(
                    repo_root,
                    runner,
                    "Certificate generation failed.",
                    findings,
                    vec![runtime_dir(repo_root).display().to_string()],
                );
            }
        }
    }

    let verify = run_script(repo_root, runner, &script, "-V");
    findings.push(process_finding(
        &verify,
        "runtime.cert.verify",
        "gvm-manage-certs -V",
    ));
    findings.extend(cert_file_findings(&files, "fail"));
    result(
        repo_root,
        runner,
        "Runtime certificate initialization completed.",
        findings,
        vec![
            public_dir.display().to_string(),
            private_dir.display().to_string(),
        ],
    )
}

fn cert_public_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("certs/CA")
}

fn cert_private_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("certs/private/CA")
}

fn cert_files(repo_root: &Path) -> Vec<CertFile> {
    let public = cert_public_dir(repo_root);
    let private = cert_private_dir(repo_root);
    vec![
        CertFile {
            name: "ca_key",
            path: private.join("cakey.pem"),
            private: true,
        },
        CertFile {
            name: "ca_cert",
            path: public.join("cacert.pem"),
            private: false,
        },
        CertFile {
            name: "server_key",
            path: private.join("serverkey.pem"),
            private: true,
        },
        CertFile {
            name: "server_cert",
            path: public.join("servercert.pem"),
            private: false,
        },
        CertFile {
            name: "client_key",
            path: private.join("clientkey.pem"),
            private: true,
        },
        CertFile {
            name: "client_cert",
            path: public.join("clientcert.pem"),
            private: false,
        },
    ]
}

fn cert_state(files: &[CertFile]) -> CertState {
    let existing = files.iter().filter(|file| path_exists(&file.path)).count();
    if existing == 0 {
        CertState::Empty
    } else if files.iter().all(cert_file_valid) {
        CertState::Complete
    } else {
        CertState::Partial
    }
}

pub(crate) fn runtime_certificates_complete(repo_root: &Path) -> bool {
    matches!(cert_state(&cert_files(repo_root)), CertState::Complete)
}

fn cert_file_valid(file: &CertFile) -> bool {
    let Ok(metadata) = fs::symlink_metadata(&file.path) else {
        return false;
    };
    metadata.file_type().is_file()
        && metadata.len() > 0
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && (!file.private || metadata.mode() & 0o077 == 0)
}

fn cert_file_findings(files: &[CertFile], invalid_status: &'static str) -> Vec<Finding> {
    files
        .iter()
        .map(|file| {
            let valid = cert_file_valid(file);
            Finding::new(
                if valid { "pass" } else { invalid_status },
                "runtime.cert",
                if valid {
                    format!("{} exists with a safe file identity.", file.name)
                } else {
                    format!(
                        "{} is missing, empty, linked, not current-user-owned, or has unsafe key permissions.",
                        file.name
                    )
                },
            )
            .with_path(&file.path.display().to_string())
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
            Finding::new(
                "fail",
                check,
                format!("Certificate directory is not usable: {error}"),
            )
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

fn safe_executable(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.uid() == current_euid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o111 != 0
    })
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    unsafe { libc::geteuid() }
}

fn cert_environment(repo_root: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = build_env(repo_root);
    for (name, value) in [
        (
            "GVM_KEY_LOCATION",
            cert_private_dir(repo_root).display().to_string(),
        ),
        (
            "GVM_CERT_LOCATION",
            cert_public_dir(repo_root).display().to_string(),
        ),
        ("GVM_CERTIFICATE_HOSTNAME", "localhost".into()),
        ("GVM_CERTIFICATE_SAN_DNS", "localhost".into()),
        ("GVM_CERTIFICATE_SAN_IP_ADDRESS", "127.0.0.1".into()),
    ] {
        environment.insert(OsString::from(name), OsString::from(value));
    }
    environment
}

fn run_script(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    script: &Path,
    action: &str,
) -> ProcessOutput {
    runner
        .run_with(
            &script.display().to_string(),
            &[action],
            Some(repo_root),
            Some(&cert_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: Some(127),
            stdout: String::new(),
            stderr: String::new(),
        })
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

fn failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
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
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum Generation {
        #[default]
        None,
        Complete,
    }

    type Invocation = (String, Vec<String>, BTreeMap<OsString, OsString>, Duration);

    #[derive(Default)]
    struct Runner {
        repo: Option<PathBuf>,
        generation: Generation,
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
            env: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push((
                program.into(),
                args.iter().map(|argument| (*argument).into()).collect(),
                env.cloned().unwrap_or_default(),
                timeout.unwrap(),
            ));
            if args == ["-a"] && self.generation == Generation::Complete {
                write_complete_cert_set(self.repo.as_deref().unwrap());
            }
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "ok\n".into(),
                stderr: String::new(),
            })
        }
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-certs-{}-{}-{name}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn prepare_script(repo: &Path) {
        let script = repo.join("build/prefix/bin/gvm-manage-certs");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(&script, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn write_complete_cert_set(repo: &Path) {
        let files = cert_files(repo);
        for file in files {
            fs::create_dir_all(file.path.parent().unwrap()).unwrap();
            fs::write(&file.path, "certificate-material\n").unwrap();
            fs::set_permissions(
                &file.path,
                fs::Permissions::from_mode(if file.private { 0o600 } else { 0o644 }),
            )
            .unwrap();
        }
    }

    #[test]
    fn missing_prerequisites_stop_before_process_execution() {
        let (root, repo) = fixture("missing");
        let runner = Runner::default();
        let result = command_with(&repo, &runner, false);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Certificate initialization stopped before generation."
        );
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_or_linked_state_is_never_overwritten() {
        let (root, repo) = fixture("partial");
        prepare_script(&repo);
        let private = cert_private_dir(&repo);
        fs::create_dir_all(&private).unwrap();
        let outside = root.join("outside-key");
        fs::write(&outside, "secret\n").unwrap();
        symlink(&outside, private.join("cakey.pem")).unwrap();
        let runner = Runner::default();
        let result = command_with(&repo, &runner, true);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Certificate initialization stopped at partial existing state."
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime.cert.partial" && finding.status == "fail"
        }));
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_state_is_verified_without_regeneration() {
        let (root, repo) = fixture("complete");
        prepare_script(&repo);
        write_complete_cert_set(&repo);
        let runner = Runner::default();
        let result = command_with(&repo, &runner, true);
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, ["-V"]);
        assert_eq!(calls[0].3, PROCESS_TIMEOUT);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_state_generates_then_verifies_with_bounded_environment() {
        let (root, repo) = fixture("generate");
        prepare_script(&repo);
        let runner = Runner {
            repo: Some(repo.clone()),
            generation: Generation::Complete,
            ..Runner::default()
        };
        let result = command_with(&repo, &runner, true);
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, ["-a"]);
        assert_eq!(calls[1].1, ["-V"]);
        assert_eq!(
            calls[0].2.get(&OsString::from("GVM_CERTIFICATE_HOSTNAME")),
            Some(&OsString::from("localhost"))
        );
        assert_eq!(
            calls[0]
                .2
                .get(&OsString::from("GVM_CERTIFICATE_SAN_IP_ADDRESS")),
            Some(&OsString::from("127.0.0.1"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_generator_without_complete_files_fails_closed() {
        let (root, repo) = fixture("incomplete-generation");
        prepare_script(&repo);
        let runner = Runner {
            repo: Some(repo.clone()),
            generation: Generation::None,
            ..Runner::default()
        };
        let result = command_with(&repo, &runner, true);
        assert_eq!(result.status, "fail");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| { finding.check == "runtime.cert" && finding.status == "fail" })
        );
        fs::remove_dir_all(root).unwrap();
    }
}
