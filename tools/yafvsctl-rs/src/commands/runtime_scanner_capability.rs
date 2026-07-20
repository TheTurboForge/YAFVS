// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, output_tail};
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const SERVICE: &str = "ospd-openvas";
const STABLE_HOSTNAME: &str = "yafvs-ospd-openvas";
const CAPABILITIES: [(&str, u32); 2] = [("NET_ADMIN", 12), ("NET_RAW", 13)];
const NMAP_PRIVILEGE_WARNINGS: [&str; 4] = [
    "requires root privileges",
    "requires root",
    "you requested a scan type which requires root privileges",
    "raw scans require root privileges",
];

pub fn command_runtime_scanner_capability_check(repo_root: &Path) -> ResultEnvelope {
    command_runtime_scanner_capability_check_with(repo_root, &SystemCommandRunner)
}

pub(crate) fn command_runtime_scanner_capability_check_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let running = container_running(repo_root, runner);
    findings.push(running_finding(running));
    if !running {
        return make_result(
            metadata(repo_root, "runtime-scanner-capability-check", runner),
            "Scanner capability check stopped because ospd-openvas is not running.".into(),
            findings,
        );
    }

    let pid_probe = exec_in_service(
        repo_root,
        runner,
        &[
            "sh",
            "-lc",
            r#"ps -eo pid,comm,args | awk '$2 == "ospd-openvas" && /--foreground/ { print $1; exit }'"#,
        ],
    );
    let scanner_pid = pid_probe
        .stdout
        .trim()
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    findings.push(
        Finding::new(
            if pid_probe.success && !scanner_pid.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "ospd.pid",
            if scanner_pid.is_empty() {
                "ospd-openvas scanner process PID could not be found.".into()
            } else {
                format!("ospd-openvas scanner process PID is {scanner_pid}.")
            },
        )
        .with_details(json!({"output_tail": output_tail(&pid_probe.stdout, 20)})),
    );

    let status_path = if scanner_pid.is_empty() {
        "/proc/1/status".to_string()
    } else {
        format!("/proc/{scanner_pid}/status")
    };
    let quoted_status_path = shlex::try_quote(&status_path)
        .map(|value| value.into_owned())
        .unwrap_or_else(|_| "'/proc/1/status'".into());
    let status_command = format!(
        "sed -n 's/^Uid:/Uid:/p; s/^Gid:/Gid:/p; s/^CapInh:/CapInh:/p; \
         s/^CapPrm:/CapPrm:/p; s/^CapEff:/CapEff:/p; s/^CapBnd:/CapBnd:/p; \
         s/^CapAmb:/CapAmb:/p' {quoted_status_path}"
    );
    let status_probe = exec_in_service(repo_root, runner, &["sh", "-lc", &status_command]);
    let values = parse_proc_status(&status_probe.stdout);
    let environment = runtime_environment(repo_root);
    let expected_uid = environment_value(&environment, "YAFVS_UID");
    let expected_gid = environment_value(&environment, "YAFVS_GID");
    let actual_uid = values.get("Uid").and_then(|value| first_status_id(value));
    let actual_gid = values.get("Gid").and_then(|value| first_status_id(value));

    findings.push(
        Finding::new(
            if status_probe.success { "pass" } else { "fail" },
            "ospd.proc-status",
            format!("{status_path} read exit code {}.", exit_code(&status_probe)),
        )
        .with_details(json!({"output_tail": output_tail(&status_probe.stdout, 40)})),
    );
    findings.push(
        Finding::new(
            if actual_uid == Some(expected_uid.as_str()) {
                "pass"
            } else {
                "fail"
            },
            "ospd.uid",
            format!(
                "ospd-openvas scanner process UID is {}; expected {expected_uid}.",
                actual_uid.unwrap_or("None")
            ),
        )
        .with_details(json!({
            "uid_line": values.get("Uid"),
            "expected": expected_uid,
            "pid": scanner_pid,
        })),
    );
    findings.push(
        Finding::new(
            if actual_gid == Some(expected_gid.as_str()) {
                "pass"
            } else {
                "fail"
            },
            "ospd.gid",
            format!(
                "ospd-openvas scanner process GID is {}; expected {expected_gid}.",
                actual_gid.unwrap_or("None")
            ),
        )
        .with_details(json!({
            "gid_line": values.get("Gid"),
            "expected": expected_gid,
            "pid": scanner_pid,
        })),
    );

    let hostname_probe = exec_in_service(
        repo_root,
        runner,
        &["sh", "-lc", "hostname; getent hosts $(hostname)"],
    );
    let hostname = hostname_probe
        .stdout
        .trim()
        .lines()
        .next()
        .unwrap_or("")
        .trim();
    let hostname_ok =
        hostname_probe.success && hostname == STABLE_HOSTNAME && !docker_short_hostname(hostname);
    findings.push(
        Finding::new(
            if hostname_ok { "pass" } else { "fail" },
            "ospd.hostname",
            if hostname_ok {
                format!("ospd-openvas hostname is the stable value {STABLE_HOSTNAME}.")
            } else {
                format!(
                    "ospd-openvas hostname is {}; expected {STABLE_HOSTNAME}.",
                    if hostname.is_empty() {
                        "unreadable"
                    } else {
                        hostname
                    }
                )
            },
        )
        .with_details(json!({
            "hostname": hostname,
            "expected": STABLE_HOSTNAME,
            "output_tail": output_tail(&hostname_probe.stdout, 20),
        })),
    );

    for field in ["CapPrm", "CapEff", "CapAmb"] {
        let value = values.get(field).map(String::as_str);
        let missing = missing_capabilities(value);
        findings.push(
            Finding::new(
                if missing.is_empty() { "pass" } else { "fail" },
                &format!("ospd.{}", field.to_ascii_lowercase()),
                if missing.is_empty() {
                    format!("{field} includes NET_RAW and NET_ADMIN.")
                } else {
                    format!(
                        "{field} is missing required capabilities: {}.",
                        missing.join(", ")
                    )
                },
            )
            .with_details(json!({"value": value, "missing": missing})),
        );
    }

    let raw_probe_arguments = raw_socket_probe_arguments(&environment);
    let raw_probe = exec_in_service_owned(repo_root, runner, &raw_probe_arguments);
    findings.push(
        Finding::new(
            if raw_probe.success && raw_probe.stdout.contains("raw-ok") {
                "pass"
            } else {
                "fail"
            },
            "ospd.raw-socket-probe",
            format!(
                "Service-user raw ICMP socket probe exit code {}.",
                exit_code(&raw_probe)
            ),
        )
        .with_details(json!({"output_tail": output_tail(&raw_probe.stdout, 40)})),
    );

    make_result(
        metadata(repo_root, "runtime-scanner-capability-check", runner),
        "Scanner capability check completed.".into(),
        findings,
    )
}

pub fn command_runtime_nmap_capability_check(repo_root: &Path) -> ResultEnvelope {
    command_runtime_nmap_capability_check_with(repo_root, &SystemCommandRunner)
}

pub(crate) fn command_runtime_nmap_capability_check_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let running = container_running(repo_root, runner);
    findings.push(running_finding(running));
    if !running {
        return make_result(
            metadata(repo_root, "runtime-nmap-capability-check", runner),
            "Nmap capability check stopped because ospd-openvas is not running.".into(),
            findings,
        );
    }

    let path_probe = exec_in_service(repo_root, runner, &["sh", "-lc", "command -v nmap"]);
    let path = path_probe
        .stdout
        .trim()
        .lines()
        .next_back()
        .unwrap_or("")
        .trim();
    findings.push(
        Finding::new(
            if path_probe.success && !path.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "nmap.path",
            format!("nmap path probe exit code {}.", exit_code(&path_probe)),
        )
        .with_details(json!({
            "path": path,
            "output_tail": output_tail(&path_probe.stdout, 20),
        })),
    );

    let getcap_probe = exec_in_service(
        repo_root,
        runner,
        &[
            "sh",
            "-lc",
            "command -v getcap >/dev/null 2>&1 && getcap /usr/bin/nmap || true",
        ],
    );
    let file_caps_ok = getcap_probe.stdout.contains("cap_net_raw")
        && getcap_probe.stdout.contains("cap_net_admin");
    findings.push(
        Finding::new(
            if getcap_probe.success && file_caps_ok {
                "pass"
            } else {
                "fail"
            },
            "nmap.file-capabilities",
            if file_caps_ok {
                "nmap has file capabilities for NET_RAW and NET_ADMIN.".into()
            } else {
                "nmap is missing expected NET_RAW/NET_ADMIN file capabilities.".into()
            },
        )
        .with_details(json!({"output_tail": output_tail(&getcap_probe.stdout, 40)})),
    );

    let environment_probe = exec_in_service(
        repo_root,
        runner,
        &["sh", "-lc", "printf '%s' \"${NMAP_PRIVILEGED:-}\""],
    );
    let environment_ok = environment_probe.success && environment_probe.stdout.trim() == "1";
    findings.push(
        Finding::new(
            if environment_ok { "pass" } else { "fail" },
            "nmap.env",
            if environment_ok {
                "NMAP_PRIVILEGED=1 is present in the scanner service environment.".into()
            } else {
                "NMAP_PRIVILEGED=1 is missing from the scanner service environment.".into()
            },
        )
        .with_details(json!({"output_tail": output_tail(&environment_probe.stdout, 20)})),
    );

    let environment = runtime_environment(repo_root);
    for (check, arguments) in nmap_probe_arguments(&environment) {
        let probe = exec_in_service_owned(repo_root, runner, &arguments);
        let privilege_warning = nmap_privilege_warning(&probe.stdout);
        findings.push(
            Finding::new(
                if probe.success && !privilege_warning {
                    "pass"
                } else {
                    "fail"
                },
                check,
                if privilege_warning {
                    format!("{check} probe still reports that root privileges are required.")
                } else {
                    format!("{check} probe exit code {}.", exit_code(&probe))
                },
            )
            .with_details(json!({
                "privilege_warning": privilege_warning,
                "output_tail": output_tail(&probe.stdout, 80),
            })),
        );
    }

    make_result(
        metadata(repo_root, "runtime-nmap-capability-check", runner),
        "Nmap capability check completed.".into(),
        findings,
    )
}

fn run_docker(repo_root: &Path, runner: &dyn CommandRunner, arguments: &[String]) -> ProcessOutput {
    runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or_else(failed_process)
}

fn failed_process() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn container_running(repo_root: &Path, runner: &dyn CommandRunner) -> bool {
    let ps = run_docker(
        repo_root,
        runner,
        &compose_command(repo_root, &["ps".into(), "-q".into(), SERVICE.into()]),
    );
    if !ps.success {
        return false;
    }
    let Some(container_id) = ps.stdout.trim().lines().next().map(str::trim) else {
        return false;
    };
    if container_id.is_empty() {
        return false;
    }
    let inspect = run_docker(
        repo_root,
        runner,
        &[
            "inspect".into(),
            "-f".into(),
            "{{.State.Running}}".into(),
            container_id.into(),
        ],
    );
    inspect.success && inspect.stdout.trim() == "true"
}

fn running_finding(running: bool) -> Finding {
    Finding::new(
        if running { "pass" } else { "fail" },
        "ospd.running",
        if running {
            "ospd-openvas container is running.".into()
        } else {
            "ospd-openvas container is not running; run just runtime-app-up.".into()
        },
    )
    .with_details(json!({"service": SERVICE}))
}

fn exec_in_service(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    command: &[&str],
) -> ProcessOutput {
    let arguments = command
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    exec_in_service_owned(repo_root, runner, &arguments)
}

fn exec_in_service_owned(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    command: &[String],
) -> ProcessOutput {
    let mut arguments = vec!["exec".into(), "-T".into(), SERVICE.into()];
    arguments.extend_from_slice(command);
    run_docker(repo_root, runner, &compose_command(repo_root, &arguments))
}

fn exit_code(output: &ProcessOutput) -> i32 {
    output.exit_code.unwrap_or(1)
}

fn environment_value(
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
    key: &str,
) -> String {
    environment
        .get(&std::ffi::OsString::from(key))
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn parse_proc_status(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn first_status_id(value: &str) -> Option<&str> {
    value.split_whitespace().next()
}

fn capability_present(mask: Option<&str>, bit: u32) -> bool {
    mask.and_then(|value| u64::from_str_radix(value, 16).ok())
        .is_some_and(|value| value & (1_u64 << bit) != 0)
}

fn missing_capabilities(mask: Option<&str>) -> Vec<&'static str> {
    CAPABILITIES
        .iter()
        .filter_map(|(name, bit)| (!capability_present(mask, *bit)).then_some(*name))
        .collect()
}

fn docker_short_hostname(hostname: &str) -> bool {
    hostname.len() == 12 && hostname.chars().all(|value| value.is_ascii_hexdigit())
}

fn setpriv_prefix(environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>) -> Vec<String> {
    vec![
        "setpriv".into(),
        "--reuid".into(),
        environment_value(environment, "YAFVS_UID"),
        "--regid".into(),
        environment_value(environment, "YAFVS_GID"),
        "--clear-groups".into(),
        "--inh-caps".into(),
        "+net_raw,+net_admin".into(),
        "--ambient-caps".into(),
        "+net_raw,+net_admin".into(),
    ]
}

fn raw_socket_probe_arguments(
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Vec<String> {
    let mut arguments = setpriv_prefix(environment);
    arguments.extend([
        "python3".into(),
        "-c".into(),
        "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); print('raw-ok')".into(),
    ]);
    arguments
}

fn nmap_probe_arguments(
    environment: &BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> [(&'static str, Vec<String>); 2] {
    let prefix = setpriv_prefix(environment);
    let command = |script: &str| {
        let mut arguments = prefix.clone();
        arguments.extend(["sh".into(), "-lc".into(), script.into()]);
        arguments
    };
    [
        (
            "nmap.raw-syn",
            command(
                "NMAP_PRIVILEGED=1 nmap -sS -Pn -n --max-retries 0 --host-timeout 15s -p 9 127.0.0.1",
            ),
        ),
        (
            "nmap.os-detection",
            command(
                "python3 -m http.server 18080 --bind 127.0.0.1 >/tmp/yafvs-nmap-probe.log 2>&1 & \
                 pid=$!; trap 'kill $pid 2>/dev/null || true' EXIT; sleep 1; \
                 NMAP_PRIVILEGED=1 nmap -O -Pn -n --max-retries 0 --host-timeout 25s -p 9,18080 127.0.0.1",
            ),
        ),
    ]
}

fn nmap_privilege_warning(output: &str) -> bool {
    let output = output.to_ascii_lowercase();
    NMAP_PRIVILEGE_WARNINGS
        .iter()
        .any(|warning| output.contains(warning))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::sync::Mutex;

    struct ScriptedRunner {
        outputs: Mutex<VecDeque<ProcessOutput>>,
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ScriptedRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for ScriptedRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| output(true, "deadbee\n"))
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
            self.outputs.lock().unwrap().pop_front()
        }
    }

    fn output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn scanner_outputs(hostname: &str, capabilities: &str) -> Vec<ProcessOutput> {
        vec![
            output(true, "container-id\n"),
            output(true, "true\n"),
            output(true, "7\n"),
            output(
                true,
                &format!(
                    "Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n\
                     CapPrm:\t{capabilities}\nCapEff:\t{capabilities}\nCapAmb:\t{capabilities}\n"
                ),
            ),
            output(true, &format!("{hostname}\n127.0.0.1 {hostname}\n")),
            output(true, "raw-ok\n"),
        ]
    }

    #[test]
    fn absent_service_stops_both_commands() {
        for (command, expected) in [
            (
                command_runtime_scanner_capability_check_with
                    as fn(&Path, &dyn CommandRunner) -> ResultEnvelope,
                "runtime-scanner-capability-check",
            ),
            (
                command_runtime_nmap_capability_check_with
                    as fn(&Path, &dyn CommandRunner) -> ResultEnvelope,
                "runtime-nmap-capability-check",
            ),
        ] {
            let runner = ScriptedRunner::new(vec![output(true, "")]);
            let result = command(Path::new("/srv/YAFVS"), &runner);
            assert_eq!(result.status, "fail");
            assert_eq!(result.metadata.command, expected);
            assert_eq!(result.findings.len(), 1);
            assert_eq!(result.findings[0].check, "ospd.running");
            assert_eq!(runner.calls().len(), 1);
        }
    }

    #[test]
    fn scanner_success_preserves_findings_and_non_root_probe() {
        let runner = ScriptedRunner::new(scanner_outputs(STABLE_HOSTNAME, "0000000000003000"));
        let result =
            command_runtime_scanner_capability_check_with(Path::new("/srv/YAFVS"), &runner);

        assert_eq!(result.status, "pass");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            [
                "ospd.running",
                "ospd.pid",
                "ospd.proc-status",
                "ospd.uid",
                "ospd.gid",
                "ospd.hostname",
                "ospd.capprm",
                "ospd.capeff",
                "ospd.capamb",
                "ospd.raw-socket-probe",
            ]
        );
        let calls = runner.calls();
        let raw = &calls.last().unwrap().1;
        assert!(raw.windows(2).any(|pair| pair == ["--reuid", "1000"]));
        assert!(raw.windows(2).any(|pair| pair == ["--regid", "1000"]));
        assert!(raw.contains(&"--ambient-caps".into()));
        assert!(raw.contains(&"+net_raw,+net_admin".into()));
        assert!(raw.iter().any(|value| value.contains("socket.SOCK_RAW")));
    }

    #[test]
    fn malformed_capabilities_and_docker_ids_fail_closed() {
        assert_eq!(
            missing_capabilities(Some("not-hex")),
            ["NET_ADMIN", "NET_RAW"]
        );
        assert_eq!(missing_capabilities(Some("0000000000001000")), ["NET_RAW"]);
        assert!(docker_short_hostname("b758d8ce41ff"));
        assert!(!docker_short_hostname(STABLE_HOSTNAME));

        let runner = ScriptedRunner::new(scanner_outputs("b758d8ce41ff", "not-hex"));
        let result =
            command_runtime_scanner_capability_check_with(Path::new("/srv/YAFVS"), &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.findings[5].message,
            "ospd-openvas hostname is b758d8ce41ff; expected yafvs-ospd-openvas."
        );
        assert_eq!(result.findings[6].status, "fail");
    }

    #[test]
    fn nmap_success_preserves_order_and_loopback_only_probes() {
        let runner = ScriptedRunner::new(vec![
            output(true, "container-id\n"),
            output(true, "true\n"),
            output(true, "/usr/bin/nmap\n"),
            output(true, "/usr/bin/nmap cap_net_admin,cap_net_raw=ep\n"),
            output(true, "1"),
            output(true, "Nmap done: 1 IP address scanned.\n"),
            output(true, "OS details: Linux\n"),
        ]);
        let result = command_runtime_nmap_capability_check_with(Path::new("/srv/YAFVS"), &runner);
        assert_eq!(result.status, "pass");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            [
                "ospd.running",
                "nmap.path",
                "nmap.file-capabilities",
                "nmap.env",
                "nmap.raw-syn",
                "nmap.os-detection",
            ]
        );
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(!rendered.contains("mqtt-"));
        let calls = runner.calls();
        for call in &calls[5..] {
            let script = call.1.last().unwrap();
            assert!(script.contains("127.0.0.1"));
            assert!(!script.contains("0.0.0.0"));
            assert!(call.1.contains(&"--ambient-caps".into()));
        }
        assert!(calls[6].1.last().unwrap().contains("--bind 127.0.0.1"));
    }

    #[test]
    fn nmap_root_warning_fails_even_with_zero_exit() {
        let runner = ScriptedRunner::new(vec![
            output(true, "container-id\n"),
            output(true, "true\n"),
            output(true, "/usr/bin/nmap\n"),
            output(true, "/usr/bin/nmap cap_net_admin,cap_net_raw=ep\n"),
            output(true, "1"),
            output(
                true,
                "You requested a scan type which requires root privileges.\n",
            ),
            output(true, "clean\n"),
        ]);
        let result = command_runtime_nmap_capability_check_with(Path::new("/srv/YAFVS"), &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[4].check, "nmap.raw-syn");
        assert_eq!(result.findings[4].status, "fail");
        assert_eq!(
            result.findings[4].details.as_ref().unwrap()["privilege_warning"],
            true
        );
    }
}
