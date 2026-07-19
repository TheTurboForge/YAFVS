// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::path::Path;

const RUNTIME_SERVICES: [&str; 3] = ["postgres", "redis-openvas", "mosquitto"];
const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];

pub fn command_runtime_plan(repo_root: &Path) -> ResultEnvelope {
    let root = runtime_dir(repo_root);
    let compose = "compose/dev.yaml";
    let gsad = gsad_hosts()
        .into_iter()
        .map(|host| format!("{host}:19392:9392"))
        .collect::<Vec<_>>();
    let findings = vec![
        Finding::new(
            "pass",
            "runtime.compose",
            "Development Compose file path is defined.".to_string(),
        )
        .with_path(compose),
        Finding::new(
            "pass",
            "runtime.state",
            format!(
                "Persistent runtime state lives outside the repository at {}.",
                root.display()
            ),
        )
        .with_path(&root.display().to_string()),
        Finding::new(
            "pass",
            "runtime.services",
            "Default runtime services are infrastructure: Postgres, scanner Redis, and Mosquitto."
                .to_string(),
        )
        .with_details(json!({ "services": RUNTIME_SERVICES })),
        Finding::new(
            "pass",
            "runtime.app-services",
            "Experimental application services are available behind the app profile.".to_string(),
        )
        .with_details(json!({ "services": APP_SERVICES })),
        Finding::new(
            "pass",
            "runtime.ports",
            "Infrastructure ports are loopback-only; gsad defaults to loopback but can be explicitly bound with YAFVS_GSAD_HOST or YAFVS_GSAD_HOSTS."
                .to_string(),
        )
        .with_details(json!({
            "postgres": "127.0.0.1:15432:5432",
            "mosquitto": "127.0.0.1:1883:1883",
            "gsad": gsad,
        })),
        Finding::new(
            "pass",
            "runtime.scanner-redis",
            "OpenVAS scanner KB Redis uses a runtime Unix socket, not host TCP exposure."
                .to_string(),
        )
        .with_path(&root.join("run/redis-openvas/redis.sock").display().to_string()),
        Finding::new(
            "pass",
            "runtime.feed-cache",
            "Community feed downloads use a persistent host-local cache outside the repository."
                .to_string(),
        )
        .with_path(
            &root
                .join("feed-cache/community/22.04/var-lib")
                .display()
                .to_string(),
        ),
        Finding::new(
            "pass",
            "runtime.feed-generation",
            "Runtime services consume only the journaled active immutable feed generation."
                .to_string(),
        )
        .with_path(&root.join("feed-store/current").display().to_string()),
        Finding::new(
            "pass",
            "runtime.feed-keyring",
            "OSPD and Notus share a persistent feed signature keyring under runtime state."
                .to_string(),
        )
        .with_path(&root.join("state/feed-gnupg").display().to_string()),
        Finding::new(
            "pass",
            "runtime.pg-gvm",
            "Postgres pg-gvm extension initialization is handled by just runtime-init after pg-gvm is built."
                .to_string(),
        ),
        Finding::new(
            "pass",
            "runtime.certs",
            "Certificate initialization is handled by just runtime-certs-init and persists outside the repository."
                .to_string(),
        ),
        Finding::new(
            "warn",
            "runtime.deferred",
            "Scan execution remains guarded and requires scanner capability checks.".to_string(),
        ),
    ];
    make_result(
        metadata(repo_root, "runtime-plan", &SystemCommandRunner),
        "Persistent Docker runtime plan collected.".to_string(),
        findings,
    )
    .with_artifacts(vec![root.display().to_string(), compose.to_string()])
}

pub fn command_logs(repo_root: &Path, service: Option<&str>, lines: i64) -> ResultEnvelope {
    command_logs_with_runner(repo_root, service, lines, &SystemCommandRunner)
}

fn command_logs_with_runner(
    repo_root: &Path,
    service: Option<&str>,
    lines: i64,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    if lines < 1 {
        return make_result(
            metadata(repo_root, "logs", runner),
            "Runtime logs were not collected.".to_string(),
            vec![
                Finding::new(
                    "fail",
                    "compose.logs.invalid_lines",
                    "--lines must be 1 or greater.".to_string(),
                )
                .with_details(json!({ "service": service, "lines": lines })),
            ],
        );
    }
    let mut arguments = vec!["logs".to_string(), "--tail".to_string(), lines.to_string()];
    if let Some(service) = service {
        arguments.push(service.to_string());
    }
    let command = compose_command(repo_root, &arguments);
    let argument_refs = command.iter().map(String::as_str).collect::<Vec<_>>();
    let output = runner.run_with(
        "docker",
        &argument_refs,
        Some(repo_root),
        Some(&runtime_environment(repo_root)),
        None,
    );
    let exit_code = output
        .as_ref()
        .and_then(|output| output.exit_code)
        .unwrap_or(1);
    let tail = output
        .as_ref()
        .map(|output| output_tail(&output.stdout, lines as usize))
        .unwrap_or_default();
    let mut message = format!("docker compose logs exit code {exit_code}.");
    if !tail.is_empty() {
        message.push('\n');
        message.push_str(&tail.join("\n"));
    }
    make_result(
        metadata(repo_root, "logs", runner),
        "Runtime logs collected.".to_string(),
        vec![
            Finding::new(
                if exit_code == 0 { "pass" } else { "fail" },
                "compose.logs",
                message,
            )
            .with_details(json!({ "service": service, "lines": lines, "output_tail": tail })),
        ],
    )
}

fn gsad_hosts() -> Vec<String> {
    let plural = env::var("YAFVS_GSAD_HOSTS").ok();
    let hosts = split_hosts(plural.as_deref());
    if !hosts.is_empty() {
        return hosts;
    }
    let singular = env::var("YAFVS_GSAD_HOST").ok();
    let hosts = split_hosts(singular.as_deref());
    if hosts.is_empty() {
        vec!["127.0.0.1".to_string()]
    } else {
        hosts
    }
}

fn split_hosts(value: Option<&str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .filter(|host| seen.insert((*host).to_string()))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::ffi::OsString;

    struct LogsRunner;

    impl CommandRunner for LogsRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".to_string(),
                stderr: String::new(),
            })
        }

        fn run_with(
            &self,
            program: &str,
            _args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&std::collections::BTreeMap<OsString, OsString>>,
            _timeout: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            if program == "docker" {
                return Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: "one\ntwo\nthree\n".to_string(),
                    stderr: String::new(),
                });
            }
            self.run(program, &[])
        }
    }

    #[test]
    fn host_splitting_preserves_first_seen_order() {
        assert_eq!(
            split_hosts(Some("127.0.0.1, localhost,127.0.0.1")),
            vec!["127.0.0.1", "localhost"]
        );
    }

    #[test]
    fn logs_retain_only_the_requested_tail() {
        let result =
            command_logs_with_runner(Path::new("/srv/YAFVS"), Some("gvmd"), 2, &LogsRunner);
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.findings[0].message,
            "docker compose logs exit code 0.\ntwo\nthree"
        );
        assert_eq!(
            result.findings[0].details,
            Some(json!({ "service": "gvmd", "lines": 2, "output_tail": ["two", "three"] }))
        );
    }

    #[test]
    fn logs_reject_non_positive_line_counts_without_running_docker() {
        let result = command_logs_with_runner(Path::new("/srv/YAFVS"), None, 0, &LogsRunner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "compose.logs.invalid_lines");
    }
}
