// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Private runtime configuration required before starting the feed scanners.

use super::service_runtime::ServiceRuntime;
use super::transition::{StepOutcome, StepStatus};
use crate::commands::common::runtime_dir;
use crate::commands::secret::{read_or_create_runtime_secret, write_private_text};
use crate::result::Finding;
use serde_json::json;
use std::path::Path;
use std::time::Duration;

const MQTT_OPENVAS_SECRET: &str = "mqtt-openvas-password";
const OPENVAS_CONFIG_RELATIVE: &str = "state/ospd/openvas.conf";
const REDIS_SOCKET: &str = "/run/redis-openvas/redis.sock";

pub(super) fn verify_scanner_redis(runtime: &ServiceRuntime<'_>) -> StepOutcome {
    verify_scanner_redis_with(runtime, 20, Duration::from_secs(1))
}

fn verify_scanner_redis_with(
    runtime: &ServiceRuntime<'_>,
    attempts: usize,
    retry_delay: Duration,
) -> StepOutcome {
    for attempt in 1..=attempts.max(1) {
        let running = runtime.scanner_redis_running().unwrap_or(false);
        if running {
            let arguments = [
                "exec".to_owned(),
                "-T".to_owned(),
                "redis-openvas".to_owned(),
                "redis-cli".to_owned(),
                "-s".to_owned(),
                REDIS_SOCKET.to_owned(),
                "ping".to_owned(),
            ];
            if let Ok(output) = runtime.run_compose(&arguments, Duration::from_secs(120))
                && output.success
                && output.stdout.lines().any(|line| line.trim() == "PONG")
            {
                return StepOutcome::with_evidence(
                    StepStatus::Pass,
                    vec![
                        Finding::new(
                            "pass",
                            "redis-openvas.ready",
                            "The existing scanner Redis service accepts Unix-socket health probes."
                                .to_owned(),
                        )
                        .with_details(
                            json!({"attempt": attempt, "attempt_limit": attempts.max(1)}),
                        ),
                    ],
                    Vec::new(),
                );
            }
        }
        if attempt < attempts.max(1) && !retry_delay.is_zero() {
            std::thread::sleep(retry_delay);
        }
    }
    StepOutcome::with_evidence(
        StepStatus::Fail,
        vec![Finding::new(
            "fail",
            "redis-openvas.ready",
            "The existing scanner Redis service did not accept a bounded Unix-socket health probe; initialize the runtime infrastructure before feed activation."
                .to_owned(),
        )
        .with_details(json!({"attempt_limit": attempts.max(1)}))],
        Vec::new(),
    )
}

pub(super) fn ensure_openvas_runtime_config(repo_root: &Path) -> StepOutcome {
    let path = runtime_dir(repo_root).join(OPENVAS_CONFIG_RELATIVE);
    let (secret, created) = match read_or_create_runtime_secret(repo_root, MQTT_OPENVAS_SECRET) {
        Ok(secret) => secret,
        Err(error) => {
            return failure(
                "Scanner runtime configuration stopped because the OpenVAS MQTT secret could not be read safely.",
                &path,
                &error.to_string(),
            );
        }
    };
    if let Err(error) = write_private_text(&path, &render_openvas_config(&secret)) {
        return failure(
            "Scanner runtime configuration could not be written atomically.",
            &path,
            &error.to_string(),
        );
    }
    StepOutcome::with_evidence(
        StepStatus::Pass,
        vec![Finding::new(
            "pass",
            "runtime.openvas-config",
            "OpenVAS runtime configuration uses the active Redis socket and immutable feed mapping."
                .to_owned(),
        )
        .with_path(&path.display().to_string())
        .with_details(json!({"mqtt_secret_created": created}))],
        vec![path.display().to_string()],
    )
}

fn failure(message: &str, path: &Path, reason: &str) -> StepOutcome {
    StepOutcome::with_evidence(
        StepStatus::Fail,
        vec![
            Finding::new("fail", "runtime.openvas-config", message.to_owned())
                .with_path(&path.display().to_string())
                .with_details(json!({"reason": reason})),
        ],
        vec![path.display().to_string()],
    )
}

fn render_openvas_config(mqtt_password: &str) -> String {
    format!(
        "# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>\n\
# SPDX-License-Identifier: GPL-3.0-or-later\n\
# Generated development runtime configuration.\n\
db_address = /runtime/run/redis-openvas/redis.sock\n\
plugins_folder = /runtime/feeds/openvas/plugins\n\
include_folders = /runtime/feeds/openvas/plugins\n\
mqtt_server_uri = mosquitto:1883\n\
mqtt_user = openvas\n\
mqtt_pass = {mqtt_password}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{CommandRunner, ProcessOutput};
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn fixture() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-scanner-runtime-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("TurboVAS")).unwrap();
        root
    }

    struct Runner {
        outputs: Mutex<VecDeque<Option<ProcessOutput>>>,
        commands: Mutex<Vec<Vec<String>>>,
    }

    impl Runner {
        fn new(outputs: impl IntoIterator<Item = Option<ProcessOutput>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                commands: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, _: &str, _: &[&str]) -> Option<ProcessOutput> {
            unreachable!()
        }

        fn run_with(
            &self,
            program: &str,
            arguments: &[&str],
            _: Option<&Path>,
            _: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            let mut command = vec![program.to_owned()];
            command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
            self.commands.lock().unwrap().push(command);
            self.outputs.lock().unwrap().pop_front().flatten()
        }
    }

    fn output(success: bool, stdout: &str) -> Option<ProcessOutput> {
        Some(ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.to_owned(),
            stderr: "private diagnostic".to_owned(),
        })
    }

    #[test]
    fn renders_the_exact_python_compatible_openvas_configuration() {
        assert_eq!(
            render_openvas_config("private-value"),
            "# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>\n\
# SPDX-License-Identifier: GPL-3.0-or-later\n\
# Generated development runtime configuration.\n\
db_address = /runtime/run/redis-openvas/redis.sock\n\
plugins_folder = /runtime/feeds/openvas/plugins\n\
include_folders = /runtime/feeds/openvas/plugins\n\
mqtt_server_uri = mosquitto:1883\n\
mqtt_user = openvas\n\
mqtt_pass = private-value\n"
        );
    }

    #[test]
    fn writes_owner_private_config_without_exposing_the_secret_in_evidence() {
        let root = fixture();
        let repo = root.join("TurboVAS");
        let outcome = ensure_openvas_runtime_config(&repo);
        assert_eq!(outcome.status, StepStatus::Pass);
        let path = runtime_dir(&repo).join(OPENVAS_CONFIG_RELATIVE);
        let contents = fs::read_to_string(&path).unwrap();
        let secret = contents.rsplit_once("mqtt_pass = ").unwrap().1.trim();
        assert!(!secret.is_empty());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !serde_json::to_string(&outcome.findings)
                .unwrap()
                .contains(secret)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redis_readiness_uses_the_existing_service_and_exact_unix_socket_probe() {
        let root = fixture();
        let repo = root.join("TurboVAS");
        let runner = Runner::new([
            output(true, "abc123\n"),
            output(true, "true\n"),
            output(true, "PONG\n"),
        ]);
        let environment = BTreeMap::new();
        let images = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);

        let outcome = verify_scanner_redis_with(&runtime, 1, Duration::ZERO);

        assert_eq!(outcome.status, StepStatus::Pass);
        let commands = runner.commands.lock().unwrap();
        assert_eq!(commands.len(), 3);
        assert!(commands[2].ends_with(&[
            "exec".to_owned(),
            "-T".to_owned(),
            "redis-openvas".to_owned(),
            "redis-cli".to_owned(),
            "-s".to_owned(),
            REDIS_SOCKET.to_owned(),
            "ping".to_owned(),
        ]));
        assert!(commands.iter().flatten().all(|argument| argument != "up"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redis_readiness_retries_without_leaking_process_output() {
        let root = fixture();
        let repo = root.join("TurboVAS");
        let runner = Runner::new([
            output(true, "abc123\n"),
            output(true, "true\n"),
            output(false, "private redis output\n"),
            output(true, "abc123\n"),
            output(true, "true\n"),
            output(false, "private redis output\n"),
        ]);
        let environment = BTreeMap::new();
        let images = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);

        let outcome = verify_scanner_redis_with(&runtime, 2, Duration::ZERO);

        assert_eq!(outcome.status, StepStatus::Fail);
        assert_eq!(runner.commands.lock().unwrap().len(), 6);
        assert!(
            !serde_json::to_string(&outcome.findings)
                .unwrap()
                .contains("private redis output")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
