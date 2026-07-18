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
