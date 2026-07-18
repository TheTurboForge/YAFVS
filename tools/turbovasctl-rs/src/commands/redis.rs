// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{git_tracked_files, metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use regex::Regex;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::LazyLock;

const ROOTS: [&str; 7] = [
    "compose/",
    "docker/",
    "tools/",
    "docs/",
    "components/gvmd/",
    "components/openvas-scanner/",
    "components/ospd-openvas/",
];
const FILES: [&str; 2] = ["README.md", "justfile"];
const SOCKET: &str = "/run/redis-openvas/redis.sock";
static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bredis\b|redis-openvas|hiredis|scanner_redis|scanner redis").unwrap()
});

#[derive(Clone, Debug, Serialize)]
struct Reference {
    path: String,
    category: String,
    markers: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
struct Bucket {
    count: usize,
    paths: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
struct Summary {
    total_items: usize,
    by_category: BTreeMap<String, Bucket>,
}
#[derive(Clone, Debug, Serialize)]
struct Boundaries {
    compose_file: String,
    generic_redis_service_present: bool,
    generic_redis_loopback_tcp: bool,
    scanner_redis_no_tcp_port: bool,
    scanner_redis_unix_socket: bool,
    gvmd_depends_on_generic_redis: bool,
    ospd_depends_on_scanner_redis: bool,
}
#[derive(Clone, Debug, Serialize)]
struct Runtime {
    redis: Service,
    #[serde(rename = "redis-openvas")]
    openvas: Service,
}
#[derive(Clone, Debug, Serialize)]
struct Service {
    running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ping_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_tail: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_exists: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<Metrics>,
}
#[derive(Clone, Debug, Serialize)]
struct Metrics {
    dbsize_status: String,
    dbsize: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dbsize_output_tail: Option<Vec<String>>,
    info_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_output_tail: Option<Vec<String>>,
    #[serde(flatten)]
    values: BTreeMap<String, i64>,
}

pub fn command_runtime_redis_state(root: &Path) -> ResultEnvelope {
    command_with(root, &SystemCommandRunner)
}
fn command_with(root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let references = references(root, runner);
    let summary = summary(&references);
    let boundaries = boundaries(root);
    let runtime = runtime(root, runner);
    let mut findings = vec![
        Finding::new("pass", "redis.source-map", format!("Classified {} Redis reference surface(s).", references.len())).with_details(json!(summary)),
        Finding::new(if boundaries.generic_redis_service_present { "warn" } else { "pass" }, "redis.generic-boundary", if boundaries.generic_redis_service_present { "Generic Redis is still present in the development Compose file.".into() } else { "Generic Redis is absent from the development Compose file; scanner Redis remains the retained Redis boundary.".into() }).with_path(&boundaries.compose_file).with_details(json!(boundaries)),
        Finding::new(if boundaries.scanner_redis_no_tcp_port && boundaries.scanner_redis_unix_socket { "pass" } else { "fail" }, "redis.scanner-boundary", if boundaries.scanner_redis_no_tcp_port && boundaries.scanner_redis_unix_socket { "Scanner Redis is configured with no TCP port and a runtime Unix socket.".into() } else { "Scanner Redis network/socket boundary is not as expected.".into() }).with_path(&boundaries.compose_file).with_details(json!(boundaries)),
    ];
    if runtime.redis.running {
        findings.push(Finding::new("warn", "redis.runtime-ping", "Generic Redis container is still running as stale runtime state; remove the orphan container after Compose reconciliation.".into()).with_details(json!(runtime.redis)));
    } else {
        findings.push(
            Finding::new(
                "pass",
                "redis.runtime-ping",
                "Generic Redis container is not running, as expected.".into(),
            )
            .with_details(json!(runtime.redis)),
        );
    }
    let socket = socket_path(root).display().to_string();
    if runtime.openvas.running {
        let ready = runtime.openvas.ping_status.as_deref() == Some("pass")
            && runtime.openvas.socket_exists == Some(true);
        findings.push(
            Finding::new(
                if ready { "pass" } else { "fail" },
                "redis-openvas.runtime-ping",
                if ready {
                    "Scanner Redis Unix socket responded to ping.".into()
                } else {
                    "Scanner Redis Unix socket ping failed.".into()
                },
            )
            .with_path(&socket)
            .with_details(json!(runtime.openvas)),
        );
        let metrics = runtime.openvas.metrics.as_ref();
        let complete = metrics
            .is_some_and(|value| value.dbsize_status == "pass" && value.info_status == "pass");
        let metric_details = metrics.map_or_else(|| json!({}), |value| json!(value));
        findings.push(
            Finding::new(
                if complete { "pass" } else { "warn" },
                "redis-openvas.runtime-metrics",
                if complete {
                    "Scanner Redis metrics were collected without exposing key names or values."
                        .into()
                } else {
                    "Scanner Redis metrics could not be fully collected.".into()
                },
            )
            .with_path(&socket)
            .with_details(metric_details),
        );
    } else {
        findings.push(
            Finding::new(
                "warn",
                "redis-openvas.runtime-ping",
                "Scanner Redis container is not running; runtime ping skipped.".into(),
            )
            .with_path(&socket)
            .with_details(json!(runtime.openvas)),
        );
    }
    make_result(metadata(root, "runtime-redis-state", runner), "Redis dependency and runtime boundary state collected.".into(), findings).with_details(json!({"references": references, "reference_summary": summary, "boundaries": boundaries, "runtime": runtime}))
}
fn candidate(path: &str) -> bool {
    FILES.contains(&path) || ROOTS.iter().any(|prefix| path.starts_with(prefix))
}
fn category(path: &str, text: &str) -> &'static str {
    let text = text.to_lowercase();
    if text.contains("redis-openvas")
        || text.contains("scanner_redis")
        || text.contains("scanner redis")
        || text.contains("/run/redis-openvas")
    {
        "scanner_kb"
    } else if text.contains("hiredis")
        || text.contains("redis-tools")
        || text.contains("redis-server")
        || text.contains("redis:")
    {
        "dependency_build"
    } else if path.starts_with("tools/") {
        "diagnostic_tooling"
    } else if path.starts_with("docs/") || path == "README.md" {
        "documentation"
    } else {
        "generic_runtime"
    }
}
fn references(root: &Path, runner: &dyn CommandRunner) -> Vec<Reference> {
    let mut items = git_tracked_files(runner, root)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|path| {
            if !candidate(&path) {
                return None;
            }
            let text = String::from_utf8_lossy(&std::fs::read(root.join(&path)).ok()?).into_owned();
            let mut markers = PATTERN
                .find_iter(&text)
                .map(|hit| hit.as_str().to_string())
                .collect::<Vec<_>>();
            markers.sort();
            markers.dedup();
            (!markers.is_empty()).then(|| Reference {
                category: category(&path, &text).into(),
                path,
                markers,
            })
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.path.cmp(&right.path))
    });
    items
}
fn summary(references: &[Reference]) -> Summary {
    let by_category = [
        "scanner_kb",
        "generic_runtime",
        "dependency_build",
        "diagnostic_tooling",
        "documentation",
    ]
    .into_iter()
    .map(|category| {
        let paths = references
            .iter()
            .filter(|item| item.category == category)
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();
        (
            category.to_string(),
            Bucket {
                count: paths.len(),
                paths,
            },
        )
    })
    .collect();
    Summary {
        total_items: references.len(),
        by_category,
    }
}
fn boundaries(root: &Path) -> Boundaries {
    let path = root.join("compose/dev.yaml");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    Boundaries {
        compose_file: path
            .strip_prefix(root)
            .map(|item| item.display().to_string())
            .unwrap_or_else(|_| path.display().to_string()),
        generic_redis_service_present: Regex::new(r"(?m)^  redis:\s*$").unwrap().is_match(&text),
        generic_redis_loopback_tcp: text.contains("\"127.0.0.1:16379:6379\""),
        scanner_redis_no_tcp_port: text.contains("--port 0"),
        scanner_redis_unix_socket: text.contains(SOCKET),
        gvmd_depends_on_generic_redis: text.contains("gvmd:")
            && Regex::new(r"(?m)^\s{6}redis:\s*$").unwrap().is_match(&text),
        ospd_depends_on_scanner_redis: text.contains("ospd-openvas:")
            && text.contains("redis-openvas:"),
    }
}
fn socket_path(root: &Path) -> std::path::PathBuf {
    runtime_dir(root).join("run/redis-openvas/redis.sock")
}
fn running(root: &Path, service: &str, runner: &dyn CommandRunner) -> bool {
    let args = compose_command(root, &["ps".into(), "-q".into(), service.into()]);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(id) = runner
        .run_with(
            "docker",
            &args,
            Some(root),
            Some(&runtime_environment(root)),
            None,
        )
        .filter(|out| out.success)
        .and_then(|out| {
            out.stdout
                .lines()
                .next()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
        })
    else {
        return false;
    };
    runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &id],
            Some(root),
            Some(&runtime_environment(root)),
            None,
        )
        .is_some_and(|out| out.success && out.stdout.trim() == "true")
}
fn exec(
    root: &Path,
    service: &str,
    command: &[&str],
    runner: &dyn CommandRunner,
) -> Option<ProcessOutput> {
    let mut args = vec!["exec".into(), "-T".into(), service.into()];
    args.extend(command.iter().map(|value| (*value).into()));
    let args = compose_command(root, &args);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with(
        "docker",
        &args,
        Some(root),
        Some(&runtime_environment(root)),
        None,
    )
}
fn runtime(root: &Path, runner: &dyn CommandRunner) -> Runtime {
    let redis_running = running(root, "redis", runner);
    let scanner_running = running(root, "redis-openvas", runner);
    let mut redis = Service {
        running: redis_running,
        socket: None,
        ping_status: None,
        output_tail: None,
        socket_exists: None,
        metrics: None,
    };
    let mut openvas = Service {
        running: scanner_running,
        socket: Some(socket_path(root).display().to_string()),
        ping_status: None,
        output_tail: None,
        socket_exists: None,
        metrics: None,
    };
    if redis_running && let Some(out) = exec(root, "redis", &["redis-cli", "ping"], runner) {
        redis.ping_status = Some(
            if out.success && out.stdout.contains("PONG") {
                "pass"
            } else {
                "fail"
            }
            .into(),
        );
        redis.output_tail = Some(output_tail(&out.stdout, 20));
    }
    if scanner_running
        && let Some(out) = exec(
            root,
            "redis-openvas",
            &["redis-cli", "-s", SOCKET, "ping"],
            runner,
        )
    {
        let pass = out.success && out.stdout.contains("PONG");
        openvas.ping_status = Some(if pass { "pass" } else { "fail" }.into());
        openvas.output_tail = Some(output_tail(&out.stdout, 20));
        openvas.socket_exists = Some(
            socket_path(root)
                .metadata()
                .is_ok_and(|meta| meta.file_type().is_socket()),
        );
        if pass {
            openvas.metrics = Some(metrics(root, runner));
        }
    }
    Runtime { redis, openvas }
}
fn metrics(root: &Path, runner: &dyn CommandRunner) -> Metrics {
    let dbsize = exec(
        root,
        "redis-openvas",
        &["redis-cli", "-s", SOCKET, "DBSIZE"],
        runner,
    );
    let db_ok = dbsize.as_ref().is_some_and(|out| out.success);
    let info = exec(
        root,
        "redis-openvas",
        &["redis-cli", "-s", SOCKET, "INFO"],
        runner,
    );
    let info_ok = info.as_ref().is_some_and(|out| out.success);
    Metrics {
        dbsize_status: if db_ok { "pass" } else { "fail" }.into(),
        dbsize: dbsize
            .as_ref()
            .and_then(|out| db_ok.then(|| dbsize_value(&out.stdout)).flatten()),
        dbsize_output_tail: (!db_ok).then(|| {
            dbsize
                .as_ref()
                .map(|out| output_tail(&out.stdout, 20))
                .unwrap_or_default()
        }),
        info_status: if info_ok { "pass" } else { "fail" }.into(),
        info_output_tail: (!info_ok).then(|| {
            info.as_ref()
                .map(|out| output_tail(&out.stdout, 20))
                .unwrap_or_default()
        }),
        values: if info_ok {
            info_values(&info.unwrap().stdout)
        } else {
            BTreeMap::new()
        },
    }
}
fn info_values(stdout: &str) -> BTreeMap<String, i64> {
    let keys = [
        "used_memory",
        "used_memory_peak",
        "connected_clients",
        "blocked_clients",
        "total_commands_processed",
        "instantaneous_ops_per_sec",
        "keyspace_hits",
        "keyspace_misses",
    ];
    let mut values = BTreeMap::new();
    let mut total = 0;
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if keys.contains(&key) {
            if let Ok(value) = value.parse() {
                values.insert(key.into(), value);
            }
        } else if key.starts_with("db") {
            for part in value.split(',') {
                if let Some(value) = part
                    .strip_prefix("keys=")
                    .and_then(|item| item.parse::<i64>().ok())
                {
                    total += value;
                }
            }
        }
    }
    if total != 0 {
        values.insert("keyspace_keys".into(), total);
    }
    values
}
fn dbsize_value(stdout: &str) -> Option<i64> {
    stdout.lines().find_map(|line| line.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct RuntimeRunner {
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl CommandRunner for RuntimeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.run_with(program, args, None, None, None)
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _timeout: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|argument| (*argument).to_string()));
            self.calls.borrow_mut().push(call);
            let stdout = if args.ends_with(&["ps", "-q", "redis"]) {
                String::new()
            } else if args.ends_with(&["ps", "-q", "redis-openvas"]) {
                "scanner-container\n".into()
            } else if args == ["inspect", "-f", "{{.State.Running}}", "scanner-container"] {
                "true\n".into()
            } else if args.ends_with(&["redis-cli", "-s", SOCKET, "ping"]) {
                "PONG\n".into()
            } else if args.ends_with(&["redis-cli", "-s", SOCKET, "DBSIZE"]) {
                "12\n".into()
            } else if args.ends_with(&["redis-cli", "-s", SOCKET, "INFO"]) {
                "used_memory:1024\nconnected_clients:2\ndb0:keys=12,expires=0\n".into()
            } else {
                return None;
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn parsers_match_contract_without_key_names() {
        let values = info_values(
            "connected_clients:2\nblocked_clients:0\nused_memory:1024\n\
             used_memory_peak:4096\ntotal_commands_processed:42\n\
             instantaneous_ops_per_sec:3\nkeyspace_hits:10\nkeyspace_misses:1\n\
             ignored_metric:99\ndb0:keys=7,expires=2\ndb2:keys=5,expires=0\n\
             db3:keys=not-a-number\n",
        );
        assert_eq!(values["connected_clients"], 2);
        assert_eq!(values["blocked_clients"], 0);
        assert_eq!(values["used_memory"], 1024);
        assert_eq!(values["used_memory_peak"], 4096);
        assert_eq!(values["total_commands_processed"], 42);
        assert_eq!(values["instantaneous_ops_per_sec"], 3);
        assert_eq!(values["keyspace_hits"], 10);
        assert_eq!(values["keyspace_misses"], 1);
        assert_eq!(values["keyspace_keys"], 12);
        assert!(!values.contains_key("ignored_metric"));
        assert!(!values.contains_key("db0"));
        assert_eq!(dbsize_value("bad\n5\n"), Some(5));
        assert_eq!(dbsize_value("not-an-int\n"), None);
    }

    #[test]
    fn classification_is_exact_and_deterministic() {
        assert_eq!(category("compose/dev.yaml", SOCKET), "scanner_kb");
        assert_eq!(
            category("docker/Dockerfile", "redis-tools"),
            "dependency_build"
        );
        assert!(candidate("tools/turbovasctl"));
        assert!(!candidate("services/api.rs"));
    }

    #[test]
    fn compose_boundaries_match_the_scanner_socket_contract() {
        let root = std::env::temp_dir().join(format!(
            "turbovasctl-redis-boundaries-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("compose")).unwrap();
        std::fs::write(
            root.join("compose/dev.yaml"),
            "services:\n  redis-openvas:\n    command: --port 0 --unixsocket /run/redis-openvas/redis.sock\n  ospd-openvas:\n    depends_on:\n      redis-openvas:\n",
        )
        .unwrap();
        let result = boundaries(&root);
        assert!(!result.generic_redis_service_present);
        assert!(!result.generic_redis_loopback_tcp);
        assert!(!result.gvmd_depends_on_generic_redis);
        assert!(result.scanner_redis_no_tcp_port);
        assert!(result.scanner_redis_unix_socket);
        assert!(result.ospd_depends_on_scanner_redis);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_probe_uses_only_bounded_non_enumerating_redis_commands() {
        let runner = RuntimeRunner::default();
        let state = runtime(Path::new("/srv/TurboVAS"), &runner);
        assert!(!state.redis.running);
        assert!(state.openvas.running);
        let metrics = state.openvas.metrics.unwrap();
        assert_eq!(metrics.dbsize, Some(12));
        assert_eq!(metrics.values["keyspace_keys"], 12);
        assert!(!metrics.values.contains_key("db0"));

        let calls = runner.calls.into_inner();
        let redis_commands = calls
            .iter()
            .filter_map(|call| {
                call.iter()
                    .position(|argument| argument == "redis-cli")
                    .map(|index| call[index + 1..].to_vec())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            redis_commands,
            vec![
                vec!["-s", SOCKET, "ping"],
                vec!["-s", SOCKET, "DBSIZE"],
                vec!["-s", SOCKET, "INFO"],
            ]
        );
    }
}
