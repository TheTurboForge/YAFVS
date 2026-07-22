// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{iso_system_time, metadata, output_tail};
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const STATIC_RELATIVE_PATH: &str = "build/prefix/share/gvm/gsad/web";
const GSA_PRODUCTION_BUILD_PATH: &str = "components/gsa/build";
const GSAD_PORT: &str = "19392";
const EXPECTED_API_SERVER: &str = "apiServer: window.location.host";
const GSA_SOURCE_PATHS: [&str; 7] = [
    "components/gsa/src",
    "components/gsa/public",
    "components/gsa/index.html",
    "components/gsa/package.json",
    "components/gsa/package-lock.json",
    "components/gsa/vite.config.ts",
    "components/gsa/tsconfig.json",
];
const GSA_SKIP_DIRECTORIES: [&str; 6] = [
    "node_modules",
    "build",
    "coverage",
    "dist",
    ".vite",
    ".turbo",
];
const GSA_SKIP_FILE_SUFFIXES: [&str; 12] = [
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
    ".stories.js",
    ".stories.jsx",
    ".stories.ts",
    ".stories.tsx",
];
const GSAD_SOURCE_PATHS: [&str; 1] = ["components/gsad/src/gsad_native_api.c"];
const GSAD_BUILD_PATHS: [&str; 2] = ["build/gsad/src/gsad", "build/prefix/sbin/gsad"];

pub fn command_runtime_webui_smoke(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    let environment = runtime_environment(repo_root);
    command_runtime_webui_smoke_with(repo_root, status_only, &environment, &SystemCommandRunner)
}

fn command_runtime_webui_smoke_with(
    repo_root: &Path,
    status_only: bool,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let static_dir = repo_root.join(STATIC_RELATIVE_PATH);
    let index_path = static_dir.join("index.html");
    let config_path = static_dir.join("config.js");
    let mut findings = vec![
        static_file_finding(
            &index_path,
            "webui.static-index",
            "Staged GSA index.html exists.",
            "Staged GSA index.html is missing; run just build-ui.",
        ),
        static_file_finding(
            &config_path,
            "webui.static-config",
            "Staged GSA config.js exists.",
            "Staged GSA config.js is missing; run just build-ui.",
        ),
    ];
    findings.extend(runtime_gsa_freshness_findings(
        repo_root,
        &static_dir,
        environment,
        runner,
    ));

    let index_text = fs::read_to_string(&index_path).unwrap_or_default();
    let asset_relative = first_gsa_asset_relative(&index_text);
    findings.push(
        Finding::new(
            if asset_relative.is_some() {
                "pass"
            } else {
                "fail"
            },
            "webui.static-asset-ref",
            asset_relative
                .as_ref()
                .map(|asset| format!("Found GSA asset reference {asset}."))
                .unwrap_or_else(|| "No GSA asset reference found in index.html.".to_string()),
        )
        .with_path(&index_path.display().to_string()),
    );

    let base_urls = gsad_base_urls(environment);
    for base_url in &base_urls {
        let index_url = format!("{base_url}/");
        let index_output = curl_probe(
            repo_root,
            environment,
            runner,
            &["-kfsS", "--max-time", "10", &index_url],
        );
        let index_exit_code = process_exit_code(&index_output);
        findings.push(
            Finding::new(
                if index_exit_code == 0 && index_output.stdout.contains("<div id=\"app\">") {
                    "pass"
                } else {
                    "fail"
                },
                "webui.http-index",
                format!("GSA index HTTP probe exit code {index_exit_code}."),
            )
            .with_details(json!({
                "url": index_url,
                "output_tail": output_tail(&index_output.stdout, 40),
            })),
        );

        let config_url = format!("{base_url}/config.js");
        let config_output = curl_probe(
            repo_root,
            environment,
            runner,
            &["-kfsS", "--max-time", "10", &config_url],
        );
        let config_exit_code = process_exit_code(&config_output);
        findings.push(
            Finding::new(
                if config_exit_code == 0 && config_output.stdout.contains(EXPECTED_API_SERVER) {
                    "pass"
                } else {
                    "fail"
                },
                "webui.http-config",
                format!("GSA config.js HTTP probe exit code {config_exit_code}."),
            )
            .with_details(json!({
                "url": config_url,
                "expected": EXPECTED_API_SERVER,
                "output_tail": output_tail(&config_output.stdout, 40),
            })),
        );

        if let Some(asset_relative) = &asset_relative {
            let asset_url = format!("{base_url}/{asset_relative}");
            let asset_output = curl_probe(
                repo_root,
                environment,
                runner,
                &["-kfsS", "--max-time", "10", "-o", "/dev/null", &asset_url],
            );
            let asset_exit_code = process_exit_code(&asset_output);
            findings.push(
                Finding::new(
                    if asset_exit_code == 0 { "pass" } else { "fail" },
                    "webui.http-asset",
                    format!("GSA asset HTTP probe exit code {asset_exit_code}."),
                )
                .with_details(json!({
                    "url": asset_url,
                    "output_tail": output_tail(&asset_output.stdout, 40),
                })),
            );
        }
    }

    let artifacts = std::iter::once(static_dir.display().to_string())
        .chain(base_urls)
        .collect();
    let result = make_result(
        metadata(repo_root, "runtime-webui-smoke", runner),
        "Runtime web UI smoke checks completed.".to_string(),
        findings,
    )
    .with_artifacts(artifacts);
    if status_only {
        runtime_webui_smoke_status_only_result(result)
    } else {
        result
    }
}

fn static_file_finding(
    path: &Path,
    check: &str,
    present_message: &str,
    missing_message: &str,
) -> Finding {
    Finding::new(
        if path.is_file() { "pass" } else { "fail" },
        check,
        if path.is_file() {
            present_message.to_string()
        } else {
            missing_message.to_string()
        },
    )
    .with_path(&path.display().to_string())
}

fn curl_probe(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
    arguments: &[&str],
) -> ProcessOutput {
    runner
        .run_with("curl", arguments, Some(repo_root), Some(environment), None)
        .unwrap_or_else(missing_process_output)
}

fn missing_process_output() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn process_exit_code(output: &ProcessOutput) -> i32 {
    output.exit_code.unwrap_or(1)
}

fn first_gsa_asset_relative(index_html: &str) -> Option<String> {
    Regex::new(r#"(?:src|href)=["']/(assets/[^"']+)["']"#)
        .ok()?
        .captures(index_html)?
        .get(1)
        .map(|matched| matched.as_str().to_string())
}

fn gsad_base_urls(environment: &BTreeMap<OsString, OsString>) -> Vec<String> {
    gsad_hosts(environment)
        .into_iter()
        .map(|host| format!("https://{host}:{GSAD_PORT}"))
        .collect()
}

fn gsad_hosts(environment: &BTreeMap<OsString, OsString>) -> Vec<String> {
    let plural = environment
        .get(&OsString::from("YAFVS_GSAD_HOSTS"))
        .and_then(|value| value.to_str());
    let plural_hosts = split_gsad_hosts(plural);
    if !plural_hosts.is_empty() {
        return plural_hosts;
    }
    let singular = environment
        .get(&OsString::from("YAFVS_GSAD_HOST"))
        .and_then(|value| value.to_str());
    let singular_hosts = split_gsad_hosts(singular);
    if singular_hosts.is_empty() {
        vec!["127.0.0.1".to_string()]
    } else {
        singular_hosts
    }
}

fn split_gsad_hosts(value: Option<&str>) -> Vec<String> {
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

fn runtime_gsa_freshness_findings(
    repo_root: &Path,
    static_dir: &Path,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let staged_latest = path_latest_mtime(static_dir, false);
    findings.push(gsa_build_freshness_finding(repo_root));

    let container_state = docker_container_state(repo_root, "gsad", environment, runner);
    let started_at = container_state
        .as_ref()
        .and_then(|state| state.get("StartedAt"))
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_system_time);
    let gsad_source_latest = paths_latest_mtime(repo_root, &GSAD_SOURCE_PATHS, false);
    let gsad_build_latest = paths_latest_mtime(repo_root, &GSAD_BUILD_PATHS, false);
    let compare_latest = [
        staged_latest,
        gsad_source_latest.map(|(time, _)| time),
        gsad_build_latest.map(|(time, _)| time),
    ]
    .into_iter()
    .flatten()
    .max();

    if let (Some(started_at), Some(compare_latest)) = (started_at, compare_latest)
        && compare_latest > started_at
    {
        findings.push(
            Finding::new(
                "warn",
                "gsad.runtime-freshness",
                "Running gsad predates relevant static or native-proxy build inputs; run just build-c-services, just build-ui, then refresh runtime-app-up before browser validation."
                    .to_string(),
            )
            .with_details(json!({
                "container_id": container_state
                    .as_ref()
                    .and_then(|state| state.get("container_id")),
                "started_at": container_state
                    .as_ref()
                    .and_then(|state| state.get("StartedAt")),
                "latest_gsad_source_path": gsad_source_latest.map(|(_, path)| path),
                "latest_gsad_source_mtime": gsad_source_latest
                    .and_then(|(time, _)| iso_system_time(time)),
                "latest_gsad_build_path": gsad_build_latest.map(|(_, path)| path),
                "latest_gsad_build_mtime": gsad_build_latest
                    .and_then(|(time, _)| iso_system_time(time)),
                "latest_staged_mtime": staged_latest.and_then(iso_system_time),
            })),
        );
    } else if started_at.is_some() {
        findings.push(
            Finding::new(
                "pass",
                "gsad.runtime-freshness",
                "Running gsad is not older than relevant static or native-proxy build inputs."
                    .to_string(),
            )
            .with_details(json!({
                "started_at": container_state
                    .as_ref()
                    .and_then(|state| state.get("StartedAt")),
            })),
        );
    }
    findings
}

pub(crate) fn gsa_build_freshness_finding(repo_root: &Path) -> Finding {
    let source_latest = paths_latest_mtime(repo_root, &GSA_SOURCE_PATHS, true);
    let build_path = repo_root.join(GSA_PRODUCTION_BUILD_PATH);
    let build_latest = path_latest_mtime(&build_path, false);
    match (source_latest, build_latest) {
        (Some((source_time, source_path)), Some(build_time)) if source_time > build_time => {
            Finding::new(
                "warn",
                "gsa.static-freshness",
                "GSA production assets are older than tracked source inputs; run just build-ui before deployment or browser validation."
                    .to_string(),
            )
            .with_path(&build_path.display().to_string())
            .with_details(json!({
                "latest_source_path": source_path,
                "latest_source_mtime": iso_system_time(source_time),
                "latest_build_path": GSA_PRODUCTION_BUILD_PATH,
                "latest_build_mtime": iso_system_time(build_time),
            }))
        }
        (Some((source_time, _)), Some(build_time)) => Finding::new(
            "pass",
            "gsa.static-freshness",
            "GSA production assets are not older than tracked source inputs.".to_string(),
        )
        .with_path(&build_path.display().to_string())
        .with_details(json!({
            "latest_source_mtime": iso_system_time(source_time),
            "latest_build_mtime": iso_system_time(build_time),
        })),
        (None, Some(build_time)) => Finding::new(
            "pass",
            "gsa.static-freshness",
            "GSA production assets exist and no tracked production source input was found."
                .to_string(),
        )
        .with_path(&build_path.display().to_string())
        .with_details(json!({
            "latest_source_mtime": Value::Null,
            "latest_build_mtime": iso_system_time(build_time),
        })),
        (_, None) => Finding::new(
            "warn",
            "gsa.static-freshness",
            "GSA production assets are missing; run just build-ui before deployment or browser validation."
                .to_string(),
        )
        .with_path(&build_path.display().to_string()),
    }
}

fn paths_latest_mtime<'a>(
    repo_root: &Path,
    relative_paths: &'a [&'a str],
    filter_gsa_sources: bool,
) -> Option<(SystemTime, &'a str)> {
    let mut latest = None;
    for relative_path in relative_paths {
        let Some(time) = path_latest_mtime(&repo_root.join(relative_path), filter_gsa_sources)
        else {
            continue;
        };
        if latest.is_none_or(|(latest_time, _)| time > latest_time) {
            latest = Some((time, *relative_path));
        }
    }
    latest
}

fn path_latest_mtime(path: &Path, filter_gsa_sources: bool) -> Option<SystemTime> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.is_file() {
        return (!filter_gsa_sources || !gsa_source_file_skipped(path))
            .then(|| metadata.modified().ok())
            .flatten();
    }
    if !metadata.is_dir() {
        return None;
    }
    directory_latest_mtime(path, filter_gsa_sources)
}

fn directory_latest_mtime(path: &Path, filter_gsa_sources: bool) -> Option<SystemTime> {
    let mut latest = None;
    let entries = fs::read_dir(path).ok()?;
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if filter_gsa_sources && gsa_source_directory_skipped(&child) {
                continue;
            }
            if let Some(time) = directory_latest_mtime(&child, filter_gsa_sources)
                && latest.is_none_or(|current| time > current)
            {
                latest = Some(time);
            }
            continue;
        }
        if file_type.is_symlink() && fs::metadata(&child).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }
        if filter_gsa_sources && gsa_source_file_skipped(&child) {
            continue;
        }
        if let Ok(time) = fs::metadata(&child).and_then(|metadata| metadata.modified())
            && latest.is_none_or(|current| time > current)
        {
            latest = Some(time);
        }
    }
    latest
}

fn gsa_source_directory_skipped(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| GSA_SKIP_DIRECTORIES.contains(&name))
}

fn gsa_source_file_skipped(path: &Path) -> bool {
    if path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| matches!(part, "__tests__" | "__mocks__"))
    }) {
        return true;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            GSA_SKIP_FILE_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix))
        })
}

fn docker_container_state(
    repo_root: &Path,
    service: &str,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> Option<Value> {
    let ps_arguments = compose_command(
        repo_root,
        &["ps".to_string(), "-q".to_string(), service.to_string()],
    );
    let ps_refs = ps_arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let ps = runner.run_with("docker", &ps_refs, Some(repo_root), Some(environment), None)?;
    if process_exit_code(&ps) != 0 || ps.stdout.trim().is_empty() {
        return None;
    }
    let container_id = ps.stdout.trim().lines().next()?.to_string();
    let inspect = runner.run_with(
        "docker",
        &["inspect", "--format", "{{json .State}}", &container_id],
        Some(repo_root),
        Some(environment),
        None,
    );
    let Some(inspect) = inspect else {
        return Some(json!({
            "container_id": container_id,
            "inspect_error": [],
        }));
    };
    if process_exit_code(&inspect) != 0 {
        return Some(json!({
            "container_id": container_id,
            "inspect_error": output_tail(&inspect.stdout, 40),
        }));
    }
    let last_line = inspect.stdout.trim().lines().last().unwrap_or_default();
    let mut state = serde_json::from_str::<Value>(last_line).unwrap_or_else(|_| {
        json!({
            "inspect_output": output_tail(&inspect.stdout, 40),
        })
    });
    if let Some(object) = state.as_object_mut() {
        object.insert("container_id".to_string(), Value::String(container_id));
        Some(state)
    } else {
        Some(json!({
            "container_id": container_id,
            "inspect_output": output_tail(&inspect.stdout, 40),
        }))
    }
}

fn parse_rfc3339_system_time(value: &str) -> Option<SystemTime> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let total_nanoseconds = parsed.unix_timestamp_nanos();
    let magnitude = total_nanoseconds.unsigned_abs();
    let duration = Duration::new(
        u64::try_from(magnitude / 1_000_000_000).ok()?,
        u32::try_from(magnitude % 1_000_000_000).ok()?,
    );
    if total_nanoseconds >= 0 {
        UNIX_EPOCH.checked_add(duration)
    } else {
        UNIX_EPOCH.checked_sub(duration)
    }
}

fn runtime_webui_smoke_status_only_result(mut result: ResultEnvelope) -> ResultEnvelope {
    let finding_count = result.findings.len();
    let artifact_count = result.artifacts.len();
    let mut checks = Map::new();
    let mut authorities = BTreeSet::new();
    for finding in &result.findings {
        checks.insert(finding.check.clone(), Value::String(finding.status.clone()));
        if !finding.check.starts_with("webui.http-") {
            continue;
        }
        if let Some(url) = finding
            .details
            .as_ref()
            .and_then(|details| details.get("url"))
            .and_then(Value::as_str)
            && url.starts_with("http")
            && let Some(authority) = url.split('/').nth(2)
        {
            authorities.insert(authority.to_string());
        }
    }
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_webui_finding)
        .collect::<Vec<_>>();
    let non_pass_count = non_pass.len();
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "runtime-webui-smoke.status-only",
            "Runtime web UI smoke passed with compact status-only output.".to_string(),
        ));
    }
    result.details = Some(json!({
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
        "artifact_count": artifact_count,
        "base_url_count": authorities.len(),
        "checks": checks,
    }));
    result.findings = non_pass;
    result
}

fn compact_webui_finding(finding: &Finding) -> Finding {
    let mut compact = Finding::new(&finding.status, &finding.check, finding.message.clone());
    if let Some(path) = &finding.path
        && !path.is_empty()
    {
        compact.path = Some(path.clone());
    }
    let Some(Value::Object(details)) = &finding.details else {
        return compact;
    };
    let mut compact_details = Map::new();
    for (key, value) in details {
        if key == "output_tail" {
            continue;
        }
        let value = match value {
            Value::Array(items) => json!({"type": "list", "count": items.len()}),
            Value::Object(items) => json!({"type": "object", "key_count": items.len()}),
            scalar => scalar.clone(),
        };
        compact_details.insert(key.clone(), value);
    }
    if !compact_details.is_empty() {
        compact.details = Some(Value::Object(compact_details));
    }
    compact
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug)]
    struct Call {
        program: String,
        arguments: Vec<String>,
        cwd: Option<PathBuf>,
        environment: Option<BTreeMap<OsString, OsString>>,
        timeout: Option<Duration>,
    }

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<Call>>,
        outputs: Mutex<VecDeque<Option<ProcessOutput>>>,
    }

    impl RecordingRunner {
        fn with_outputs(outputs: Vec<Option<ProcessOutput>>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs.into()),
            }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            arguments: &[&str],
            cwd: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(Call {
                program: program.to_string(),
                arguments: arguments
                    .iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
                cwd: cwd.map(Path::to_path_buf),
                environment: environment.cloned(),
                timeout,
            });
            self.outputs.lock().unwrap().pop_front().flatten()
        }
    }

    fn output(exit_code: i32, stdout: &str) -> Option<ProcessOutput> {
        Some(ProcessOutput {
            success: exit_code == 0,
            exit_code: Some(exit_code),
            stdout: stdout.to_string(),
            stderr: String::new(),
        })
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-webui-{}-{}-{name}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn environment(hosts: Option<&str>, host: Option<&str>) -> BTreeMap<OsString, OsString> {
        let mut environment = BTreeMap::new();
        if let Some(hosts) = hosts {
            environment.insert(OsString::from("YAFVS_GSAD_HOSTS"), OsString::from(hosts));
        }
        if let Some(host) = host {
            environment.insert(OsString::from("YAFVS_GSAD_HOST"), OsString::from(host));
        }
        environment.insert(OsString::from("SENTINEL"), OsString::from("yes"));
        environment
    }

    fn stage_static(repo: &Path, index: &str) -> PathBuf {
        let static_dir = repo.join(STATIC_RELATIVE_PATH);
        fs::create_dir_all(static_dir.join("assets")).unwrap();
        fs::write(static_dir.join("index.html"), index).unwrap();
        fs::write(static_dir.join("config.js"), "config = {};\n").unwrap();
        static_dir
    }

    #[test]
    fn hosts_prefer_plural_trim_deduplicate_and_default() {
        assert_eq!(
            gsad_base_urls(&environment(Some(" beta, , alpha,beta "), Some("ignored"),)),
            ["https://beta:19392", "https://alpha:19392"],
        );
        assert_eq!(
            gsad_base_urls(&environment(Some(" , "), Some(" single "))),
            ["https://single:19392"],
        );
        assert_eq!(
            gsad_base_urls(&environment(None, None)),
            ["https://127.0.0.1:19392"],
        );
    }

    #[test]
    fn extracts_only_the_first_root_relative_asset_reference() {
        assert_eq!(
            first_gsa_asset_relative(
                r#"<link href="/assets/first.css"><script src='/assets/second.js'>"#,
            ),
            Some("assets/first.css".to_string()),
        );
        assert_eq!(
            first_gsa_asset_relative(r#"<script src="assets/no-leading-slash.js">"#),
            None,
        );
    }

    #[test]
    fn mixed_probes_preserve_exact_contract_and_invocation_shape() {
        let (root, repo) = fixture("mixed");
        let static_dir = stage_static(
            &repo,
            r#"<script src="/assets/app.js"></script><div id="app"></div>"#,
        );
        let environment = environment(Some("127.0.0.1,example.test"), None);
        let runner = RecordingRunner::with_outputs(vec![
            output(0, ""),
            output(0, "<div id=\"app\">one</div>\n"),
            output(0, "apiServer: window.location.host\n"),
            output(0, ""),
            output(22, "index two\n"),
            output(7, "config two\n"),
            output(6, "asset two\n"),
        ]);

        let result = command_runtime_webui_smoke_with(&repo, false, &environment, &runner);

        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "Runtime web UI smoke checks completed.");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            [
                "webui.static-index",
                "webui.static-config",
                "gsa.static-freshness",
                "webui.static-asset-ref",
                "webui.http-index",
                "webui.http-config",
                "webui.http-asset",
                "webui.http-index",
                "webui.http-config",
                "webui.http-asset",
            ],
        );
        assert_eq!(
            result.artifacts,
            [
                static_dir.display().to_string(),
                "https://127.0.0.1:19392".to_string(),
                "https://example.test:19392".to_string(),
            ],
        );
        assert_eq!(
            result.findings[4].message,
            "GSA index HTTP probe exit code 0."
        );
        assert_eq!(
            result.findings[8].message,
            "GSA config.js HTTP probe exit code 7.",
        );
        assert_eq!(
            result.findings[8].details.as_ref().unwrap()["expected"],
            EXPECTED_API_SERVER,
        );
        assert_eq!(
            result.findings[9].details.as_ref().unwrap()["output_tail"],
            json!(["asset two"]),
        );

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 7);
        assert_eq!(calls[0].program, "docker");
        assert_eq!(
            calls[0].arguments,
            [
                "compose",
                "-f",
                &repo.join("compose/dev.yaml").display().to_string(),
                "ps",
                "-q",
                "gsad",
            ],
        );
        assert_eq!(
            calls[1].arguments,
            ["-kfsS", "--max-time", "10", "https://127.0.0.1:19392/",],
        );
        assert_eq!(
            calls[3].arguments,
            [
                "-kfsS",
                "--max-time",
                "10",
                "-o",
                "/dev/null",
                "https://127.0.0.1:19392/assets/app.js",
            ],
        );
        assert!(
            calls
                .iter()
                .all(|call| call.cwd.as_deref() == Some(repo.as_path())),
        );
        assert!(calls.iter().all(|call| call.timeout.is_none()));
        assert!(calls.iter().all(|call| {
            call.environment
                .as_ref()
                .and_then(|env| env.get(&OsString::from("SENTINEL")))
                == Some(&OsString::from("yes"))
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_static_files_still_probe_index_and_config_without_asset() {
        let (root, repo) = fixture("missing");
        let environment = environment(None, None);
        let runner = RecordingRunner::with_outputs(vec![output(0, ""), None, None]);

        let result = command_runtime_webui_smoke_with(&repo, false, &environment, &runner);

        assert_eq!(result.status, "fail");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            [
                "webui.static-index",
                "webui.static-config",
                "gsa.static-freshness",
                "webui.static-asset-ref",
                "webui.http-index",
                "webui.http-config",
            ],
        );
        assert_eq!(
            result.findings[4].message,
            "GSA index HTTP probe exit code 1.",
        );
        assert_eq!(
            result.findings[5].message,
            "GSA config.js HTTP probe exit code 1.",
        );
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(
            calls
                .iter()
                .all(|call| !call.arguments.iter().any(|argument| argument == "-o")),
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compact_mode_keeps_only_non_pass_signal_and_removes_output_tails() {
        let repo = Path::new("/tmp/YAFVS");
        let findings = vec![
            Finding::new("pass", "webui.static-index", "index".to_string()),
            Finding::new("pass", "webui.http-index", "index http".to_string()).with_details(
                json!({
                    "url": "https://one/",
                    "output_tail": ["large"],
                }),
            ),
            Finding::new("warn", "webui.http-config", "config warning".to_string()).with_details(
                json!({
                    "url": "https://two/config.js",
                    "output_tail": ["large"],
                }),
            ),
        ];
        let result = make_result(
            metadata(repo, "runtime-webui-smoke", &RecordingRunner::default()),
            "Runtime web UI smoke checks completed.".to_string(),
            findings,
        )
        .with_artifacts(vec![
            "/tmp/static".to_string(),
            "https://one".to_string(),
            "https://two".to_string(),
        ]);

        let compact = runtime_webui_smoke_status_only_result(result);

        assert_eq!(compact.status, "warn");
        assert_eq!(compact.details.as_ref().unwrap()["finding_count"], 3);
        assert_eq!(compact.details.as_ref().unwrap()["non_pass_count"], 1);
        assert_eq!(compact.details.as_ref().unwrap()["artifact_count"], 3);
        assert_eq!(compact.details.as_ref().unwrap()["base_url_count"], 2);
        assert_eq!(compact.findings[0].check, "webui.http-config");
        assert!(
            !serde_json::to_string(&compact.findings)
                .unwrap()
                .contains("output_tail"),
        );
    }

    #[test]
    fn compact_mode_replaces_all_pass_findings_with_one_summary_finding() {
        let repo = Path::new("/tmp/YAFVS");
        let result = make_result(
            metadata(repo, "runtime-webui-smoke", &RecordingRunner::default()),
            "Runtime web UI smoke checks completed.".to_string(),
            vec![Finding::new(
                "pass",
                "webui.static-index",
                "index".to_string(),
            )],
        );

        let compact = runtime_webui_smoke_status_only_result(result);

        assert_eq!(compact.findings.len(), 1);
        assert_eq!(compact.findings[0].check, "runtime-webui-smoke.status-only",);
        assert_eq!(compact.details.as_ref().unwrap()["non_pass_count"], 0);
    }

    #[test]
    fn compact_checks_match_python_last_status_wins_without_hiding_non_pass_findings() {
        let result = make_result(
            metadata(
                Path::new("/tmp/YAFVS"),
                "runtime-webui-smoke",
                &RecordingRunner::default(),
            ),
            "Runtime web UI smoke checks completed.".to_string(),
            vec![
                Finding::new("fail", "webui.http-index", "first host failed".to_string())
                    .with_details(json!({"url": "https://one/"})),
                Finding::new("pass", "webui.http-index", "second host passed".to_string())
                    .with_details(json!({"url": "https://two/"})),
            ],
        );

        let compact = runtime_webui_smoke_status_only_result(result);

        assert_eq!(
            compact.details.as_ref().unwrap()["checks"]["webui.http-index"],
            "pass",
        );
        assert_eq!(compact.findings.len(), 1);
        assert_eq!(compact.findings[0].status, "fail");
        assert_eq!(compact.findings[0].message, "first host failed");
    }

    #[test]
    fn rfc3339_parser_accepts_offsets_and_pre_epoch_docker_timestamps() {
        assert_eq!(
            parse_rfc3339_system_time("2026-07-19T08:00:00+02:00"),
            parse_rfc3339_system_time("2026-07-19T06:00:00Z"),
        );
        assert!(parse_rfc3339_system_time("0001-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339_system_time("not-a-timestamp").is_none());
    }

    #[test]
    fn static_freshness_warns_for_new_source_and_skips_tests_and_build_trees() {
        let (root, repo) = fixture("static-freshness");
        let static_dir = stage_static(&repo, r#"<script src="/assets/app.js"></script>"#);
        let production_build = repo.join(GSA_PRODUCTION_BUILD_PATH);
        fs::create_dir_all(production_build.join("assets")).unwrap();
        fs::write(production_build.join("index.html"), "built\n").unwrap();
        thread::sleep(Duration::from_millis(20));
        let source = repo.join("components/gsa/src");
        fs::create_dir_all(source.join("__tests__")).unwrap();
        fs::create_dir_all(source.join("node_modules/pkg")).unwrap();
        let outside = root.join("outside-source");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("ignored.ts"), "ignored\n").unwrap();
        symlink(&outside, source.join("linked-directory")).unwrap();
        fs::write(source.join("__tests__/ignored.ts"), "ignored\n").unwrap();
        fs::write(source.join("node_modules/pkg/ignored.js"), "ignored\n").unwrap();
        let runner = RecordingRunner::with_outputs(vec![output(0, "")]);
        let environment = environment(None, None);

        let skipped = runtime_gsa_freshness_findings(&repo, &static_dir, &environment, &runner);
        assert_eq!(skipped[0].status, "pass");
        assert_eq!(
            skipped[0].details.as_ref().unwrap()["latest_source_mtime"],
            Value::Null,
        );

        thread::sleep(Duration::from_millis(20));
        fs::write(source.join("newer.ts"), "newer\n").unwrap();
        let runner = RecordingRunner::with_outputs(vec![output(0, "")]);
        let stale = runtime_gsa_freshness_findings(&repo, &static_dir, &environment, &runner);
        assert_eq!(stale[0].status, "warn");
        assert_eq!(
            stale[0].details.as_ref().unwrap()["latest_source_path"],
            "components/gsa/src",
        );
        assert_eq!(
            stale[0].details.as_ref().unwrap()["latest_build_path"],
            GSA_PRODUCTION_BUILD_PATH,
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gsad_runtime_freshness_compares_started_at_with_native_inputs() {
        let (root, repo) = fixture("gsad-freshness");
        let source = repo.join(GSAD_SOURCE_PATHS[0]);
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, "source\n").unwrap();
        let environment = environment(None, None);
        let stale_runner = RecordingRunner::with_outputs(vec![
            output(0, "container-id\n"),
            output(
                0,
                "{\"Running\":true,\"StartedAt\":\"2000-01-01T00:00:00Z\"}\n",
            ),
        ]);

        let stale = runtime_gsa_freshness_findings(
            &repo,
            &repo.join(STATIC_RELATIVE_PATH),
            &environment,
            &stale_runner,
        );

        let stale = stale
            .iter()
            .find(|finding| finding.check == "gsad.runtime-freshness")
            .unwrap();
        assert_eq!(stale.status, "warn");
        assert_eq!(
            stale.details.as_ref().unwrap()["container_id"],
            "container-id",
        );
        assert_eq!(
            stale.details.as_ref().unwrap()["latest_gsad_source_path"],
            GSAD_SOURCE_PATHS[0],
        );

        let fresh_runner = RecordingRunner::with_outputs(vec![
            output(0, "container-id\n"),
            output(
                0,
                "{\"Running\":true,\"StartedAt\":\"2099-01-01T00:00:00Z\"}\n",
            ),
        ]);
        let fresh = runtime_gsa_freshness_findings(
            &repo,
            &repo.join(STATIC_RELATIVE_PATH),
            &environment,
            &fresh_runner,
        );
        let fresh = fresh
            .iter()
            .find(|finding| finding.check == "gsad.runtime-freshness")
            .unwrap();
        assert_eq!(fresh.status, "pass");
        assert_eq!(
            fresh.details.as_ref().unwrap()["started_at"],
            "2099-01-01T00:00:00Z",
        );
        let calls = fresh_runner.calls.lock().unwrap();
        assert_eq!(calls[1].program, "docker");
        assert_eq!(
            calls[1].arguments,
            ["inspect", "--format", "{{json .State}}", "container-id",],
        );
        fs::remove_dir_all(root).unwrap();
    }
}
