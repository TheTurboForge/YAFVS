// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::metadata;
use super::compose::{compose_command, runtime_environment};
use super::secret::{rotate_runtime_secret, runtime_secret_path};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const SECRET_NAME: &str = "native-api-bearer-token";
const CONTAINER_PORT: &str = "9081";

pub fn command_runtime_native_api_direct_token(repo_root: &Path, rotate: bool) -> ResultEnvelope {
    command_runtime_native_api_direct_token_with_runner(repo_root, rotate, &SystemCommandRunner)
}

fn command_runtime_native_api_direct_token_with_runner(
    repo_root: &Path,
    rotate: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let path = runtime_secret_path(repo_root, SECRET_NAME);
    let mut findings = Vec::new();
    if rotate {
        rotate_runtime_secret(repo_root, SECRET_NAME)
            .expect("could not rotate native API bearer token");
        findings.push(
            Finding::new(
                "pass",
                "native-api-direct-token.rotate",
                "Direct native API runtime bearer token was rotated without printing the secret value."
                    .to_string(),
            )
            .with_path(&path.display().to_string()),
        );
    }
    let token = if path.is_file() {
        fs::read_to_string(&path)
            .map(|text| text.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let exists = !token.is_empty();
    let acceptable = exists && bearer_token_is_acceptable(&token);
    let file = secret_file_metadata(&path);
    let permission_ok = file
        .get("permission_ok")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = if exists && acceptable && permission_ok {
        "pass"
    } else if exists && acceptable {
        "fail"
    } else {
        "warn"
    };
    findings.push(
        Finding::new(
            status,
            "native-api-direct-token.runtime-secret",
            if status == "pass" {
                "Direct native API runtime bearer token file exists, satisfies the local strength contract, and is not group/world accessible."
                    .to_string()
            } else {
                "Direct native API runtime bearer token file is missing, weak, or group/world accessible."
                    .to_string()
            },
        )
        .with_path(&path.display().to_string())
        .with_details(json!({
            "exists": exists,
            "acceptable": acceptable,
            "secret_path": path.display().to_string(),
            "mode": file.get("mode").cloned().unwrap_or(Value::Null),
            "permission_ok": permission_ok,
            "group_or_world_accessible": file.get("group_or_world_accessible").and_then(Value::as_bool).unwrap_or(false),
            "token_value_reported": false,
        })),
    );
    if rotate {
        let bindings = current_published_bindings(repo_root, runner);
        findings.push(
            Finding::new(
                if bindings.is_empty() { "pass" } else { "warn" },
                "native-api-direct-token.running-listener-reload",
                if bindings.is_empty() {
                    "No running direct native API listener publication was detected; no live direct listener needs token reload."
                        .to_string()
                } else {
                    "A running direct native API listener is currently published and may still require yafvs-api restart or runtime-native-api-direct-smoke before it accepts the rotated token."
                        .to_string()
                },
            )
            .with_details(json!({
                "published_bindings": bindings,
                "token_value_reported": false,
            })),
        );
        findings.push(Finding::new(
            "pass",
            "native-api-direct-token.reload-required",
            "Restart yafvs-api or rerun runtime-native-api-direct-smoke before expecting any running direct listener to accept the rotated token."
                .to_string(),
        ));
    }
    make_result(
        metadata(repo_root, "runtime-native-api-direct-token", runner),
        if rotate {
            "Direct native API runtime bearer token rotated.".to_string()
        } else {
            "Direct native API runtime bearer token inspected.".to_string()
        },
        findings,
    )
}

fn secret_file_metadata(path: &Path) -> Value {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return json!({
            "exists": false,
            "mode": null,
            "permission_ok": false,
            "group_or_world_accessible": false,
            "regular_file": false,
            "symlink": false,
        });
    };
    let mode = metadata.permissions().mode() & 0o7777;
    let regular_file = metadata.file_type().is_file();
    let symlink = metadata.file_type().is_symlink();
    let group_or_world_accessible = mode & 0o077 != 0;
    json!({
        "exists": true,
        "mode": format!("{mode:04o}"),
        "permission_ok": regular_file && !group_or_world_accessible,
        "group_or_world_accessible": group_or_world_accessible,
        "regular_file": regular_file,
        "symlink": symlink,
    })
}

fn bearer_token_is_acceptable(token: &str) -> bool {
    (32..=1024).contains(&token.chars().count())
        && token.chars().all(|character| {
            character.is_ascii() && !character.is_whitespace() && ('!'..='~').contains(&character)
        })
}

fn current_published_bindings(repo_root: &Path, runner: &dyn CommandRunner) -> Vec<Value> {
    let environment = runtime_environment(repo_root);
    let compose = compose_command(
        repo_root,
        &["ps".to_string(), "-q".to_string(), "yafvs-api".to_string()],
    );
    let compose_args = compose.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(container) = runner
        .run_with(
            "docker",
            &compose_args,
            Some(repo_root),
            Some(&environment),
            None,
        )
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .map(str::to_string)
        })
        .filter(|container| !container.is_empty())
    else {
        return Vec::new();
    };
    let Some(output) = runner
        .run_with(
            "docker",
            &[
                "inspect",
                "-f",
                "{{json .NetworkSettings.Ports}}",
                &container,
            ],
            Some(repo_root),
            Some(&environment),
            None,
        )
        .filter(|output| output.success && !output.stdout.trim().is_empty())
    else {
        return Vec::new();
    };
    let Ok(payload) = serde_json::from_str::<Value>(&output.stdout) else {
        return Vec::new();
    };
    let Some(bindings) = payload
        .get(format!("{CONTAINER_PORT}/tcp"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut published = Vec::new();
    for binding in bindings {
        let Some(binding) = binding.as_object() else {
            continue;
        };
        let host = binding
            .get("HostIp")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0.0")
            .trim();
        let host = if host.is_empty() { "0.0.0.0" } else { host };
        let port = binding
            .get("HostPort")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        if port.is_empty() || !seen.insert((host.to_string(), port.to_string())) {
            continue;
        }
        published.push(json!({
            "host": host,
            "host_port": port,
            "container_port": CONTAINER_PORT,
        }));
    }
    published
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-direct-token-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let repo = root.join("YAFVS");
            fs::create_dir_all(&repo).unwrap();
            Self { root, repo }
        }

        fn token_path(&self) -> PathBuf {
            runtime_secret_path(&self.repo, SECRET_NAME)
        }

        fn write_token(&self, text: &str, mode: u32) {
            let path = self.token_path();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Invocation {
        program: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        environment_present: bool,
        timeout: Option<Duration>,
    }

    #[derive(Default)]
    struct FakeRunner {
        calls: RefCell<Vec<Invocation>>,
        compose: Option<(bool, String)>,
        inspect: Option<(bool, String)>,
    }

    impl FakeRunner {
        fn listener(json: &str) -> Self {
            Self {
                compose: Some((true, "container-123\n".into())),
                inspect: Some((true, json.into())),
                ..Self::default()
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "test-head\n".into(),
                stderr: String::new(),
            })
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            cwd: Option<&Path>,
            environment: Option<&std::collections::BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.borrow_mut().push(Invocation {
                program: program.into(),
                args: args.iter().map(|arg| (*arg).into()).collect(),
                cwd: cwd.map(Path::to_path_buf),
                environment_present: environment.is_some(),
                timeout,
            });
            let response = match args.first().copied() {
                Some("compose") => self.compose.clone(),
                Some("inspect") => self.inspect.clone(),
                _ => None,
            }?;
            Some(ProcessOutput {
                success: response.0,
                exit_code: Some(if response.0 { 0 } else { 1 }),
                stdout: response.1,
                stderr: String::new(),
            })
        }
    }

    fn finding<'a>(result: &'a ResultEnvelope, check: &str) -> &'a Finding {
        result
            .findings
            .iter()
            .find(|finding| finding.check == check)
            .unwrap()
    }

    #[test]
    fn token_contract_accepts_boundaries_and_rejects_unsafe_values() {
        assert!(bearer_token_is_acceptable(&"a".repeat(32)));
        assert!(bearer_token_is_acceptable(&"~".repeat(1024)));
        assert!(!bearer_token_is_acceptable("short"));
        assert!(!bearer_token_is_acceptable(&"a".repeat(1025)));
        assert!(!bearer_token_is_acceptable(&format!("{} ", "a".repeat(32))));
        assert!(!bearer_token_is_acceptable(&format!(
            "{}\n",
            "a".repeat(32)
        )));
        assert!(!bearer_token_is_acceptable(&format!("{}é", "a".repeat(31))));
    }

    #[test]
    fn secret_metadata_never_approves_unsafe_paths() {
        let fixture = Fixture::new();
        assert_eq!(
            secret_file_metadata(&fixture.token_path())["permission_ok"],
            false
        );
        fixture.write_token(&"a".repeat(32), 0o600);
        let private = secret_file_metadata(&fixture.token_path());
        assert_eq!(private["mode"], "0600");
        assert_eq!(private["regular_file"], true);
        assert_eq!(private["permission_ok"], true);
        fixture.write_token(&"a".repeat(32), 0o644);
        let broad = secret_file_metadata(&fixture.token_path());
        assert_eq!(broad["mode"], "0644");
        assert_eq!(broad["permission_ok"], false);
        let directory = fixture.root.join("directory");
        fs::create_dir(&directory).unwrap();
        assert_eq!(secret_file_metadata(&directory)["permission_ok"], false);
        let link = fixture.root.join("link");
        std::os::unix::fs::symlink(fixture.token_path(), &link).unwrap();
        let linked = secret_file_metadata(&link);
        assert_eq!(linked["symlink"], true);
        assert_eq!(linked["permission_ok"], false);
    }

    #[test]
    fn inspection_reports_missing_weak_private_and_broad_tokens_without_disclosure() {
        for (token, mode, status) in [
            (None, 0o600, "warn"),
            (Some("a".repeat(31)), 0o600, "warn"),
            (Some("a".repeat(32)), 0o600, "pass"),
            (Some("b".repeat(32)), 0o644, "fail"),
        ] {
            let fixture = Fixture::new();
            if let Some(token) = &token {
                fixture.write_token(token, mode);
            }
            let result = command_runtime_native_api_direct_token_with_runner(
                &fixture.repo,
                false,
                &FakeRunner::default(),
            );
            let secret = finding(&result, "native-api-direct-token.runtime-secret");
            assert_eq!(secret.status, status);
            assert_eq!(
                secret.details.as_ref().unwrap()["token_value_reported"],
                false
            );
            let output = serde_json::to_string(&result).unwrap();
            if let Some(token) = token {
                assert!(!output.contains(&token));
            }
        }
    }

    #[test]
    fn rotation_replaces_private_value_and_requires_reload_without_listener() {
        let fixture = Fixture::new();
        let old = "old-token-value-that-is-long-enough";
        fixture.write_token(old, 0o600);
        let result = command_runtime_native_api_direct_token_with_runner(
            &fixture.repo,
            true,
            &FakeRunner::default(),
        );
        let new = fs::read_to_string(fixture.token_path())
            .unwrap()
            .trim()
            .to_string();
        assert_ne!(new, old);
        assert!(bearer_token_is_acceptable(&new));
        assert_eq!(
            secret_file_metadata(&fixture.token_path())["permission_ok"],
            true
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            finding(&result, "native-api-direct-token.running-listener-reload").status,
            "pass"
        );
        assert_eq!(
            finding(&result, "native-api-direct-token.reload-required").status,
            "pass"
        );
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains(old));
        assert!(!output.contains(&new));
    }

    #[test]
    fn listener_detection_uses_exact_commands_and_deduplicates_bindings() {
        let fixture = Fixture::new();
        let runner = FakeRunner::listener(
            r#"{"9081/tcp":[{"HostIp":"","HostPort":"19081"},{"HostIp":"0.0.0.0","HostPort":"19081"},{"HostIp":"127.0.0.1","HostPort":"29081"}]}"#,
        );
        assert_eq!(
            current_published_bindings(&fixture.repo, &runner),
            vec![
                json!({"host":"0.0.0.0","host_port":"19081","container_port":"9081"}),
                json!({"host":"127.0.0.1","host_port":"29081","container_port":"9081"}),
            ]
        );
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, "docker");
        assert_eq!(
            calls[0].args,
            vec![
                "compose",
                "-f",
                &fixture.repo.join("compose/dev.yaml").display().to_string(),
                "ps",
                "-q",
                "yafvs-api",
            ]
        );
        assert_eq!(
            calls[1].args,
            vec![
                "inspect",
                "-f",
                "{{json .NetworkSettings.Ports}}",
                "container-123"
            ]
        );
        for call in calls.iter() {
            assert_eq!(call.cwd.as_deref(), Some(fixture.repo.as_path()));
            assert!(call.environment_present);
            assert_eq!(call.timeout, None);
        }
    }

    #[test]
    fn absent_failed_or_invalid_listener_queries_have_no_bindings() {
        for runner in [
            FakeRunner::default(),
            FakeRunner {
                compose: Some((false, "container-123\n".into())),
                ..FakeRunner::default()
            },
            FakeRunner {
                compose: Some((true, "container-123\n".into())),
                inspect: Some((true, "not-json".into())),
                ..FakeRunner::default()
            },
        ] {
            let fixture = Fixture::new();
            assert!(current_published_bindings(&fixture.repo, &runner).is_empty());
        }
    }

    #[test]
    fn rotation_warns_with_deduplicated_listener_bindings_without_token_disclosure() {
        let fixture = Fixture::new();
        let old = "old-token-value-that-is-long-enough";
        fixture.write_token(old, 0o600);
        let runner = FakeRunner::listener(
            r#"{"9081/tcp":[{"HostIp":"127.0.0.1","HostPort":"19081"},{"HostIp":"127.0.0.1","HostPort":"19081"}]}"#,
        );
        let result =
            command_runtime_native_api_direct_token_with_runner(&fixture.repo, true, &runner);
        let listener = finding(&result, "native-api-direct-token.running-listener-reload");
        assert_eq!(listener.status, "warn");
        assert_eq!(
            listener.details.as_ref().unwrap()["published_bindings"],
            json!([{"host":"127.0.0.1","host_port":"19081","container_port":"9081"}])
        );
        assert_eq!(
            listener.details.as_ref().unwrap()["token_value_reported"],
            false
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(old));
    }
}
