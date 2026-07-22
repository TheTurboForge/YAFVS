// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pinned application-image and rendered Compose execution identity.

use super::canonical_json::to_ascii_compact;
use super::deployment::{APP_SERVICES, validate_app_compose_contract};
use crate::commands::common::runtime_dir;
use crate::commands::compose::compose_command_with_environment_and_files;
use crate::commands::secret::write_private_text;
use crate::process::CommandRunner;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

const OVERRIDE_PATH: &str = "state/feed-generation/app-images.json";

pub(super) fn write_image_override(
    repo_root: &Path,
    image_ids: &BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    exact_image_services(image_ids)?;
    let services = APP_SERVICES
        .iter()
        .map(|service| {
            (
                (*service).to_owned(),
                json!({"image": image_ids.get(*service).expect("validated service")}),
            )
        })
        .collect::<Map<_, _>>();
    let mut text = serde_json::to_string_pretty(&json!({"services": services}))
        .map_err(|_| "pinned application image override serialization failed".to_owned())?;
    text.push('\n');
    let path = runtime_dir(repo_root).join(OVERRIDE_PATH);
    write_private_text(&path, &text)
        .map_err(|_| "pinned application image override write failed".to_owned())?;
    Ok(path)
}

pub(super) fn pinned_compose_command(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    image_ids: &BTreeMap<String, String>,
    arguments: &[String],
) -> Result<Vec<String>, String> {
    let override_path = write_image_override(repo_root, image_ids)?;
    compose_command_with_environment_and_files(repo_root, environment, &[&override_path], arguments)
        .map_err(|error| format!("runtime Compose override generation failed: {error}"))
}

pub(super) fn unavailable_images(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    image_ids: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    exact_image_services(image_ids)?;
    let mut unavailable = Vec::new();
    for service in APP_SERVICES {
        let expected = image_ids.get(service).expect("validated service");
        let output = runner.run_with(
            "docker",
            &["image", "inspect", "--format", "{{.Id}}", expected],
            Some(repo_root),
            Some(environment),
            Some(Duration::from_secs(120)),
        );
        let observed = output
            .as_ref()
            .filter(|output| output.success)
            .and_then(|output| output.stdout.lines().next_back())
            .map(str::trim)
            .unwrap_or_default();
        if observed != expected {
            unavailable.push(service.to_owned());
        }
    }
    Ok(unavailable)
}

pub(super) fn compose_contract_manifest(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    image_ids: &BTreeMap<String, String>,
) -> Result<Value, String> {
    let command = pinned_compose_command(
        repo_root,
        environment,
        image_ids,
        &[
            "--profile".to_owned(),
            "app".to_owned(),
            "config".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ],
    )?;
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    let output = runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(environment),
            Some(Duration::from_secs(120)),
        )
        .ok_or_else(|| "rendered application Compose contract could not be started".to_owned())?;
    if !output.success {
        return Err("rendered application Compose contract is unavailable".into());
    }
    let config: Value = serde_json::from_str(&output.stdout)
        .map_err(|_| "rendered application Compose contract is not valid JSON".to_owned())?;
    let services = config
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| "rendered application Compose services are incomplete".to_owned())?;
    let mut normalized_services = Map::new();
    for service in APP_SERVICES {
        let mut normalized = services
            .get(service)
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| "rendered application Compose services are incomplete".to_owned())?;
        if let Some(ports) = normalized.get_mut("ports").and_then(Value::as_array_mut) {
            let mut keyed = ports
                .drain(..)
                .map(|port| to_ascii_compact(&port).map(|key| (key, port)))
                .collect::<Result<Vec<_>, _>>()?;
            keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
            ports.extend(keyed.into_iter().map(|(_, port)| port));
        }
        normalized_services.insert(service.to_owned(), Value::Object(normalized));
    }
    let contract = json!({
        "services": normalized_services,
        "networks": config.get("networks").cloned().unwrap_or_else(|| json!({})),
        "volumes": config.get("volumes").cloned().unwrap_or_else(|| json!({})),
        "secrets": config.get("secrets").cloned().unwrap_or_else(|| json!({})),
        "configs": config.get("configs").cloned().unwrap_or_else(|| json!({})),
    });
    let digest = hex_sha256(&to_ascii_compact(&contract)?);
    let manifest = json!({
        "schema_version": 1,
        "algorithm": "sha256",
        "digest": digest,
        "services": APP_SERVICES,
    });
    validate_app_compose_contract(&manifest)?;
    Ok(manifest)
}

fn exact_image_services(image_ids: &BTreeMap<String, String>) -> Result<(), String> {
    let observed = image_ids
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = APP_SERVICES.into_iter().collect::<BTreeSet<_>>();
    if observed == expected
        && image_ids.values().all(|image| {
            image.len() == 71
                && image.starts_with("sha256:")
                && image[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        Ok(())
    } else {
        Err("feed activation app image identities are incomplete".into())
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

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
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            unreachable!("identity helpers use run_with")
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            assert_eq!(timeout, Some(Duration::from_secs(120)));
            let mut command = vec![program.to_owned()];
            command.extend(args.iter().map(|argument| (*argument).to_owned()));
            self.commands.lock().unwrap().push(command);
            self.outputs.lock().unwrap().pop_front().flatten()
        }
    }

    fn output(success: bool, stdout: impl Into<String>) -> Option<ProcessOutput> {
        Some(ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    fn fixture_repo() -> (PathBuf, PathBuf) {
        let base = std::env::current_dir().unwrap().join(format!(
            ".yafvsctl-compose-identity-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("YAFVS");
        std::fs::create_dir_all(repo.join("compose")).unwrap();
        (base, repo)
    }

    fn image_ids() -> BTreeMap<String, String> {
        APP_SERVICES
            .iter()
            .enumerate()
            .map(|(index, service)| {
                (
                    (*service).to_owned(),
                    format!("sha256:{}", format!("{index:x}").repeat(64)),
                )
            })
            .collect()
    }

    fn rendered(ports: Value) -> String {
        let images = image_ids();
        let services = APP_SERVICES
            .iter()
            .map(|service| {
                let mut value = json!({"image": images.get(*service).unwrap()});
                if *service == "gsad" {
                    value["ports"] = ports.clone();
                }
                ((*service).to_owned(), value)
            })
            .collect::<Map<_, _>>();
        serde_json::to_string(&json!({
            "services": services,
            "networks": {"default": {"name": "turboväs"}},
        }))
        .unwrap()
    }

    #[test]
    fn compose_contract_is_stable_across_port_declaration_order() {
        let (base, repo) = fixture_repo();
        let first = Runner::new([output(
            true,
            rendered(json!([{"published": "2"}, {"published": "1"}])),
        )]);
        let second = Runner::new([output(
            true,
            rendered(json!([{"published": "1"}, {"published": "2"}])),
        )]);
        let environment = BTreeMap::new();
        let images = image_ids();
        let left = compose_contract_manifest(&repo, &first, &environment, &images).unwrap();
        let right = compose_contract_manifest(&repo, &second, &environment, &images).unwrap();
        assert_eq!(left, right);
        assert_eq!(left["services"], json!(APP_SERVICES));
        assert_eq!(
            left["digest"],
            "90fff5083b3b38083682ea8aa4ac4721dd7cf346ddea42812ff2cb62b97c7fde"
        );
        let command = &first.commands.lock().unwrap()[0];
        let override_position = command
            .iter()
            .position(|item| item.ends_with(OVERRIDE_PATH))
            .unwrap();
        let operation_position = command.iter().position(|item| item == "--profile").unwrap();
        assert!(override_position < operation_position);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn image_availability_requires_exact_observed_ids() {
        let images = image_ids();
        let outputs = APP_SERVICES.iter().map(|service| {
            let id = images.get(*service).unwrap();
            output(*service != "gsad", format!("{id}\n"))
        });
        let runner = Runner::new(outputs);
        assert_eq!(
            unavailable_images(Path::new("/repo"), &runner, &BTreeMap::new(), &images).unwrap(),
            vec!["gsad"]
        );
    }
}
