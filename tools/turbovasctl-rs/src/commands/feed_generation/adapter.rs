// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Concrete fail-closed adapter for feed-generation transition primitives.

use super::Limits;
use super::artifact_identity::app_runtime_artifact_manifest;
use super::compose_identity::{compose_contract_manifest, unavailable_images};
use super::database::DatabaseAttestationAdapter;
use super::deployment::{
    validate_app_compose_contract, validate_app_runtime_artifact_manifest,
    validate_app_service_image_ids,
};
use super::feed_mappings;
use super::journal;
use super::manager_import;
use super::manager_init;
use super::ospd_readiness;
use super::payload::{self, DeploymentIdentity};
use super::provenance;
use super::scanner_runtime;
use super::selector;
use super::service_runtime::{SCANNER_SERVICES, ServiceRuntime};
use super::transition::{
    AdapterError, AttestationOutcome, AttestationReceipt, CompletedJournalRequest, GenerationId,
    StepOutcome, StepStatus, StopReason, TransitionAdapter, TransitionPhase, TransitionRequest,
};
use crate::commands::common::runtime_dir;
use crate::process::CommandRunner;
use crate::result::Finding;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const ACTIVE_SCAN_SQL: &str =
    "SELECT count(*) FROM tasks WHERE run_status IN (0, 3, 4, 10, 11, 14, 16, 17, 18, 19);";
const FULL_AND_FAST_SCAN_CONFIG_ID: &str = "daba56c8-73ec-11df-a475-002264764cea";
const IANA_TCP_UDP_PORT_LIST_ID: &str = "4a4717fe-57d2-11e1-9a26-406186ea4fc5";

#[derive(Clone, Debug)]
pub(super) struct PinnedDeployment {
    pub(super) restore_gsad_hosts: Option<Value>,
    pub(super) app_image_ids: Value,
    pub(super) app_runtime_artifacts: Value,
    pub(super) app_compose_contract: Value,
}

impl PinnedDeployment {
    pub(super) fn validate(self) -> Result<Self, String> {
        validate_app_service_image_ids(&self.app_image_ids)?;
        validate_app_runtime_artifact_manifest(&self.app_runtime_artifacts)?;
        validate_app_compose_contract(&self.app_compose_contract)?;
        if let Some(hosts) = &self.restore_gsad_hosts
            && !hosts.as_array().is_some_and(|hosts| {
                hosts.iter().all(|host| {
                    host.as_str().is_some_and(|host| {
                        !host.is_empty()
                            && host.len() <= 255
                            && !host
                                .bytes()
                                .any(|byte| byte.is_ascii_control() || matches!(byte, b',' | b'\0'))
                    })
                })
            })
        {
            return Err("feed transition restore hosts are invalid".into());
        }
        Ok(self)
    }
}

pub(super) struct ConcreteTransitionAdapter<'a> {
    repo_root: &'a Path,
    runtime: PathBuf,
    runner: &'a dyn CommandRunner,
    environment: BTreeMap<OsString, OsString>,
    deployment: PinnedDeployment,
    image_ids: BTreeMap<String, String>,
    preflight_controls: Vec<String>,
}

impl<'a> ConcreteTransitionAdapter<'a> {
    pub(super) fn new(
        repo_root: &'a Path,
        runner: &'a dyn CommandRunner,
        environment: BTreeMap<OsString, OsString>,
        deployment: PinnedDeployment,
    ) -> Result<Self, String> {
        let deployment = deployment.validate()?;
        let image_ids = validate_app_service_image_ids(&deployment.app_image_ids)?;
        Ok(Self {
            repo_root,
            runtime: runtime_dir(repo_root),
            runner,
            environment,
            deployment,
            image_ids,
            preflight_controls: Vec::new(),
        })
    }

    fn services(&self) -> ServiceRuntime<'_> {
        ServiceRuntime::new(
            self.repo_root,
            self.runner,
            &self.environment,
            &self.image_ids,
        )
    }

    fn native_feed_objects(&self) -> Result<StepOutcome, AdapterError> {
        let services = self.services();
        let mut findings = Vec::new();
        for (check, resource, expected) in [
            (
                "feed-objects.native-scan-config",
                "scan-configs",
                FULL_AND_FAST_SCAN_CONFIG_ID,
            ),
            (
                "feed-objects.native-port-list",
                "port-lists",
                IANA_TCP_UDP_PORT_LIST_ID,
            ),
        ] {
            let path = format!("/api/v1/{resource}/{expected}");
            let arguments = [
                "exec".to_owned(),
                "-T".to_owned(),
                "turbovas-api".to_owned(),
                "curl".to_owned(),
                "-fsS".to_owned(),
                "--max-time".to_owned(),
                "10".to_owned(),
                "--max-filesize".to_owned(),
                (1024 * 1024).to_string(),
                format!("http://127.0.0.1:9080{path}"),
            ];
            let output = services
                .run_compose(&arguments, std::time::Duration::from_secs(30))
                .map_err(|error| adapter_error("native feed object probe failed", error))?;
            let observed = if output.success && output.stdout.len() <= 1024 * 1024 {
                serde_json::from_str::<Value>(&output.stdout)
                    .ok()
                    .and_then(|value| value.get("id").and_then(Value::as_str).map(str::to_owned))
            } else {
                None
            };
            let passed = observed.as_deref() == Some(expected);
            findings.push(
                Finding::new(
                    if passed { "pass" } else { "fail" },
                    check,
                    if passed {
                        "Required imported feed object is available through the native API."
                    } else {
                        "Required imported feed object was not available through the native API."
                    }
                    .to_owned(),
                )
                .with_details(json!({
                    "expected_id": expected,
                    "observed_id": observed,
                    "resource": resource,
                })),
            );
        }
        let failed = findings.iter().any(|finding| finding.status == "fail");
        Ok(StepOutcome::with_evidence(
            if failed {
                StepStatus::Fail
            } else {
                StepStatus::Pass
            },
            findings,
            Vec::new(),
        ))
    }

    fn deployment_identity(&self) -> DeploymentIdentity<'_> {
        DeploymentIdentity {
            restore_gsad_hosts: self.deployment.restore_gsad_hosts.as_ref(),
            app_image_ids: &self.deployment.app_image_ids,
            app_runtime_artifacts: &self.deployment.app_runtime_artifacts,
            app_compose_contract: &self.deployment.app_compose_contract,
        }
    }

    fn scan_quiescence(&self) -> Result<StepOutcome, AdapterError> {
        let value = DatabaseAttestationAdapter::new(self.repo_root, self.runner)
            .query_single_value(ACTIVE_SCAN_SQL)
            .map_err(|error| adapter_error("active scan query failed", error))?
            .ok_or_else(|| adapter_error("active scan query returned no value", "missing value"))?;
        let active = value
            .parse::<u64>()
            .map_err(|_| adapter_error("active scan query was invalid", "invalid count"))?;
        let passed = active == 0;
        Ok(single_outcome(
            if passed {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            "feed-generation.active-scans",
            if passed {
                "No active scan task blocks the feed transition."
            } else {
                "One or more active scan tasks block the feed transition."
            },
            json!({"active_task_count": active}),
        ))
    }

    fn artifact_identity(&self, check: &str) -> Result<StepOutcome, AdapterError> {
        let observed = app_runtime_artifact_manifest(self.repo_root)
            .map_err(|error| adapter_error("runtime artifact identity failed", error))?;
        let expected = &self.deployment.app_runtime_artifacts;
        let matches = observed.get("digest").and_then(Value::as_str)
            == expected.get("digest").and_then(Value::as_str);
        Ok(single_outcome(
            if matches {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            check,
            if matches {
                "Bind-mounted runtime artifacts match the captured deployment identity."
            } else {
                "Bind-mounted runtime artifacts changed during the feed transition."
            },
            json!({"expected": expected, "observed": observed}),
        ))
    }

    fn compose_identity(&self, check: &str) -> Result<StepOutcome, AdapterError> {
        let observed = compose_contract_manifest(
            self.repo_root,
            self.runner,
            &self.environment,
            &self.image_ids,
        )
        .map_err(|error| adapter_error("Compose execution identity failed", error))?;
        let expected = &self.deployment.app_compose_contract;
        let matches = observed.get("digest").and_then(Value::as_str)
            == expected.get("digest").and_then(Value::as_str);
        Ok(single_outcome(
            if matches {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            check,
            if matches {
                "Rendered application Compose execution contract matches the prepared deployment."
            } else {
                "Rendered application Compose execution contract changed after deployment preparation."
            },
            json!({"expected": expected, "observed": observed}),
        ))
    }

    fn restore_preflight_after_failure(
        &mut self,
        mut evidence: StepOutcome,
    ) -> Result<StepOutcome, AdapterError> {
        let controls = std::mem::take(&mut self.preflight_controls);
        let restored = match self.services().restore_controls(&controls) {
            Ok(restored) => restored,
            Err(error) => {
                evidence.findings.push(Finding::new(
                    "fail",
                    "feed-generation.control-restore",
                    "Scanner-control service restoration failed after an aborted feed preflight."
                        .into(),
                ));
                return Err(AdapterError::with_evidence(
                    format!("feed-control restoration failed: {error}"),
                    evidence.findings,
                    evidence.artifacts,
                ));
            }
        };
        absorb(&mut evidence, restored);
        Ok(evidence)
    }

    fn restore_preflight_after_error(&mut self, error: AdapterError) -> AdapterError {
        let message = error.message;
        let evidence =
            StepOutcome::with_evidence(StepStatus::Fail, error.findings, error.artifacts);
        match self.restore_preflight_after_failure(evidence) {
            Ok(restored) => {
                AdapterError::with_evidence(message, restored.findings, restored.artifacts)
            }
            Err(restoration) => AdapterError::with_evidence(
                format!("{message}; {}", restoration.message),
                restoration.findings,
                restoration.artifacts,
            ),
        }
    }

    fn cleanup_started_apps_after_error(
        &self,
        check: &str,
        mut error: AdapterError,
        evidence: StepOutcome,
    ) -> AdapterError {
        error.findings.extend(evidence.findings);
        error.artifacts.extend(evidence.artifacts);
        match self.services().remove_apps(check) {
            Ok(cleanup) => {
                error.findings.extend(cleanup.findings);
                error.artifacts.extend(cleanup.artifacts);
            }
            Err(cleanup_error) => {
                error.message.push_str("; application cleanup failed: ");
                error.message.push_str(&cleanup_error);
            }
        }
        error
    }

    pub(super) fn verify_or_recover_active_runtime(&mut self) -> Result<StepOutcome, AdapterError> {
        let services = self.services();
        let running = services
            .running_services(&super::deployment::APP_SERVICES)
            .map_err(|error| adapter_error("active application state query failed", error))?;
        if running.len() != super::deployment::APP_SERVICES.len() {
            return self.restart_and_verify_apps(false);
        }

        let mut evidence = StepOutcome::pass();
        absorb(
            &mut evidence,
            services
                .running_app_image_identity()
                .map_err(|error| adapter_error("active app image validation failed", error))?,
        );
        absorb(
            &mut evidence,
            self.compose_identity("feed-generation.noop-app-compose")?,
        );
        absorb(
            &mut evidence,
            self.artifact_identity("feed-generation.noop-app-artifacts")?,
        );
        evidence.findings.push(
            Finding::new(
                status_name(evidence.status),
                "feed-generation.noop",
                if evidence.status == StepStatus::Fail {
                    "The active application runtime failed deployment identity verification."
                } else {
                    "The requested feed generation and complete pinned application runtime are already active."
                }
                .into(),
            )
            .with_details(json!({"running_services": running})),
        );
        Ok(evidence)
    }

    pub(super) fn verify_pinned_images(&self) -> Result<StepOutcome, AdapterError> {
        let unavailable = unavailable_images(
            self.repo_root,
            self.runner,
            &self.environment,
            &self.image_ids,
        )
        .map_err(|error| adapter_error("pinned image validation failed", error))?;
        if unavailable.is_empty() {
            return Ok(single_outcome(
                StepStatus::Pass,
                "feed-generation.app-images",
                "Every prepared immutable application image object is available.",
                json!({"unavailable_services": []}),
            ));
        }
        Ok(single_outcome(
            StepStatus::Fail,
            "feed-generation.app-images",
            "One or more prepared immutable application image objects are unavailable.",
            json!({"unavailable_services": unavailable}),
        ))
    }
}

impl TransitionAdapter for ConcreteTransitionAdapter<'_> {
    fn preflight(&mut self, _request: &TransitionRequest) -> Result<StepOutcome, AdapterError> {
        let mut evidence = self.verify_pinned_images()?;
        if evidence.status == StepStatus::Fail {
            return Ok(evidence);
        }
        absorb(
            &mut evidence,
            self.services()
                .running_app_image_identity()
                .map_err(|error| adapter_error("running app image validation failed", error))?,
        );
        absorb(
            &mut evidence,
            self.artifact_identity("feed-generation.app-artifacts")?,
        );
        absorb(
            &mut evidence,
            self.compose_identity("feed-generation.app-compose")?,
        );
        absorb(&mut evidence, self.scan_quiescence()?);
        if evidence.status == StepStatus::Fail {
            return Ok(evidence);
        }

        let (stopped, controls) = self
            .services()
            .stop_controls()
            .map_err(|error| adapter_error("feed-control stop failed", error))?;
        self.preflight_controls = controls;
        let stopped_passed = stopped.status != StepStatus::Fail;
        absorb(&mut evidence, stopped);
        if !stopped_passed {
            return self.restore_preflight_after_failure(evidence);
        }

        let stable = match self.scan_quiescence() {
            Ok(stable) => stable,
            Err(error) => return Err(self.restore_preflight_after_error(error)),
        };
        let stable_passed = stable.status != StepStatus::Fail;
        absorb(&mut evidence, stable);
        if !stable_passed {
            return self.restore_preflight_after_failure(evidence);
        }
        Ok(evidence)
    }

    fn write_transitioning_journal(
        &mut self,
        request: &TransitionRequest,
    ) -> Result<StepOutcome, AdapterError> {
        let started_at = now_utc()?;
        let state = payload::transitioning(request, self.deployment_identity(), &started_at)
            .map_err(|error| adapter_error("transition journal payload failed", error))?;
        journal::write_activation_state(&self.runtime, state)
            .map_err(|error| adapter_error("transition journal write failed", error))?;
        Ok(single_outcome(
            StepStatus::Pass,
            "feed-generation.journal",
            "Durable transition journal was recorded before service or selector changes.",
            json!({}),
        ))
    }

    fn restore_preflight_controls(&mut self) -> Result<StepOutcome, AdapterError> {
        let controls = std::mem::take(&mut self.preflight_controls);
        self.services()
            .restore_controls(&controls)
            .map_err(|error| adapter_error("feed-control restoration failed", error))
    }

    fn stop_apps(&mut self, reason: StopReason) -> Result<StepOutcome, AdapterError> {
        let check = match reason {
            StopReason::Forward => "feed-generation.stop-app",
            StopReason::Compensation => "feed-generation.compensation-stop",
            StopReason::TargetArtifactFailure => "feed-generation.artifact-change-stop",
            StopReason::CompensationArtifactFailure => "feed-generation.compensation-artifact-stop",
        };
        self.services()
            .remove_apps(check)
            .map_err(|error| adapter_error("application service stop failed", error))
    }

    fn select_generation(
        &mut self,
        generation: &GenerationId,
    ) -> Result<StepOutcome, AdapterError> {
        let selected =
            selector::select_generation(&self.runtime, generation.as_str(), &Limits::default())
                .map_err(|error| adapter_error("feed generation selection failed", error))?;
        Ok(single_outcome(
            StepStatus::Pass,
            "feed-generation.select",
            "Active feed selector changed atomically to the verified generation.",
            selected,
        ))
    }

    fn import_generation(
        &mut self,
        generation: &GenerationId,
    ) -> Result<StepOutcome, AdapterError> {
        let mut evidence = StepOutcome::pass();
        let generation_root = self
            .runtime
            .join("feed-store/generations")
            .join(generation.as_str());
        let (signature_findings, _) =
            provenance::signature_findings(self.repo_root, &generation_root, self.runner);
        let signature_failed = signature_findings
            .iter()
            .any(|finding| finding.status == "fail");
        absorb(
            &mut evidence,
            StepOutcome::with_evidence(
                if signature_failed {
                    StepStatus::Fail
                } else {
                    StepStatus::Pass
                },
                signature_findings,
                vec![generation_root.display().to_string()],
            ),
        );
        if signature_failed {
            return Ok(evidence);
        }

        let services = self.services();
        let redis = scanner_runtime::verify_scanner_redis(&services);
        let redis_passed = redis.status != StepStatus::Fail;
        absorb(&mut evidence, redis);
        if !redis_passed {
            return Ok(evidence);
        }

        let config = scanner_runtime::ensure_openvas_runtime_config(self.repo_root);
        let config_passed = config.status != StepStatus::Fail;
        absorb(&mut evidence, config);
        if !config_passed {
            return Ok(evidence);
        }

        let mappings = feed_mappings::ensure_runtime_feed_mappings(self.repo_root);
        let mappings_passed = mappings.status != StepStatus::Fail;
        absorb(&mut evidence, mappings);
        if !mappings_passed {
            return Ok(evidence);
        }

        let manager = manager_init::initialize_manager(self.repo_root, self.runner, &services);
        let manager_passed = manager.status != StepStatus::Fail;
        absorb(&mut evidence, manager);
        if !manager_passed {
            return Ok(evidence);
        }

        let scanners = services
            .start_pinned_services(
                &SCANNER_SERVICES,
                "runtime.scanner-services-up",
                std::time::Duration::from_secs(900),
            )
            .map_err(|error| adapter_error("scanner service start failed", error))?;
        let scanners_passed = scanners.status != StepStatus::Fail;
        absorb(&mut evidence, scanners);
        if !scanners_passed {
            return Ok(evidence);
        }

        let socket_path = self.runtime.join("run/ospd/ospd-openvas.sock");
        match ospd_readiness::wait_for_ospd_vts_version(
            &socket_path,
            std::time::Duration::from_secs(180),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(5),
        ) {
            Ok(version) => absorb(
                &mut evidence,
                single_outcome(
                    StepStatus::Pass,
                    "ospd.vts-version",
                    "ospd-openvas reported a VT feed version over the bounded runtime Unix socket.",
                    json!({"feed_version": version}),
                ),
            ),
            Err(error) => {
                absorb(
                    &mut evidence,
                    single_outcome(
                        StepStatus::Fail,
                        "ospd.vts-version",
                        "ospd-openvas did not report a VT feed version before the bounded readiness deadline.",
                        json!({"reason": error.to_string()}),
                    ),
                );
                return Ok(evidence);
            }
        }

        let imported = manager_import::import_manager_feed(&services);
        absorb(&mut evidence, imported);
        Ok(evidence)
    }

    fn runtime_artifacts_unchanged(
        &mut self,
        compensation: bool,
    ) -> Result<StepOutcome, AdapterError> {
        self.artifact_identity(if compensation {
            "feed-generation.app-artifacts-after-compensation"
        } else {
            "feed-generation.app-artifacts-after-import"
        })
    }

    fn verify_selected_generation(
        &mut self,
        generation: &GenerationId,
    ) -> Result<StepOutcome, AdapterError> {
        let current = selector::read_current_generation(&self.runtime, &Limits::default())
            .map_err(|error| adapter_error("selected feed verification failed", error))?;
        let observed = current
            .as_ref()
            .and_then(|current| current.get("generation_id"))
            .and_then(Value::as_str);
        let matches = observed == Some(generation.as_str());
        Ok(single_outcome(
            if matches {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            "feed-generation.post-verify",
            if matches {
                "Active generation and imported runtime agree."
            } else {
                "Active generation changed after import."
            },
            json!({"expected": generation.as_str(), "observed": observed}),
        ))
    }

    fn attest_database(
        &mut self,
        generation: &GenerationId,
    ) -> Result<AttestationOutcome, AdapterError> {
        let completed_at = now_utc()?;
        let attestation = DatabaseAttestationAdapter::new(self.repo_root, self.runner)
            .write(generation.as_str(), &completed_at)
            .map_err(|error| adapter_error("database attestation failed", error))?;
        let details = attestation.as_value();
        Ok(AttestationOutcome {
            receipt: AttestationReceipt {
                completed_at,
                details: details.clone(),
            },
            evidence: single_outcome(
                StepStatus::Pass,
                "feed-generation.database-attestation",
                "Database import attestation matches the selected immutable generation.",
                details,
            ),
        })
    }

    fn write_completed_journal(
        &mut self,
        request: &CompletedJournalRequest,
    ) -> Result<StepOutcome, AdapterError> {
        let state = payload::completed(request, self.deployment_identity())
            .map_err(|error| adapter_error("completed journal payload failed", error))?;
        journal::write_activation_state(&self.runtime, state)
            .map_err(|error| adapter_error("completed journal write failed", error))?;
        Ok(single_outcome(
            StepStatus::Pass,
            "feed-generation.journal-complete",
            "Durable activation journal matches the verified selector and completed import.",
            json!({}),
        ))
    }

    fn restart_and_verify_apps(&mut self, compensation: bool) -> Result<StepOutcome, AdapterError> {
        let mut evidence = StepOutcome::pass();
        absorb(
            &mut evidence,
            self.artifact_identity("feed-generation.app-artifacts-before-restart")?,
        );
        absorb(
            &mut evidence,
            self.compose_identity("feed-generation.app-compose-before-restart")?,
        );
        if evidence.status == StepStatus::Fail {
            return Ok(evidence);
        }

        let services = self.services();
        let started = match services.start_pinned_services(
            &super::deployment::APP_SERVICES,
            "feed-generation.app-restart",
            std::time::Duration::from_secs(900),
        ) {
            Ok(started) => started,
            Err(error) => {
                return Err(self.cleanup_started_apps_after_error(
                    "feed-generation.app-restart-error-stop",
                    adapter_error("application service restart failed", error),
                    evidence,
                ));
            }
        };
        let started_passed = started.status != StepStatus::Fail;
        absorb(&mut evidence, started);
        if !started_passed {
            absorb(
                &mut evidence,
                services
                    .remove_apps("feed-generation.app-restart-failure-stop")
                    .map_err(|error| adapter_error("partial app restart cleanup failed", error))?,
            );
            return Ok(evidence);
        }

        let post_start_identity = (|| -> Result<StepOutcome, AdapterError> {
            let mut identity = StepOutcome::pass();
            absorb(
                &mut identity,
                services.running_app_image_identity().map_err(|error| {
                    adapter_error("restarted app image validation failed", error)
                })?,
            );
            absorb(
                &mut identity,
                self.compose_identity("feed-generation.app-compose-after-restart")?,
            );
            absorb(
                &mut identity,
                self.artifact_identity("feed-generation.app-artifacts-after-restart")?,
            );
            Ok(identity)
        })();
        let post_start_identity = match post_start_identity {
            Ok(identity) => identity,
            Err(error) => {
                return Err(self.cleanup_started_apps_after_error(
                    "feed-generation.app-identity-error-stop",
                    error,
                    evidence,
                ));
            }
        };
        absorb(&mut evidence, post_start_identity);
        if evidence.status == StepStatus::Fail {
            absorb(
                &mut evidence,
                services
                    .remove_apps("feed-generation.app-identity-failure-stop")
                    .map_err(|error| adapter_error("app identity failure cleanup failed", error))?,
            );
            return Ok(evidence);
        }

        let gvmd_socket = self.runtime.join("run/gvmd-gmp/gvmd.sock");
        let gvmd_ready = ospd_readiness::wait_for_unix_socket(
            &gvmd_socket,
            std::time::Duration::from_secs(180),
            std::time::Duration::from_secs(1),
        );
        absorb(
            &mut evidence,
            single_outcome(
                if gvmd_ready {
                    StepStatus::Pass
                } else {
                    StepStatus::Fail
                },
                "feed-generation.gvmd-ready",
                if gvmd_ready {
                    "gvmd socket accepts connections after feed activation."
                } else {
                    "gvmd socket did not accept connections before the readiness deadline."
                },
                json!({
                    "compensation": compensation,
                    "path": gvmd_socket.display().to_string(),
                }),
            ),
        );
        if !gvmd_ready {
            return Ok(evidence);
        }

        absorb(&mut evidence, self.native_feed_objects()?);
        Ok(evidence)
    }

    fn clear_selector(&mut self, expected: &GenerationId) -> Result<StepOutcome, AdapterError> {
        selector::clear_current_generation(&self.runtime, expected.as_str())
            .map_err(|error| adapter_error("failed selector clear", error))?;
        Ok(single_outcome(
            StepStatus::Pass,
            "feed-generation.compensation-clear",
            "Cleared failed first-activation selector; app services remain stopped for manual recovery.",
            json!({"generation_id": expected.as_str()}),
        ))
    }

    fn emit_phase(&mut self, _phase: TransitionPhase) {}
}

fn now_utc() -> Result<String, AdapterError> {
    let timestamp = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| adapter_error("UTC clock normalization failed", "invalid clock"))?;
    timestamp
        .format(&Rfc3339)
        .map_err(|_| adapter_error("UTC timestamp formatting failed", "invalid clock"))
}

fn single_outcome(status: StepStatus, check: &str, message: &str, details: Value) -> StepOutcome {
    StepOutcome::with_evidence(
        status,
        vec![Finding::new(status_name(status), check, message.to_owned()).with_details(details)],
        Vec::new(),
    )
}

fn absorb(target: &mut StepOutcome, additional: StepOutcome) {
    target.status = combined_status(target.status, additional.status);
    target.findings.extend(additional.findings);
    target.artifacts.extend(additional.artifacts);
}

fn combined_status(left: StepStatus, right: StepStatus) -> StepStatus {
    match (left, right) {
        (StepStatus::Fail, _) | (_, StepStatus::Fail) => StepStatus::Fail,
        (StepStatus::Warn, _) | (_, StepStatus::Warn) => StepStatus::Warn,
        _ => StepStatus::Pass,
    }
}

fn status_name(status: StepStatus) -> &'static str {
    match status {
        StepStatus::Pass => "pass",
        StepStatus::Warn => "warn",
        StepStatus::Fail => "fail",
    }
}

fn adapter_error(context: impl Into<String>, error: impl std::fmt::Display) -> AdapterError {
    AdapterError::with_evidence(
        format!("{}: {error}", context.into()),
        Vec::new(),
        Vec::new(),
    )
}
