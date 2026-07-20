// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Production command boundary for guarded feed-generation activation.

use super::super::common::{metadata, runtime_dir};
use super::super::compose::runtime_app_environment;
use super::super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use super::adapter::{ConcreteTransitionAdapter, PinnedDeployment};
use super::database::DatabaseAttestationAdapter;
use super::deployment::require_app_deployment_receipt;
use super::journal;
use super::provenance;
use super::selector;
use super::transition::{
    AdapterError, GenerationId, StepStatus, TransitionAction, TransitionDisposition,
    TransitionOutcome, TransitionRequest, run_transition,
};
use super::{Limits, VerificationWitness, verify_with_witness};
use crate::process::SystemCommandRunner;
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
struct PreparedTransition {
    request: TransitionRequest,
    no_op: bool,
}

#[derive(Clone, Copy, Debug)]
struct PreparationError {
    check: &'static str,
    message: &'static str,
}

pub(super) fn command(
    repo_root: &Path,
    generation_id: &str,
    rollback: bool,
    allow_first_activation: bool,
    repair_attestation: bool,
    repair_deployment: bool,
) -> ResultEnvelope {
    command_with_timeout(
        repo_root,
        generation_id,
        rollback,
        allow_first_activation,
        repair_attestation,
        repair_deployment,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_with_timeout(
    repo_root: &Path,
    generation_id: &str,
    rollback: bool,
    allow_first_activation: bool,
    repair_attestation: bool,
    repair_deployment: bool,
    timeout: Duration,
) -> ResultEnvelope {
    let command_name = if rollback {
        "feed-generation-rollback"
    } else {
        "feed-generation-activate"
    };
    match RuntimeOperationLock::acquire(
        repo_root,
        FEED_ACTIVATION_LOCK,
        command_name,
        timeout,
    ) {
        Ok(_lock) => command_unlocked(
            repo_root,
            generation_id,
            rollback,
            allow_first_activation,
            repair_attestation,
            repair_deployment,
            command_name,
        ),
        Err(RuntimeLockError::Timeout {
            name,
            operation,
            holder,
        }) => make_result(
            metadata(repo_root, command_name, &SystemCommandRunner),
            "Feed generation transition stopped while waiting for the feed lifecycle lock.".into(),
            vec![Finding::new(
                "fail",
                "feed-generation.activation-lock",
                format!(
                    "Timed out waiting for runtime lock '{name}'; another operation may still be running."
                ),
            )
            .with_details(json!({"operation": operation, "holder": holder}))],
        )
        .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()]),
        Err(RuntimeLockError::Setup(error)) => make_result(
            metadata(repo_root, command_name, &SystemCommandRunner),
            "Feed generation transition stopped because the lifecycle lock failed closed.".into(),
            vec![Finding::new(
                "fail",
                "feed-generation.activation-lock",
                format!("Feed lifecycle lock failed closed: {error}"),
            )],
        )
        .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()]),
    }
}

fn command_unlocked(
    repo_root: &Path,
    generation_id: &str,
    rollback: bool,
    allow_first_activation: bool,
    repair_attestation: bool,
    repair_deployment: bool,
    command_name: &str,
) -> ResultEnvelope {
    let runtime = runtime_dir(repo_root);
    let generations = runtime.join("feed-store/generations");
    let target_id = match GenerationId::parse(generation_id) {
        Ok(target) => target,
        Err(error) => {
            return failure(
                repo_root,
                command_name,
                "Feed generation transition stopped at target verification.",
                "feed-generation.target",
                &error,
                vec![generations.display().to_string()],
            );
        }
    };
    let target = match verify_with_witness(&generations, generation_id, &Limits::default()) {
        Ok(target) => target,
        Err(error) => {
            return failure(
                repo_root,
                command_name,
                "Feed generation transition stopped at target verification.",
                "feed-generation.target",
                &format!("Target feed generation verification failed closed: {error}"),
                vec![generations.display().to_string()],
            );
        }
    };
    let (target_details, target_witness) = target.into_parts();
    let mut findings = vec![
        Finding::new(
            "pass",
            "feed-generation.target",
            "Target feed generation is complete and verified.".into(),
        )
        .with_path(&generations.join(generation_id).display().to_string())
        .with_details(target_details),
    ];
    let mut verified_generations = std::collections::BTreeMap::new();
    verified_generations.insert(generation_id.to_owned(), target_witness);
    let signature_findings = provenance::signature_findings(
        repo_root,
        &generations.join(generation_id),
        &SystemCommandRunner,
    )
    .0;
    let signature_failed = signature_findings
        .iter()
        .any(|finding| finding.status == "fail");
    findings.extend(signature_findings);
    if signature_failed {
        return make_result(
            metadata(repo_root, command_name, &SystemCommandRunner),
            "Feed generation transition stopped because target provenance could not be revalidated."
                .into(),
            findings,
        )
        .with_artifacts(vec![generations.join(generation_id).display().to_string()]);
    }
    let current = match selector::read_current_generation_reference(&runtime) {
        Ok(current) => current,
        Err(error) => {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped at selector verification.",
                findings,
                "feed-generation.current",
                &format!("Active feed selector verification failed closed: {error}"),
                vec![runtime.join("feed-store").display().to_string()],
            );
        }
    };
    let current_id = current
        .as_ref()
        .and_then(|value| value.get("generation_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(current_id) = current_id.as_deref()
        && current_id != generation_id
    {
        let verified = match verify_with_witness(&generations, current_id, &Limits::default()) {
            Ok(verified) => verified,
            Err(error) => {
                return failure_with(
                    repo_root,
                    command_name,
                    "Feed generation transition stopped at selector verification.",
                    findings,
                    "feed-generation.current",
                    &format!("Active feed generation verification failed closed: {error}"),
                    vec![runtime.join("feed-store").display().to_string()],
                );
            }
        };
        let (details, witness) = verified.into_parts();
        let observed = selector::read_current_generation_reference(&runtime)
            .ok()
            .flatten()
            .and_then(|value| {
                value
                    .get("generation_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        if observed.as_deref() != Some(current_id) {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped at selector verification.",
                findings,
                "feed-generation.current",
                "Active feed selector changed while its generation was being verified.",
                vec![runtime.join("feed-store").display().to_string()],
            );
        }
        findings.push(
            Finding::new(
                "pass",
                "feed-generation.current",
                "Existing active feed generation is verified for guarded recovery.".into(),
            )
            .with_details(details),
        );
        verified_generations.insert(current_id.to_owned(), witness);
    }
    let state_result = if repair_attestation {
        journal::read_activation_state_for_repair(&runtime)
    } else {
        journal::read_activation_state(&runtime).map(|state| (state, false))
    };
    let (state, legacy_identity) = match state_result {
        Ok(state) => state,
        Err(error) => {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped at activation-journal verification.",
                findings,
                "feed-generation.journal",
                &format!("Activation journal verification failed closed: {error}"),
                vec![
                    journal::activation_state_path(&runtime)
                        .display()
                        .to_string(),
                ],
            );
        }
    };
    if legacy_identity {
        findings.push(
            Finding::new(
                "warn",
                "feed-generation.journal-identity-migration",
                "Explicit attestation repair accepted the completed pre-rename application identity; the current prepared receipt will replace it after real imports."
                    .into(),
            )
            .with_details(json!({
                "legacy_service": "turbovas-api",
                "current_service": "yafvs-api",
            })),
        );
    }

    let active_state = state
        .as_ref()
        .is_some_and(|value| value["status"] == "active");
    let database = if active_state {
        match DatabaseAttestationAdapter::new(repo_root, &SystemCommandRunner).read() {
            Ok(attestation) => attestation,
            Err(error) => {
                findings.push(
                    Finding::new(
                        "warn",
                        "feed-generation.database-attestation-read",
                        "The active database import attestation could not be read.".into(),
                    )
                    .with_details(json!({"reason": error})),
                );
                None
            }
        }
    } else {
        None
    };
    let database_generation_id = database.as_ref().map(|value| value.generation_id());
    let prepared = match resolve_request(
        target_id,
        current_id.as_deref(),
        state.as_ref(),
        database_generation_id,
        rollback,
        allow_first_activation,
        repair_attestation,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped at guarded request preparation.",
                findings,
                error.check,
                error.message,
                vec![
                    journal::activation_state_path(&runtime)
                        .display()
                        .to_string(),
                ],
            );
        }
    };
    if repair_deployment && !prepared.request.resume_existing {
        return failure_with(
            repo_root,
            command_name,
            "Feed generation transition stopped at deployment-repair scope validation.",
            findings,
            "feed-generation.deployment-repair-scope",
            "Deployment repair is limited to an explicitly interrupted transition.",
            vec![
                journal::activation_state_path(&runtime)
                    .display()
                    .to_string(),
            ],
        );
    }

    if let Some(current_id) = current_id.as_deref()
        && current_id == generation_id
    {
        findings.push(
            Finding::new(
                "pass",
                "feed-generation.current",
                "Existing active feed generation is verified for guarded recovery.".into(),
            )
            .with_details(json!({"generation_id": current_id})),
        );
    }
    if active_state && database_generation_id == current_id.as_deref() {
        findings.push(
            Finding::new(
                "pass",
                "feed-generation.database-attestation-preflight",
                "Active database import attestation matches the selector and journal.".into(),
            )
            .with_details(json!({"generation_id": current_id})),
        );
    }
    if repair_attestation {
        findings.push(
            Finding::new(
                "warn",
                "feed-generation.attestation-repair",
                "The active immutable generation will be re-imported before its database attestation is rewritten; metadata is never fabricated."
                    .into(),
            )
            .with_details(json!({"generation_id": generation_id})),
        );
    }
    if prepared.request.resume_existing {
        findings.push(
            Finding::new(
                "warn",
                "feed-generation.interrupted",
                "Resuming explicit recovery from an interrupted feed transition journal.".into(),
            )
            .with_details(state.clone().unwrap_or(Value::Null)),
        );
    }

    let mut environment = match runtime_app_environment(repo_root) {
        Ok(environment) => environment,
        Err(error) => {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped while preparing the secret-safe application environment.",
                findings,
                "feed-generation.app-environment",
                &format!("Application runtime environment preparation failed: {error}"),
                vec![runtime.display().to_string()],
            );
        }
    };
    let restore_gsad_hosts = match restore_hosts(state.as_ref(), &mut environment) {
        Ok(hosts) => hosts,
        Err(error) => {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped at published-host restoration.",
                findings,
                "feed-generation.restore-hosts",
                &error,
                vec![
                    journal::activation_state_path(&runtime)
                        .display()
                        .to_string(),
                ],
            );
        }
    };
    if !prepared.request.resume_existing || repair_deployment {
        match require_app_deployment_receipt(&runtime) {
            Ok(receipt) => {
                if repair_deployment {
                    findings.push(
                        Finding::new(
                            "warn",
                            "feed-generation.deployment-repair",
                            "Explicit interrupted-transition recovery selected the current verified application deployment receipt; feed and database attestations will still be recreated by real import and runtime verification."
                                .into(),
                        )
                        .with_details(json!({"generation_id": generation_id})),
                    );
                }
                return run_with_deployment(
                    repo_root,
                    command_name,
                    prepared,
                    findings,
                    environment,
                    PinnedDeployment {
                        restore_gsad_hosts,
                        app_image_ids: receipt["image_ids"].clone(),
                        app_runtime_artifacts: receipt["runtime_artifacts"].clone(),
                        app_compose_contract: receipt["compose_contract"].clone(),
                    },
                    generation_id,
                    verified_generations,
                );
            }
            Err(error) => {
                return failure_with(
                    repo_root,
                    command_name,
                    "Feed generation transition stopped because no verified application deployment was prepared.",
                    findings,
                    "feed-generation.app-images",
                    &error,
                    vec![
                        runtime
                            .join("state/app-deployment.json")
                            .display()
                            .to_string(),
                    ],
                );
            }
        }
    }
    let identity_source = state
        .as_ref()
        .expect("resumed request has activation state");
    run_with_deployment(
        repo_root,
        command_name,
        prepared,
        findings,
        environment,
        PinnedDeployment {
            restore_gsad_hosts,
            app_image_ids: identity_source["app_image_ids"].clone(),
            app_runtime_artifacts: identity_source["app_runtime_artifacts"].clone(),
            app_compose_contract: identity_source["app_compose_contract"].clone(),
        },
        generation_id,
        verified_generations,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_with_deployment(
    repo_root: &Path,
    command_name: &str,
    prepared: PreparedTransition,
    mut findings: Vec<Finding>,
    environment: std::collections::BTreeMap<OsString, OsString>,
    deployment: PinnedDeployment,
    generation_id: &str,
    verified_generations: std::collections::BTreeMap<String, VerificationWitness>,
) -> ResultEnvelope {
    let mut adapter = match ConcreteTransitionAdapter::new(
        repo_root,
        &SystemCommandRunner,
        environment,
        deployment,
    ) {
        Ok(adapter) => adapter.with_verified_generations(verified_generations),
        Err(error) => {
            return failure_with(
                repo_root,
                command_name,
                "Feed generation transition stopped at application deployment validation.",
                findings,
                "feed-generation.app-deployment",
                &error,
                vec![runtime_dir(repo_root).display().to_string()],
            );
        }
    };
    if prepared.no_op {
        match adapter.verify_pinned_images() {
            Ok(images) => {
                let failed = images.status == StepStatus::Fail;
                findings.extend(images.findings);
                if failed {
                    return make_result(
                        metadata(repo_root, command_name, &SystemCommandRunner),
                        "Requested feed generation is active, but its pinned images are unavailable."
                            .into(),
                        findings,
                    );
                }
            }
            Err(error) => {
                return adapter_failure_result(
                    repo_root,
                    command_name,
                    "Requested feed generation runtime verification failed.",
                    findings,
                    error,
                );
            }
        }
        return match adapter.verify_or_recover_active_runtime() {
            Ok(runtime) => {
                findings.extend(runtime.findings);
                make_result(
                    metadata(repo_root, command_name, &SystemCommandRunner),
                    if findings.iter().any(|finding| finding.status == "fail") {
                        "Active feed generation is durable, but application runtime recovery failed."
                    } else {
                        "Requested feed generation is already active and its runtime is verified."
                    }
                    .into(),
                    findings,
                )
                .with_artifacts(vec![
                    runtime_dir(repo_root)
                        .join(format!("feed-store/generations/{generation_id}"))
                        .display()
                        .to_string(),
                ])
            }
            Err(error) => adapter_failure_result(
                repo_root,
                command_name,
                "Active feed generation is durable, but application runtime recovery failed.",
                findings,
                error,
            ),
        };
    }

    let outcome = run_transition(&mut adapter, prepared.request);
    transition_result(repo_root, command_name, generation_id, findings, outcome)
}

fn resolve_request(
    target: GenerationId,
    current_id: Option<&str>,
    state: Option<&Value>,
    database_generation_id: Option<&str>,
    rollback: bool,
    allow_first_activation: bool,
    repair_attestation: bool,
) -> Result<PreparedTransition, PreparationError> {
    let interrupted = state.is_some_and(|value| value["status"] == "transitioning");
    let active = state.is_some_and(|value| value["status"] == "active");
    let state_current = state
        .and_then(|value| value.get("current_generation_id"))
        .and_then(Value::as_str);
    if active && state_current != current_id {
        return Err(PreparationError {
            check: "feed-generation.journal-selector",
            message: "Completed feed activation journal does not match the verified selector.",
        });
    }
    if state.is_none() && current_id.is_some() {
        return Err(PreparationError {
            check: "feed-generation.journal-missing",
            message: "A feed selector exists without a completed activation journal; database state will not be inferred.",
        });
    }
    if active && !repair_attestation && database_generation_id != current_id {
        return Err(PreparationError {
            check: "feed-generation.database-attestation-preflight",
            message: "The active database import attestation does not match the selector and journal; explicitly re-import the active generation with --repair-attestation before another transition.",
        });
    }

    let target_text = target.as_str();
    if repair_attestation && (rollback || interrupted || !active || current_id != Some(target_text))
    {
        return Err(PreparationError {
            check: "feed-generation.attestation-repair-scope",
            message: "Database attestation repair is limited to explicitly re-importing the completed active generation.",
        });
    }

    let prior_rollback = state
        .and_then(|value| value.get("rollback_generation_id"))
        .and_then(Value::as_str);
    let (previous, recovery_only) = if interrupted {
        let interrupted_target = state
            .and_then(|value| value.get("target_generation_id"))
            .and_then(Value::as_str);
        let interrupted_previous = state
            .and_then(|value| value.get("previous_generation_id"))
            .and_then(Value::as_str);
        match interrupted_previous {
            None => {
                if rollback || interrupted_target != Some(target_text) || !allow_first_activation {
                    return Err(PreparationError {
                        check: "feed-generation.interrupted-first",
                        message: "Interrupted first activation may only resume the recorded target with --allow-first-activation.",
                    });
                }
                (None, false)
            }
            Some(previous) => {
                if !rollback || previous != target_text {
                    return Err(PreparationError {
                        check: "feed-generation.interrupted-recovery",
                        message: "Interrupted transition must recover to its recorded prior generation through feed-generation-rollback.",
                    });
                }
                (Some(parse_recorded(previous)?), true)
            }
        }
    } else if rollback {
        if current_id.is_none() || prior_rollback != Some(target_text) {
            return Err(PreparationError {
                check: "feed-generation.rollback-source",
                message: "Rollback target must be the recorded prior known-good generation.",
            });
        }
        (current_id.map(parse_recorded).transpose()?, false)
    } else {
        if current_id.is_none() && !allow_first_activation {
            return Err(PreparationError {
                check: "feed-generation.first-activation",
                message: "First activation requires --allow-first-activation because no known-good generation exists for compensation.",
            });
        }
        (current_id.map(parse_recorded).transpose()?, false)
    };
    let success_rollback = if interrupted || repair_attestation {
        prior_rollback.map(parse_recorded).transpose()?
    } else {
        current_id.map(parse_recorded).transpose()?
    };
    let restored_rollback = prior_rollback.map(parse_recorded).transpose()?;
    Ok(PreparedTransition {
        no_op: active && current_id == Some(target_text) && !repair_attestation,
        request: TransitionRequest {
            action: if rollback {
                TransitionAction::Rollback
            } else {
                TransitionAction::Activate
            },
            target,
            previous,
            success_rollback,
            restored_rollback,
            resume_existing: interrupted,
            recovery_only,
        },
    })
}

fn parse_recorded(value: &str) -> Result<GenerationId, PreparationError> {
    GenerationId::parse(value).map_err(|_| PreparationError {
        check: "feed-generation.recorded-identifier",
        message: "A recorded feed generation identifier is invalid.",
    })
}

fn restore_hosts(
    state: Option<&Value>,
    environment: &mut std::collections::BTreeMap<OsString, OsString>,
) -> Result<Option<Value>, String> {
    if let Some(hosts) = state
        .and_then(|value| value.get("restore_gsad_hosts"))
        .filter(|value| !value.is_null())
    {
        let values = hosts
            .as_array()
            .and_then(|hosts| hosts.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
            .ok_or_else(|| "Recorded GSAD published hosts are invalid".to_owned())?;
        let values = canonical_restore_hosts(values)?;
        apply_restore_hosts(environment, &values);
        return Ok(Some(hosts.clone()));
    }
    let Some(text) = ["YAFVS_GSAD_HOSTS", "YAFVS_GSAD_HOST"]
        .iter()
        .find_map(|name| {
            environment
                .get(&OsString::from(name))
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
        })
    else {
        return Ok(None);
    };
    let hosts = canonical_restore_hosts(text.split(','))?;
    apply_restore_hosts(environment, &hosts);
    Ok(Some(json!(hosts)))
}

fn canonical_restore_hosts<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, String> {
    let mut hosts = Vec::new();
    for host in values {
        let parsed = host
            .parse::<IpAddr>()
            .map_err(|_| "GSAD published host is not a canonical IP address".to_owned())?;
        if parsed.to_string() != host || hosts.iter().any(|value| value == host) {
            return Err("GSAD published host is not a unique canonical IP address".into());
        }
        hosts.push(host.to_owned());
    }
    if hosts.is_empty() || hosts.len() > 16 {
        return Err("GSAD published host set is invalid".into());
    }
    Ok(hosts)
}

fn apply_restore_hosts(
    environment: &mut std::collections::BTreeMap<OsString, OsString>,
    hosts: &[String],
) {
    environment.insert(
        OsString::from("YAFVS_GSAD_HOST"),
        OsString::from(hosts.first().expect("validated host set")),
    );
    let plural = OsString::from("YAFVS_GSAD_HOSTS");
    if hosts.len() > 1 {
        environment.insert(plural, OsString::from(hosts.join(",")));
    } else {
        environment.remove(&plural);
    }
}

fn transition_result(
    repo_root: &Path,
    command_name: &str,
    generation_id: &str,
    mut findings: Vec<Finding>,
    outcome: TransitionOutcome,
) -> ResultEnvelope {
    let status = status_name(outcome.status);
    let disposition = disposition_name(outcome.disposition);
    let details = json!({
        "disposition": disposition,
        "phases": outcome.phases.iter().map(|phase| phase.as_str()).collect::<Vec<_>>(),
        "forward_failure": outcome.forward_failure.as_ref().map(|failure| json!({
            "step": format!("{:?}", failure.step), "message": failure.message,
        })),
        "compensation_failure": outcome.compensation_failure.as_ref().map(|failure| json!({
            "step": format!("{:?}", failure.step), "message": failure.message,
        })),
        "recovery_failures": outcome.recovery_failures.iter().map(|failure| json!({
            "step": format!("{:?}", failure.step), "message": failure.message,
        })).collect::<Vec<_>>(),
    });
    findings.extend(outcome.findings);
    findings.push(
        Finding::new(
            status,
            "feed-generation.transition",
            transition_message(outcome.disposition).into(),
        )
        .with_details(details),
    );
    make_result(
        metadata(repo_root, command_name, &SystemCommandRunner),
        transition_summary(command_name, outcome.disposition).into(),
        findings,
    )
    .with_artifacts(
        std::iter::once(
            runtime_dir(repo_root)
                .join(format!("feed-store/generations/{generation_id}"))
                .display()
                .to_string(),
        )
        .chain(outcome.artifacts)
        .collect(),
    )
}

fn adapter_failure_result(
    repo_root: &Path,
    command_name: &str,
    summary: &str,
    mut findings: Vec<Finding>,
    error: AdapterError,
) -> ResultEnvelope {
    findings.extend(error.findings);
    findings.push(Finding::new(
        "fail",
        "feed-generation.runtime-verify",
        format!(
            "Application runtime verification failed closed: {}",
            error.message
        ),
    ));
    make_result(
        metadata(repo_root, command_name, &SystemCommandRunner),
        summary.into(),
        findings,
    )
    .with_artifacts(error.artifacts)
}

fn status_name(status: StepStatus) -> &'static str {
    match status {
        StepStatus::Pass => "pass",
        StepStatus::Warn => "warn",
        StepStatus::Fail => "fail",
    }
}

fn disposition_name(disposition: TransitionDisposition) -> &'static str {
    match disposition {
        TransitionDisposition::Activated => "activated",
        TransitionDisposition::Restored => "restored",
        TransitionDisposition::ForwardFailed => "forward-failed",
        TransitionDisposition::ManualRecovery => "manual-recovery",
        TransitionDisposition::CompensationFailed => "compensation-failed",
        TransitionDisposition::DurableButRuntimeFailed => "durable-but-runtime-failed",
        TransitionDisposition::RestoredButRuntimeFailed => "restored-but-runtime-failed",
    }
}

fn transition_message(disposition: TransitionDisposition) -> &'static str {
    match disposition {
        TransitionDisposition::Activated => {
            "The target generation was imported, attested, journaled, and restarted."
        }
        TransitionDisposition::Restored => {
            "The target transition failed and the prior known-good generation was restored."
        }
        TransitionDisposition::DurableButRuntimeFailed => {
            "The target generation is durable, but application runtime verification failed."
        }
        TransitionDisposition::RestoredButRuntimeFailed => {
            "The prior generation was durably restored, but application runtime verification failed."
        }
        TransitionDisposition::ForwardFailed => "The transition failed before a safe commit.",
        TransitionDisposition::ManualRecovery => {
            "The transition stopped in a state that requires explicit manual recovery."
        }
        TransitionDisposition::CompensationFailed => {
            "The transition failed and automatic compensation did not complete."
        }
    }
}

fn transition_summary(command_name: &str, disposition: TransitionDisposition) -> &'static str {
    match disposition {
        TransitionDisposition::Activated if command_name == "feed-generation-rollback" => {
            "Feed generation rollback and import completed."
        }
        TransitionDisposition::Activated => "Feed generation activation and import completed.",
        TransitionDisposition::Restored => {
            "Feed generation transition failed; the prior generation was restored."
        }
        TransitionDisposition::DurableButRuntimeFailed => {
            "Feed generation activation is durable, but application runtime recovery failed."
        }
        TransitionDisposition::RestoredButRuntimeFailed => {
            "The prior generation is restored, but application runtime recovery failed."
        }
        TransitionDisposition::ForwardFailed => "Feed generation transition stopped safely.",
        TransitionDisposition::ManualRecovery => {
            "Feed generation transition requires explicit manual recovery."
        }
        TransitionDisposition::CompensationFailed => {
            "Feed generation transition and compensation failed."
        }
    }
}

fn failure(
    repo_root: &Path,
    command_name: &str,
    summary: &str,
    check: &str,
    message: &str,
    artifacts: Vec<String>,
) -> ResultEnvelope {
    failure_with(
        repo_root,
        command_name,
        summary,
        Vec::new(),
        check,
        message,
        artifacts,
    )
}

#[allow(clippy::too_many_arguments)]
fn failure_with(
    repo_root: &Path,
    command_name: &str,
    summary: &str,
    mut findings: Vec<Finding>,
    check: &str,
    message: &str,
    artifacts: Vec<String>,
) -> ResultEnvelope {
    findings.push(Finding::new("fail", check, message.into()));
    make_result(
        metadata(repo_root, command_name, &SystemCommandRunner),
        summary.into(),
        findings,
    )
    .with_artifacts(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: char) -> String {
        value.to_string().repeat(64)
    }

    fn active(current: &str, rollback: Option<&str>) -> Value {
        json!({
            "status": "active",
            "current_generation_id": current,
            "rollback_generation_id": rollback,
        })
    }

    fn transitioning(target: &str, previous: Option<&str>, rollback: Option<&str>) -> Value {
        json!({
            "status": "transitioning",
            "target_generation_id": target,
            "previous_generation_id": previous,
            "rollback_generation_id": rollback,
        })
    }

    fn resolve(
        target: &str,
        current: Option<&str>,
        state: Option<&Value>,
        database: Option<&str>,
        rollback: bool,
        first: bool,
        repair: bool,
    ) -> Result<PreparedTransition, PreparationError> {
        resolve_request(
            GenerationId::parse(target).unwrap(),
            current,
            state,
            database,
            rollback,
            first,
            repair,
        )
    }

    #[test]
    fn first_activation_requires_explicit_acknowledgement() {
        assert_eq!(
            resolve(&id('a'), None, None, None, false, false, false)
                .unwrap_err()
                .check,
            "feed-generation.first-activation"
        );
        let prepared = resolve(&id('a'), None, None, None, false, true, false).unwrap();
        assert_eq!(prepared.request.previous, None);
        assert_eq!(prepared.request.success_rollback, None);
    }

    #[test]
    fn activation_preserves_current_and_prior_rollback_roles() {
        let current = id('b');
        let prior = id('c');
        let state = active(&current, Some(&prior));
        let prepared = resolve(
            &id('a'),
            Some(&current),
            Some(&state),
            Some(&current),
            false,
            false,
            false,
        )
        .unwrap();
        assert_eq!(prepared.request.previous.unwrap().as_str(), current);
        assert_eq!(prepared.request.success_rollback.unwrap().as_str(), current);
        assert_eq!(prepared.request.restored_rollback.unwrap().as_str(), prior);
        assert!(!prepared.no_op);
    }

    #[test]
    fn rollback_accepts_only_the_recorded_predecessor() {
        let current = id('b');
        let prior = id('c');
        let state = active(&current, Some(&prior));
        assert!(
            resolve(
                &id('a'),
                Some(&current),
                Some(&state),
                Some(&current),
                true,
                false,
                false,
            )
            .is_err()
        );
        let prepared = resolve(
            &prior,
            Some(&current),
            Some(&state),
            Some(&current),
            true,
            false,
            false,
        )
        .unwrap();
        assert_eq!(prepared.request.action, TransitionAction::Rollback);
        assert_eq!(prepared.request.success_rollback.unwrap().as_str(), current);
    }

    #[test]
    fn interrupted_transition_requires_recorded_recovery_direction() {
        let target = id('a');
        let previous = id('b');
        let prior = id('c');
        let state = transitioning(&target, Some(&previous), Some(&prior));
        assert_eq!(
            resolve(
                &target,
                Some(&target),
                Some(&state),
                None,
                false,
                false,
                false,
            )
            .unwrap_err()
            .check,
            "feed-generation.interrupted-recovery"
        );
        let prepared = resolve(
            &previous,
            Some(&target),
            Some(&state),
            None,
            true,
            false,
            false,
        )
        .unwrap();
        assert!(prepared.request.resume_existing);
        assert!(prepared.request.recovery_only);
        assert_eq!(prepared.request.success_rollback.unwrap().as_str(), prior);
    }

    #[test]
    fn interrupted_first_activation_resumes_only_with_acknowledgement() {
        let target = id('a');
        let state = transitioning(&target, None, None);
        assert!(
            resolve(
                &target,
                Some(&target),
                Some(&state),
                None,
                false,
                false,
                false,
            )
            .is_err()
        );
        let prepared = resolve(
            &target,
            Some(&target),
            Some(&state),
            None,
            false,
            true,
            false,
        )
        .unwrap();
        assert!(prepared.request.resume_existing);
        assert_eq!(prepared.request.previous, None);
    }

    #[test]
    fn repair_is_scoped_to_active_target_and_keeps_prior_rollback() {
        let current = id('a');
        let prior = id('b');
        let state = active(&current, Some(&prior));
        let prepared = resolve(
            &current,
            Some(&current),
            Some(&state),
            None,
            false,
            false,
            true,
        )
        .unwrap();
        assert_eq!(prepared.request.success_rollback.unwrap().as_str(), prior);
        assert!(!prepared.no_op);
        assert!(
            resolve(
                &id('c'),
                Some(&current),
                Some(&state),
                None,
                false,
                false,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn active_state_requires_selector_and_database_agreement() {
        let current = id('a');
        let other = id('b');
        let state = active(&current, None);
        assert_eq!(
            resolve(
                &other,
                Some(&other),
                Some(&state),
                Some(&other),
                false,
                false,
                false,
            )
            .unwrap_err()
            .check,
            "feed-generation.journal-selector"
        );
        assert_eq!(
            resolve(
                &other,
                Some(&current),
                Some(&state),
                Some(&other),
                false,
                false,
                false,
            )
            .unwrap_err()
            .check,
            "feed-generation.database-attestation-preflight"
        );
    }

    #[test]
    fn matching_active_target_is_a_noop_only_without_repair() {
        let current = id('a');
        let state = active(&current, None);
        assert!(
            resolve(
                &current,
                Some(&current),
                Some(&state),
                Some(&current),
                false,
                false,
                false,
            )
            .unwrap()
            .no_op
        );
    }

    #[test]
    fn restore_hosts_prefers_recorded_state_and_requires_canonical_environment_ips() {
        let state = json!({
            "restore_gsad_hosts": ["192.0.2.10", "2001:db8::10"],
        });
        let mut environment = std::collections::BTreeMap::from([(
            OsString::from("YAFVS_GSAD_HOST"),
            OsString::from("127.0.0.1"),
        )]);
        let restored = restore_hosts(Some(&state), &mut environment).unwrap();
        assert_eq!(restored, Some(state["restore_gsad_hosts"].clone()));
        assert_eq!(
            environment[&OsString::from("YAFVS_GSAD_HOST")],
            OsString::from("192.0.2.10")
        );
        assert_eq!(
            environment[&OsString::from("YAFVS_GSAD_HOSTS")],
            OsString::from("192.0.2.10,2001:db8::10")
        );

        let mut environment = std::collections::BTreeMap::from([
            (
                OsString::from("YAFVS_GSAD_HOSTS"),
                OsString::from("198.51.100.4,2001:db8::4"),
            ),
            (
                OsString::from("YAFVS_GSAD_HOST"),
                OsString::from("127.0.0.1"),
            ),
        ]);
        assert_eq!(
            restore_hosts(None, &mut environment).unwrap(),
            Some(json!(["198.51.100.4", "2001:db8::4"]))
        );
        assert_eq!(
            environment[&OsString::from("YAFVS_GSAD_HOST")],
            OsString::from("198.51.100.4")
        );
        environment.insert(OsString::from("YAFVS_GSAD_HOSTS"), OsString::new());
        environment.insert(
            OsString::from("YAFVS_GSAD_HOST"),
            OsString::from("not-an-ip"),
        );
        assert!(restore_hosts(None, &mut environment).is_err());

        for malformed in ["192.0.2.1,", ",192.0.2.1", "192.0.2.1,,2001:db8::1"] {
            environment.insert(
                OsString::from("YAFVS_GSAD_HOSTS"),
                OsString::from(malformed),
            );
            assert!(restore_hosts(None, &mut environment).is_err());
        }

        let single = json!({"restore_gsad_hosts": ["192.0.2.20"]});
        assert_eq!(
            restore_hosts(Some(&single), &mut environment).unwrap(),
            Some(single["restore_gsad_hosts"].clone())
        );
        assert_eq!(
            environment[&OsString::from("YAFVS_GSAD_HOST")],
            OsString::from("192.0.2.20")
        );
        assert!(!environment.contains_key(&OsString::from("YAFVS_GSAD_HOSTS")));
    }
}
