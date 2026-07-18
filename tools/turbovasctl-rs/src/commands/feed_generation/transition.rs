// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Typed ordering for feed-generation activation commits and compensation.
//!
//! Concrete filesystem, database, process, and container work stays behind
//! [`TransitionAdapter`]. This module decides when compensation is safe and
//! preserves the adapter's full findings and artifacts.

use crate::result::Finding;
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GenerationId(String);

impl GenerationId {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err("feed generation identifier is invalid".into())
        }
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransitionAction {
    Activate,
    Rollback,
}

impl TransitionAction {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TransitionRequest {
    pub(super) action: TransitionAction,
    pub(super) target: GenerationId,
    pub(super) previous: Option<GenerationId>,
    pub(super) success_rollback: Option<GenerationId>,
    pub(super) restored_rollback: Option<GenerationId>,
    pub(super) resume_existing: bool,
    pub(super) recovery_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompletionKind {
    Target,
    Compensation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AttestationReceipt {
    pub(super) completed_at: String,
    pub(super) details: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompletedJournalRequest {
    pub(super) kind: CompletionKind,
    pub(super) active: GenerationId,
    pub(super) rollback_generation: Option<GenerationId>,
    pub(super) completed_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StepStatus {
    Pass,
    Warn,
    Fail,
}

impl StepStatus {
    fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Fail => 2,
        }
    }

    fn from_finding(finding: &Finding) -> Self {
        match finding.status.as_str() {
            "pass" => Self::Pass,
            "warn" => Self::Warn,
            _ => Self::Fail,
        }
    }

    fn max(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    fn is_pass(self) -> bool {
        self == Self::Pass
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct StepOutcome {
    pub(super) status: StepStatus,
    pub(super) findings: Vec<Finding>,
    pub(super) artifacts: Vec<String>,
}

impl StepOutcome {
    pub(super) fn pass() -> Self {
        Self {
            status: StepStatus::Pass,
            findings: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    pub(super) fn with_evidence(
        status: StepStatus,
        findings: Vec<Finding>,
        artifacts: Vec<String>,
    ) -> Self {
        Self {
            status,
            findings,
            artifacts,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct AttestationOutcome {
    pub(super) receipt: AttestationReceipt,
    pub(super) evidence: StepOutcome,
}

#[derive(Debug, PartialEq)]
pub(super) struct AdapterError {
    pub(super) message: String,
    pub(super) findings: Vec<Finding>,
    pub(super) artifacts: Vec<String>,
}

impl AdapterError {
    pub(super) fn with_evidence(
        message: impl Into<String>,
        findings: Vec<Finding>,
        artifacts: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            findings,
            artifacts,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransitionPhase {
    TransitionJournalRecorded,
    SelectorSelected,
    TargetImportReturned,
    DatabaseAttested,
    ActivationJournalCompleted,
    CompensationSelectorSelected,
    CompensationImportReturned,
    CompensationDatabaseAttested,
    CompensationJournalCompleted,
}

impl TransitionPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::TransitionJournalRecorded => "transition-journal-recorded",
            Self::SelectorSelected => "selector-selected",
            Self::TargetImportReturned => "target-import-returned",
            Self::DatabaseAttested => "database-attested",
            Self::ActivationJournalCompleted => "activation-journal-completed",
            Self::CompensationSelectorSelected => "compensation-selector-selected",
            Self::CompensationImportReturned => "compensation-import-returned",
            Self::CompensationDatabaseAttested => "compensation-database-attested",
            Self::CompensationJournalCompleted => "compensation-journal-completed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StopReason {
    Forward,
    Compensation,
    TargetArtifactFailure,
    CompensationArtifactFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransitionStep {
    Preflight,
    WriteTransitioningJournal,
    RestorePreflightControls,
    StopForward,
    SelectTarget,
    ImportTarget,
    VerifyTargetArtifacts,
    VerifyTarget,
    AttestTargetDatabase,
    WriteCompletedActivationJournal,
    RestartTarget,
    StopCompensation,
    ClearFailedSelector,
    SelectCompensation,
    ImportCompensation,
    VerifyCompensationArtifacts,
    VerifyCompensation,
    AttestCompensationDatabase,
    WriteCompletedCompensationJournal,
    RestartCompensation,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct StepFailure {
    pub(super) step: TransitionStep,
    pub(super) message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransitionDisposition {
    Activated,
    Restored,
    ForwardFailed,
    ManualRecovery,
    CompensationFailed,
    DurableButRuntimeFailed,
    RestoredButRuntimeFailed,
}

#[derive(Debug, PartialEq)]
pub(super) struct TransitionOutcome {
    pub(super) status: StepStatus,
    pub(super) disposition: TransitionDisposition,
    pub(super) phases: Vec<TransitionPhase>,
    pub(super) findings: Vec<Finding>,
    pub(super) artifacts: Vec<String>,
    pub(super) forward_failure: Option<StepFailure>,
    pub(super) compensation_failure: Option<StepFailure>,
    pub(super) recovery_failures: Vec<StepFailure>,
}

impl TransitionOutcome {
    fn new() -> Self {
        Self {
            status: StepStatus::Pass,
            disposition: TransitionDisposition::Activated,
            phases: Vec::new(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            forward_failure: None,
            compensation_failure: None,
            recovery_failures: Vec::new(),
        }
    }

    fn absorb(&mut self, outcome: StepOutcome) -> StepStatus {
        let status = outcome
            .findings
            .iter()
            .fold(outcome.status, |current, finding| {
                current.max(StepStatus::from_finding(finding))
            });
        self.status = self.status.max(status);
        self.findings.extend(outcome.findings);
        self.artifacts.extend(outcome.artifacts);
        status
    }

    fn absorb_error(&mut self, error: AdapterError) {
        self.status = StepStatus::Fail;
        self.findings.extend(error.findings);
        self.artifacts.extend(error.artifacts);
    }
}

pub(super) trait TransitionAdapter {
    /// Validate the pinned deployment and scan quiescence, temporarily stopping
    /// feed-control services for the race-free second quiescence check. If the
    /// method fails after stopping controls, it must restore them before return
    /// or include the restoration failure in its evidence.
    fn preflight(&mut self, request: &TransitionRequest) -> Result<StepOutcome, AdapterError>;
    fn write_transitioning_journal(
        &mut self,
        request: &TransitionRequest,
    ) -> Result<StepOutcome, AdapterError>;
    /// Restore only the feed-control services stopped by a successful preflight.
    fn restore_preflight_controls(&mut self) -> Result<StepOutcome, AdapterError>;
    fn stop_apps(&mut self, reason: StopReason) -> Result<StepOutcome, AdapterError>;
    fn select_generation(&mut self, generation: &GenerationId)
    -> Result<StepOutcome, AdapterError>;
    fn import_generation(&mut self, generation: &GenerationId)
    -> Result<StepOutcome, AdapterError>;
    fn runtime_artifacts_unchanged(
        &mut self,
        compensation: bool,
    ) -> Result<StepOutcome, AdapterError>;
    fn verify_selected_generation(
        &mut self,
        generation: &GenerationId,
    ) -> Result<StepOutcome, AdapterError>;
    fn attest_database(
        &mut self,
        generation: &GenerationId,
    ) -> Result<AttestationOutcome, AdapterError>;
    fn write_completed_journal(
        &mut self,
        request: &CompletedJournalRequest,
    ) -> Result<StepOutcome, AdapterError>;
    fn restart_and_verify_apps(&mut self, compensation: bool) -> Result<StepOutcome, AdapterError>;
    fn clear_selector(&mut self, expected: &GenerationId) -> Result<StepOutcome, AdapterError>;
    fn emit_phase(&mut self, phase: TransitionPhase);
}

pub(super) fn run_transition<A: TransitionAdapter>(
    adapter: &mut A,
    request: TransitionRequest,
) -> TransitionOutcome {
    Engine {
        adapter,
        outcome: TransitionOutcome::new(),
    }
    .run(request)
}

struct Engine<'a, A> {
    adapter: &'a mut A,
    outcome: TransitionOutcome,
}

impl<A: TransitionAdapter> Engine<'_, A> {
    fn run(mut self, request: TransitionRequest) -> TransitionOutcome {
        if let Err(failure) = self.require_step(
            TransitionStep::Preflight,
            "feed transition preflight failed",
            |adapter| adapter.preflight(&request),
        ) {
            self.forward_failed(failure, TransitionDisposition::ForwardFailed);
            return self.outcome;
        }
        if !request.resume_existing {
            if let Err(failure) = self.require_step(
                TransitionStep::WriteTransitioningJournal,
                "transition journal write failed",
                |adapter| adapter.write_transitioning_journal(&request),
            ) {
                self.forward_failed(failure, TransitionDisposition::ForwardFailed);
                if let Err(recovery_failure) = self.require_step(
                    TransitionStep::RestorePreflightControls,
                    "feed-control restoration failed after journal write failure",
                    |adapter| adapter.restore_preflight_controls(),
                ) {
                    self.outcome.disposition = TransitionDisposition::ManualRecovery;
                    self.outcome.recovery_failures.push(recovery_failure);
                }
                return self.outcome;
            }
            self.emit(TransitionPhase::TransitionJournalRecorded);
        }

        if let Err(failure) = self.require_step(
            TransitionStep::StopForward,
            "application stop failed before selector mutation",
            |adapter| adapter.stop_apps(StopReason::Forward),
        ) {
            self.forward_failed(failure, TransitionDisposition::ForwardFailed);
            return self.outcome;
        }
        if let Err(failure) = self.require_step(
            TransitionStep::SelectTarget,
            "target selector change failed",
            |adapter| adapter.select_generation(&request.target),
        ) {
            self.forward_failed(failure, TransitionDisposition::ManualRecovery);
            return self.outcome;
        }
        self.emit(TransitionPhase::SelectorSelected);

        if let Err(failure) = self.commit_target(&request) {
            self.compensate(&request, failure);
        }
        self.outcome
    }

    fn commit_target(&mut self, request: &TransitionRequest) -> Result<(), StepFailure> {
        let imported = self.call_step(TransitionStep::ImportTarget, |adapter| {
            adapter.import_generation(&request.target)
        })?;
        self.emit(TransitionPhase::TargetImportReturned);
        if !imported.is_pass() {
            return Err(StepFailure {
                step: TransitionStep::ImportTarget,
                message: "target import reported failure".into(),
            });
        }

        match self.require_step(
            TransitionStep::VerifyTargetArtifacts,
            "runtime artifacts changed during target import",
            |adapter| adapter.runtime_artifacts_unchanged(false),
        ) {
            Ok(()) => {}
            Err(failure) => {
                let _ = self.call_step(TransitionStep::StopForward, |adapter| {
                    adapter.stop_apps(StopReason::TargetArtifactFailure)
                });
                self.forward_failed(failure, TransitionDisposition::ManualRecovery);
                return Ok(());
            }
        }

        self.require_step(
            TransitionStep::VerifyTarget,
            "selected target changed after import",
            |adapter| adapter.verify_selected_generation(&request.target),
        )?;

        let attestation =
            self.call_attestation(TransitionStep::AttestTargetDatabase, &request.target)?;
        self.emit(TransitionPhase::DatabaseAttested);
        let completed = CompletedJournalRequest {
            kind: CompletionKind::Target,
            active: request.target.clone(),
            rollback_generation: request.success_rollback.clone(),
            completed_at: attestation.completed_at,
        };
        self.require_step(
            TransitionStep::WriteCompletedActivationJournal,
            "completed activation journal write failed",
            |adapter| adapter.write_completed_journal(&completed),
        )?;
        self.emit(TransitionPhase::ActivationJournalCompleted);

        match self.call_step(TransitionStep::RestartTarget, |adapter| {
            adapter.restart_and_verify_apps(false)
        }) {
            Ok(StepStatus::Fail) => {
                self.outcome.disposition = TransitionDisposition::DurableButRuntimeFailed;
                self.outcome.forward_failure = Some(StepFailure {
                    step: TransitionStep::RestartTarget,
                    message: "activation is durable but runtime restart failed".into(),
                });
            }
            Err(failure) => {
                self.outcome.disposition = TransitionDisposition::DurableButRuntimeFailed;
                self.outcome.forward_failure = Some(failure);
            }
            Ok(StepStatus::Pass | StepStatus::Warn) => {
                self.outcome.disposition = TransitionDisposition::Activated;
            }
        }
        Ok(())
    }

    fn compensate(&mut self, request: &TransitionRequest, failure: StepFailure) {
        if self.outcome.forward_failure.is_some() {
            return;
        }
        self.forward_failed(failure, TransitionDisposition::ManualRecovery);
        if let Err(failure) = self.require_step(
            TransitionStep::StopCompensation,
            "application stop failed before compensation",
            |adapter| adapter.stop_apps(StopReason::Compensation),
        ) {
            self.compensation_failed(failure);
            return;
        }
        if request.recovery_only {
            return;
        }
        let Some(previous) = request.previous.as_ref() else {
            match self.require_step(
                TransitionStep::ClearFailedSelector,
                "failed first-activation selector could not be cleared",
                |adapter| adapter.clear_selector(&request.target),
            ) {
                Ok(()) => self.outcome.disposition = TransitionDisposition::ManualRecovery,
                Err(failure) => self.compensation_failed(failure),
            }
            return;
        };

        if let Err(failure) = self.restore_previous(request, previous) {
            self.compensation_failed(failure);
        }
    }

    fn restore_previous(
        &mut self,
        request: &TransitionRequest,
        previous: &GenerationId,
    ) -> Result<(), StepFailure> {
        self.require_step(
            TransitionStep::SelectCompensation,
            "prior selector restoration failed",
            |adapter| adapter.select_generation(previous),
        )?;
        self.emit(TransitionPhase::CompensationSelectorSelected);

        let imported = self.call_step(TransitionStep::ImportCompensation, |adapter| {
            adapter.import_generation(previous)
        })?;
        self.emit(TransitionPhase::CompensationImportReturned);
        if !imported.is_pass() {
            return Err(StepFailure {
                step: TransitionStep::ImportCompensation,
                message: "compensation import reported failure".into(),
            });
        }
        if let Err(failure) = self.require_step(
            TransitionStep::VerifyCompensationArtifacts,
            "runtime artifacts changed during compensation",
            |adapter| adapter.runtime_artifacts_unchanged(true),
        ) {
            let _ = self.call_step(TransitionStep::StopCompensation, |adapter| {
                adapter.stop_apps(StopReason::CompensationArtifactFailure)
            });
            return Err(failure);
        }
        self.require_step(
            TransitionStep::VerifyCompensation,
            "restored selector changed after compensation import",
            |adapter| adapter.verify_selected_generation(previous),
        )?;

        let attestation =
            self.call_attestation(TransitionStep::AttestCompensationDatabase, previous)?;
        self.emit(TransitionPhase::CompensationDatabaseAttested);
        let completed = CompletedJournalRequest {
            kind: CompletionKind::Compensation,
            active: previous.clone(),
            rollback_generation: request.restored_rollback.clone(),
            completed_at: attestation.completed_at,
        };
        self.require_step(
            TransitionStep::WriteCompletedCompensationJournal,
            "completed compensation journal write failed",
            |adapter| adapter.write_completed_journal(&completed),
        )?;
        self.emit(TransitionPhase::CompensationJournalCompleted);

        match self.call_step(TransitionStep::RestartCompensation, |adapter| {
            adapter.restart_and_verify_apps(true)
        }) {
            Ok(StepStatus::Pass | StepStatus::Warn) => {
                self.outcome.disposition = TransitionDisposition::Restored;
            }
            Ok(StepStatus::Fail) => {
                self.outcome.disposition = TransitionDisposition::RestoredButRuntimeFailed;
                self.outcome.compensation_failure = Some(StepFailure {
                    step: TransitionStep::RestartCompensation,
                    message: "restored activation is durable but runtime restart failed".into(),
                });
            }
            Err(failure) => {
                self.outcome.disposition = TransitionDisposition::RestoredButRuntimeFailed;
                self.outcome.compensation_failure = Some(failure);
            }
        }
        Ok(())
    }

    fn call_step(
        &mut self,
        step: TransitionStep,
        operation: impl FnOnce(&mut A) -> Result<StepOutcome, AdapterError>,
    ) -> Result<StepStatus, StepFailure> {
        match operation(self.adapter) {
            Ok(outcome) => Ok(self.outcome.absorb(outcome)),
            Err(error) => {
                let message = error.message.clone();
                self.outcome.absorb_error(error);
                Err(StepFailure { step, message })
            }
        }
    }

    fn require_step(
        &mut self,
        step: TransitionStep,
        message: &'static str,
        operation: impl FnOnce(&mut A) -> Result<StepOutcome, AdapterError>,
    ) -> Result<(), StepFailure> {
        let status = self.call_step(step, operation)?;
        if status.is_pass() {
            Ok(())
        } else {
            Err(StepFailure {
                step,
                message: message.into(),
            })
        }
    }

    fn call_attestation(
        &mut self,
        step: TransitionStep,
        generation: &GenerationId,
    ) -> Result<AttestationReceipt, StepFailure> {
        match self.adapter.attest_database(generation) {
            Ok(attestation) => {
                let status = self.outcome.absorb(attestation.evidence);
                if status.is_pass() {
                    Ok(attestation.receipt)
                } else {
                    Err(StepFailure {
                        step,
                        message: "database attestation reported failure".into(),
                    })
                }
            }
            Err(error) => {
                let message = error.message.clone();
                self.outcome.absorb_error(error);
                Err(StepFailure { step, message })
            }
        }
    }

    fn emit(&mut self, phase: TransitionPhase) {
        self.adapter.emit_phase(phase);
        self.outcome.phases.push(phase);
    }

    fn forward_failed(&mut self, failure: StepFailure, disposition: TransitionDisposition) {
        self.outcome.status = StepStatus::Fail;
        self.outcome.disposition = disposition;
        self.outcome.forward_failure = Some(failure);
    }

    fn compensation_failed(&mut self, failure: StepFailure) {
        self.outcome.status = StepStatus::Fail;
        self.outcome.disposition = TransitionDisposition::CompensationFailed;
        self.outcome.compensation_failure = Some(failure);
    }
}
