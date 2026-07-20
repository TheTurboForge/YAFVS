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

/// Manager imports are incremental only for a new, clean forward transition.
/// Compensation and every recovery-shaped path deliberately use `Full`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ManagerImportPlan {
    Full,
    Incremental { baseline: GenerationId },
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
    fn import_generation(
        &mut self,
        generation: &GenerationId,
        plan: &ManagerImportPlan,
    ) -> Result<StepOutcome, AdapterError>;
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
        let plan = clean_forward_import_plan(request);
        let imported = self.call_step(TransitionStep::ImportTarget, |adapter| {
            adapter.import_generation(&request.target, &plan)
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
            // Compensation always rebuilds every manager feed class.
            adapter.import_generation(previous, &ManagerImportPlan::Full)
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

fn clean_forward_import_plan(request: &TransitionRequest) -> ManagerImportPlan {
    match (
        &request.previous,
        request.resume_existing,
        request.recovery_only,
    ) {
        (Some(previous), false, false) if previous != &request.target => {
            ManagerImportPlan::Incremental {
                baseline: previous.clone(),
            }
        }
        // First activation, attestation repair (same generation), interrupted
        // recovery, and recovery-only transitions must retain full imports.
        _ => ManagerImportPlan::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Preflight,
        Journal,
        RestoreControls,
        Stop(StopReason),
        Select(String),
        Import(String, ManagerImportPlan),
        Artifacts(bool),
        Verify(String),
        Attest(String),
        Completed(CompletionKind),
        Restart(bool),
        Clear(String),
        Phase(TransitionPhase),
    }

    struct MockAdapter {
        events: Vec<Event>,
        imports: VecDeque<StepOutcome>,
        artifacts: VecDeque<StepOutcome>,
        verifies: VecDeque<StepOutcome>,
        restarts: VecDeque<StepOutcome>,
        reported_failure: Option<TransitionStep>,
        adapter_error: Option<(TransitionStep, AdapterError)>,
    }

    impl MockAdapter {
        fn passing() -> Self {
            Self {
                events: Vec::new(),
                imports: VecDeque::from([StepOutcome::pass()]),
                artifacts: VecDeque::from([StepOutcome::pass()]),
                verifies: VecDeque::from([StepOutcome::pass()]),
                restarts: VecDeque::from([StepOutcome::pass()]),
                reported_failure: None,
                adapter_error: None,
            }
        }

        fn step(&mut self, step: TransitionStep) -> Result<StepOutcome, AdapterError> {
            if let Some(error) = self.take_error(step) {
                return Err(error);
            }
            if self.reported_failure == Some(step) {
                self.reported_failure = None;
                return Ok(failure("mock.reported", "step reported failure"));
            }
            Ok(StepOutcome::pass())
        }

        fn take_error(&mut self, step: TransitionStep) -> Option<AdapterError> {
            if self
                .adapter_error
                .as_ref()
                .is_some_and(|(candidate, _)| *candidate == step)
            {
                self.adapter_error.take().map(|(_, error)| error)
            } else {
                None
            }
        }

        fn phases(&self) -> Vec<TransitionPhase> {
            self.events
                .iter()
                .filter_map(|event| match event {
                    Event::Phase(phase) => Some(*phase),
                    _ => None,
                })
                .collect()
        }
    }

    impl TransitionAdapter for MockAdapter {
        fn preflight(&mut self, _: &TransitionRequest) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Preflight);
            self.step(TransitionStep::Preflight)
        }

        fn write_transitioning_journal(
            &mut self,
            _: &TransitionRequest,
        ) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Journal);
            self.step(TransitionStep::WriteTransitioningJournal)
        }

        fn restore_preflight_controls(&mut self) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::RestoreControls);
            self.step(TransitionStep::RestorePreflightControls)
        }

        fn stop_apps(&mut self, reason: StopReason) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Stop(reason));
            let step = match reason {
                StopReason::Forward | StopReason::TargetArtifactFailure => {
                    TransitionStep::StopForward
                }
                StopReason::Compensation | StopReason::CompensationArtifactFailure => {
                    TransitionStep::StopCompensation
                }
            };
            self.step(step)
        }

        fn select_generation(
            &mut self,
            generation: &GenerationId,
        ) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Select(generation.0.clone()));
            let step =
                if self.events.iter().any(|event| {
                    matches!(event, Event::Phase(TransitionPhase::TargetImportReturned))
                }) {
                    TransitionStep::SelectCompensation
                } else {
                    TransitionStep::SelectTarget
                };
            self.step(step)
        }

        fn import_generation(
            &mut self,
            generation: &GenerationId,
            plan: &ManagerImportPlan,
        ) -> Result<StepOutcome, AdapterError> {
            self.events
                .push(Event::Import(generation.0.clone(), plan.clone()));
            let step = if self.events.iter().any(|event| {
                matches!(
                    event,
                    Event::Phase(TransitionPhase::CompensationSelectorSelected)
                )
            }) {
                TransitionStep::ImportCompensation
            } else {
                TransitionStep::ImportTarget
            };
            if let Some(error) = self.take_error(step) {
                return Err(error);
            }
            Ok(self.imports.pop_front().expect("configured import outcome"))
        }

        fn runtime_artifacts_unchanged(
            &mut self,
            compensation: bool,
        ) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Artifacts(compensation));
            Ok(self
                .artifacts
                .pop_front()
                .expect("configured artifact outcome"))
        }

        fn verify_selected_generation(
            &mut self,
            generation: &GenerationId,
        ) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Verify(generation.0.clone()));
            Ok(self
                .verifies
                .pop_front()
                .expect("configured verification outcome"))
        }

        fn attest_database(
            &mut self,
            generation: &GenerationId,
        ) -> Result<AttestationOutcome, AdapterError> {
            self.events.push(Event::Attest(generation.0.clone()));
            let step = if self.events.iter().any(|event| {
                matches!(
                    event,
                    Event::Phase(TransitionPhase::CompensationImportReturned)
                )
            }) {
                TransitionStep::AttestCompensationDatabase
            } else {
                TransitionStep::AttestTargetDatabase
            };
            self.step(step).map(|evidence| AttestationOutcome {
                receipt: AttestationReceipt {
                    completed_at: "2026-07-18T10:00:00+00:00".into(),
                    details: json!({"generation_id": generation.as_str()}),
                },
                evidence,
            })
        }

        fn write_completed_journal(
            &mut self,
            request: &CompletedJournalRequest,
        ) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Completed(request.kind));
            let step = match request.kind {
                CompletionKind::Target => TransitionStep::WriteCompletedActivationJournal,
                CompletionKind::Compensation => TransitionStep::WriteCompletedCompensationJournal,
            };
            self.step(step)
        }

        fn restart_and_verify_apps(
            &mut self,
            compensation: bool,
        ) -> Result<StepOutcome, AdapterError> {
            let required = if compensation {
                TransitionPhase::CompensationJournalCompleted
            } else {
                TransitionPhase::ActivationJournalCompleted
            };
            assert!(matches!(self.events.last(), Some(Event::Phase(phase)) if *phase == required));
            self.events.push(Event::Restart(compensation));
            let step = if compensation {
                TransitionStep::RestartCompensation
            } else {
                TransitionStep::RestartTarget
            };
            if let Some(error) = self.take_error(step) {
                return Err(error);
            }
            Ok(self
                .restarts
                .pop_front()
                .expect("configured restart outcome"))
        }

        fn clear_selector(&mut self, expected: &GenerationId) -> Result<StepOutcome, AdapterError> {
            self.events.push(Event::Clear(expected.0.clone()));
            self.step(TransitionStep::ClearFailedSelector)
        }

        fn emit_phase(&mut self, phase: TransitionPhase) {
            self.events.push(Event::Phase(phase));
        }
    }

    fn id(byte: char) -> GenerationId {
        GenerationId::parse(&byte.to_string().repeat(64)).unwrap()
    }

    fn request(action: TransitionAction, previous: bool) -> TransitionRequest {
        TransitionRequest {
            action,
            target: id('a'),
            previous: previous.then(|| id('b')),
            success_rollback: previous.then(|| id('b')),
            restored_rollback: Some(id('c')),
            resume_existing: false,
            recovery_only: false,
        }
    }

    #[test]
    fn only_clean_forward_transitions_claim_an_incremental_baseline() {
        let clean = request(TransitionAction::Activate, true);
        assert_eq!(
            clean_forward_import_plan(&clean),
            ManagerImportPlan::Incremental { baseline: id('b') }
        );
        let mut interrupted = clean.clone();
        interrupted.resume_existing = true;
        assert_eq!(
            clean_forward_import_plan(&interrupted),
            ManagerImportPlan::Full
        );
        let mut recovery = clean.clone();
        recovery.recovery_only = true;
        assert_eq!(
            clean_forward_import_plan(&recovery),
            ManagerImportPlan::Full
        );
        assert_eq!(
            clean_forward_import_plan(&request(TransitionAction::Activate, false)),
            ManagerImportPlan::Full
        );
        let mut repair = clean;
        repair.previous = Some(repair.target.clone());
        assert_eq!(clean_forward_import_plan(&repair), ManagerImportPlan::Full);
    }

    #[test]
    fn compensation_import_is_always_full() {
        let mut adapter = MockAdapter::passing();
        adapter.imports = VecDeque::from([failure("target.import", "failed"), StepOutcome::pass()]);
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.disposition, TransitionDisposition::Restored);
        let imports = adapter
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Import(_, plan) => Some(plan),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[1], &ManagerImportPlan::Full);
    }

    #[test]
    fn resumed_transition_keeps_the_existing_journal_and_skips_its_phase() {
        let mut adapter = MockAdapter::passing();
        let mut resumed = request(TransitionAction::Rollback, true);
        resumed.resume_existing = true;
        resumed.recovery_only = true;
        let outcome = run_transition(&mut adapter, resumed);
        assert_eq!(outcome.disposition, TransitionDisposition::Activated);
        assert!(!adapter.events.contains(&Event::Journal));
        assert!(
            !outcome
                .phases
                .contains(&TransitionPhase::TransitionJournalRecorded)
        );
        assert!(matches!(
            adapter.events.as_slice(),
            [Event::Preflight, Event::Stop(StopReason::Forward), ..]
        ));
    }

    fn failure(check: &str, message: &str) -> StepOutcome {
        StepOutcome::with_evidence(
            StepStatus::Fail,
            vec![Finding::new("fail", check, message.into())],
            Vec::new(),
        )
    }

    fn forward_phases() -> Vec<TransitionPhase> {
        vec![
            TransitionPhase::TransitionJournalRecorded,
            TransitionPhase::SelectorSelected,
            TransitionPhase::TargetImportReturned,
            TransitionPhase::DatabaseAttested,
            TransitionPhase::ActivationJournalCompleted,
        ]
    }

    #[test]
    fn generation_ids_and_external_names_are_exact() {
        assert!(GenerationId::parse(&"a".repeat(64)).is_ok());
        assert!(GenerationId::parse(&"A".repeat(64)).is_err());
        assert!(GenerationId::parse("short").is_err());
        assert_eq!(TransitionAction::Rollback.as_str(), "rollback");
        assert_eq!(
            forward_phases()
                .into_iter()
                .map(TransitionPhase::as_str)
                .collect::<Vec<_>>(),
            [
                "transition-journal-recorded",
                "selector-selected",
                "target-import-returned",
                "database-attested",
                "activation-journal-completed",
            ]
        );
    }

    #[test]
    fn activate_and_rollback_have_exact_forward_order() {
        for action in [TransitionAction::Activate, TransitionAction::Rollback] {
            let mut adapter = MockAdapter::passing();
            let outcome = run_transition(&mut adapter, request(action, true));
            assert_eq!(outcome.status, StepStatus::Pass);
            assert_eq!(outcome.disposition, TransitionDisposition::Activated);
            assert_eq!(outcome.phases, forward_phases());
            assert_eq!(adapter.phases(), forward_phases());
            assert!(matches!(
                adapter.events.as_slice(),
                [
                    ..,
                    Event::Completed(CompletionKind::Target),
                    Event::Phase(TransitionPhase::ActivationJournalCompleted),
                    Event::Restart(false)
                ]
            ));
        }
    }

    #[test]
    fn early_failure_never_starts_compensation() {
        for step in [
            TransitionStep::Preflight,
            TransitionStep::WriteTransitioningJournal,
            TransitionStep::StopForward,
            TransitionStep::SelectTarget,
        ] {
            let mut adapter = MockAdapter::passing();
            adapter.reported_failure = Some(step);
            let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
            assert_eq!(outcome.status, StepStatus::Fail);
            assert!(outcome.phases.iter().all(|phase| !matches!(
                phase,
                TransitionPhase::CompensationSelectorSelected
                    | TransitionPhase::CompensationImportReturned
                    | TransitionPhase::CompensationDatabaseAttested
                    | TransitionPhase::CompensationJournalCompleted
            )));
            assert!(
                !adapter
                    .events
                    .contains(&Event::Stop(StopReason::Compensation))
            );
        }
    }

    #[test]
    fn preflight_precedes_journal_and_runtime_mutation() {
        let mut adapter = MockAdapter::passing();
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.status, StepStatus::Pass);
        assert!(matches!(
            adapter.events.as_slice(),
            [
                Event::Preflight,
                Event::Journal,
                Event::Phase(TransitionPhase::TransitionJournalRecorded),
                Event::Stop(StopReason::Forward),
                ..
            ]
        ));
    }

    #[test]
    fn journal_failure_restores_preflight_controls() {
        let mut adapter = MockAdapter::passing();
        adapter.reported_failure = Some(TransitionStep::WriteTransitioningJournal);
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.disposition, TransitionDisposition::ForwardFailed);
        assert!(outcome.recovery_failures.is_empty());
        assert!(matches!(
            adapter.events.as_slice(),
            [Event::Preflight, Event::Journal, Event::RestoreControls]
        ));
    }

    #[test]
    fn failed_preflight_control_restoration_requires_manual_recovery() {
        let mut adapter = MockAdapter::passing();
        adapter.adapter_error = Some((
            TransitionStep::RestorePreflightControls,
            AdapterError::with_evidence(
                "control restoration failed",
                vec![Finding::new(
                    "fail",
                    "preflight.restore",
                    "control restoration failed".into(),
                )],
                Vec::new(),
            ),
        ));
        adapter.reported_failure = Some(TransitionStep::WriteTransitioningJournal);
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.disposition, TransitionDisposition::ManualRecovery);
        assert_eq!(outcome.recovery_failures.len(), 1);
        assert_eq!(
            outcome.recovery_failures[0].step,
            TransitionStep::RestorePreflightControls
        );
        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.check == "preflight.restore")
        );
    }

    #[test]
    fn compensation_preserves_full_target_evidence_and_overall_failure() {
        let target = Finding::new("fail", "target.import", "target failed".into())
            .with_path("/target")
            .with_details(json!({"reason":"fixture"}))
            .with_top_findings(vec![json!({"check":"nested"})]);
        let expected = Finding::new("fail", "target.import", "target failed".into())
            .with_path("/target")
            .with_details(json!({"reason":"fixture"}))
            .with_top_findings(vec![json!({"check":"nested"})]);
        let mut adapter = MockAdapter::passing();
        adapter.imports = VecDeque::from([
            StepOutcome::with_evidence(
                StepStatus::Fail,
                vec![target],
                vec!["target-artifact".into()],
            ),
            StepOutcome::pass(),
        ]);
        adapter.artifacts = VecDeque::from([StepOutcome::pass()]);
        adapter.verifies = VecDeque::from([StepOutcome::pass()]);
        adapter.restarts = VecDeque::from([StepOutcome::pass()]);

        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.status, StepStatus::Fail);
        assert_eq!(outcome.disposition, TransitionDisposition::Restored);
        assert_eq!(outcome.findings, vec![expected]);
        assert_eq!(outcome.artifacts, vec!["target-artifact"]);
        assert_eq!(
            outcome.phases,
            vec![
                TransitionPhase::TransitionJournalRecorded,
                TransitionPhase::SelectorSelected,
                TransitionPhase::TargetImportReturned,
                TransitionPhase::CompensationSelectorSelected,
                TransitionPhase::CompensationImportReturned,
                TransitionPhase::CompensationDatabaseAttested,
                TransitionPhase::CompensationJournalCompleted,
            ]
        );
    }

    #[test]
    fn first_activation_failure_clears_exact_target_and_stays_stopped() {
        let mut adapter = MockAdapter::passing();
        adapter.imports = VecDeque::from([failure("target.import", "failed")]);
        adapter.artifacts.clear();
        adapter.verifies.clear();
        adapter.restarts.clear();
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, false));
        assert_eq!(outcome.disposition, TransitionDisposition::ManualRecovery);
        assert!(adapter.events.contains(&Event::Clear("a".repeat(64))));
        assert!(
            !adapter
                .events
                .iter()
                .any(|event| matches!(event, Event::Restart(_)))
        );
    }

    #[test]
    fn artifact_identity_failure_is_manual_not_compensated() {
        let mut adapter = MockAdapter::passing();
        adapter.artifacts = VecDeque::from([failure("artifact", "changed")]);
        adapter.verifies.clear();
        adapter.restarts.clear();
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.disposition, TransitionDisposition::ManualRecovery);
        assert!(
            adapter
                .events
                .contains(&Event::Stop(StopReason::TargetArtifactFailure))
        );
        assert!(
            !outcome
                .phases
                .contains(&TransitionPhase::CompensationSelectorSelected)
        );
    }

    #[test]
    fn durable_restart_failure_never_rolls_back() {
        let mut adapter = MockAdapter::passing();
        adapter.restarts = VecDeque::from([failure("restart", "failed")]);
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(
            outcome.disposition,
            TransitionDisposition::DurableButRuntimeFailed
        );
        assert_eq!(outcome.phases, forward_phases());
        assert_eq!(
            outcome.forward_failure.unwrap().step,
            TransitionStep::RestartTarget
        );
        assert!(
            !adapter
                .events
                .contains(&Event::Stop(StopReason::Compensation))
        );
        assert_eq!(
            adapter
                .events
                .iter()
                .filter(|event| matches!(event, Event::Select(_)))
                .count(),
            1
        );
    }

    #[test]
    fn restart_warning_is_preserved_without_rollback() {
        let warning = Finding::new("warn", "restart", "restart degraded".into())
            .with_details(json!({"service":"gvmd"}));
        let expected = Finding::new("warn", "restart", "restart degraded".into())
            .with_details(json!({"service":"gvmd"}));
        let mut adapter = MockAdapter::passing();
        adapter.restarts = VecDeque::from([StepOutcome::with_evidence(
            StepStatus::Warn,
            vec![warning],
            Vec::new(),
        )]);
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.status, StepStatus::Warn);
        assert_eq!(outcome.disposition, TransitionDisposition::Activated);
        assert_eq!(outcome.findings, vec![expected]);
        assert!(
            !adapter
                .events
                .contains(&Event::Stop(StopReason::Compensation))
        );
    }

    #[test]
    fn adapter_error_preserves_complete_evidence() {
        let finding = Finding::new("fail", "select", "uncertain".into())
            .with_path("/selector")
            .with_details(json!({"observed":null}));
        let expected = Finding::new("fail", "select", "uncertain".into())
            .with_path("/selector")
            .with_details(json!({"observed":null}));
        let mut adapter = MockAdapter::passing();
        adapter.adapter_error = Some((
            TransitionStep::SelectTarget,
            AdapterError::with_evidence(
                "selector uncertain",
                vec![finding],
                vec!["selector-artifact".into()],
            ),
        ));
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.disposition, TransitionDisposition::ManualRecovery);
        assert_eq!(outcome.findings, vec![expected]);
        assert_eq!(outcome.artifacts, vec!["selector-artifact"]);
        assert_eq!(
            outcome.forward_failure.unwrap().message,
            "selector uncertain"
        );
    }

    #[test]
    fn interrupted_recovery_failure_does_not_attempt_a_second_transition() {
        let mut adapter = MockAdapter::passing();
        adapter.imports = VecDeque::from([failure("recovery.import", "failed")]);
        adapter.artifacts.clear();
        adapter.verifies.clear();
        adapter.restarts.clear();
        let mut recovery = request(TransitionAction::Rollback, true);
        recovery.recovery_only = true;
        let outcome = run_transition(&mut adapter, recovery);
        assert_eq!(outcome.disposition, TransitionDisposition::ManualRecovery);
        assert!(
            !outcome
                .phases
                .contains(&TransitionPhase::CompensationSelectorSelected)
        );
        assert!(!adapter.events.contains(&Event::Clear("a".repeat(64))));
    }

    #[test]
    fn compensation_failure_is_distinct_and_keeps_apps_stopped() {
        let mut adapter = MockAdapter::passing();
        adapter.imports = VecDeque::from([
            failure("target.import", "failed"),
            failure("compensation.import", "also failed"),
        ]);
        adapter.artifacts.clear();
        adapter.verifies.clear();
        adapter.restarts.clear();
        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(
            outcome.disposition,
            TransitionDisposition::CompensationFailed
        );
        assert_eq!(
            outcome.compensation_failure.unwrap().step,
            TransitionStep::ImportCompensation
        );
        assert!(
            !adapter
                .events
                .iter()
                .any(|event| matches!(event, Event::Restart(_)))
        );
    }

    #[test]
    fn compensation_restart_failure_preserves_restored_durable_state() {
        let mut adapter = MockAdapter::passing();
        adapter.imports = VecDeque::from([failure("target.import", "failed"), StepOutcome::pass()]);
        adapter.artifacts = VecDeque::from([StepOutcome::pass()]);
        adapter.verifies = VecDeque::from([StepOutcome::pass()]);
        adapter.restarts = VecDeque::from([failure("restart", "restored runtime failed")]);

        let outcome = run_transition(&mut adapter, request(TransitionAction::Activate, true));
        assert_eq!(outcome.status, StepStatus::Fail);
        assert_eq!(
            outcome.disposition,
            TransitionDisposition::RestoredButRuntimeFailed
        );
        assert_eq!(
            outcome.compensation_failure.unwrap().step,
            TransitionStep::RestartCompensation
        );
        assert!(
            outcome
                .phases
                .contains(&TransitionPhase::CompensationJournalCompleted)
        );
        assert_eq!(
            adapter
                .events
                .iter()
                .filter(|event| matches!(event, Event::Select(_)))
                .count(),
            2
        );
    }
}
