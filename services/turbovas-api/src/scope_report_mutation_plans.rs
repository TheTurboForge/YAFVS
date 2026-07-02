// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeReportMutationOperation {
    Generate,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeReportMutationStep {
    ResolveOperatorOwner,
    BeginTransaction,
    ResolveScope,
    ResolveScopeReport,
    DecideAuthorizationAndProvenancePolicy,
    SelectScopeTargets,
    SelectLatestCompletedSourceReports,
    InsertScopeReportHeader,
    InsertScopeReportSources,
    RebuildScopeReportCounts,
    RebuildScopeReportMetrics,
    DeleteScopeReportSourceLinks,
    DeleteScopeReportSnapshot,
    RelyOnCascadeMetricCleanup,
    PreserveRawReportEvidence,
    CommitTransaction,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScopeReportMutationPlan {
    pub(crate) operation: ScopeReportMutationOperation,
    pub(crate) steps: Vec<ScopeReportMutationStep>,
}

pub(crate) fn scope_report_generation_plan() -> ScopeReportMutationPlan {
    ScopeReportMutationPlan {
        operation: ScopeReportMutationOperation::Generate,
        steps: vec![
            ScopeReportMutationStep::ResolveOperatorOwner,
            ScopeReportMutationStep::BeginTransaction,
            ScopeReportMutationStep::ResolveScope,
            ScopeReportMutationStep::DecideAuthorizationAndProvenancePolicy,
            ScopeReportMutationStep::SelectScopeTargets,
            ScopeReportMutationStep::SelectLatestCompletedSourceReports,
            ScopeReportMutationStep::InsertScopeReportHeader,
            ScopeReportMutationStep::InsertScopeReportSources,
            ScopeReportMutationStep::RebuildScopeReportCounts,
            ScopeReportMutationStep::RebuildScopeReportMetrics,
            ScopeReportMutationStep::CommitTransaction,
        ],
    }
}

pub(crate) fn scope_report_delete_plan() -> ScopeReportMutationPlan {
    ScopeReportMutationPlan {
        operation: ScopeReportMutationOperation::Delete,
        steps: vec![
            ScopeReportMutationStep::ResolveOperatorOwner,
            ScopeReportMutationStep::BeginTransaction,
            ScopeReportMutationStep::ResolveScopeReport,
            ScopeReportMutationStep::DecideAuthorizationAndProvenancePolicy,
            ScopeReportMutationStep::DeleteScopeReportSourceLinks,
            ScopeReportMutationStep::DeleteScopeReportSnapshot,
            ScopeReportMutationStep::RelyOnCascadeMetricCleanup,
            ScopeReportMutationStep::PreserveRawReportEvidence,
            ScopeReportMutationStep::CommitTransaction,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(plan: &ScopeReportMutationPlan, step: ScopeReportMutationStep) -> usize {
        plan.steps
            .iter()
            .position(|candidate| *candidate == step)
            .unwrap_or_else(|| panic!("{step:?} must be in {plan:?}"))
    }

    #[test]
    fn generation_plan_keeps_policy_decision_before_snapshot_mutation() {
        assert_eq!(
            scope_report_generation_plan(),
            ScopeReportMutationPlan {
                operation: ScopeReportMutationOperation::Generate,
                steps: vec![
                    ScopeReportMutationStep::ResolveOperatorOwner,
                    ScopeReportMutationStep::BeginTransaction,
                    ScopeReportMutationStep::ResolveScope,
                    ScopeReportMutationStep::DecideAuthorizationAndProvenancePolicy,
                    ScopeReportMutationStep::SelectScopeTargets,
                    ScopeReportMutationStep::SelectLatestCompletedSourceReports,
                    ScopeReportMutationStep::InsertScopeReportHeader,
                    ScopeReportMutationStep::InsertScopeReportSources,
                    ScopeReportMutationStep::RebuildScopeReportCounts,
                    ScopeReportMutationStep::RebuildScopeReportMetrics,
                    ScopeReportMutationStep::CommitTransaction,
                ],
            }
        );
        let plan = scope_report_generation_plan();
        let policy = index_of(
            &plan,
            ScopeReportMutationStep::DecideAuthorizationAndProvenancePolicy,
        );
        assert!(policy < index_of(&plan, ScopeReportMutationStep::InsertScopeReportHeader));
        assert!(policy < index_of(&plan, ScopeReportMutationStep::InsertScopeReportSources));
        assert!(
            index_of(&plan, ScopeReportMutationStep::InsertScopeReportSources)
                < index_of(&plan, ScopeReportMutationStep::RebuildScopeReportCounts)
        );
        assert!(
            index_of(&plan, ScopeReportMutationStep::RebuildScopeReportCounts)
                < index_of(&plan, ScopeReportMutationStep::RebuildScopeReportMetrics)
        );
    }

    #[test]
    fn delete_plan_keeps_policy_decision_and_raw_evidence_preservation_explicit() {
        assert_eq!(
            scope_report_delete_plan(),
            ScopeReportMutationPlan {
                operation: ScopeReportMutationOperation::Delete,
                steps: vec![
                    ScopeReportMutationStep::ResolveOperatorOwner,
                    ScopeReportMutationStep::BeginTransaction,
                    ScopeReportMutationStep::ResolveScopeReport,
                    ScopeReportMutationStep::DecideAuthorizationAndProvenancePolicy,
                    ScopeReportMutationStep::DeleteScopeReportSourceLinks,
                    ScopeReportMutationStep::DeleteScopeReportSnapshot,
                    ScopeReportMutationStep::RelyOnCascadeMetricCleanup,
                    ScopeReportMutationStep::PreserveRawReportEvidence,
                    ScopeReportMutationStep::CommitTransaction,
                ],
            }
        );
        let plan = scope_report_delete_plan();
        let policy = index_of(
            &plan,
            ScopeReportMutationStep::DecideAuthorizationAndProvenancePolicy,
        );
        assert!(policy < index_of(&plan, ScopeReportMutationStep::DeleteScopeReportSourceLinks));
        assert!(policy < index_of(&plan, ScopeReportMutationStep::DeleteScopeReportSnapshot));
        assert!(
            index_of(&plan, ScopeReportMutationStep::DeleteScopeReportSnapshot)
                < index_of(&plan, ScopeReportMutationStep::PreserveRawReportEvidence)
        );
    }
}
