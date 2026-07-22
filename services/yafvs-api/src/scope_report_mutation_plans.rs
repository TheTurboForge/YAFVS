// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeReportMutationOperation {
    Generate,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeReportMutationStep {
    RequireOperatorIdentity,
    BeginTransaction,
    ResolveScope,
    ResolveScopeReport,
    VerifyScopeOwnerMatch,
    VerifyScopeReportOwnerMatch,
    SelectScopeTargets,
    SelectLatestCompletedSourceReports,
    InsertScopeReportHeaderWithGeneratedByOperator,
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
            ScopeReportMutationStep::RequireOperatorIdentity,
            ScopeReportMutationStep::BeginTransaction,
            ScopeReportMutationStep::ResolveScope,
            ScopeReportMutationStep::VerifyScopeOwnerMatch,
            ScopeReportMutationStep::SelectScopeTargets,
            ScopeReportMutationStep::SelectLatestCompletedSourceReports,
            ScopeReportMutationStep::InsertScopeReportHeaderWithGeneratedByOperator,
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
            ScopeReportMutationStep::RequireOperatorIdentity,
            ScopeReportMutationStep::BeginTransaction,
            ScopeReportMutationStep::ResolveScopeReport,
            ScopeReportMutationStep::VerifyScopeReportOwnerMatch,
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
    fn generation_plan_requires_scope_owner_before_snapshot_mutation() {
        assert_eq!(
            scope_report_generation_plan(),
            ScopeReportMutationPlan {
                operation: ScopeReportMutationOperation::Generate,
                steps: vec![
                    ScopeReportMutationStep::RequireOperatorIdentity,
                    ScopeReportMutationStep::BeginTransaction,
                    ScopeReportMutationStep::ResolveScope,
                    ScopeReportMutationStep::VerifyScopeOwnerMatch,
                    ScopeReportMutationStep::SelectScopeTargets,
                    ScopeReportMutationStep::SelectLatestCompletedSourceReports,
                    ScopeReportMutationStep::InsertScopeReportHeaderWithGeneratedByOperator,
                    ScopeReportMutationStep::InsertScopeReportSources,
                    ScopeReportMutationStep::RebuildScopeReportCounts,
                    ScopeReportMutationStep::RebuildScopeReportMetrics,
                    ScopeReportMutationStep::CommitTransaction,
                ],
            }
        );
        let plan = scope_report_generation_plan();
        let owner = index_of(&plan, ScopeReportMutationStep::VerifyScopeOwnerMatch);
        assert!(owner < index_of(&plan, ScopeReportMutationStep::SelectScopeTargets));
        assert!(
            owner
                < index_of(
                    &plan,
                    ScopeReportMutationStep::InsertScopeReportHeaderWithGeneratedByOperator,
                )
        );
        assert!(owner < index_of(&plan, ScopeReportMutationStep::InsertScopeReportSources));
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
    fn delete_plan_requires_report_owner_before_snapshot_mutation() {
        assert_eq!(
            scope_report_delete_plan(),
            ScopeReportMutationPlan {
                operation: ScopeReportMutationOperation::Delete,
                steps: vec![
                    ScopeReportMutationStep::RequireOperatorIdentity,
                    ScopeReportMutationStep::BeginTransaction,
                    ScopeReportMutationStep::ResolveScopeReport,
                    ScopeReportMutationStep::VerifyScopeReportOwnerMatch,
                    ScopeReportMutationStep::DeleteScopeReportSourceLinks,
                    ScopeReportMutationStep::DeleteScopeReportSnapshot,
                    ScopeReportMutationStep::RelyOnCascadeMetricCleanup,
                    ScopeReportMutationStep::PreserveRawReportEvidence,
                    ScopeReportMutationStep::CommitTransaction,
                ],
            }
        );
        let plan = scope_report_delete_plan();
        let owner = index_of(&plan, ScopeReportMutationStep::VerifyScopeReportOwnerMatch);
        assert!(owner < index_of(&plan, ScopeReportMutationStep::DeleteScopeReportSourceLinks));
        assert!(owner < index_of(&plan, ScopeReportMutationStep::DeleteScopeReportSnapshot));
        assert!(
            index_of(&plan, ScopeReportMutationStep::DeleteScopeReportSnapshot)
                < index_of(&plan, ScopeReportMutationStep::PreserveRawReportEvidence)
        );
    }

    #[test]
    fn scope_report_mutations_require_operator_identity_before_transaction_work() {
        for plan in [scope_report_generation_plan(), scope_report_delete_plan()] {
            assert_eq!(
                plan.steps.first(),
                Some(&ScopeReportMutationStep::RequireOperatorIdentity),
                "{plan:?} must reject anonymous or unbound mutation attempts before DB work"
            );
            assert!(
                index_of(&plan, ScopeReportMutationStep::RequireOperatorIdentity)
                    < index_of(&plan, ScopeReportMutationStep::BeginTransaction)
            );
        }
    }

    #[test]
    fn scope_report_generation_records_provenance_before_source_rows() {
        let plan = scope_report_generation_plan();
        assert!(
            index_of(
                &plan,
                ScopeReportMutationStep::InsertScopeReportHeaderWithGeneratedByOperator,
            ) < index_of(&plan, ScopeReportMutationStep::InsertScopeReportSources)
        );
    }
}
