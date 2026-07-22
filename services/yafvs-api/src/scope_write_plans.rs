// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::scope_write_validation::{ValidatedScopeCreate, ValidatedScopePatch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeWriteOperation {
    Create,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeWriteStep {
    ResolveOperatorOwner,
    VerifyScopeMutable,
    VerifyHumanOwner,
    VerifyReferenceVisibility,
    InsertScope,
    UpdateScopeMetadata,
    ReplaceTargetMembership,
    ReplaceHostMembership,
    VerifyNoScopeReportHistory,
    DeleteScopeMembership,
    DeleteScope,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScopeWriteTransactionPlan {
    pub(crate) operation: ScopeWriteOperation,
    pub(crate) steps: Vec<ScopeWriteStep>,
}

pub(crate) fn scope_create_transaction_plan(
    request: &ValidatedScopeCreate,
) -> ScopeWriteTransactionPlan {
    let mut steps = vec![ScopeWriteStep::ResolveOperatorOwner];
    if !request.target_ids.is_empty() || !request.host_ids.is_empty() {
        steps.push(ScopeWriteStep::VerifyReferenceVisibility);
    }
    steps.extend([
        ScopeWriteStep::InsertScope,
        ScopeWriteStep::ReplaceTargetMembership,
        ScopeWriteStep::ReplaceHostMembership,
    ]);
    ScopeWriteTransactionPlan {
        operation: ScopeWriteOperation::Create,
        steps,
    }
}

pub(crate) fn scope_patch_transaction_plan(
    request: &ValidatedScopePatch,
) -> ScopeWriteTransactionPlan {
    let mut steps = vec![
        ScopeWriteStep::ResolveOperatorOwner,
        ScopeWriteStep::VerifyScopeMutable,
        ScopeWriteStep::VerifyHumanOwner,
    ];
    if request.target_ids.is_some() || request.host_ids.is_some() {
        steps.push(ScopeWriteStep::VerifyReferenceVisibility);
    }
    if request.name.is_some()
        || request.comment.is_some()
        || request.protection_requirement.is_some()
    {
        steps.push(ScopeWriteStep::UpdateScopeMetadata);
    }
    if request.target_ids.is_some() {
        steps.push(ScopeWriteStep::ReplaceTargetMembership);
    }
    if request.host_ids.is_some() {
        steps.push(ScopeWriteStep::ReplaceHostMembership);
    }
    ScopeWriteTransactionPlan {
        operation: ScopeWriteOperation::Patch,
        steps,
    }
}

pub(crate) fn scope_delete_transaction_plan() -> ScopeWriteTransactionPlan {
    ScopeWriteTransactionPlan {
        operation: ScopeWriteOperation::Delete,
        steps: vec![
            ScopeWriteStep::ResolveOperatorOwner,
            ScopeWriteStep::VerifyScopeMutable,
            ScopeWriteStep::VerifyHumanOwner,
            ScopeWriteStep::VerifyNoScopeReportHistory,
            ScopeWriteStep::DeleteScopeMembership,
            ScopeWriteStep::DeleteScope,
        ],
    }
}
