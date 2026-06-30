// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::port_list_write_validation::ValidatedPortListClone;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortListWriteOperation {
    Create,
    Clone,
    Patch,
    Delete,
    Restore,
    HardDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortListWriteStep {
    ResolveOperatorOwner,
    VerifyExistingPortListMutable,
    VerifyExistingTrashedPortListRestorable,
    VerifyNotPredefined,
    ValidatePortRanges,
    VerifyUniqueLiveAndTrashName,
    VerifyTargetDeleteSafety,
    InsertPortList,
    ClonePortListMetadata,
    ClonePortListRanges,
    ClonePortListTags,
    ReplacePortRanges,
    UpdatePortListMetadata,
    MovePortListToTrash,
    MovePortRangesToTrash,
    VerifyTrashTargetDeleteSafety,
    RemoveTrashTagLinks,
    DeletePortRangesFromTrash,
    HardDeletePortListFromTrash,
    RestorePortListFromTrash,
    RestorePortRangesFromTrash,
    RelocateTargets,
    RelocatePermissionsAndTags,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PortListWriteTransactionPlan {
    pub(crate) operation: PortListWriteOperation,
    pub(crate) steps: Vec<PortListWriteStep>,
}

pub(crate) fn port_list_create_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Create,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::InsertPortList,
            PortListWriteStep::ReplacePortRanges,
        ],
    }
}

pub(crate) fn port_list_patch_transaction_plan(
    replaces_ranges: bool,
) -> PortListWriteTransactionPlan {
    let mut steps = vec![
        PortListWriteStep::ResolveOperatorOwner,
        PortListWriteStep::VerifyExistingPortListMutable,
        PortListWriteStep::VerifyNotPredefined,
        PortListWriteStep::VerifyUniqueLiveAndTrashName,
    ];
    if replaces_ranges {
        steps.extend([
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::VerifyTrashTargetDeleteSafety,
        ]);
    }
    steps.push(PortListWriteStep::UpdatePortListMetadata);
    if replaces_ranges {
        steps.push(PortListWriteStep::ReplacePortRanges);
    }
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Patch,
        steps,
    }
}

pub(crate) fn port_list_clone_transaction_plan(
    request: &ValidatedPortListClone,
) -> PortListWriteTransactionPlan {
    let mut steps = vec![
        PortListWriteStep::ResolveOperatorOwner,
        PortListWriteStep::VerifyExistingPortListMutable,
    ];
    if request.name.is_some() {
        steps.push(PortListWriteStep::VerifyUniqueLiveAndTrashName);
    }
    steps.extend([
        PortListWriteStep::ClonePortListMetadata,
        PortListWriteStep::ClonePortListRanges,
        PortListWriteStep::ClonePortListTags,
    ]);
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Clone,
        steps,
    }
}

pub(crate) fn port_list_delete_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Delete,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::MovePortListToTrash,
            PortListWriteStep::MovePortRangesToTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

pub(crate) fn port_list_restore_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Restore,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::RestorePortListFromTrash,
            PortListWriteStep::RestorePortRangesFromTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

pub(crate) fn port_list_hard_delete_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::HardDelete,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyTrashTargetDeleteSafety,
            PortListWriteStep::RemoveTrashTagLinks,
            PortListWriteStep::DeletePortRangesFromTrash,
            PortListWriteStep::HardDeletePortListFromTrash,
        ],
    }
}
