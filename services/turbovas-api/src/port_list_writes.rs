// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortListWriteOperation {
    Create,
    Patch,
    Delete,
    Restore,
}

#[cfg(test)]
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
    ReplacePortRanges,
    UpdatePortListMetadata,
    MovePortListToTrash,
    MovePortRangesToTrash,
    RestorePortListFromTrash,
    RestorePortRangesFromTrash,
    RelocateTargets,
    RelocatePermissionsAndTags,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PortListWriteTransactionPlan {
    pub(crate) operation: PortListWriteOperation,
    pub(crate) steps: Vec<PortListWriteStep>,
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn port_list_patch_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Patch,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyNotPredefined,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::UpdatePortListMetadata,
        ],
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
#[path = "port_list_writes_tests.rs"]
mod port_list_writes_tests;
