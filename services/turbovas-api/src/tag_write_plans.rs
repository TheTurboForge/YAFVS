// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::tag_write_validation::{
    TagResourceUpdateAction, ValidatedTagClone, ValidatedTagCreate, ValidatedTagPatch,
    ValidatedTagResourceUpdate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteOperation {
    CreateMetadata,
    CloneMetadataAndAssignments,
    PatchMetadata,
    DeleteMetadata,
    UpdateResourceAssignments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteStep {
    ResolveOperatorOwner,
    VerifyResourceTypeSupported,
    VerifyTagExists,
    VerifyTagUnassigned,
    VerifyResourceExists,
    InsertMetadata,
    CopyResourceAssignments,
    UpdateMetadata,
    DeleteMetadata,
    InsertResourceAssignment,
    DeleteResourceAssignment,
    TouchMetadata,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TagWriteTransactionPlan {
    pub(crate) operation: TagWriteOperation,
    pub(crate) steps: Vec<TagWriteStep>,
}

pub(crate) fn tag_resource_update_transaction_plan(
    request: &ValidatedTagResourceUpdate,
) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::UpdateResourceAssignments,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::VerifyResourceExists,
            match request.action {
                TagResourceUpdateAction::Add => TagWriteStep::InsertResourceAssignment,
                TagResourceUpdateAction::Remove => TagWriteStep::DeleteResourceAssignment,
            },
            TagWriteStep::TouchMetadata,
        ],
    }
}

pub(crate) fn tag_create_transaction_plan(
    _request: &ValidatedTagCreate,
) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::CreateMetadata,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::InsertMetadata,
        ],
    }
}

pub(crate) fn tag_clone_transaction_plan(_request: &ValidatedTagClone) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::CloneMetadataAndAssignments,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::InsertMetadata,
            TagWriteStep::CopyResourceAssignments,
        ],
    }
}

pub(crate) fn tag_patch_transaction_plan(_request: &ValidatedTagPatch) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::PatchMetadata,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::UpdateMetadata,
        ],
    }
}

pub(crate) fn tag_delete_transaction_plan() -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::DeleteMetadata,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyTagUnassigned,
            TagWriteStep::DeleteMetadata,
        ],
    }
}
