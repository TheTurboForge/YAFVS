// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::tag_write_validation::{
    TagResourceUpdateAction, ValidatedTagClone, ValidatedTagCreate, ValidatedTagPatch,
    ValidatedTagResourceUpdate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteOperation {
    CreateMetadata,
    CloneMetadataAndAssignments,
    PatchMetadata,
    PatchMetadataAndAssignments,
    MoveToTrash,
    UpdateResourceAssignments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteStep {
    ResolveOperatorOwner,
    VerifyOwnerMatch,
    VerifyResourceTypeSupported,
    VerifyTagExists,
    VerifyResourceExists,
    VerifyResourceOwnerMatch,
    InsertMetadata,
    InsertTrashMetadata,
    CopyResourceAssignments,
    MoveTagAsResourceLinks,
    UpdateMetadata,
    DeleteLiveMetadata,
    InsertResourceAssignment,
    DeleteResourceAssignment,
    ClearResourceAssignments,
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
    let mut steps = vec![
        TagWriteStep::ResolveOperatorOwner,
        TagWriteStep::VerifyTagExists,
        TagWriteStep::VerifyOwnerMatch,
        TagWriteStep::VerifyResourceTypeSupported,
        TagWriteStep::VerifyResourceExists,
        TagWriteStep::VerifyResourceOwnerMatch,
    ];
    match request.action {
        TagResourceUpdateAction::Add => steps.push(TagWriteStep::InsertResourceAssignment),
        TagResourceUpdateAction::Remove => steps.push(TagWriteStep::DeleteResourceAssignment),
        TagResourceUpdateAction::Set => {
            steps.push(TagWriteStep::ClearResourceAssignments);
            steps.push(TagWriteStep::InsertResourceAssignment);
        }
    }
    steps.push(TagWriteStep::TouchMetadata);

    TagWriteTransactionPlan {
        operation: TagWriteOperation::UpdateResourceAssignments,
        steps,
    }
}

pub(crate) fn tag_create_transaction_plan(request: &ValidatedTagCreate) -> TagWriteTransactionPlan {
    let mut steps = vec![
        TagWriteStep::ResolveOperatorOwner,
        TagWriteStep::VerifyResourceTypeSupported,
        TagWriteStep::InsertMetadata,
    ];
    if !request.resource_ids.is_empty() {
        steps.extend([
            TagWriteStep::VerifyResourceExists,
            TagWriteStep::VerifyResourceOwnerMatch,
            TagWriteStep::InsertResourceAssignment,
        ]);
    }
    TagWriteTransactionPlan {
        operation: TagWriteOperation::CreateMetadata,
        steps,
    }
}

pub(crate) fn tag_clone_transaction_plan(_request: &ValidatedTagClone) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::CloneMetadataAndAssignments,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyOwnerMatch,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::InsertMetadata,
            TagWriteStep::CopyResourceAssignments,
        ],
    }
}

pub(crate) fn tag_patch_transaction_plan(request: &ValidatedTagPatch) -> TagWriteTransactionPlan {
    let mut steps = vec![
        TagWriteStep::ResolveOperatorOwner,
        TagWriteStep::VerifyTagExists,
        TagWriteStep::VerifyOwnerMatch,
        TagWriteStep::VerifyResourceTypeSupported,
    ];
    let operation = if let Some(resources) = request.resources.as_ref() {
        steps.extend([
            TagWriteStep::VerifyResourceExists,
            TagWriteStep::VerifyResourceOwnerMatch,
        ]);
        steps.push(TagWriteStep::UpdateMetadata);
        match resources.action {
            TagResourceUpdateAction::Add => steps.push(TagWriteStep::InsertResourceAssignment),
            TagResourceUpdateAction::Remove => steps.push(TagWriteStep::DeleteResourceAssignment),
            TagResourceUpdateAction::Set => {
                steps.push(TagWriteStep::ClearResourceAssignments);
                steps.push(TagWriteStep::InsertResourceAssignment);
            }
        }
        steps.push(TagWriteStep::TouchMetadata);
        TagWriteOperation::PatchMetadataAndAssignments
    } else {
        steps.push(TagWriteStep::UpdateMetadata);
        TagWriteOperation::PatchMetadata
    };
    TagWriteTransactionPlan { operation, steps }
}

pub(crate) fn tag_delete_transaction_plan() -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::MoveToTrash,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyOwnerMatch,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::InsertTrashMetadata,
            TagWriteStep::CopyResourceAssignments,
            TagWriteStep::MoveTagAsResourceLinks,
            TagWriteStep::DeleteResourceAssignment,
            TagWriteStep::DeleteLiveMetadata,
        ],
    }
}
