// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::schedule_write_validation::ValidatedScheduleClone;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleWriteOperation {
    Create,
    Clone,
    Patch,
    Delete,
    Restore,
    HardDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleWriteStep {
    ResolveOperatorOwner,
    VerifyExistingScheduleMutable,
    ResolveTimezone,
    ValidateTimezone,
    ParseICalendar,
    DeriveScheduleFields,
    VerifyUniqueLiveName,
    VerifyTaskDeleteSafety,
    VerifyTrashTaskDeleteSafety,
    InsertSchedule,
    CloneScheduleMetadata,
    CloneScheduleTags,
    UpdateScheduleMetadata,
    RefreshTaskNextTimes,
    MoveScheduleToTrash,
    RestoreScheduleFromTrash,
    RemoveTrashTagLinks,
    HardDeleteScheduleFromTrash,
    RelocateTasks,
    RelocatePermissionsAndTags,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScheduleWriteTransactionPlan {
    pub(crate) operation: ScheduleWriteOperation,
    pub(crate) steps: Vec<ScheduleWriteStep>,
}

pub(crate) fn schedule_clone_transaction_plan(
    request: &ValidatedScheduleClone,
) -> ScheduleWriteTransactionPlan {
    let mut steps = vec![
        ScheduleWriteStep::ResolveOperatorOwner,
        ScheduleWriteStep::VerifyExistingScheduleMutable,
    ];
    if request.name.is_some() {
        steps.push(ScheduleWriteStep::VerifyUniqueLiveName);
    }
    steps.extend([
        ScheduleWriteStep::CloneScheduleMetadata,
        ScheduleWriteStep::CloneScheduleTags,
    ]);
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Clone,
        steps,
    }
}

pub(crate) fn schedule_restore_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Restore,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::RestoreScheduleFromTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

pub(crate) fn schedule_create_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Create,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::InsertSchedule,
        ],
    }
}

pub(crate) fn schedule_hard_delete_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::HardDelete,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTrashTaskDeleteSafety,
            ScheduleWriteStep::RemoveTrashTagLinks,
            ScheduleWriteStep::HardDeleteScheduleFromTrash,
        ],
    }
}

pub(crate) fn schedule_patch_transaction_plan(
    changes_calendar: bool,
) -> ScheduleWriteTransactionPlan {
    let mut steps = vec![
        ScheduleWriteStep::ResolveOperatorOwner,
        ScheduleWriteStep::VerifyExistingScheduleMutable,
    ];
    if changes_calendar {
        steps.extend([
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
        ]);
    }
    steps.extend([
        ScheduleWriteStep::VerifyUniqueLiveName,
        ScheduleWriteStep::UpdateScheduleMetadata,
    ]);
    if changes_calendar {
        steps.push(ScheduleWriteStep::RefreshTaskNextTimes);
    }
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Patch,
        steps,
    }
}

pub(crate) fn schedule_delete_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Delete,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTaskDeleteSafety,
            ScheduleWriteStep::MoveScheduleToTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ],
    }
}
