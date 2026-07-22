// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::filter_write_validation::ValidatedFilterClone;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterWriteOperation {
    Create,
    Clone,
    Patch,
    Delete,
    Restore,
    HardDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterWriteStep {
    ResolveOperatorOwner,
    NormalizeFilterType,
    ValidateFilterSubtype,
    CleanFilterTerm,
    VerifyUniqueLiveName,
    VerifyExistingFilterMutable,
    VerifyAlertLinkedTypeChangeAllowed,
    InsertFilter,
    CloneFilterMetadata,
    CloneFilterTags,
    UpdateFilterMetadata,
    MoveFilterToTrash,
    RestoreFilterFromTrash,
    VerifyTrashAlertDeleteSafety,
    RemoveTrashTagLinks,
    HardDeleteFilterFromTrash,
    RelocateTrashAlerts,
    RelocatePermissionsAndTags,
    CleanupFilterSettings,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FilterWriteTransactionPlan {
    pub(crate) operation: FilterWriteOperation,
    pub(crate) steps: Vec<FilterWriteStep>,
}

pub(crate) fn filter_hard_delete_transaction_plan() -> FilterWriteTransactionPlan {
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::HardDelete,
        steps: vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::VerifyTrashAlertDeleteSafety,
            FilterWriteStep::RemoveTrashTagLinks,
            FilterWriteStep::HardDeleteFilterFromTrash,
        ],
    }
}

pub(crate) fn filter_clone_transaction_plan(
    request: &ValidatedFilterClone,
) -> FilterWriteTransactionPlan {
    let mut steps = vec![
        FilterWriteStep::ResolveOperatorOwner,
        FilterWriteStep::VerifyExistingFilterMutable,
    ];
    if request.name.is_some() {
        steps.push(FilterWriteStep::VerifyUniqueLiveName);
    }
    steps.extend([
        FilterWriteStep::CloneFilterMetadata,
        FilterWriteStep::CloneFilterTags,
    ]);
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Clone,
        steps,
    }
}

pub(crate) fn filter_restore_transaction_plan() -> FilterWriteTransactionPlan {
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Restore,
        steps: vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::RestoreFilterFromTrash,
            FilterWriteStep::RelocateTrashAlerts,
            FilterWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

pub(crate) fn filter_create_transaction_plan() -> FilterWriteTransactionPlan {
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Create,
        steps: vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::InsertFilter,
        ],
    }
}

pub(crate) fn filter_patch_transaction_plan(
    changes_alert_sensitive_metadata: bool,
) -> FilterWriteTransactionPlan {
    let mut steps = vec![
        FilterWriteStep::ResolveOperatorOwner,
        FilterWriteStep::VerifyExistingFilterMutable,
        FilterWriteStep::NormalizeFilterType,
        FilterWriteStep::ValidateFilterSubtype,
        FilterWriteStep::CleanFilterTerm,
    ];
    if changes_alert_sensitive_metadata {
        steps.push(FilterWriteStep::VerifyAlertLinkedTypeChangeAllowed);
    }
    steps.extend([
        FilterWriteStep::VerifyUniqueLiveName,
        FilterWriteStep::UpdateFilterMetadata,
    ]);
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Patch,
        steps,
    }
}

pub(crate) fn filter_delete_transaction_plan() -> FilterWriteTransactionPlan {
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Delete,
        steps: vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::MoveFilterToTrash,
            FilterWriteStep::CleanupFilterSettings,
            FilterWriteStep::RelocatePermissionsAndTags,
        ],
    }
}
