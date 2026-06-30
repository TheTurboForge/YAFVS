// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterWriteOperation {
    Create,
    Patch,
    Delete,
}

#[cfg(test)]
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
    UpdateFilterMetadata,
    MoveFilterToTrash,
    RelocatePermissionsAndTags,
    CleanupFilterSettings,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FilterWriteTransactionPlan {
    pub(crate) operation: FilterWriteOperation,
    pub(crate) steps: Vec<FilterWriteStep>,
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn filter_patch_transaction_plan(
    changes_filter_type: bool,
) -> FilterWriteTransactionPlan {
    let mut steps = vec![
        FilterWriteStep::ResolveOperatorOwner,
        FilterWriteStep::VerifyExistingFilterMutable,
        FilterWriteStep::NormalizeFilterType,
        FilterWriteStep::ValidateFilterSubtype,
        FilterWriteStep::CleanFilterTerm,
    ];
    if changes_filter_type {
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

#[cfg(test)]
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

#[cfg(test)]
#[path = "filter_writes_tests.rs"]
mod filter_writes_tests;
