// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn filter_create_plan_keeps_normalization_before_insert() {
    assert_eq!(
        filter_create_transaction_plan().steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::InsertFilter,
        ]
    );
}

#[test]
fn filter_patch_plan_adds_alert_guard_only_for_type_changes() {
    assert_eq!(
        filter_patch_transaction_plan(false).steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::UpdateFilterMetadata,
        ]
    );
    assert_eq!(
        filter_patch_transaction_plan(true).steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyAlertLinkedTypeChangeAllowed,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::UpdateFilterMetadata,
        ]
    );
}

#[test]
fn filter_delete_plan_keeps_trash_and_side_effects_explicit() {
    assert_eq!(
        filter_delete_transaction_plan().steps,
        vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::MoveFilterToTrash,
            FilterWriteStep::CleanupFilterSettings,
            FilterWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
