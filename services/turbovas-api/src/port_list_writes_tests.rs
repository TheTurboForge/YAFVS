// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn port_list_create_plan_validates_ranges_before_insert() {
    assert_eq!(
        port_list_create_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::InsertPortList,
            PortListWriteStep::ReplacePortRanges,
        ]
    );
}

#[test]
fn port_list_patch_plan_stays_metadata_only_and_blocks_predefined_lists() {
    assert_eq!(
        port_list_patch_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyNotPredefined,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::UpdatePortListMetadata,
        ]
    );
}

#[test]
fn port_list_delete_plan_keeps_range_target_and_tag_side_effects_explicit() {
    assert_eq!(
        port_list_delete_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::MovePortListToTrash,
            PortListWriteStep::MovePortRangesToTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ]
    );
}

#[test]
fn port_list_restore_plan_keeps_range_target_and_tag_side_effects_explicit() {
    assert_eq!(
        port_list_restore_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::RestorePortListFromTrash,
            PortListWriteStep::RestorePortRangesFromTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
