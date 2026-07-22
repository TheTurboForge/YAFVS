// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::errors::{ApiError, mutation_committed_response_unavailable};

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");

#[test]
fn committed_response_failures_are_reported_without_reclassifying_the_mutation() {
    assert!(matches!(
        mutation_committed_response_unavailable("reload failed", "test response reload"),
        ApiError::MutationCommittedResponseUnavailable
    ));
}

#[test]
fn committed_transaction_response_paths_use_the_shared_mapping() {
    for source in [
        include_str!("alert_writes.rs"),
        include_str!("credential_writes.rs"),
        include_str!("filter_writes.rs"),
        include_str!("host_writes.rs"),
        include_str!("port_list_writes.rs"),
        include_str!("scan_config_backup.rs"),
        include_str!("scan_config_writes.rs"),
        include_str!("scanner_writes.rs"),
        include_str!("schedule_writes.rs"),
        include_str!("scope_report_mutations.rs"),
        include_str!("scope_writes.rs"),
        include_str!("target_writes.rs"),
        include_str!("task_writes.rs"),
    ] {
        assert!(source.contains("mutation_committed_response_unavailable"));
    }
}

#[test]
fn committed_response_operations_document_the_indeterminate_retry_contract() {
    for operation_id in [
        "postHosts",
        "patchHostsByHostId",
        "postScanners",
        "patchScannersByScannerId",
        "postScannersByScannerIdReplaceConfiguration",
        "patchCredentialsByCredentialId",
        "postFilters",
        "patchFiltersByFilterId",
        "postFiltersByFilterIdClone",
        "postFiltersByFilterIdRestore",
        "patchAlertsByAlertId",
        "postAlertsByAlertIdClone",
        "postPortLists",
        "patchPortListsByPortListId",
        "postPortListsByPortListIdClone",
        "postPortListsByPortListIdRestore",
        "postPortListImports",
        "postSchedulesByScheduleIdClone",
        "postSchedulesByScheduleIdRestore",
        "postScanConfigs",
        "patchScanConfigsByScanConfigId",
        "postScanConfigsByScanConfigIdClone",
        "postScanConfigsByScanConfigIdRestore",
        "postScanConfigsImport",
        "postScopes",
        "patchScopesByScopeId",
        "postScopesByScopeIdReports",
        "postTargets",
        "patchTargetsByTargetId",
        "postTargetsByTargetIdClone",
        "postTargetsByTargetIdRestore",
        "postTasks",
        "patchTasksByTaskId",
        "postTasksByTaskIdReplaceConfiguration",
    ] {
        let marker = format!("operationId: {operation_id}");
        let start = OPENAPI
            .find(&marker)
            .unwrap_or_else(|| panic!("missing OpenAPI operation {operation_id}"));
        let remainder = &OPENAPI[start..];
        let end = remainder[marker.len()..]
            .find("\n      operationId:")
            .map_or(remainder.len(), |offset| marker.len() + offset);
        let operation = &remainder[..end];
        assert!(
            operation.contains("'502':\n          $ref: '#/components/responses/BadGateway'"),
            "{operation_id} must document committed_response_unavailable"
        );
    }
}
