// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::report_config_write_validation::{
    ValidatedReportConfigCreate, ValidatedReportConfigPatch,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportConfigWriteOperation {
    Create,
    Patch,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportConfigWriteStep {
    ResolveOperatorOwner,
    VerifyReportFormatVisible,
    VerifyReportFormatParams,
    VerifyUniqueLiveName,
    VerifyExistingReportConfigMutable,
    InsertReportConfig,
    UpdateReportConfigMetadata,
    ReplaceReportConfigParams,
    MoveReportConfigToTrash,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteTransactionPlan {
    pub(crate) operation: ReportConfigWriteOperation,
    pub(crate) steps: Vec<ReportConfigWriteStep>,
}

pub(crate) fn report_config_create_transaction_plan(
    _request: &ValidatedReportConfigCreate,
) -> ReportConfigWriteTransactionPlan {
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Create,
        steps: vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyReportFormatVisible,
            ReportConfigWriteStep::VerifyReportFormatParams,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::InsertReportConfig,
            ReportConfigWriteStep::ReplaceReportConfigParams,
        ],
    }
}

pub(crate) fn report_config_patch_transaction_plan(
    request: &ValidatedReportConfigPatch,
) -> ReportConfigWriteTransactionPlan {
    let mut steps = vec![
        ReportConfigWriteStep::ResolveOperatorOwner,
        ReportConfigWriteStep::VerifyExistingReportConfigMutable,
    ];
    if request.params.is_some() {
        steps.push(ReportConfigWriteStep::VerifyReportFormatParams);
    }
    if request.name.is_some() {
        steps.push(ReportConfigWriteStep::VerifyUniqueLiveName);
    }
    if request.name.is_some() || request.comment.is_some() {
        steps.push(ReportConfigWriteStep::UpdateReportConfigMetadata);
    }
    if request.params.is_some() {
        steps.push(ReportConfigWriteStep::ReplaceReportConfigParams);
    }
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Patch,
        steps,
    }
}

pub(crate) fn report_config_delete_transaction_plan() -> ReportConfigWriteTransactionPlan {
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Delete,
        steps: vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::MoveReportConfigToTrash,
        ],
    }
}
