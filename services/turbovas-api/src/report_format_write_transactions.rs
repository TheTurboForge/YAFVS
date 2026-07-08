// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    report_format_write_db::{ReportFormatWriteRecord, query_report_format_write_record},
    report_format_write_sql::report_format_update_metadata_sql,
    report_format_write_validation::ValidatedReportFormatPatch,
};

pub(crate) async fn execute_report_format_patch_transaction(
    tx: &Transaction<'_>,
    report_format_internal_id: i32,
    request: &ValidatedReportFormatPatch,
) -> Result<ReportFormatWriteRecord, ApiError> {
    query_report_format_write_record(
        tx,
        report_format_update_metadata_sql(),
        &[
            &report_format_internal_id,
            &request.name,
            &request.summary,
            &request.active,
        ],
        "update report format metadata",
    )
    .await
}
