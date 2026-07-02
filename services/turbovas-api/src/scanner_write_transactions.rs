// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    scanner_write_db::{ScannerWriteRecord, query_scanner_write_record},
    scanner_write_sql::scanner_update_metadata_sql,
    scanner_write_validation::ValidatedScannerPatch,
};

pub(crate) async fn execute_scanner_patch_transaction(
    tx: &Transaction<'_>,
    scanner_internal_id: i32,
    request: &ValidatedScannerPatch,
) -> Result<ScannerWriteRecord, ApiError> {
    query_scanner_write_record(
        tx,
        scanner_update_metadata_sql(),
        &[&scanner_internal_id, &request.name, &request.comment],
        "update scanner metadata",
    )
    .await
}
