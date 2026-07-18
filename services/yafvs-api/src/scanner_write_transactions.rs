// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    scanner_write_db::{ScannerWriteRecord, query_scanner_write_record},
    scanner_write_sql::{
        scanner_create_configuration_sql, scanner_replace_configuration_sql,
        scanner_update_metadata_sql,
    },
    scanner_write_validation::{ValidatedScannerConfiguration, ValidatedScannerPatch},
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

pub(crate) async fn execute_scanner_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    credential_internal_id: Option<i32>,
    request: &ValidatedScannerConfiguration,
) -> Result<ScannerWriteRecord, ApiError> {
    query_scanner_write_record(
        tx,
        scanner_create_configuration_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.host,
            &request.port,
            &request.scanner_type,
            &request.ca_pub,
            &credential_internal_id,
        ],
        "create scanner configuration",
    )
    .await
}

pub(crate) async fn execute_scanner_replace_transaction(
    tx: &Transaction<'_>,
    scanner_internal_id: i32,
    credential_internal_id: Option<i32>,
    request: &ValidatedScannerConfiguration,
) -> Result<ScannerWriteRecord, ApiError> {
    query_scanner_write_record(
        tx,
        scanner_replace_configuration_sql(),
        &[
            &scanner_internal_id,
            &request.name,
            &request.comment,
            &request.host,
            &request.port,
            &request.scanner_type,
            &request.ca_pub,
            &credential_internal_id,
        ],
        "replace scanner configuration",
    )
    .await
}
