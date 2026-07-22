// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    scanner_write_db::{
        ScannerWriteRecord, ScannerWriteRecordWithInternalId, map_scanner_write_db_error,
        query_scanner_write_record, query_scanner_write_record_with_internal_id,
    },
    scanner_write_sql::*,
    scanner_write_validation::{
        ValidatedScannerClone, ValidatedScannerConfiguration, ValidatedScannerPatch,
    },
};

async fn execute_scanner_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    action: &'static str,
) -> Result<(), ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scanner_write_db_error(error, action))?;
    Ok(())
}

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

pub(crate) async fn execute_scanner_clone_transaction(
    tx: &Transaction<'_>,
    source_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScannerClone,
) -> Result<ScannerWriteRecord, ApiError> {
    let record = query_scanner_write_record_with_internal_id(
        tx,
        scanner_clone_metadata_sql(),
        &[
            &source_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone scanner metadata",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_clone_tags_sql(),
        &[&source_internal_id, &record.internal_id, &record.uuid],
        "clone scanner tag links",
    )
    .await?;
    Ok(ScannerWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_scanner_trash_transaction(
    tx: &Transaction<'_>,
    scanner_internal_id: i32,
) -> Result<ScannerWriteRecordWithInternalId, ApiError> {
    let record = query_scanner_write_record_with_internal_id(
        tx,
        scanner_trash_insert_sql(),
        &[&scanner_internal_id],
        "move scanner metadata to trash",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_trash_task_relink_sql(),
        &[&record.internal_id, &scanner_internal_id],
        "relink tasks to trashed scanner",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scanner_internal_id],
        "move scanner tag links to trash",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scanner_internal_id],
        "move trashed tag links to scanner trash id",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_delete_live_metadata_sql(),
        &[&scanner_internal_id],
        "delete live scanner after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scanner_restore_transaction(
    tx: &Transaction<'_>,
    trash_scanner_internal_id: i32,
) -> Result<ScannerWriteRecordWithInternalId, ApiError> {
    let record = query_scanner_write_record_with_internal_id(
        tx,
        scanner_restore_metadata_sql(),
        &[&trash_scanner_internal_id],
        "restore scanner metadata from trash",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_restore_task_relink_sql(),
        &[&trash_scanner_internal_id, &record.internal_id],
        "relink tasks to restored scanner",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_tag_locations_to_live_sql(),
        &[&trash_scanner_internal_id, &record.internal_id],
        "restore scanner tag links from trash",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_trash_tag_locations_to_live_sql(),
        &[&trash_scanner_internal_id, &record.internal_id],
        "restore trashed tag links from scanner trash id",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_delete_trash_metadata_sql(),
        &[&trash_scanner_internal_id],
        "delete scanner trash metadata after restore",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scanner_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_scanner_internal_id: i32,
) -> Result<(), ApiError> {
    execute_scanner_write_sql(
        tx,
        scanner_trash_tag_delete_sql(),
        &[&trash_scanner_internal_id],
        "delete scanner trash tag links",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_trash_tag_trash_delete_sql(),
        &[&trash_scanner_internal_id],
        "delete trashed tag links to scanner trash id",
    )
    .await?;
    execute_scanner_write_sql(
        tx,
        scanner_delete_trash_metadata_sql(),
        &[&trash_scanner_internal_id],
        "hard-delete scanner trash metadata",
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
