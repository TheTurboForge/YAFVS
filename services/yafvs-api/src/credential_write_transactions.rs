// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    credential_write_db::{
        CredentialWriteRecord, execute_credential_write_sql, query_credential_write_record,
        query_credential_write_record_with_internal_id,
    },
    credential_write_sql::*,
    credential_write_validation::ValidatedCredentialPatch,
    errors::ApiError,
};

pub(crate) async fn execute_credential_restore_transaction(
    tx: &Transaction<'_>,
    trash_internal_id: i32,
) -> Result<CredentialWriteRecord, ApiError> {
    let restored = query_credential_write_record_with_internal_id(
        tx,
        credential_restore_metadata_sql(),
        &[&trash_internal_id],
        "restore credential metadata",
    )
    .await?;
    for (sql, action) in [
        (
            credential_restore_data_sql(),
            "restore credential secret data",
        ),
        (
            credential_restore_target_references_sql(),
            "restore trash target credential references",
        ),
        (
            credential_restore_scanner_references_sql(),
            "restore trash scanner credential references",
        ),
        (
            credential_restore_tag_locations_sql(),
            "restore credential tag links",
        ),
        (
            credential_restore_trash_tag_locations_sql(),
            "restore trashed credential tag links",
        ),
    ] {
        execute_credential_write_sql(
            tx,
            sql,
            &[&trash_internal_id, &restored.internal_id],
            action,
        )
        .await?;
    }
    execute_credential_write_sql(
        tx,
        credential_delete_trash_data_sql(),
        &[&trash_internal_id],
        "delete restored credential trash data",
    )
    .await?;
    query_credential_write_record(
        tx,
        credential_delete_trash_metadata_sql(),
        &[&trash_internal_id],
        "delete restored credential trash metadata",
    )
    .await
}

pub(crate) async fn execute_credential_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_internal_id: i32,
) -> Result<CredentialWriteRecord, ApiError> {
    for (sql, action) in [
        (
            credential_delete_trash_tag_links_sql(),
            "delete credential trash tag links",
        ),
        (
            credential_delete_trash_trash_tag_links_sql(),
            "delete trashed tag links to credential trash id",
        ),
        (
            credential_delete_trash_data_sql(),
            "delete credential trash secret data",
        ),
    ] {
        execute_credential_write_sql(tx, sql, &[&trash_internal_id], action).await?;
    }
    query_credential_write_record(
        tx,
        credential_delete_trash_metadata_sql(),
        &[&trash_internal_id],
        "delete credential trash metadata",
    )
    .await
}

pub(crate) async fn execute_credential_patch_transaction(
    tx: &Transaction<'_>,
    credential_internal_id: i32,
    request: &ValidatedCredentialPatch,
) -> Result<CredentialWriteRecord, ApiError> {
    query_credential_write_record(
        tx,
        credential_update_metadata_sql(),
        &[&credential_internal_id, &request.name, &request.comment],
        "update credential metadata",
    )
    .await
}
