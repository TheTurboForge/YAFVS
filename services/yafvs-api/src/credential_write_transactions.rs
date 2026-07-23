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

pub(crate) async fn execute_credential_clone_transaction(
    tx: &Transaction<'_>,
    source_internal_id: i32,
    owner_id: i32,
) -> Result<CredentialWriteRecord, ApiError> {
    let cloned = query_credential_write_record_with_internal_id(
        tx,
        credential_clone_metadata_sql(),
        &[&source_internal_id, &owner_id],
        "clone credential metadata",
    )
    .await?;
    for (sql, action) in [
        (
            credential_clone_data_sql(),
            "clone credential secret data opaquely",
        ),
        (credential_clone_tags_sql(), "clone credential tag links"),
    ] {
        execute_credential_write_sql(tx, sql, &[&source_internal_id, &cloned.internal_id], action)
            .await?;
    }
    Ok(CredentialWriteRecord { uuid: cloned.uuid })
}

pub(crate) async fn execute_credential_trash_transaction(
    tx: &Transaction<'_>,
    credential_internal_id: i32,
) -> Result<(), ApiError> {
    let trash = query_credential_write_record_with_internal_id(
        tx,
        credential_trash_insert_sql(),
        &[&credential_internal_id],
        "move credential metadata to trash",
    )
    .await?;
    for (sql, action) in [
        (
            credential_trash_data_insert_sql(),
            "copy credential secret data to trash opaquely",
        ),
        (
            credential_trash_target_references_sql(),
            "relink trash target credential references",
        ),
        (
            credential_trash_scanner_references_sql(),
            "relink trash scanner credential references",
        ),
        (
            credential_tag_locations_to_trash_sql(),
            "move credential tag links to trash",
        ),
        (
            credential_trash_tag_locations_to_trash_sql(),
            "move trashed credential tag links to credential trash id",
        ),
    ] {
        execute_credential_write_sql(
            tx,
            sql,
            &[&credential_internal_id, &trash.internal_id],
            action,
        )
        .await?;
    }
    execute_credential_write_sql(
        tx,
        credential_delete_live_data_sql(),
        &[&credential_internal_id],
        "delete live credential secret data after trash copy",
    )
    .await?;
    execute_credential_write_sql(
        tx,
        credential_delete_live_metadata_sql(),
        &[&credential_internal_id],
        "delete live credential metadata after trash move",
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
