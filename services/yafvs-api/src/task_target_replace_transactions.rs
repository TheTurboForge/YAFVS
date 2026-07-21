// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    target_write_db::{
        TargetWriteRecordWithInternalId, execute_target_write_sql,
        query_target_write_record_with_internal_id,
    },
    target_write_sql::{target_clone_login_data_sql, target_clone_tags_sql},
    target_write_transactions::execute_target_trash_transaction,
    task_status::TaskStatus,
    task_target_replace_db::task_target_replace_source_is_unreferenced,
    task_target_replace_sql::*,
    task_target_replace_validation::ValidatedTaskTargetReplace,
    task_write_db::query_task_write_record,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OldTargetDisposition {
    Trashed,
    Retained,
}

pub(crate) async fn execute_task_target_replace_transaction(
    tx: &Transaction<'_>,
    task_internal_id: i32,
    source_target_internal_id: i32,
    owner_id: i32,
    request: &ValidatedTaskTargetReplace,
) -> Result<(TargetWriteRecordWithInternalId, OldTargetDisposition), ApiError> {
    let new_target = query_target_write_record_with_internal_id(
        tx,
        task_target_replace_clone_metadata_sql(),
        &[
            &source_target_internal_id,
            &owner_id,
            &request.hosts,
            &request.exclude_hosts,
        ],
        "clone replacement target metadata",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_login_data_sql(),
        &[&source_target_internal_id, &new_target.internal_id],
        "clone replacement target credential references",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_tags_sql(),
        &[
            &source_target_internal_id,
            &new_target.internal_id,
            &new_target.uuid,
        ],
        "clone replacement target tags",
    )
    .await?;
    let done_status = TaskStatus::Done.as_i32();
    let new_status = TaskStatus::New.as_i32();
    query_task_write_record(
        tx,
        task_target_replace_task_rebind_sql(),
        &[
            &task_internal_id,
            &new_target.internal_id,
            &source_target_internal_id,
            &done_status,
            &new_status,
        ],
        "rebind task to replacement target",
    )
    .await?;

    let disposition =
        if task_target_replace_source_is_unreferenced(tx, source_target_internal_id).await? {
            execute_target_trash_transaction(tx, source_target_internal_id).await?;
            OldTargetDisposition::Trashed
        } else {
            OldTargetDisposition::Retained
        };
    Ok((new_target, disposition))
}
