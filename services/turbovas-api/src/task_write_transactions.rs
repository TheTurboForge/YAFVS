// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    task_write_db::{TaskWriteRecord, query_task_write_record},
    task_write_sql::task_update_metadata_sql,
    task_write_validation::ValidatedTaskPatch,
};

pub(crate) async fn execute_task_patch_transaction(
    tx: &Transaction<'_>,
    task_internal_id: i32,
    request: &ValidatedTaskPatch,
) -> Result<TaskWriteRecord, ApiError> {
    query_task_write_record(
        tx,
        task_update_metadata_sql(),
        &[&task_internal_id, &request.name, &request.comment],
        "update task metadata",
    )
    .await
}
