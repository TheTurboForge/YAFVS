// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    alert_write_db::{AlertWriteRecord, query_alert_write_record},
    alert_write_sql::alert_update_metadata_sql,
    alert_write_validation::ValidatedAlertPatch,
    errors::ApiError,
};

pub(crate) async fn execute_alert_patch_transaction(
    tx: &Transaction<'_>,
    alert_internal_id: i32,
    request: &ValidatedAlertPatch,
) -> Result<AlertWriteRecord, ApiError> {
    query_alert_write_record(
        tx,
        alert_update_metadata_sql(),
        &[&alert_internal_id, &request.name, &request.comment],
        "update alert metadata",
    )
    .await
}
