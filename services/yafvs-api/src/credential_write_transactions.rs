// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    credential_write_db::{CredentialWriteRecord, query_credential_write_record},
    credential_write_sql::credential_update_metadata_sql,
    credential_write_validation::ValidatedCredentialPatch,
    errors::ApiError,
};

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
