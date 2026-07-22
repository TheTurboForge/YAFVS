// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
};

use crate::{
    app_state::AppState, auth::DirectApiOperator, errors::ApiError, tls_certificate_write_db::*,
    tls_certificate_write_transactions::execute_tls_certificate_delete_transaction,
};

pub(crate) async fn delete_tls_certificate(
    State(state): State<AppState>,
    Path(certificate_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tls_certificate_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_tls_certificate_write_db_error(error, "begin delete TLS certificate transaction")
    })?;
    resolve_tls_certificate_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tls_certificates, tls_certificate_sources, tls_certificate_locations, tls_certificate_origins, permissions, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tls_certificate_write_db_error(error, "lock TLS certificate delete tables"))?;
    let certificate_state = load_tls_certificate_write_state(&tx, &certificate_id).await?;
    ensure_tls_certificate_is_human_owned(certificate_state.owner_id)?;
    execute_tls_certificate_delete_transaction(&tx, certificate_state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_tls_certificate_write_db_error(error, "commit delete TLS certificate transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}
