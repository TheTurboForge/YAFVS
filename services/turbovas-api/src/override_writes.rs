// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    override_write_db::{
        ensure_override_owner_matches_operator, load_override_write_state,
        map_override_write_db_error, require_override_write_operator,
        resolve_override_write_operator_owner,
    },
    override_write_transactions::execute_override_trash_transaction,
};

pub(crate) async fn delete_override(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_override_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_override_write_db_error(error, "begin delete override transaction"))?;
    let operator_owner_id = resolve_override_write_operator_owner(&tx, &operator).await?;
    let override_state = load_override_write_state(&tx, &override_id).await?;
    ensure_override_owner_matches_operator(override_state.owner_id, operator_owner_id)?;
    execute_override_trash_transaction(&tx, &override_state).await?;
    tx.commit().await.map_err(|error| {
        map_override_write_db_error(error, "commit delete override transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[path = "override_writes_tests.rs"]
mod override_writes_tests;
