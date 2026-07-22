// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
};

use crate::{
    alert_definition_db::{
        ensure_alert_definition_is_human_owned, ensure_alert_definition_revision_matches,
        ensure_snmp_community_preserve_allowed, ensure_unique_alert_definition_name,
        load_alert_definition, load_alert_definition_state_for_update,
        lock_alert_definition_references, map_alert_definition_commit_error,
        map_alert_definition_db_error, resolve_alert_definition_operator_owner,
    },
    alert_definition_payloads::{
        AlertDefinition, AlertDefinitionReplaceRequest, validate_alert_definition_replace_request,
    },
    alert_definition_transactions::execute_alert_definition_replace_transaction,
    alert_write_db::require_alert_write_operator,
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
};

pub(crate) async fn get_alert_definition(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<AlertDefinition>, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_alert_definition(&client, &alert_id, &operator).await?,
    ))
}

pub(crate) async fn put_alert_definition(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<AlertDefinitionReplaceRequest>, JsonRejection>,
) -> Result<Json<AlertDefinition>, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let request = parse_alert_definition_replace_payload(payload)?;
    let (expected_revision, request) = validate_alert_definition_replace_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_alert_definition_db_error(error, "begin alert definition replacement transaction")
    })?;
    resolve_alert_definition_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE alerts, alert_condition_data, alert_event_data, alert_method_data IN SHARE ROW EXCLUSIVE MODE; LOCK TABLE credentials_data IN SHARE MODE;",
    )
    .await
    .map_err(|error| {
        map_alert_definition_db_error(error, "lock alert definition replacement namespace")
    })?;
    let alert_state = load_alert_definition_state_for_update(&tx, &alert_id).await?;
    ensure_alert_definition_is_human_owned(alert_state.owner_id)?;
    ensure_alert_definition_revision_matches(&alert_state, &expected_revision)?;
    ensure_snmp_community_preserve_allowed(&alert_state, &request)?;
    ensure_unique_alert_definition_name(&tx, request.name(), alert_state.internal_id).await?;
    lock_alert_definition_references(&tx, &request).await?;
    let alert_id =
        execute_alert_definition_replace_transaction(&tx, alert_state.internal_id, &request)
            .await?;
    tx.commit().await.map_err(|error| {
        map_alert_definition_commit_error(error, "commit alert definition replacement transaction")
    })?;

    load_alert_definition(&client, &alert_id, &operator)
        .await
        .map(Json)
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)
}

pub(crate) fn parse_alert_definition_replace_payload(
    payload: Result<Json<AlertDefinitionReplaceRequest>, JsonRejection>,
) -> Result<AlertDefinitionReplaceRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|_| {
        ApiError::BadRequest(
            "request body must be application/json matching AlertDefinitionReplaceRequest"
                .to_string(),
        )
    })
}
