// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::{ApiError, mutation_committed_response_unavailable},
    scope_payload_rows::ScopeItem,
    scope_payloads::load_scope_detail,
    scope_write_db::*,
    scope_write_transactions::*,
    scope_write_validation::{
        ScopeCreateRequest, ScopePatchRequest, validate_scope_create_request,
        validate_scope_patch_request,
    },
};

pub(crate) async fn create_scope(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScopeCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScopeItem>), ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let request = validate_scope_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scope_write_db_error(error, "begin create scope transaction"))?;
    let owner_id = resolve_scope_write_operator_owner(&tx, &operator).await?;
    verify_scope_write_references_visible(&tx, &request.target_ids, &request.host_ids).await?;
    let record = execute_scope_create_transaction(&tx, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scope_write_db_error(error, "commit create scope transaction"))?;

    let scope = load_scope_detail(&client, &record.uuid)
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "create scope response reload")
        })?;
    Ok((
        StatusCode::CREATED,
        scope_write_location_headers(&record.uuid).map_err(|error| {
            mutation_committed_response_unavailable(error, "create scope response header")
        })?,
        Json(scope),
    ))
}

pub(crate) async fn patch_scope(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScopePatchRequest>,
) -> Result<Json<ScopeItem>, ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let request = validate_scope_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scope_write_db_error(error, "begin patch scope transaction"))?;
    resolve_scope_write_operator_owner(&tx, &operator).await?;
    let state = load_mutable_scope_write_state(&tx, &scope_id).await?;
    ensure_scope_is_human_owned(state.owner_id)?;
    verify_scope_write_references_visible(
        &tx,
        request.target_ids.as_deref().unwrap_or(&[]),
        request.host_ids.as_deref().unwrap_or(&[]),
    )
    .await?;
    let record = execute_scope_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scope_write_db_error(error, "commit patch scope transaction"))?;

    Ok(Json(
        load_scope_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "patch scope response reload")
            })?,
    ))
}

pub(crate) async fn delete_scope(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scope_write_db_error(error, "begin delete scope transaction"))?;
    resolve_scope_write_operator_owner(&tx, &operator).await?;
    let state = load_mutable_scope_write_state(&tx, &scope_id).await?;
    ensure_scope_is_human_owned(state.owner_id)?;
    ensure_scope_has_no_report_history(&tx, &state.uuid).await?;
    execute_scope_delete_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_scope_write_db_error(error, "commit delete scope transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

fn scope_write_location_headers(scope_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/scopes/{scope_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

#[cfg(test)]
#[path = "scope_writes_tests.rs"]
mod scope_writes_tests;
