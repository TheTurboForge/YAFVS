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
    errors::ApiError,
    gvmd_control::{gvmd_control_secret, gvmd_control_socket_path},
    path_ids::parse_uuid,
    tag_control::{request_tag_modify, request_tag_resource_update},
    tag_payloads::TagAssetItem,
    tag_write_db::*,
    tag_write_transactions::*,
    tag_write_validation::{
        TagCloneRequest, TagCreateRequest, TagPatchRequest, TagResourceUpdateRequest,
        ValidatedTagResourceSelection, validate_tag_clone_request, validate_tag_create_request,
        validate_tag_patch_request, validate_tag_resource_update_request,
    },
};

pub(crate) async fn create_tag(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin create tag transaction"))?;
    let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    let record = execute_tag_create_transaction(&tx, owner_id, &request).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit create tag transaction"))?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn restore_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin restore tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags, tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag tables for restore"))?;
    let trash = load_tag_trash_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(trash.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;
    ensure_tag_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_tag_restore_transaction(&tx, trash.internal_id).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit restore tag transaction"))?;

    Ok(Json(tag))
}

pub(crate) async fn hard_delete_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin hard-delete tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag trash tables for hard delete"))?;
    let trash = load_tag_trash_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(trash.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;
    execute_tag_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit hard-delete tag transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn patch_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagPatchRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_patch_request(request)?;
    parse_uuid(&tag_id)?;
    if tag_patch_requires_control(&request) {
        let control_secret = gvmd_control_secret()?;
        request_tag_modify(
            &gvmd_control_socket_path(),
            &control_secret,
            operator.user_uuid(),
            &tag_id,
            &request,
        )
        .await?;
        return Ok(Json(load_committed_tag_detail(&state, &tag_id).await?));
    }
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin patch tag transaction"))?;
    let selection = request
        .resources
        .as_ref()
        .and_then(|value| value.resource_selection.as_ref());
    if let Some(credential_selection @ ValidatedTagResourceSelection::Credential { .. }) = selection
    {
        // Stabilize owner-name search without taking an incompatible
        // credentials table lock. Credential rows are locked before tag tables
        // to match inherited credential deletion order.
        tx.batch_execute("LOCK TABLE users IN SHARE MODE;")
            .await
            .map_err(|error| {
                map_tag_write_db_error(error, "lock credential owners for tag patch")
            })?;
        resolve_tag_write_operator_owner(&tx, &operator).await?;
        let resources = resolve_tag_credential_selection_records(&tx, credential_selection).await?;
        tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
            .await
            .map_err(|error| map_tag_write_db_error(error, "lock tag tables for patch"))?;
        let state = load_tag_write_state(&tx, &tag_id).await?;
        ensure_tag_is_human_owned(state.owner_id)?;
        let effective_resource_type = request
            .resource_type
            .as_deref()
            .unwrap_or(&state.resource_type);
        ensure_tag_resource_direct_write_type_is_supported(effective_resource_type)?;
        if state.resource_type != "credential" || effective_resource_type != "credential" {
            return Err(ApiError::BadRequest(
                "resource_selection requires a credential tag".to_string(),
            ));
        }
        let record =
            execute_tag_patch_with_resolved_resources(&tx, &state, &request, Some(resources))
                .await?;
        let tag = load_tag_write_detail(&tx, &record.uuid).await?;
        tx.commit()
            .await
            .map_err(|error| map_tag_commit_error(error, "commit patch tag transaction"))?;
        return Ok(Json(tag));
    }
    tx.batch_execute(tag_resource_update_lock_sql(selection))
        .await
        .map_err(|error| map_tag_write_db_error(error, "lock tag tables for patch"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(state.owner_id)?;
    let effective_resource_type = request
        .resource_type
        .as_deref()
        .unwrap_or(&state.resource_type);
    ensure_tag_resource_direct_write_type_is_supported(effective_resource_type)?;
    if let Some(selection) = selection {
        let required_type = selection.resource_type();
        if state.resource_type != required_type || effective_resource_type != required_type {
            return Err(ApiError::BadRequest(format!(
                "resource_selection requires a {required_type} tag"
            )));
        }
    }
    let record = execute_tag_patch_transaction(&tx, &state, &request).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit patch tag transaction"))?;

    Ok(Json(tag))
}

fn tag_resource_update_lock_sql(selection: Option<&ValidatedTagResourceSelection>) -> &'static str {
    match selection {
        Some(ValidatedTagResourceSelection::PortList { .. }) => {
            // Port-list writers acquire port_lists before tag_resources. Keep
            // the same global order here so concurrent lifecycle and selection
            // writes cannot form a table-lock cycle.
            "LOCK TABLE port_lists, tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;"
        }
        Some(ValidatedTagResourceSelection::Credential { .. }) => {
            unreachable!("credential selections use row locks before tag tables")
        }
        None => "LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    }
}

fn tag_patch_requires_control(request: &crate::tag_write_validation::ValidatedTagPatch) -> bool {
    request
        .resources
        .as_ref()
        .is_some_and(|resources| resources.resource_filter.is_some())
}

pub(crate) async fn clone_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin clone tag transaction"))?;
    let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_tag_write_db_error(error, "lock tag tables for clone"))?;
    let source = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(source.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&source.resource_type)?;
    let record = execute_tag_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit clone tag transaction"))?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn delete_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin delete tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags, tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag tables for delete"))?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(state.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    execute_tag_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit delete tag transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn update_tag_resources(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagResourceUpdateRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_resource_update_request(request)?;
    parse_uuid(&tag_id)?;
    if request.resource_filter.is_some() {
        let control_secret = gvmd_control_secret()?;
        request_tag_resource_update(
            &gvmd_control_socket_path(),
            &control_secret,
            operator.user_uuid(),
            &tag_id,
            &request,
        )
        .await?;
        return Ok(Json(load_committed_tag_detail(&state, &tag_id).await?));
    }
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin tag resource transaction"))?;
    if let Some(credential_selection @ ValidatedTagResourceSelection::Credential { .. }) =
        request.resource_selection.as_ref()
    {
        tx.batch_execute("LOCK TABLE users IN SHARE MODE;")
            .await
            .map_err(|error| {
                map_tag_write_db_error(error, "lock credential owners for tag resource update")
            })?;
        resolve_tag_write_operator_owner(&tx, &operator).await?;
        let resources = resolve_tag_credential_selection_records(&tx, credential_selection).await?;
        tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
            .await
            .map_err(|error| map_tag_write_db_error(error, "lock tag resource tables"))?;
        let state = load_tag_write_state(&tx, &tag_id).await?;
        ensure_tag_is_human_owned(state.owner_id)?;
        ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
        if state.resource_type != "credential" {
            return Err(ApiError::BadRequest(
                "resource_selection requires a credential tag".to_string(),
            ));
        }
        apply_tag_resource_update_transaction(&tx, &state, &request, resources).await?;
        let tag = load_tag_write_detail(&tx, &state.uuid).await?;
        tx.commit()
            .await
            .map_err(|error| map_tag_commit_error(error, "commit tag resource transaction"))?;
        return Ok(Json(tag));
    }
    tx.batch_execute(tag_resource_update_lock_sql(
        request.resource_selection.as_ref(),
    ))
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag resource tables"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(state.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    if let Some(selection) = request.resource_selection.as_ref() {
        let required_type = selection.resource_type();
        if state.resource_type != required_type {
            return Err(ApiError::BadRequest(format!(
                "resource_selection requires a {required_type} tag"
            )));
        }
    }
    execute_tag_resource_update_transaction(&tx, &state, &request).await?;
    let tag = load_tag_write_detail(&tx, &state.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit tag resource transaction"))?;

    Ok(Json(tag))
}

async fn load_committed_tag_detail(
    state: &AppState,
    tag_id: &str,
) -> Result<TagAssetItem, ApiError> {
    let client = state
        .pool
        .get()
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    load_tag_write_detail(&client, tag_id)
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)
}

fn tag_write_location_headers(tag_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/tags/{tag_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

#[cfg(test)]
#[path = "tag_writes_tests.rs"]
mod tag_writes_tests;
