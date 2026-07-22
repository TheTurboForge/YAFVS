// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::{ApiError, mutation_committed_response_unavailable},
    gvmd_control::{gvmd_control_secret, gvmd_control_socket_path},
    task_clone_control::request_task_clone,
    task_handlers::{load_task_detail, load_task_detail_for_operator},
    task_target_payloads::TaskItem,
    task_write_db::*,
    task_write_transactions::{
        execute_task_create_transaction, execute_task_patch_transaction,
        execute_task_replace_transaction, execute_task_trash_transaction,
    },
    task_write_validation::{
        TaskCreateRequest, TaskPatchRequest, TaskReplaceRequest, validate_task_create_request,
        validate_task_patch_request, validate_task_replace_request,
    },
};

pub(crate) async fn clone_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<(StatusCode, HeaderMap, Json<TaskItem>), ApiError> {
    let operator = require_task_write_operator(operator)?;
    let control_secret = gvmd_control_secret()?;
    let cloned_task_id = request_task_clone(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &task_id,
    )
    .await?;
    let task = load_committed_task_detail_for_operator(&state, &cloned_task_id, &operator).await?;

    Ok((
        StatusCode::CREATED,
        task_write_location_headers(&cloned_task_id)?,
        Json(task),
    ))
}

pub(crate) async fn create_task(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TaskCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TaskItem>), ApiError> {
    let operator = require_task_write_operator(operator)?;
    let request = validate_task_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_task_write_db_error(error, "begin create task transaction"))?;
    let operator_owner_id = resolve_task_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, configs, scanners, schedules, alerts, tags, tag_resources, task_alerts, tasks, task_preferences IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_task_write_db_error(error, "lock task create tables"))?;
    ensure_unique_task_name(&tx, &request.name, -1, operator_owner_id).await?;
    let target = load_assignable_task_target(&tx, &request.target_id, operator_owner_id).await?;
    let config = load_assignable_task_config(&tx, &request.config_id, operator_owner_id).await?;
    let scanner = load_assignable_task_scanner(&tx, &request.scanner_id, operator_owner_id).await?;
    let (schedule_internal_id, schedule_next_time) = if let Some(schedule_id) =
        request.schedule_id.as_deref()
    {
        let schedule = load_assignable_task_schedule(&tx, schedule_id, operator_owner_id).await?;
        (schedule.internal_id, schedule.next_time)
    } else {
        (0, 0)
    };
    let mut alert_internal_ids = Vec::with_capacity(request.alert_ids.len());
    for alert_id in &request.alert_ids {
        let alert = load_assignable_task_alert(&tx, alert_id, operator_owner_id).await?;
        alert_internal_ids.push(alert.internal_id);
    }
    let tag_internal_id = if let Some(tag_id) = request.tag_id.as_deref() {
        Some(
            load_assignable_task_tag(&tx, tag_id, operator_owner_id)
                .await?
                .internal_id,
        )
    } else {
        None
    };
    let record = execute_task_create_transaction(
        &tx,
        operator_owner_id,
        target.internal_id,
        config.internal_id,
        scanner.internal_id,
        schedule_internal_id,
        schedule_next_time,
        &alert_internal_ids,
        tag_internal_id,
        &request,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_task_write_db_error(error, "commit create task transaction"))?;

    Ok((
        StatusCode::CREATED,
        task_write_location_headers(&record.uuid).map_err(|error| {
            mutation_committed_response_unavailable(error, "create task response header")
        })?,
        Json(
            load_task_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(error, "create task response reload")
                })?,
        ),
    ))
}

pub(crate) async fn patch_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TaskPatchRequest>,
) -> Result<Json<TaskItem>, ApiError> {
    let operator = require_task_write_operator(operator)?;
    let request = validate_task_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_task_write_db_error(error, "begin patch task transaction"))?;
    resolve_task_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE tasks IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_task_write_db_error(error, "lock tasks for patch"))?;
    let task_state = load_task_write_state(&tx, &task_id).await?;
    let task_owner_id = ensure_task_is_human_owned(task_state.owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_task_name(&tx, name, task_state.internal_id, task_owner_id).await?;
    }
    let record = execute_task_patch_transaction(&tx, task_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_task_write_db_error(error, "commit patch task transaction"))?;

    Ok(Json(
        load_task_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "patch task response reload")
            })?,
    ))
}

pub(crate) async fn replace_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TaskReplaceRequest>,
) -> Result<Json<TaskItem>, ApiError> {
    let operator = require_task_write_operator(operator)?;
    let request = validate_task_replace_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_task_write_db_error(error, "begin replace task transaction"))?;
    let operator_owner_id = resolve_task_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, configs, scanners, schedules, alerts, task_alerts, tasks, task_preferences IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_task_write_db_error(error, "lock task replacement tables"))?;
    let task_state = load_task_write_state(&tx, &task_id).await?;
    let task_owner_id = ensure_task_is_human_owned(task_state.owner_id)?;
    ensure_task_configuration_mutable(task_state.run_status, task_state.alterable)?;
    ensure_unique_task_name(&tx, &request.name, task_state.internal_id, task_owner_id).await?;
    let target = load_assignable_task_target(&tx, &request.target_id, operator_owner_id).await?;
    let config = load_assignable_task_config(&tx, &request.config_id, operator_owner_id).await?;
    let scanner = load_assignable_task_scanner(&tx, &request.scanner_id, operator_owner_id).await?;
    let (schedule_internal_id, schedule_next_time) = if let Some(schedule_id) =
        request.schedule_id.as_deref()
    {
        let schedule = load_assignable_task_schedule(&tx, schedule_id, operator_owner_id).await?;
        (schedule.internal_id, schedule.next_time)
    } else {
        (0, 0)
    };
    let mut alert_internal_ids = Vec::with_capacity(request.alert_ids.len());
    for alert_id in &request.alert_ids {
        alert_internal_ids.push(
            load_assignable_task_alert(&tx, alert_id, operator_owner_id)
                .await?
                .internal_id,
        );
    }
    let record = execute_task_replace_transaction(
        &tx,
        task_state.internal_id,
        target.internal_id,
        config.internal_id,
        scanner.internal_id,
        schedule_internal_id,
        schedule_next_time,
        &alert_internal_ids,
        &request,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_task_write_db_error(error, "commit replace task transaction"))?;

    Ok(Json(
        load_task_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "replace task response reload")
            })?,
    ))
}

pub(crate) async fn delete_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_task_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_task_write_db_error(error, "begin delete task transaction"))?;
    resolve_task_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tasks, reports, report_counts, results, results_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_task_write_db_error(error, "lock task trash tables"))?;
    let task_state = load_task_write_state(&tx, &task_id).await?;
    ensure_task_is_human_owned(task_state.owner_id)?;
    ensure_task_not_in_use_for_native_trash(task_state.run_status)?;
    execute_task_trash_transaction(&tx, task_state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_task_write_db_error(error, "commit delete task transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

fn task_write_location_headers(task_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location =
        HeaderValue::from_str(&format!("/api/v1/tasks/{task_id}")).map_err(|_| ApiError::Config)?;
    headers.insert(header::LOCATION, location);
    Ok(headers)
}

async fn load_committed_task_detail_for_operator(
    state: &AppState,
    task_id: &str,
    operator: &DirectApiOperator,
) -> Result<TaskItem, ApiError> {
    let client = state
        .pool
        .get()
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    load_task_detail_for_operator(&client, task_id, operator.user_uuid())
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)
}
