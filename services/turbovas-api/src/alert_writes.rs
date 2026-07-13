// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use uuid::Uuid;

use crate::{
    alert_payloads::AlertAssetItem,
    alert_write_db::*,
    alert_write_transactions::{
        execute_alert_clone_transaction, execute_alert_patch_transaction,
        execute_alert_trash_transaction,
    },
    alert_write_validation::{
        AlertCloneRequest, AlertCreateRequest, AlertPatchRequest, ValidatedAlertCreate,
        ValidatedAlertEmailCreate, ValidatedAlertSmbCreate, validate_alert_clone_request,
        validate_alert_create_request, validate_alert_patch_request,
    },
    alerts::load_alert_asset_detail,
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    gvmd_control::{
        ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response_bytes,
    },
};

pub(crate) async fn create_alert(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<AlertCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<AlertAssetItem>), ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let request = parse_alert_create_payload(payload)?;
    let request = validate_alert_create_request(request)?;
    let control_secret = gvmd_control_secret()?;
    let alert_id = match &request {
        ValidatedAlertCreate::Email(request) => {
            request_alert_email_create(
                &gvmd_control_socket_path(),
                &control_secret,
                operator.user_uuid(),
                request,
            )
            .await?
        }
        ValidatedAlertCreate::Smb(request) => {
            request_alert_smb_create(
                &gvmd_control_socket_path(),
                &control_secret,
                operator.user_uuid(),
                request,
            )
            .await?
        }
    };
    let client = state
        .pool
        .get()
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    let owner_matches = client
        .query_opt(
            concat!(
                "SELECT 1 FROM alerts a",
                " JOIN users u ON u.id = a.owner",
                " WHERE a.uuid = $1 AND u.uuid = $2;"
            ),
            &[&alert_id, &operator.user_uuid()],
        )
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?
        .is_some();
    if !owner_matches {
        tracing::warn!("created alert does not resolve to the authenticated operator");
        return Err(ApiError::MutationCommittedResponseUnavailable);
    }
    let alert = load_alert_asset_detail(&client, &alert_id)
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    Ok((StatusCode::CREATED, Json(alert)))
}

pub(crate) fn parse_alert_create_payload(
    payload: Result<Json<AlertCreateRequest>, JsonRejection>,
) -> Result<AlertCreateRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|_| {
        ApiError::BadRequest(
            "request body must be application/json matching AlertCreateRequest".to_string(),
        )
    })
}

pub(crate) async fn request_alert_email_create(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedAlertEmailCreate,
) -> Result<String, ApiError> {
    let command = alert_email_create_command(control_secret, operator_uuid, request);
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes()).await;
    let response = response.map_err(map_control_socket_error)?;
    parse_alert_create_response(&response)
}

pub(crate) fn alert_email_create_command(
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedAlertEmailCreate,
) -> ScrubbedControlFrame {
    let mut command = Vec::with_capacity(25_600);
    command.extend_from_slice(b"alert-email-create ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.push(if request.active { b'1' } else { b'0' });
    for field in [
        request.name.as_bytes(),
        request.comment.as_bytes(),
        request.status.as_str().as_bytes(),
        request.to_address.as_bytes(),
        request.from_address.as_bytes(),
        request.subject.as_bytes(),
    ] {
        command.push(b' ');
        append_alert_create_base64(&mut command, field);
    }
    command.push(b' ');
    command.push(b'0' + request.notice.control_token());
    for field in [
        request.recipient_credential_id.as_bytes(),
        request.report_format_id.as_bytes(),
        request.report_config_id.as_bytes(),
        request.message.as_bytes(),
    ] {
        command.push(b' ');
        append_alert_create_base64(&mut command, field);
    }
    command.push(b'\n');
    ScrubbedControlFrame::new(command)
}

pub(crate) async fn request_alert_smb_create(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedAlertSmbCreate,
) -> Result<String, ApiError> {
    let command = alert_smb_create_command(control_secret, operator_uuid, request);
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes()).await;
    let response = response.map_err(map_control_socket_error)?;
    parse_alert_create_response(&response)
}

pub(crate) fn alert_smb_create_command(
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedAlertSmbCreate,
) -> ScrubbedControlFrame {
    let mut command = Vec::with_capacity(25_600);
    command.extend_from_slice(b"alert-smb-create ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.push(if request.active { b'1' } else { b'0' });
    for field in [
        request.name.as_bytes(),
        request.comment.as_bytes(),
        request.status.as_str().as_bytes(),
        request.smb_credential_id.as_bytes(),
        request.smb_share_path.as_bytes(),
        request.smb_file_path.as_bytes(),
        request.report_format_id.as_bytes(),
        request.report_config_id.as_bytes(),
        request.smb_max_protocol.as_bytes(),
    ] {
        command.push(b' ');
        append_alert_create_base64(&mut command, field);
    }
    command.push(b'\n');
    ScrubbedControlFrame::new(command)
}

fn append_alert_create_base64(command: &mut Vec<u8>, value: &[u8]) {
    let start = command.len();
    let encoded_capacity = value.len().div_ceil(3) * 4;
    command.resize(start + encoded_capacity, 0);
    let written = STANDARD
        .encode_slice(value, &mut command[start..])
        .expect("preallocated base64 output must be sufficient");
    command.truncate(start + written);
}

pub(crate) fn parse_alert_create_response(response: &[u8]) -> Result<String, ApiError> {
    match response {
        b"1 exists" => Err(ApiError::Conflict(
            "An alert with this name already exists.".to_string(),
        )),
        b"2 invalid_email"
        | b"4 invalid_filter_type"
        | b"5 invalid_condition_name"
        | b"6 invalid_condition_data"
        | b"7 subject_too_long"
        | b"8 message_too_long"
        | b"12 invalid_send_host"
        | b"13 invalid_send_port"
        | b"15 invalid_scp_host"
        | b"16 invalid_scp_port"
        | b"18 invalid_scp_credential"
        | b"19 invalid_scp_path"
        | b"20 method_event_mismatch"
        | b"21 condition_event_mismatch"
        | b"31 invalid_event_name"
        | b"32 invalid_event_data"
        | b"40 invalid_smb_credential"
        | b"41 invalid_smb_share"
        | b"42 invalid_smb_path"
        | b"43 dotted_smb_path"
        | b"50 invalid_tp_credential"
        | b"51 invalid_tp_host"
        | b"52 invalid_tp_certificate"
        | b"53 invalid_tp_tls"
        | b"61 invalid_recipient_credential"
        | b"71 invalid_vfire_credential" => Err(ApiError::BadRequest(
            "The alert delivery request was rejected.".to_string(),
        )),
        b"3 filter_not_found"
        | b"9 condition_filter_not_found"
        | b"14 send_format_not_found"
        | b"17 scp_format_not_found"
        | b"60 recipient_credential_not_found"
        | b"70 vfire_credential_not_found" => Err(ApiError::NotFound),
        b"90 report_format_not_found" | b"91 report_config_not_found" => Err(ApiError::NotFound),
        b"92 report_config_mismatch" => Err(ApiError::BadRequest(
            "The report config does not belong to the selected report format.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The alert control request was rejected.".to_string(),
        )),
        b"-1 internal" => Err(ApiError::Database),
        b"-3 committed_indeterminate" => Err(ApiError::MutationCommittedResponseUnavailable),
        _ => parse_created_alert_id(response),
    }
}

fn parse_created_alert_id(response: &[u8]) -> Result<String, ApiError> {
    let Some(uuid) = response.strip_prefix(b"0 created ") else {
        return Err(ApiError::MutationOutcomeIndeterminate);
    };
    let uuid =
        std::str::from_utf8(uuid).map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    let uuid = Uuid::parse_str(uuid).map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    Ok(uuid.to_string())
}

pub(crate) async fn clone_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<AlertCloneRequest>,
) -> Result<(StatusCode, Json<AlertAssetItem>), ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let request = validate_alert_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_alert_write_db_error(error, "begin clone alert transaction"))?;
    let owner_id = resolve_alert_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE alerts, alert_condition_data, alert_event_data, alert_method_data, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_alert_write_db_error(error, "lock alert tables for clone"))?;
    let source = load_alert_write_state(&tx, &alert_id).await?;
    ensure_alert_owner_matches_operator(source.owner_id, owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_alert_name(&tx, name, -1).await?;
    }
    let record =
        execute_alert_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_alert_write_db_error(error, "commit clone alert transaction"))?;

    Ok((
        StatusCode::CREATED,
        Json(load_alert_asset_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn delete_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_alert_write_db_error(error, "begin delete alert transaction"))?;
    let operator_owner_id = resolve_alert_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE alerts, alerts_trash, alert_condition_data, alert_condition_data_trash, alert_event_data, alert_event_data_trash, alert_method_data, alert_method_data_trash, task_alerts, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_alert_write_db_error(error, "lock alert tables for delete"))?;
    let state = load_alert_write_state(&tx, &alert_id).await?;
    ensure_alert_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_alert_not_in_use_by_live_tasks(&tx, state.internal_id).await?;
    execute_alert_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_alert_write_db_error(error, "commit delete alert transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn patch_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<AlertPatchRequest>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let request = validate_alert_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_alert_write_db_error(error, "begin patch alert transaction"))?;
    let operator_owner_id = resolve_alert_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE alerts IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_alert_write_db_error(error, "lock alerts for patch"))?;
    let alert_state = load_alert_write_state(&tx, &alert_id).await?;
    ensure_alert_owner_matches_operator(alert_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_alert_name(&tx, name, alert_state.internal_id).await?;
    }
    let record = execute_alert_patch_transaction(&tx, alert_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_alert_write_db_error(error, "commit patch alert transaction"))?;

    Ok(Json(load_alert_asset_detail(&client, &record.uuid).await?))
}
