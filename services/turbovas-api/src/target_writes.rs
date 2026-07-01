// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    target_handlers::load_target_detail,
    target_write_db::*,
    target_write_sql::*,
    target_write_validation::{
        TargetCloneRequest, TargetCreateRequest, TargetPatchRequest,
        ValidatedCredentialPatchAction, ValidatedTargetClone, ValidatedTargetCreate,
        ValidatedTargetCredentialsPatch, ValidatedTargetPatch, validate_target_clone_request,
        validate_target_create_request, validate_target_patch_request,
    },
    task_target_payloads::TargetItem,
};

const SSH_CREDENTIAL_TYPES: &[&str] = &["up", "usk", "cs_up", "cs_usk"];
const ELEVATE_CREDENTIAL_TYPES: &[&str] = &["up", "cs_up"];
const SMB_CREDENTIAL_TYPES: &[&str] = &["up", "cs_up"];
const ESXI_CREDENTIAL_TYPES: &[&str] = &["up", "cs_up"];
const SNMP_CREDENTIAL_TYPES: &[&str] = &["snmp", "cs_snmp"];
const KRB5_CREDENTIAL_TYPES: &[&str] = &["krb5"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedCredentialPatchAction {
    Set { internal_id: i32, port: i32 },
    Clear,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ResolvedTargetCredentialsPatch {
    ssh: Option<ResolvedCredentialPatchAction>,
    ssh_elevate: Option<ResolvedCredentialPatchAction>,
    smb: Option<ResolvedCredentialPatchAction>,
    esxi: Option<ResolvedCredentialPatchAction>,
    snmp: Option<ResolvedCredentialPatchAction>,
    krb5: Option<ResolvedCredentialPatchAction>,
}

pub(crate) async fn create_target(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin create target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE targets, port_lists IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_target_write_db_error(error, "lock targets for create"))?;
    ensure_unique_target_name(&tx, &request.name, -1, owner_id).await?;
    let port_list = load_assignable_target_port_list(&tx, &request.port_list_id, owner_id).await?;
    let record =
        execute_target_create_transaction(&tx, owner_id, port_list.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit create target transaction"))?;

    Ok((
        StatusCode::CREATED,
        target_write_location_headers(&record.uuid)?,
        Json(load_target_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn clone_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin clone target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_login_data, port_lists, credentials, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for clone"))?;
    let source = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(source.owner_id, owner_id)?;
    ensure_target_source_port_list_assignable(&tx, source.internal_id, owner_id).await?;
    ensure_target_source_credentials_assignable(&tx, source.internal_id, owner_id).await?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, -1, owner_id).await?;
    }
    let record =
        execute_target_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit clone target transaction"))?;

    Ok((
        StatusCode::CREATED,
        target_write_location_headers(&record.uuid)?,
        Json(load_target_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn delete_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin delete target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_trash, targets_login_data, targets_trash_login_data, tasks, scope_targets, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for delete"))?;
    let state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(state.owner_id, owner_id)?;
    ensure_target_not_in_use_for_delete(&tx, state.internal_id).await?;
    ensure_target_not_in_scope(&tx, state.internal_id).await?;
    execute_target_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit delete target transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_target_write_db_error(error, "begin hard-delete target transaction")
    })?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets_trash, targets_trash_login_data, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target trash tables for hard delete"))?;
    let trash = load_target_trash_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(trash.owner_id, owner_id)?;
    ensure_trash_target_not_in_use(&tx, trash.internal_id).await?;
    execute_target_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_target_write_db_error(error, "commit hard-delete target transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin restore target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_trash, targets_login_data, targets_trash_login_data, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for restore"))?;
    let trash = load_target_trash_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(trash.owner_id, owner_id)?;
    ensure_unique_live_target_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_target_uuid_not_live(&tx, &trash.uuid).await?;
    ensure_trash_target_references_live_resources(&tx, trash.internal_id).await?;
    let record = execute_target_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit restore target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
}

pub(crate) async fn patch_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetPatchRequest>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin patch target transaction"))?;
    let operator_owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_login_data, port_lists, credentials IN SHARE ROW EXCLUSIVE MODE;",
    )
        .await
        .map_err(|error| map_target_write_db_error(error, "lock targets for patch"))?;
    let target_state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(target_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, target_state.internal_id, target_state.owner_id)
            .await?;
    }
    let port_list_internal_id = if let Some(port_list_id) = request.port_list_id.as_ref() {
        Some(
            load_assignable_target_port_list(&tx, port_list_id, operator_owner_id)
                .await?
                .internal_id,
        )
    } else {
        None
    };
    if request.changes_task_in_use_guarded_scan_inputs() {
        ensure_target_not_in_use_for_scan_inputs(&tx, target_state.internal_id).await?;
    }
    let credential_links = if request.changes_credential_links() {
        ensure_target_not_in_use_for_scan_inputs(&tx, target_state.internal_id).await?;
        resolve_target_credential_link_changes(
            &tx,
            target_state.internal_id,
            operator_owner_id,
            &request.credentials,
        )
        .await?
    } else {
        ResolvedTargetCredentialsPatch::default()
    };
    let record = execute_target_patch_transaction(
        &tx,
        target_state.internal_id,
        &request,
        &port_list_internal_id,
        &credential_links,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit patch target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
}

async fn execute_target_patch_transaction(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    request: &ValidatedTargetPatch,
    port_list_internal_id: &Option<i32>,
    credential_links: &ResolvedTargetCredentialsPatch,
) -> Result<TargetWriteRecord, ApiError> {
    let record = if request.changes_target_metadata_or_scan_inputs() {
        query_target_write_record(
            tx,
            target_update_metadata_sql(),
            &[
                &target_internal_id,
                &request.name,
                &request.comment,
                &request.alive_test,
                &request.allow_simultaneous_ips,
                &request.reverse_lookup_only,
                &request.reverse_lookup_unify,
                port_list_internal_id,
                &request.hosts,
                &request.exclude_hosts,
            ],
            "update target metadata",
        )
        .await?
    } else {
        query_target_write_record(
            tx,
            target_uuid_by_internal_id_sql(),
            &[&target_internal_id],
            "load target uuid after credential patch",
        )
        .await?
    };
    apply_target_credential_link_changes(tx, target_internal_id, credential_links).await?;
    Ok(record)
}

async fn resolve_target_credential_link_changes(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    operator_owner_id: i32,
    patch: &ValidatedTargetCredentialsPatch,
) -> Result<ResolvedTargetCredentialsPatch, ApiError> {
    let resolved = ResolvedTargetCredentialsPatch {
        ssh: resolve_credential_patch_action(
            tx,
            patch.ssh.as_ref(),
            operator_owner_id,
            SSH_CREDENTIAL_TYPES,
            "credentials.ssh",
        )
        .await?,
        ssh_elevate: resolve_credential_patch_action(
            tx,
            patch.ssh_elevate.as_ref(),
            operator_owner_id,
            ELEVATE_CREDENTIAL_TYPES,
            "credentials.ssh_elevate",
        )
        .await?,
        smb: resolve_credential_patch_action(
            tx,
            patch.smb.as_ref(),
            operator_owner_id,
            SMB_CREDENTIAL_TYPES,
            "credentials.smb",
        )
        .await?,
        esxi: resolve_credential_patch_action(
            tx,
            patch.esxi.as_ref(),
            operator_owner_id,
            ESXI_CREDENTIAL_TYPES,
            "credentials.esxi",
        )
        .await?,
        snmp: resolve_credential_patch_action(
            tx,
            patch.snmp.as_ref(),
            operator_owner_id,
            SNMP_CREDENTIAL_TYPES,
            "credentials.snmp",
        )
        .await?,
        krb5: resolve_credential_patch_action(
            tx,
            patch.krb5.as_ref(),
            operator_owner_id,
            KRB5_CREDENTIAL_TYPES,
            "credentials.krb5",
        )
        .await?,
    };
    let final_ssh =
        final_target_credential_internal_id(tx, target_internal_id, "ssh", resolved.ssh.as_ref())
            .await?;
    let final_elevate = final_target_credential_internal_id(
        tx,
        target_internal_id,
        "elevate",
        resolved.ssh_elevate.as_ref(),
    )
    .await?;
    let final_smb =
        final_target_credential_internal_id(tx, target_internal_id, "smb", resolved.smb.as_ref())
            .await?;
    let final_krb5 =
        final_target_credential_internal_id(tx, target_internal_id, "krb5", resolved.krb5.as_ref())
            .await?;
    if final_elevate.is_some() && final_ssh.is_none() {
        return Err(ApiError::BadRequest(
            "credentials.ssh_elevate requires an ssh credential".to_string(),
        ));
    }
    if final_ssh.is_some() && final_ssh == final_elevate {
        return Err(ApiError::BadRequest(
            "credentials.ssh and credentials.ssh_elevate must be different credentials".to_string(),
        ));
    }
    if final_smb.is_some() && final_krb5.is_some() {
        return Err(ApiError::BadRequest(
            "credentials.smb and credentials.krb5 cannot both be assigned".to_string(),
        ));
    }
    Ok(resolved)
}

async fn resolve_credential_patch_action(
    tx: &Transaction<'_>,
    action: Option<&ValidatedCredentialPatchAction>,
    operator_owner_id: i32,
    allowed_types: &[&str],
    field_name: &'static str,
) -> Result<Option<ResolvedCredentialPatchAction>, ApiError> {
    match action {
        Some(ValidatedCredentialPatchAction::Set(link)) => {
            let credential = load_assignable_target_credential(
                tx,
                &link.id,
                operator_owner_id,
                allowed_types,
                field_name,
            )
            .await?;
            Ok(Some(ResolvedCredentialPatchAction::Set {
                internal_id: credential.internal_id,
                port: link.port.unwrap_or(0),
            }))
        }
        Some(ValidatedCredentialPatchAction::Clear) => {
            Ok(Some(ResolvedCredentialPatchAction::Clear))
        }
        None => Ok(None),
    }
}

async fn final_target_credential_internal_id(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    credential_use: &'static str,
    action: Option<&ResolvedCredentialPatchAction>,
) -> Result<Option<i32>, ApiError> {
    match action {
        Some(ResolvedCredentialPatchAction::Set { internal_id, .. }) => Ok(Some(*internal_id)),
        Some(ResolvedCredentialPatchAction::Clear) => Ok(None),
        None => {
            load_current_target_credential_internal_id(tx, target_internal_id, credential_use).await
        }
    }
}

async fn apply_target_credential_link_changes(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    patch: &ResolvedTargetCredentialsPatch,
) -> Result<(), ApiError> {
    apply_target_credential_patch_action(tx, target_internal_id, "ssh", patch.ssh.as_ref()).await?;
    apply_target_credential_patch_action(
        tx,
        target_internal_id,
        "elevate",
        patch.ssh_elevate.as_ref(),
    )
    .await?;
    apply_target_credential_patch_action(tx, target_internal_id, "smb", patch.smb.as_ref()).await?;
    apply_target_credential_patch_action(tx, target_internal_id, "esxi", patch.esxi.as_ref())
        .await?;
    apply_target_credential_patch_action(tx, target_internal_id, "snmp", patch.snmp.as_ref())
        .await?;
    apply_target_credential_patch_action(tx, target_internal_id, "krb5", patch.krb5.as_ref())
        .await?;
    Ok(())
}

async fn apply_target_credential_patch_action(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    credential_use: &'static str,
    action: Option<&ResolvedCredentialPatchAction>,
) -> Result<(), ApiError> {
    let Some(action) = action else {
        return Ok(());
    };
    execute_target_write_sql(
        tx,
        target_delete_login_data_by_type_sql(),
        &[&target_internal_id, &credential_use],
        "delete target credential link",
    )
    .await?;
    if let ResolvedCredentialPatchAction::Set { internal_id, port } = action {
        execute_target_write_sql(
            tx,
            target_insert_login_data_sql(),
            &[&target_internal_id, &credential_use, internal_id, port],
            "insert target credential link",
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn execute_target_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    port_list_internal_id: i32,
    request: &ValidatedTargetCreate,
) -> Result<TargetWriteRecord, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_create_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.hosts,
            &request.exclude_hosts,
            &request.reverse_lookup_only,
            &request.reverse_lookup_unify,
            &request.comment,
            &port_list_internal_id,
            &request.alive_test,
            &request.allow_simultaneous_ips,
        ],
        "create target metadata",
    )
    .await?;
    Ok(TargetWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_target_clone_transaction(
    tx: &Transaction<'_>,
    source_internal_id: i32,
    owner_id: i32,
    request: &ValidatedTargetClone,
) -> Result<TargetWriteRecord, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_clone_metadata_sql(),
        &[
            &source_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone target metadata",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_login_data_sql(),
        &[&source_internal_id, &record.internal_id],
        "clone target credential references",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_tags_sql(),
        &[&source_internal_id, &record.internal_id, &record.uuid],
        "clone target tag links",
    )
    .await?;
    Ok(TargetWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_target_trash_transaction(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_trash_insert_sql(),
        &[&target_internal_id],
        "move target metadata to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_login_data_insert_sql(),
        &[&record.internal_id, &target_internal_id],
        "move target credential references to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_task_relink_sql(),
        &[&record.internal_id, &target_internal_id],
        "relink trash tasks to trashed target",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_tag_locations_to_trash_sql(),
        &[&record.internal_id, &target_internal_id],
        "move target tag links to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &target_internal_id],
        "move trashed tag links to target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_login_data_sql(),
        &[&target_internal_id],
        "delete live target credential references after trash move",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_metadata_sql(),
        &[&target_internal_id],
        "delete live target after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_target_restore_transaction(
    tx: &Transaction<'_>,
    trash_target_internal_id: i32,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_restore_metadata_sql(),
        &[&trash_target_internal_id],
        "restore target metadata from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_restore_login_data_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore target credential references from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_restore_task_relink_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "relink trash tasks to restored target",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_tag_locations_to_live_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore target tag links from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_locations_to_live_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore trashed tag links from target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_login_data_sql(),
        &[&trash_target_internal_id],
        "delete target trash credential references after restore",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_metadata_sql(),
        &[&trash_target_internal_id],
        "delete target trash metadata after restore",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_target_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_target_internal_id: i32,
) -> Result<(), ApiError> {
    execute_target_write_sql(
        tx,
        target_trash_tag_delete_sql(),
        &[&trash_target_internal_id],
        "delete target trash tag links",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_trash_delete_sql(),
        &[&trash_target_internal_id],
        "delete trashed tag links to target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_login_data_sql(),
        &[&trash_target_internal_id],
        "delete target trash credential references for hard delete",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_metadata_sql(),
        &[&trash_target_internal_id],
        "delete target trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

fn target_write_location_headers(target_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/targets/{target_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}
