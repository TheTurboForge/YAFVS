// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    target_write_db::{
        TargetWriteRecord, TargetWriteRecordWithInternalId, execute_target_write_sql,
        load_assignable_target_credential, load_current_target_credential_internal_id,
        query_target_write_record, query_target_write_record_with_internal_id,
    },
    target_write_sql::*,
    target_write_validation::{
        ValidatedCredentialPatchAction, ValidatedTargetClone, ValidatedTargetCreate,
        ValidatedTargetCredentialsPatch, ValidatedTargetPatch,
    },
};

const SSH_CREDENTIAL_TYPES: &[&str] = &["up", "usk"];
const ELEVATE_CREDENTIAL_TYPES: &[&str] = &["up"];
const SMB_CREDENTIAL_TYPES: &[&str] = &["up"];
const ESXI_CREDENTIAL_TYPES: &[&str] = &["up"];
const SNMP_CREDENTIAL_TYPES: &[&str] = &["snmp"];
const KRB5_CREDENTIAL_TYPES: &[&str] = &["krb5"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedCredentialPatchAction {
    Set {
        internal_id: i32,
        port: i32,
        host_key_pins: String,
    },
    Clear,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedTargetCredentialsPatch {
    ssh: Option<ResolvedCredentialPatchAction>,
    ssh_elevate: Option<ResolvedCredentialPatchAction>,
    smb: Option<ResolvedCredentialPatchAction>,
    esxi: Option<ResolvedCredentialPatchAction>,
    snmp: Option<ResolvedCredentialPatchAction>,
    krb5: Option<ResolvedCredentialPatchAction>,
}

pub(crate) async fn execute_target_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    port_list_internal_id: i32,
    request: &ValidatedTargetCreate,
    credential_links: &ResolvedTargetCredentialsPatch,
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
    apply_target_credential_link_changes(tx, record.internal_id, credential_links).await?;
    Ok(TargetWriteRecord { uuid: record.uuid })
}

pub(crate) async fn resolve_target_create_credential_links(
    tx: &Transaction<'_>,
    operator_owner_id: i32,
    credentials: &ValidatedTargetCredentialsPatch,
) -> Result<ResolvedTargetCredentialsPatch, ApiError> {
    let resolved = ResolvedTargetCredentialsPatch {
        ssh: resolve_credential_patch_action(
            tx,
            credentials.ssh.as_ref(),
            operator_owner_id,
            SSH_CREDENTIAL_TYPES,
            "credentials.ssh",
        )
        .await?,
        ssh_elevate: resolve_credential_patch_action(
            tx,
            credentials.ssh_elevate.as_ref(),
            operator_owner_id,
            ELEVATE_CREDENTIAL_TYPES,
            "credentials.ssh_elevate",
        )
        .await?,
        smb: resolve_credential_patch_action(
            tx,
            credentials.smb.as_ref(),
            operator_owner_id,
            SMB_CREDENTIAL_TYPES,
            "credentials.smb",
        )
        .await?,
        esxi: resolve_credential_patch_action(
            tx,
            credentials.esxi.as_ref(),
            operator_owner_id,
            ESXI_CREDENTIAL_TYPES,
            "credentials.esxi",
        )
        .await?,
        snmp: resolve_credential_patch_action(
            tx,
            credentials.snmp.as_ref(),
            operator_owner_id,
            SNMP_CREDENTIAL_TYPES,
            "credentials.snmp",
        )
        .await?,
        krb5: resolve_credential_patch_action(
            tx,
            credentials.krb5.as_ref(),
            operator_owner_id,
            KRB5_CREDENTIAL_TYPES,
            "credentials.krb5",
        )
        .await?,
    };
    let final_ssh = resolved_credential_internal_id(resolved.ssh.as_ref());
    let final_elevate = resolved_credential_internal_id(resolved.ssh_elevate.as_ref());
    let final_smb = resolved_credential_internal_id(resolved.smb.as_ref());
    let final_krb5 = resolved_credential_internal_id(resolved.krb5.as_ref());
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

pub(crate) async fn execute_target_patch_transaction(
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

pub(crate) async fn resolve_target_credential_link_changes(
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
                host_key_pins: serde_json::to_string(&link.host_key_pins)
                    .map_err(|_| ApiError::Config)?,
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

fn resolved_credential_internal_id(action: Option<&ResolvedCredentialPatchAction>) -> Option<i32> {
    match action {
        Some(ResolvedCredentialPatchAction::Set { internal_id, .. }) => Some(*internal_id),
        Some(ResolvedCredentialPatchAction::Clear) | None => None,
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
    if let ResolvedCredentialPatchAction::Set {
        internal_id,
        port,
        host_key_pins,
    } = action
    {
        execute_target_write_sql(
            tx,
            target_insert_login_data_sql(),
            &[
                &target_internal_id,
                &credential_use,
                internal_id,
                port,
                host_key_pins,
            ],
            "insert target credential link",
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ELEVATE_CREDENTIAL_TYPES, ESXI_CREDENTIAL_TYPES, SMB_CREDENTIAL_TYPES,
        SNMP_CREDENTIAL_TYPES, SSH_CREDENTIAL_TYPES,
    };

    #[test]
    fn target_credential_links_accept_only_local_credential_types() {
        assert_eq!(SSH_CREDENTIAL_TYPES, ["up", "usk"]);
        assert_eq!(ELEVATE_CREDENTIAL_TYPES, ["up"]);
        assert_eq!(SMB_CREDENTIAL_TYPES, ["up"]);
        assert_eq!(ESXI_CREDENTIAL_TYPES, ["up"]);
        assert_eq!(SNMP_CREDENTIAL_TYPES, ["snmp"]);
    }
}
