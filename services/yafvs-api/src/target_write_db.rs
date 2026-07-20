// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, target_write_sql::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetWriteRecordWithInternalId {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetTrashState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
    pub(crate) name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssignableTargetPortList {
    pub(crate) internal_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssignableTargetCredential {
    pub(crate) internal_id: i32,
    pub(crate) credential_type: String,
}

pub(crate) fn require_target_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("target write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_target_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        target_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_target_write_db_error(error, "resolve target write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API target write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_target_write_state(
    tx: &Transaction<'_>,
    target_id: &str,
) -> Result<TargetWriteState, ApiError> {
    let target_id = parse_uuid(target_id)?.to_string();
    tx.query_opt(target_write_state_sql(), &[&target_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "load target write state"))?
        .map(|row| TargetWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_target_trash_state(
    tx: &Transaction<'_>,
    target_id: &str,
) -> Result<TargetTrashState, ApiError> {
    let target_id = parse_uuid(target_id)?.to_string();
    tx.query_opt(target_trash_state_sql(), &[&target_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "load target trash state"))?
        .map(|row| TargetTrashState {
            internal_id: row.get(0),
            uuid: row.get(1),
            owner_id: row.get(2),
            name: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn query_target_write_record_with_internal_id(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_target_write_db_error(error, action))?
        .map(|row| TargetWriteRecordWithInternalId {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn execute_target_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<(), ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_target_write_db_error(error, action))?;
    Ok(())
}

pub(crate) async fn ensure_unique_target_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            target_unique_name_sql(),
            &[&name, &except_internal_id, &owner_id],
        )
        .await
        .map_err(|error| map_target_write_db_error(error, "check target name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn load_assignable_target_credential(
    tx: &Transaction<'_>,
    credential_id: &str,
    operator_owner_id: i32,
    allowed_types: &[&str],
    field_name: &'static str,
) -> Result<AssignableTargetCredential, ApiError> {
    let credential_id = parse_uuid(credential_id)?.to_string();
    let Some(row) = tx
        .query_opt(target_assignable_credential_state_sql(), &[&credential_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "load target credential reference"))?
    else {
        return Err(ApiError::NotFound);
    };
    let internal_id: i32 = row.get(0);
    let owner_id: Option<i32> = row.get(1);
    let credential_type: String = row.get(2);
    if owner_id.is_none() {
        tracing::warn!(
            credential_owner_id = owner_id,
            operator_owner_id,
            field_name,
            "direct API target write rejects an ownerless credential"
        );
        return Err(ApiError::Forbidden);
    }
    if !allowed_types.contains(&credential_type.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} credential has unsupported type {credential_type}"
        )));
    }
    Ok(AssignableTargetCredential {
        internal_id,
        credential_type,
    })
}

pub(crate) async fn load_current_target_credential_internal_id(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    credential_use: &'static str,
) -> Result<Option<i32>, ApiError> {
    tx.query_opt(
        target_current_credential_sql(),
        &[&target_internal_id, &credential_use],
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "load current target credential"))
    .map(|row| row.map(|row| row.get(0)))
}

pub(crate) async fn ensure_target_not_in_use_for_delete(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(target_in_use_sql(), &[&target_internal_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "check target task references"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target cannot be deleted while it is used by a live task".to_string(),
        ))
    }
}

pub(crate) async fn ensure_target_not_in_scope(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(target_scope_membership_count_sql(), &[&target_internal_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "check target scope memberships"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target cannot be deleted while it belongs to a scope".to_string(),
        ))
    }
}

pub(crate) async fn ensure_trash_target_not_in_use(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(target_trash_task_count_sql(), &[&target_internal_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "check trash target task references"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target cannot be hard-deleted while trash tasks reference it".to_string(),
        ))
    }
}

pub(crate) async fn ensure_trash_target_references_live_resources(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            target_trash_blocked_reference_count_sql(),
            &[&target_internal_id],
        )
        .await
        .map_err(|error| map_target_write_db_error(error, "check target restore references"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target cannot be restored while its port list or credentials are in trash".to_string(),
        ))
    }
}

pub(crate) async fn ensure_target_uuid_not_live(
    tx: &Transaction<'_>,
    target_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(target_live_uuid_conflict_sql(), &[&target_uuid])
        .await
        .map_err(|error| map_target_write_db_error(error, "check live target uuid conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_target_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            target_trash_unique_live_owner_name_sql(),
            &[&name, &owner_id],
        )
        .await
        .map_err(|error| map_target_write_db_error(error, "check live target name conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_target_not_in_use_for_scan_inputs(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(target_in_use_sql(), &[&target_internal_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "check target task references"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "target scan settings cannot be changed while the target is used by a live task"
                .to_string(),
        ))
    }
}

pub(crate) async fn load_assignable_target_port_list(
    tx: &Transaction<'_>,
    port_list_id: &str,
    operator_owner_id: i32,
) -> Result<AssignableTargetPortList, ApiError> {
    let port_list_id = parse_uuid(port_list_id)?.to_string();
    let Some(row) = tx
        .query_opt(target_assignable_port_list_state_sql(), &[&port_list_id])
        .await
        .map_err(|error| map_target_write_db_error(error, "load target port list reference"))?
    else {
        return Err(ApiError::NotFound);
    };
    let internal_id: i32 = row.get(0);
    let owner_id: Option<i32> = row.get(1);
    let predefined = row.get::<_, i32>(2) != 0;
    if predefined || owner_id.is_some() {
        Ok(AssignableTargetPortList { internal_id })
    } else {
        tracing::warn!(
            port_list_owner_id = owner_id,
            operator_owner_id,
            "direct API target write rejects an ownerless port list"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn ensure_target_source_port_list_assignable(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            target_source_port_list_is_assignable_sql(),
            &[&target_internal_id],
        )
        .await
        .map_err(|error| map_target_write_db_error(error, "check target clone port list"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        tracing::warn!(
            target_internal_id,
            "direct API target clone source references an unassignable port list"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn ensure_target_source_credentials_assignable(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            target_source_unassignable_credential_count_sql(),
            &[&target_internal_id],
        )
        .await
        .map_err(|error| map_target_write_db_error(error, "check target clone credentials"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        tracing::warn!(
            target_internal_id,
            unassignable_credential_count = count,
            "direct API target clone source references unassignable credentials"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) fn ensure_target_is_human_owned(target_owner_id: Option<i32>) -> Result<i32, ApiError> {
    target_owner_id.ok_or_else(|| {
        tracing::warn!("direct API target write rejects an ownerless target");
        ApiError::Forbidden
    })
}

pub(crate) async fn query_target_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TargetWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_target_write_db_error(error, action))?
        .map(|row| TargetWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_target_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "target write database operation failed");
    ApiError::Database
}
