// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    alert_definition_payloads::{
        AlertDefinition, AlertDefinitionBase, ValidatedAlertDefinitionReplace,
        build_alert_definition,
    },
    alert_definition_sql::*,
    alert_write_validation::SensitiveAlertField,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlertDefinitionWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
    pub(crate) revision: String,
    pub(crate) method: i32,
    pub(crate) snmp_community_configured: bool,
}

pub(crate) async fn load_alert_definition<C>(
    client: &C,
    alert_id: &str,
    operator: &DirectApiOperator,
) -> Result<AlertDefinition, ApiError>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let alert_id = parse_uuid(alert_id)?.to_string();
    client
        .query_opt(
            alert_definition_operator_owner_sql(),
            &[&operator.user_uuid()],
        )
        .await
        .map_err(|error| map_alert_definition_db_error(error, "resolve alert definition operator"))?
        .map(|row| row.get::<_, i32>(0))
        .ok_or(ApiError::Forbidden)?;
    let row = client
        .query_opt(alert_definition_read_sql(), &[&alert_id])
        .await
        .map_err(|error| map_alert_definition_db_error(error, "load alert definition"))?
        .ok_or(ApiError::NotFound)?;
    let alert_owner_id: Option<i32> = row.get("owner_id");
    ensure_alert_definition_is_human_owned(alert_owner_id)?;
    let event: i32 = row.get("event");
    let condition: i32 = row.get("condition");
    let filter_id: Option<i32> = row.get("filter_id");
    if event != 1 || condition != 1 || !alert_definition_filter_is_retained(filter_id) {
        return Err(non_retained_definition());
    }
    let event_names: Vec<String> = row.get("event_names");
    let event_values: Vec<Option<String>> = row.get("event_values");
    let method_names: Vec<String> = row.get("method_names");
    let method_values: Vec<Option<String>> = row.get("method_values");
    if event_names.len() != event_values.len() || method_names.len() != method_values.len() {
        return Err(non_retained_definition());
    }
    build_alert_definition(
        AlertDefinitionBase {
            revision: row.get("revision"),
            name: row.get("name"),
            comment: row.get("comment"),
            active: row.get("active"),
            status: row.get("status"),
        },
        row.get("method"),
        row.get("condition_data_count"),
        row.get("snmp_community_configured"),
        event_names.into_iter().zip(event_values).collect(),
        method_names.into_iter().zip(method_values).collect(),
    )
}

pub(crate) fn alert_definition_filter_is_retained(filter_id: Option<i32>) -> bool {
    matches!(filter_id, None | Some(0))
}

pub(crate) async fn resolve_alert_definition_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        alert_definition_operator_owner_for_update_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| map_alert_definition_db_error(error, "lock alert definition operator"))?
    .map(|row| row.get(0))
    .ok_or(ApiError::Forbidden)
}

pub(crate) async fn load_alert_definition_state_for_update(
    tx: &Transaction<'_>,
    alert_id: &str,
) -> Result<AlertDefinitionWriteState, ApiError> {
    let alert_id = parse_uuid(alert_id)?.to_string();
    tx.query_opt(alert_definition_state_for_update_sql(), &[&alert_id])
        .await
        .map_err(|error| map_alert_definition_db_error(error, "lock alert definition target"))?
        .map(|row| AlertDefinitionWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
            revision: row.get(2),
            method: row.get(3),
            snmp_community_configured: row.get(4),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_alert_definition_revision_matches(
    state: &AlertDefinitionWriteState,
    expected_revision: &str,
) -> Result<(), ApiError> {
    if state.revision == expected_revision {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "alert definition changed after it was read; reload before saving".to_string(),
        ))
    }
}

pub(crate) fn ensure_alert_definition_is_human_owned(
    alert_owner_id: Option<i32>,
) -> Result<i32, ApiError> {
    alert_owner_id.ok_or_else(|| {
        tracing::warn!("alert definition request rejected an ownerless alert");
        ApiError::Forbidden
    })
}

pub(crate) fn ensure_snmp_community_preserve_allowed(
    state: &AlertDefinitionWriteState,
    request: &ValidatedAlertDefinitionReplace,
) -> Result<(), ApiError> {
    if request.preserves_snmp_community() && (state.method != 9 || !state.snmp_community_configured)
    {
        Err(ApiError::BadRequest(
            "snmp_community_mode preserve requires an existing SNMP community".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(crate) async fn ensure_unique_alert_definition_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            alert_definition_unique_name_sql(),
            &[&name, &except_internal_id],
        )
        .await
        .map_err(|error| {
            map_alert_definition_db_error(error, "check alert definition name uniqueness")
        })?
        .get(0);
    ensure_alert_definition_name_count_is_unique(count)
}

pub(crate) fn ensure_alert_definition_name_count_is_unique(
    conflicting_count: i64,
) -> Result<(), ApiError> {
    if conflicting_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "alert with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn lock_alert_definition_references(
    tx: &Transaction<'_>,
    request: &ValidatedAlertDefinitionReplace,
) -> Result<(), ApiError> {
    match request {
        ValidatedAlertDefinitionReplace::Email(request) => {
            let recipient_id = sensitive_text(&request.recipient_credential_id);
            if !recipient_id.is_empty() {
                let credential = load_credential_reference(tx, recipient_id).await?;
                ensure_human_owned_credential(&credential)?;
                if !matches!(credential.credential_type.as_str(), "pgp" | "smime") {
                    return Err(ApiError::BadRequest(
                        "recipient_credential_id must reference a PGP or S/MIME credential"
                            .to_string(),
                    ));
                }
            }
            let report_format_id = sensitive_text(&request.report_format_id);
            if !report_format_id.is_empty() {
                lock_report_format_reference(tx, report_format_id).await?;
            }
        }
        ValidatedAlertDefinitionReplace::Smb(request) => {
            let credential =
                load_credential_reference(tx, sensitive_text(&request.smb_credential_id)).await?;
            ensure_human_owned_credential(&credential)?;
            if credential.credential_type != "up" || !credential.smb_username_valid() {
                return Err(ApiError::BadRequest(
                    "smb_credential_id must reference an SMB-compatible username/password credential"
                        .to_string(),
                ));
            }
            lock_report_format_reference(tx, sensitive_text(&request.report_format_id)).await?;
        }
        ValidatedAlertDefinitionReplace::Scp(request) => {
            let credential =
                load_credential_reference(tx, sensitive_text(&request.scp_credential_id)).await?;
            ensure_human_owned_credential(&credential)?;
            if !matches!(credential.credential_type.as_str(), "up" | "usk")
                || !credential.scp_username_valid()
            {
                return Err(ApiError::BadRequest(
                    "scp_credential_id must reference an SCP-compatible credential".to_string(),
                ));
            }
            lock_report_format_reference(tx, sensitive_text(&request.report_format_id)).await?;
        }
        ValidatedAlertDefinitionReplace::StartTask(request) => {
            let task_id = sensitive_text(&request.task_id);
            let task_id = parse_uuid(task_id)?.to_string();
            let row = tx
                .query_opt(alert_definition_task_reference_sql(), &[&task_id])
                .await
                .map_err(|error| {
                    map_alert_definition_db_error(error, "lock alert definition task reference")
                })?
                .ok_or(ApiError::NotFound)?;
            let task_owner_id: Option<i32> = row.get(1);
            task_owner_id.ok_or(ApiError::Forbidden)?;
        }
        ValidatedAlertDefinitionReplace::Syslog(_) | ValidatedAlertDefinitionReplace::Snmp(_) => {}
    }
    Ok(())
}

struct CredentialReference {
    owner_id: Option<i32>,
    credential_type: String,
    username: String,
    username_count: i64,
}

impl CredentialReference {
    fn smb_username_valid(&self) -> bool {
        self.username_count == 1
            && !self.username.is_empty()
            && !self.username.contains(['@', ':', '\r', '\n'])
    }

    fn scp_username_valid(&self) -> bool {
        self.username_count == 1
            && !self.username.is_empty()
            && !self.username.contains([':', '\r', '\n'])
    }
}

async fn load_credential_reference(
    tx: &Transaction<'_>,
    credential_id: &str,
) -> Result<CredentialReference, ApiError> {
    let credential_id = parse_uuid(credential_id)?.to_string();
    tx.query_opt(
        alert_definition_credential_reference_sql(),
        &[&credential_id],
    )
    .await
    .map_err(|error| {
        map_alert_definition_db_error(error, "lock alert definition credential reference")
    })?
    .map(|row| CredentialReference {
        owner_id: row.get(1),
        credential_type: row.get(2),
        username: row.get(3),
        username_count: row.get(4),
    })
    .ok_or(ApiError::NotFound)
}

fn ensure_human_owned_credential(credential: &CredentialReference) -> Result<(), ApiError> {
    if credential.owner_id.is_some() {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

async fn lock_report_format_reference(
    tx: &Transaction<'_>,
    report_format_id: &str,
) -> Result<(), ApiError> {
    let report_format_id = parse_uuid(report_format_id)?.to_string();
    tx.query_opt(
        alert_definition_report_format_reference_sql(),
        &[&report_format_id],
    )
    .await
    .map_err(|error| {
        map_alert_definition_db_error(error, "lock alert definition report format reference")
    })?
    .ok_or(ApiError::NotFound)?;
    Ok(())
}

pub(crate) fn sensitive_text(value: &SensitiveAlertField) -> &str {
    std::str::from_utf8(value.as_bytes()).expect("validated alert definition text")
}

pub(crate) fn map_alert_definition_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(action, database_code = ?error.code(), "alert definition database operation failed");
    ApiError::Database
}

pub(crate) fn map_alert_definition_commit_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::error!(action, database_code = ?error.code(), "alert definition commit outcome is indeterminate");
    ApiError::MutationOutcomeIndeterminate
}

fn non_retained_definition() -> ApiError {
    ApiError::Conflict("alert is not a retained fixed task-status definition".to_string())
}
