// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::{Statement, Transaction};

use crate::{
    alert_definition_db::{map_alert_definition_db_error, sensitive_text},
    alert_definition_payloads::{ValidatedAlertDefinitionReplace, ValidatedSnmpCommunity},
    alert_definition_sql::*,
    alert_write_validation::AlertEmailNoticeMode,
    errors::ApiError,
};

pub(crate) async fn execute_alert_definition_replace_transaction(
    tx: &Transaction<'_>,
    alert_internal_id: i32,
    request: &ValidatedAlertDefinitionReplace,
) -> Result<String, ApiError> {
    let method = method_id(request);
    let (name, comment, active, status) = common_fields(request);
    let active = alert_definition_active_database_value(active);
    let row = tx
        .query_one(
            alert_definition_update_metadata_sql(),
            &[&alert_internal_id, &name, &comment, &active, &method],
        )
        .await
        .map_err(|error| {
            map_alert_definition_db_error(error, "replace alert definition metadata")
        })?;
    execute_sql(
        tx,
        alert_definition_delete_condition_data_sql(),
        &[&alert_internal_id],
        "clear alert definition condition data",
    )
    .await?;
    execute_sql(
        tx,
        alert_definition_delete_event_data_sql(),
        &[&alert_internal_id],
        "clear alert definition event data",
    )
    .await?;
    let preserve_community = request.preserves_snmp_community();
    execute_sql(
        tx,
        alert_definition_delete_method_data_sql(),
        &[&alert_internal_id, &preserve_community],
        "clear alert definition method data",
    )
    .await?;

    let event_statement = tx
        .prepare(alert_definition_insert_event_data_sql())
        .await
        .map_err(|error| {
            map_alert_definition_db_error(error, "prepare alert definition event insert")
        })?;
    insert_data(tx, &event_statement, alert_internal_id, "status", status).await?;
    let method_statement = tx
        .prepare(alert_definition_insert_method_data_sql())
        .await
        .map_err(|error| {
            map_alert_definition_db_error(error, "prepare alert definition method insert")
        })?;
    insert_method_data(tx, &method_statement, alert_internal_id, request).await?;
    Ok(row.get(0))
}

pub(crate) fn alert_definition_active_database_value(active: bool) -> i32 {
    if active { 1 } else { 0 }
}

fn method_id(request: &ValidatedAlertDefinitionReplace) -> i32 {
    match request {
        ValidatedAlertDefinitionReplace::Email(_) => 1,
        ValidatedAlertDefinitionReplace::StartTask(_) => 4,
        ValidatedAlertDefinitionReplace::Syslog(_) => 5,
        ValidatedAlertDefinitionReplace::Scp(_) => 8,
        ValidatedAlertDefinitionReplace::Snmp(_) => 9,
        ValidatedAlertDefinitionReplace::Smb(_) => 10,
    }
}

fn common_fields(request: &ValidatedAlertDefinitionReplace) -> (&str, &str, bool, &str) {
    match request {
        ValidatedAlertDefinitionReplace::Email(request) => (
            &request.name,
            &request.comment,
            request.active,
            request.status.as_str(),
        ),
        ValidatedAlertDefinitionReplace::Smb(request) => (
            &request.name,
            &request.comment,
            request.active,
            request.status.as_str(),
        ),
        ValidatedAlertDefinitionReplace::Syslog(request) => (
            &request.name,
            &request.comment,
            request.active,
            request.status.as_str(),
        ),
        ValidatedAlertDefinitionReplace::Snmp(request) => (
            &request.name,
            &request.comment,
            request.active,
            request.status.as_str(),
        ),
        ValidatedAlertDefinitionReplace::Scp(request) => (
            &request.name,
            &request.comment,
            request.active,
            request.status.as_str(),
        ),
        ValidatedAlertDefinitionReplace::StartTask(request) => (
            &request.name,
            &request.comment,
            request.active,
            request.status.as_str(),
        ),
    }
}

async fn insert_method_data(
    tx: &Transaction<'_>,
    statement: &Statement,
    alert_id: i32,
    request: &ValidatedAlertDefinitionReplace,
) -> Result<(), ApiError> {
    match request {
        ValidatedAlertDefinitionReplace::Email(request) => {
            insert_data(
                tx,
                statement,
                alert_id,
                "to_address",
                sensitive_text(&request.to_address),
            )
            .await?;
            insert_nonempty(
                tx,
                statement,
                alert_id,
                "from_address",
                sensitive_text(&request.from_address),
            )
            .await?;
            insert_data(
                tx,
                statement,
                alert_id,
                "subject",
                sensitive_text(&request.subject),
            )
            .await?;
            let notice = match request.notice {
                AlertEmailNoticeMode::Simple => "1",
                AlertEmailNoticeMode::Include => "0",
                AlertEmailNoticeMode::Attach => "2",
            };
            insert_data(tx, statement, alert_id, "notice", notice).await?;
            insert_nonempty(
                tx,
                statement,
                alert_id,
                "recipient_credential",
                sensitive_text(&request.recipient_credential_id),
            )
            .await?;
            match request.notice {
                AlertEmailNoticeMode::Simple => {}
                AlertEmailNoticeMode::Include => {
                    insert_data(
                        tx,
                        statement,
                        alert_id,
                        "notice_report_format",
                        sensitive_text(&request.report_format_id),
                    )
                    .await?;
                }
                AlertEmailNoticeMode::Attach => {
                    insert_data(
                        tx,
                        statement,
                        alert_id,
                        "notice_attach_format",
                        sensitive_text(&request.report_format_id),
                    )
                    .await?;
                }
            }
            insert_nonempty(
                tx,
                statement,
                alert_id,
                "message",
                sensitive_text(&request.message),
            )
            .await?;
        }
        ValidatedAlertDefinitionReplace::Smb(request) => {
            for (name, value) in [
                ("smb_credential", sensitive_text(&request.smb_credential_id)),
                ("smb_share_path", sensitive_text(&request.smb_share_path)),
                ("smb_file_path", sensitive_text(&request.smb_file_path)),
                (
                    "smb_report_format",
                    sensitive_text(&request.report_format_id),
                ),
            ] {
                insert_data(tx, statement, alert_id, name, value).await?;
            }
            let max_protocol = std::str::from_utf8(request.smb_max_protocol.as_bytes())
                .expect("static SMB protocol token");
            insert_nonempty(tx, statement, alert_id, "smb_max_protocol", max_protocol).await?;
        }
        ValidatedAlertDefinitionReplace::Syslog(_) => {
            insert_data(tx, statement, alert_id, "submethod", "syslog").await?;
        }
        ValidatedAlertDefinitionReplace::Snmp(request) => {
            insert_data(
                tx,
                statement,
                alert_id,
                "snmp_agent",
                sensitive_text(&request.snmp_agent),
            )
            .await?;
            if let ValidatedSnmpCommunity::Replace(community) = &request.community {
                insert_data(
                    tx,
                    statement,
                    alert_id,
                    "snmp_community",
                    sensitive_text(community),
                )
                .await?;
            }
            insert_data(
                tx,
                statement,
                alert_id,
                "snmp_message",
                sensitive_text(&request.snmp_message),
            )
            .await?;
        }
        ValidatedAlertDefinitionReplace::Scp(request) => {
            let port = request.scp_port.to_string();
            for (name, value) in [
                ("scp_credential", sensitive_text(&request.scp_credential_id)),
                ("scp_host", sensitive_text(&request.scp_host)),
                ("scp_port", port.as_str()),
                ("scp_known_hosts", sensitive_text(&request.scp_known_hosts)),
                ("scp_path", sensitive_text(&request.scp_path)),
                (
                    "scp_report_format",
                    sensitive_text(&request.report_format_id),
                ),
            ] {
                insert_data(tx, statement, alert_id, name, value).await?;
            }
        }
        ValidatedAlertDefinitionReplace::StartTask(request) => {
            insert_data(
                tx,
                statement,
                alert_id,
                "start_task_task",
                sensitive_text(&request.task_id),
            )
            .await?;
        }
    }
    Ok(())
}

async fn insert_nonempty(
    tx: &Transaction<'_>,
    statement: &Statement,
    alert_id: i32,
    name: &str,
    value: &str,
) -> Result<(), ApiError> {
    if !value.is_empty() {
        insert_data(tx, statement, alert_id, name, value).await?;
    }
    Ok(())
}

async fn insert_data(
    tx: &Transaction<'_>,
    statement: &Statement,
    alert_id: i32,
    name: &str,
    value: &str,
) -> Result<(), ApiError> {
    tx.execute(statement, &[&alert_id, &name, &value])
        .await
        .map_err(|error| map_alert_definition_db_error(error, "insert alert definition data"))?;
    Ok(())
}

async fn execute_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    action: &'static str,
) -> Result<(), ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_alert_definition_db_error(error, action))?;
    Ok(())
}
