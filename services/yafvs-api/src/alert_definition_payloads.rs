// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    alert_write_validation::{
        AlertCreateStatus, AlertEmailCreateRequest, AlertScpCreateRequest, AlertSmbCreateRequest,
        AlertStartTaskCreateRequest, AlertSyslogCreateRequest, MAX_ALERT_MESSAGE_BYTES,
        MAX_ALERT_TEXT_BYTES, SensitiveAlertField, ValidatedAlertEmailCreate,
        ValidatedAlertScpCreate, ValidatedAlertSmbCreate, ValidatedAlertStartTaskCreate,
        ValidatedAlertSyslogCreate, normalize_alert_create_text,
        validate_alert_email_create_request, validate_alert_scp_create_request,
        validate_alert_smb_create_request, validate_alert_start_task_create_request,
        validate_alert_syslog_create_request, validate_sensitive_alert_message,
        validate_sensitive_alert_text,
    },
    errors::ApiError,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertDefinitionReplaceRequest {
    pub(crate) expected_revision: String,
    pub(crate) definition: AlertDefinitionReplaceBody,
}

#[derive(Deserialize)]
#[serde(tag = "method")]
pub(crate) enum AlertDefinitionReplaceBody {
    #[serde(rename = "EMAIL")]
    Email(AlertEmailCreateRequest),
    #[serde(rename = "SMB")]
    Smb(AlertSmbCreateRequest),
    #[serde(rename = "SYSLOG")]
    Syslog(AlertSyslogCreateRequest),
    #[serde(rename = "SNMP")]
    Snmp(AlertSnmpDefinitionReplaceRequest),
    #[serde(rename = "SCP")]
    Scp(AlertScpCreateRequest),
    #[serde(rename = "START_TASK")]
    StartTask(AlertStartTaskCreateRequest),
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SnmpCommunityMode {
    Preserve,
    Replace,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertSnmpDefinitionReplaceRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) snmp_agent: SensitiveAlertField,
    pub(crate) snmp_community_mode: SnmpCommunityMode,
    #[serde(default)]
    pub(crate) snmp_community: Option<SensitiveAlertField>,
    pub(crate) snmp_message: SensitiveAlertField,
}

pub(crate) enum ValidatedAlertDefinitionReplace {
    Email(ValidatedAlertEmailCreate),
    Smb(ValidatedAlertSmbCreate),
    Syslog(ValidatedAlertSyslogCreate),
    Snmp(ValidatedAlertSnmpDefinitionReplace),
    Scp(ValidatedAlertScpCreate),
    StartTask(ValidatedAlertStartTaskCreate),
}

pub(crate) struct ValidatedAlertSnmpDefinitionReplace {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) snmp_agent: SensitiveAlertField,
    pub(crate) community: ValidatedSnmpCommunity,
    pub(crate) snmp_message: SensitiveAlertField,
}

pub(crate) enum ValidatedSnmpCommunity {
    Preserve,
    Replace(SensitiveAlertField),
}

impl ValidatedAlertDefinitionReplace {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Email(request) => &request.name,
            Self::Smb(request) => &request.name,
            Self::Syslog(request) => &request.name,
            Self::Snmp(request) => &request.name,
            Self::Scp(request) => &request.name,
            Self::StartTask(request) => &request.name,
        }
    }

    pub(crate) fn preserves_snmp_community(&self) -> bool {
        matches!(
            self,
            Self::Snmp(ValidatedAlertSnmpDefinitionReplace {
                community: ValidatedSnmpCommunity::Preserve,
                ..
            })
        )
    }
}

pub(crate) fn validate_alert_definition_replace_request(
    request: AlertDefinitionReplaceRequest,
) -> Result<(String, ValidatedAlertDefinitionReplace), ApiError> {
    let expected_revision = validate_alert_definition_revision(request.expected_revision)?;
    let definition = match request.definition {
        AlertDefinitionReplaceBody::Email(request) => {
            validate_alert_email_create_request(request).map(ValidatedAlertDefinitionReplace::Email)
        }
        AlertDefinitionReplaceBody::Smb(request) => {
            validate_alert_smb_create_request(request).map(ValidatedAlertDefinitionReplace::Smb)
        }
        AlertDefinitionReplaceBody::Syslog(request) => {
            validate_alert_syslog_create_request(request)
                .map(ValidatedAlertDefinitionReplace::Syslog)
        }
        AlertDefinitionReplaceBody::Snmp(request) => {
            validate_alert_snmp_definition_replace_request(request)
                .map(ValidatedAlertDefinitionReplace::Snmp)
        }
        AlertDefinitionReplaceBody::Scp(request) => {
            validate_alert_scp_create_request(request).map(ValidatedAlertDefinitionReplace::Scp)
        }
        AlertDefinitionReplaceBody::StartTask(request) => {
            validate_alert_start_task_create_request(request)
                .map(ValidatedAlertDefinitionReplace::StartTask)
        }
    }?;
    Ok((expected_revision, definition))
}

fn validate_alert_definition_revision(revision: String) -> Result<String, ApiError> {
    if revision.is_empty()
        || revision.len() > 20
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
    {
        Err(ApiError::BadRequest(
            "expected_revision must be a bounded opaque decimal revision".to_string(),
        ))
    } else {
        Ok(revision)
    }
}

fn validate_alert_snmp_definition_replace_request(
    request: AlertSnmpDefinitionReplaceRequest,
) -> Result<ValidatedAlertSnmpDefinitionReplace, ApiError> {
    let name = normalize_alert_create_text(request.name, "name", true)?;
    let comment = request
        .comment
        .map(|value| normalize_alert_create_text(value, "comment", false))
        .transpose()?
        .unwrap_or_default();
    let snmp_agent = validate_sensitive_alert_text(
        request.snmp_agent,
        "snmp_agent",
        true,
        MAX_ALERT_TEXT_BYTES,
    )?;
    let snmp_message = validate_sensitive_alert_message(
        request.snmp_message,
        "snmp_message",
        MAX_ALERT_MESSAGE_BYTES,
    )?;
    if snmp_message.as_bytes().is_empty() {
        return Err(ApiError::BadRequest("snmp_message is required".to_string()));
    }
    let community = match (request.snmp_community_mode, request.snmp_community) {
        (SnmpCommunityMode::Preserve, None) => ValidatedSnmpCommunity::Preserve,
        (SnmpCommunityMode::Preserve, Some(_)) => {
            return Err(ApiError::BadRequest(
                "snmp_community must be omitted when snmp_community_mode is preserve".to_string(),
            ));
        }
        (SnmpCommunityMode::Replace, Some(community)) => ValidatedSnmpCommunity::Replace(
            validate_sensitive_alert_text(community, "snmp_community", true, MAX_ALERT_TEXT_BYTES)?,
        ),
        (SnmpCommunityMode::Replace, None) => {
            return Err(ApiError::BadRequest(
                "snmp_community is required when snmp_community_mode is replace".to_string(),
            ));
        }
    };

    Ok(ValidatedAlertSnmpDefinitionReplace {
        name,
        comment,
        active: request.active,
        status: request.status,
        snmp_agent,
        community,
        snmp_message,
    })
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "method")]
pub(crate) enum AlertDefinition {
    #[serde(rename = "EMAIL")]
    Email(AlertEmailDefinition),
    #[serde(rename = "SMB")]
    Smb(AlertSmbDefinition),
    #[serde(rename = "SYSLOG")]
    Syslog(AlertSyslogDefinition),
    #[serde(rename = "SNMP")]
    Snmp(AlertSnmpDefinition),
    #[serde(rename = "SCP")]
    Scp(AlertScpDefinition),
    #[serde(rename = "START_TASK")]
    StartTask(AlertStartTaskDefinition),
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertDefinitionBase {
    pub(crate) revision: String,
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) active: bool,
    pub(crate) status: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertEmailDefinition {
    #[serde(flatten)]
    base: AlertDefinitionBase,
    to_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_address: Option<String>,
    subject: String,
    notice: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_format_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertSmbDefinition {
    #[serde(flatten)]
    base: AlertDefinitionBase,
    smb_credential_id: String,
    smb_share_path: String,
    smb_file_path: String,
    report_format_id: String,
    smb_max_protocol: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertSyslogDefinition {
    #[serde(flatten)]
    base: AlertDefinitionBase,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertSnmpDefinition {
    #[serde(flatten)]
    base: AlertDefinitionBase,
    snmp_agent: String,
    snmp_community_configured: bool,
    snmp_message: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertScpDefinition {
    #[serde(flatten)]
    base: AlertDefinitionBase,
    scp_credential_id: String,
    scp_host: String,
    scp_port: u16,
    scp_known_hosts: String,
    scp_path: String,
    report_format_id: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AlertStartTaskDefinition {
    #[serde(flatten)]
    base: AlertDefinitionBase,
    task_id: String,
}

pub(crate) fn build_alert_definition(
    base: AlertDefinitionBase,
    method: i32,
    condition_data_count: i64,
    snmp_community_configured: bool,
    event_data: Vec<(String, Option<String>)>,
    method_data: Vec<(String, Option<String>)>,
) -> Result<AlertDefinition, ApiError> {
    if condition_data_count != 0 {
        return Err(non_retained_definition());
    }
    let mut event_data = strict_data_map(event_data)?;
    let status = take_required(&mut event_data, "status")?;
    if !event_data.is_empty() || !alert_status_is_valid(&status) || status != base.status {
        return Err(non_retained_definition());
    }
    let mut method_data = strict_data_map(method_data)?;
    let definition = match method {
        1 => {
            let to_address = take_required(&mut method_data, "to_address")?;
            let from_address = take_optional(&mut method_data, "from_address")?;
            let subject = take_required(&mut method_data, "subject")?;
            let notice_value = take_required(&mut method_data, "notice")?;
            let recipient_credential_id = take_optional(&mut method_data, "recipient_credential")?;
            let message = take_optional(&mut method_data, "message")?;
            let (notice, report_format_id) = match notice_value.as_str() {
                "1" => ("simple".to_string(), None),
                "0" => (
                    "include".to_string(),
                    Some(take_required(&mut method_data, "notice_report_format")?),
                ),
                "2" => (
                    "attach".to_string(),
                    Some(take_required(&mut method_data, "notice_attach_format")?),
                ),
                _ => return Err(non_retained_definition()),
            };
            ensure_empty(&method_data)?;
            AlertDefinition::Email(AlertEmailDefinition {
                base,
                to_address,
                from_address,
                subject,
                notice,
                recipient_credential_id,
                report_format_id,
                message,
            })
        }
        4 => {
            let task_id = take_required(&mut method_data, "start_task_task")?;
            ensure_empty(&method_data)?;
            AlertDefinition::StartTask(AlertStartTaskDefinition { base, task_id })
        }
        5 => {
            if take_required(&mut method_data, "submethod")? != "syslog" {
                return Err(non_retained_definition());
            }
            ensure_empty(&method_data)?;
            AlertDefinition::Syslog(AlertSyslogDefinition { base })
        }
        8 => {
            let scp_credential_id = take_required(&mut method_data, "scp_credential")?;
            let scp_host = take_required(&mut method_data, "scp_host")?;
            let scp_port = take_required(&mut method_data, "scp_port")?
                .parse::<u16>()
                .map_err(|_| non_retained_definition())?;
            if scp_port == 0 {
                return Err(non_retained_definition());
            }
            let scp_known_hosts = take_required(&mut method_data, "scp_known_hosts")?;
            let scp_path = take_required(&mut method_data, "scp_path")?;
            let report_format_id = take_required(&mut method_data, "scp_report_format")?;
            ensure_empty(&method_data)?;
            AlertDefinition::Scp(AlertScpDefinition {
                base,
                scp_credential_id,
                scp_host,
                scp_port,
                scp_known_hosts,
                scp_path,
                report_format_id,
            })
        }
        9 => {
            let snmp_agent = take_required(&mut method_data, "snmp_agent")?;
            let snmp_community_configured = match method_data.remove("snmp_community") {
                Some(None) if snmp_community_configured => true,
                _ => return Err(non_retained_definition()),
            };
            let snmp_message = take_required(&mut method_data, "snmp_message")?;
            ensure_empty(&method_data)?;
            AlertDefinition::Snmp(AlertSnmpDefinition {
                base,
                snmp_agent,
                snmp_community_configured,
                snmp_message,
            })
        }
        10 => {
            let smb_credential_id = take_required(&mut method_data, "smb_credential")?;
            let smb_share_path = take_required(&mut method_data, "smb_share_path")?;
            let smb_file_path = take_required(&mut method_data, "smb_file_path")?;
            let report_format_id = take_required(&mut method_data, "smb_report_format")?;
            let smb_max_protocol = take_optional(&mut method_data, "smb_max_protocol")?
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "default".to_string());
            if !matches!(
                smb_max_protocol.as_str(),
                "default" | "NT1" | "SMB2" | "SMB3"
            ) {
                return Err(non_retained_definition());
            }
            ensure_empty(&method_data)?;
            AlertDefinition::Smb(AlertSmbDefinition {
                base,
                smb_credential_id,
                smb_share_path,
                smb_file_path,
                report_format_id,
                smb_max_protocol,
            })
        }
        _ => return Err(non_retained_definition()),
    };
    Ok(definition)
}

fn strict_data_map(
    rows: Vec<(String, Option<String>)>,
) -> Result<HashMap<String, Option<String>>, ApiError> {
    let mut values = HashMap::with_capacity(rows.len());
    for (name, value) in rows {
        if values.insert(name, value).is_some() {
            return Err(non_retained_definition());
        }
    }
    Ok(values)
}

fn take_required(
    values: &mut HashMap<String, Option<String>>,
    name: &str,
) -> Result<String, ApiError> {
    values
        .remove(name)
        .flatten()
        .filter(|value| !value.is_empty())
        .ok_or_else(non_retained_definition)
}

fn take_optional(
    values: &mut HashMap<String, Option<String>>,
    name: &str,
) -> Result<Option<String>, ApiError> {
    match values.remove(name) {
        Some(Some(value)) if !value.is_empty() => Ok(Some(value)),
        Some(Some(_)) | None => Ok(None),
        Some(None) => Err(non_retained_definition()),
    }
}

fn ensure_empty(values: &HashMap<String, Option<String>>) -> Result<(), ApiError> {
    if values.is_empty() {
        Ok(())
    } else {
        Err(non_retained_definition())
    }
}

fn alert_status_is_valid(status: &str) -> bool {
    matches!(
        status,
        "Delete Requested"
            | "Ultimate Delete Requested"
            | "Ultimate Delete Waiting"
            | "Delete Waiting"
            | "Done"
            | "New"
            | "Requested"
            | "Running"
            | "Queued"
            | "Stop Requested"
            | "Stop Waiting"
            | "Stopped"
            | "Processing"
            | "Interrupted"
    )
}

fn non_retained_definition() -> ApiError {
    ApiError::Conflict("alert is not a retained fixed task-status definition".to_string())
}
