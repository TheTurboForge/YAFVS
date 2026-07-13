// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Deserializer};
use uuid::Uuid;

use crate::errors::ApiError;

pub(crate) const MAX_ALERT_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_ALERT_STATUS_BYTES: usize = 32;
pub(crate) const MAX_ALERT_SUBJECT_BYTES: usize = 80;
pub(crate) const MAX_ALERT_MESSAGE_BYTES: usize = 2000;
pub(crate) const MAX_ALERT_UUID_BYTES: usize = 36;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub(crate) enum AlertCreateStatus {
    #[serde(rename = "Delete Requested")]
    DeleteRequested,
    #[serde(rename = "Ultimate Delete Requested")]
    UltimateDeleteRequested,
    #[serde(rename = "Ultimate Delete Waiting")]
    UltimateDeleteWaiting,
    #[serde(rename = "Delete Waiting")]
    DeleteWaiting,
    Done,
    New,
    Requested,
    Running,
    Queued,
    #[serde(rename = "Stop Requested")]
    StopRequested,
    #[serde(rename = "Stop Waiting")]
    StopWaiting,
    Stopped,
    Processing,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) enum AlertSmbMaxProtocol {
    #[default]
    #[serde(rename = "default")]
    Default,
    NT1,
    SMB2,
    SMB3,
}

impl AlertSmbMaxProtocol {
    pub(crate) fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Default => b"",
            Self::NT1 => b"NT1",
            Self::SMB2 => b"SMB2",
            Self::SMB3 => b"SMB3",
        }
    }
}

impl AlertCreateStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DeleteRequested => "Delete Requested",
            Self::UltimateDeleteRequested => "Ultimate Delete Requested",
            Self::UltimateDeleteWaiting => "Ultimate Delete Waiting",
            Self::DeleteWaiting => "Delete Waiting",
            Self::Done => "Done",
            Self::New => "New",
            Self::Requested => "Requested",
            Self::Running => "Running",
            Self::Queued => "Queued",
            Self::StopRequested => "Stop Requested",
            Self::StopWaiting => "Stop Waiting",
            Self::Stopped => "Stopped",
            Self::Processing => "Processing",
            Self::Interrupted => "Interrupted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AlertEmailNoticeMode {
    Simple,
    Include,
    Attach,
}

impl AlertEmailNoticeMode {
    pub(crate) fn control_token(self) -> u8 {
        match self {
            Self::Simple => 1,
            Self::Include => 0,
            Self::Attach => 2,
        }
    }
}

pub(crate) struct SensitiveAlertField(Vec<u8>);

impl SensitiveAlertField {
    fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SensitiveAlertField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(value.into_bytes()))
    }
}

impl Drop for SensitiveAlertField {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertEmailCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) to_address: SensitiveAlertField,
    #[serde(default)]
    pub(crate) from_address: Option<SensitiveAlertField>,
    pub(crate) subject: SensitiveAlertField,
    pub(crate) notice: AlertEmailNoticeMode,
    #[serde(default)]
    pub(crate) recipient_credential_id: Option<SensitiveAlertField>,
    #[serde(default)]
    pub(crate) report_format_id: Option<SensitiveAlertField>,
    #[serde(default)]
    pub(crate) message: Option<SensitiveAlertField>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertSmbCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) smb_credential_id: SensitiveAlertField,
    pub(crate) smb_share_path: SensitiveAlertField,
    pub(crate) smb_file_path: SensitiveAlertField,
    pub(crate) report_format_id: SensitiveAlertField,
    #[serde(default)]
    pub(crate) smb_max_protocol: AlertSmbMaxProtocol,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertSyslogCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertSnmpCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) snmp_agent: SensitiveAlertField,
    pub(crate) snmp_community: SensitiveAlertField,
    pub(crate) snmp_message: SensitiveAlertField,
}

#[derive(Deserialize)]
#[serde(tag = "method")]
pub(crate) enum AlertCreateRequest {
    #[serde(rename = "EMAIL")]
    Email(AlertEmailCreateRequest),
    #[serde(rename = "SMB")]
    Smb(AlertSmbCreateRequest),
    #[serde(rename = "SYSLOG")]
    Syslog(AlertSyslogCreateRequest),
    #[serde(rename = "SNMP")]
    Snmp(AlertSnmpCreateRequest),
}

pub(crate) struct ValidatedAlertEmailCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) to_address: SensitiveAlertField,
    pub(crate) from_address: SensitiveAlertField,
    pub(crate) subject: SensitiveAlertField,
    pub(crate) notice: AlertEmailNoticeMode,
    pub(crate) recipient_credential_id: SensitiveAlertField,
    pub(crate) report_format_id: SensitiveAlertField,
    pub(crate) message: SensitiveAlertField,
}

pub(crate) struct ValidatedAlertSmbCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) smb_credential_id: SensitiveAlertField,
    pub(crate) smb_share_path: SensitiveAlertField,
    pub(crate) smb_file_path: SensitiveAlertField,
    pub(crate) report_format_id: SensitiveAlertField,
    pub(crate) smb_max_protocol: AlertSmbMaxProtocol,
}

pub(crate) struct ValidatedAlertSyslogCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
}

pub(crate) struct ValidatedAlertSnmpCreate {
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) active: bool,
    pub(crate) status: AlertCreateStatus,
    pub(crate) snmp_agent: SensitiveAlertField,
    pub(crate) snmp_community: SensitiveAlertField,
    pub(crate) snmp_message: SensitiveAlertField,
}

pub(crate) enum ValidatedAlertCreate {
    Email(ValidatedAlertEmailCreate),
    Smb(ValidatedAlertSmbCreate),
    Syslog(ValidatedAlertSyslogCreate),
    Snmp(ValidatedAlertSnmpCreate),
}

pub(crate) fn validate_alert_create_request(
    request: AlertCreateRequest,
) -> Result<ValidatedAlertCreate, ApiError> {
    match request {
        AlertCreateRequest::Email(request) => {
            validate_alert_email_create_request(request).map(ValidatedAlertCreate::Email)
        }
        AlertCreateRequest::Smb(request) => {
            validate_alert_smb_create_request(request).map(ValidatedAlertCreate::Smb)
        }
        AlertCreateRequest::Syslog(request) => {
            validate_alert_syslog_create_request(request).map(ValidatedAlertCreate::Syslog)
        }
        AlertCreateRequest::Snmp(request) => {
            validate_alert_snmp_create_request(request).map(ValidatedAlertCreate::Snmp)
        }
    }
}

pub(crate) fn validate_alert_syslog_create_request(
    request: AlertSyslogCreateRequest,
) -> Result<ValidatedAlertSyslogCreate, ApiError> {
    let name = normalize_alert_create_text(request.name, "name", true)?;
    let comment = request
        .comment
        .map(|value| normalize_alert_create_text(value, "comment", false))
        .transpose()?
        .unwrap_or_default();
    debug_assert!(request.status.as_str().len() <= MAX_ALERT_STATUS_BYTES);

    Ok(ValidatedAlertSyslogCreate {
        name,
        comment,
        active: request.active,
        status: request.status,
    })
}

pub(crate) fn validate_alert_snmp_create_request(
    request: AlertSnmpCreateRequest,
) -> Result<ValidatedAlertSnmpCreate, ApiError> {
    let name = normalize_alert_create_text(request.name, "name", true)?;
    let comment = request
        .comment
        .map(|value| normalize_alert_create_text(value, "comment", false))
        .transpose()?
        .unwrap_or_default();
    debug_assert!(request.status.as_str().len() <= MAX_ALERT_STATUS_BYTES);
    let snmp_agent = validate_sensitive_alert_text(
        request.snmp_agent,
        "snmp_agent",
        true,
        MAX_ALERT_TEXT_BYTES,
    )?;
    let snmp_community = validate_sensitive_alert_text(
        request.snmp_community,
        "snmp_community",
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

    Ok(ValidatedAlertSnmpCreate {
        name,
        comment,
        active: request.active,
        status: request.status,
        snmp_agent,
        snmp_community,
        snmp_message,
    })
}

pub(crate) fn validate_alert_email_create_request(
    request: AlertEmailCreateRequest,
) -> Result<ValidatedAlertEmailCreate, ApiError> {
    let name = normalize_alert_create_text(request.name, "name", true)?;
    let comment = request
        .comment
        .map(|value| normalize_alert_create_text(value, "comment", false))
        .transpose()?
        .unwrap_or_default();
    debug_assert!(request.status.as_str().len() <= MAX_ALERT_STATUS_BYTES);
    let to_address = validate_sensitive_alert_text(
        request.to_address,
        "to_address",
        true,
        MAX_ALERT_TEXT_BYTES,
    )?;
    let from_address = validate_sensitive_alert_text(
        request
            .from_address
            .unwrap_or_else(SensitiveAlertField::empty),
        "from_address",
        false,
        MAX_ALERT_TEXT_BYTES,
    )?;
    let subject =
        validate_sensitive_alert_text(request.subject, "subject", true, MAX_ALERT_SUBJECT_BYTES)?;
    let recipient_credential_id =
        validate_optional_alert_uuid(request.recipient_credential_id, "recipient_credential_id")?;
    let report_format_id =
        validate_optional_alert_uuid(request.report_format_id, "report_format_id")?;
    let message = validate_sensitive_alert_message(
        request.message.unwrap_or_else(SensitiveAlertField::empty),
        "message",
        MAX_ALERT_MESSAGE_BYTES,
    )?;

    match request.notice {
        AlertEmailNoticeMode::Simple if !report_format_id.as_bytes().is_empty() => {
            return Err(ApiError::BadRequest(
                "simple notice forbids report_format_id".to_string(),
            ));
        }
        AlertEmailNoticeMode::Include | AlertEmailNoticeMode::Attach
            if report_format_id.as_bytes().is_empty() =>
        {
            return Err(ApiError::BadRequest(format!(
                "{} notice requires report_format_id",
                match request.notice {
                    AlertEmailNoticeMode::Include => "include",
                    AlertEmailNoticeMode::Attach => "attach",
                    AlertEmailNoticeMode::Simple => unreachable!(),
                }
            )));
        }
        _ => {}
    }

    Ok(ValidatedAlertEmailCreate {
        name,
        comment,
        active: request.active,
        status: request.status,
        to_address,
        from_address,
        subject,
        notice: request.notice,
        recipient_credential_id,
        report_format_id,
        message,
    })
}

pub(crate) fn validate_alert_smb_create_request(
    request: AlertSmbCreateRequest,
) -> Result<ValidatedAlertSmbCreate, ApiError> {
    let name = normalize_alert_create_text(request.name, "name", true)?;
    let comment = request
        .comment
        .map(|value| normalize_alert_create_text(value, "comment", false))
        .transpose()?
        .unwrap_or_default();
    debug_assert!(request.status.as_str().len() <= MAX_ALERT_STATUS_BYTES);
    let smb_credential_id =
        validate_required_alert_uuid(request.smb_credential_id, "smb_credential_id")?;
    let smb_share_path = validate_smb_share_path(request.smb_share_path)?;
    let smb_file_path = validate_smb_file_path(request.smb_file_path)?;
    let report_format_id =
        validate_required_alert_uuid(request.report_format_id, "report_format_id")?;

    Ok(ValidatedAlertSmbCreate {
        name,
        comment,
        active: request.active,
        status: request.status,
        smb_credential_id,
        smb_share_path,
        smb_file_path,
        report_format_id,
        smb_max_protocol: request.smb_max_protocol,
    })
}

fn validate_smb_share_path(value: SensitiveAlertField) -> Result<SensitiveAlertField, ApiError> {
    let value = validate_sensitive_alert_text(value, "smb_share_path", true, MAX_ALERT_TEXT_BYTES)?;
    let path = std::str::from_utf8(value.as_bytes()).expect("validated UTF-8 SMB share path");
    let (separator, remainder) = if let Some(remainder) = path.strip_prefix(r"\\") {
        ('\\', remainder)
    } else if let Some(remainder) = path.strip_prefix("//") {
        ('/', remainder)
    } else {
        return Err(invalid_smb_path("smb_share_path"));
    };
    let Some((host, share)) = remainder.split_once(separator) else {
        return Err(invalid_smb_path("smb_share_path"));
    };
    if !is_valid_smb_share_component(host) || !is_valid_smb_share_component(share) {
        return Err(invalid_smb_path("smb_share_path"));
    }
    Ok(value)
}

fn validate_smb_file_path(value: SensitiveAlertField) -> Result<SensitiveAlertField, ApiError> {
    let value = validate_sensitive_alert_text(value, "smb_file_path", true, MAX_ALERT_TEXT_BYTES)?;
    let path = std::str::from_utf8(value.as_bytes()).expect("validated UTF-8 SMB file path");
    if !path.split(['/', '\\']).all(is_valid_smb_file_component) {
        return Err(invalid_smb_path("smb_file_path"));
    }
    Ok(value)
}

fn is_valid_smb_share_component(component: &str) -> bool {
    !component.is_empty()
        && !component.ends_with('.')
        && component.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

fn is_valid_smb_file_component(component: &str) -> bool {
    !component.is_empty()
        && !component.ends_with('.')
        && component.chars().any(|character| character != ' ')
        && component.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ' ' | '.' | '_' | '-' | '%')
        })
}

fn invalid_smb_path(field_name: &str) -> ApiError {
    ApiError::BadRequest(format!(
        "{field_name} must use the restricted SMB delivery path grammar"
    ))
}

fn validate_sensitive_alert_message(
    value: SensitiveAlertField,
    field_name: &str,
    max_bytes: usize,
) -> Result<SensitiveAlertField, ApiError> {
    let text = std::str::from_utf8(value.as_bytes())
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be valid UTF-8 text")))?;
    if value.as_bytes().len() > max_bytes
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be UTF-8 text up to {max_bytes} bytes without unsupported control characters"
        )));
    }
    Ok(value)
}

fn normalize_alert_create_text(
    value: String,
    field_name: &str,
    required: bool,
) -> Result<String, ApiError> {
    if value.len() > MAX_ALERT_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be {}printable text up to {MAX_ALERT_TEXT_BYTES} bytes",
            if required { "non-empty " } else { "" }
        )));
    }
    let value = value.trim().to_string();
    if required && value.is_empty() {
        return Err(ApiError::BadRequest(format!("{field_name} is required")));
    }
    Ok(value)
}

fn validate_sensitive_alert_text(
    value: SensitiveAlertField,
    field_name: &str,
    required: bool,
    max_bytes: usize,
) -> Result<SensitiveAlertField, ApiError> {
    let text = std::str::from_utf8(value.as_bytes())
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be valid UTF-8 text")))?;
    let trimmed = text.trim();
    if (required && trimmed.is_empty())
        || value.as_bytes().len() > max_bytes
        || trimmed.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be {}printable text up to {max_bytes} bytes",
            if required { "non-empty " } else { "" }
        )));
    }
    Ok(SensitiveAlertField(trimmed.as_bytes().to_vec()))
}

fn validate_optional_alert_uuid(
    value: Option<SensitiveAlertField>,
    field_name: &str,
) -> Result<SensitiveAlertField, ApiError> {
    let Some(value) = value else {
        return Ok(SensitiveAlertField::empty());
    };
    let text = std::str::from_utf8(value.as_bytes())
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be a UUID")))?;
    if text.len() != MAX_ALERT_UUID_BYTES {
        return Err(ApiError::BadRequest(format!("{field_name} must be a UUID")));
    }
    let uuid = Uuid::parse_str(text)
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be a UUID")))?;
    Ok(SensitiveAlertField(uuid.to_string().into_bytes()))
}

fn validate_required_alert_uuid(
    value: SensitiveAlertField,
    field_name: &str,
) -> Result<SensitiveAlertField, ApiError> {
    let value = validate_optional_alert_uuid(Some(value), field_name)?;
    if value.as_bytes().is_empty() {
        return Err(ApiError::BadRequest(format!("{field_name} must be a UUID")));
    }
    Ok(value)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedAlertPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedAlertClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

pub(crate) fn validate_alert_patch_request(
    request: AlertPatchRequest,
) -> Result<ValidatedAlertPatch, ApiError> {
    let validated = ValidatedAlertPatch {
        name: normalize_optional_required_alert_text(request.name, "name")?,
        comment: normalize_optional_alert_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "alert patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_alert_clone_request(
    request: AlertCloneRequest,
) -> Result<ValidatedAlertClone, ApiError> {
    Ok(ValidatedAlertClone {
        name: normalize_optional_required_alert_text(request.name, "name")?,
        comment: normalize_optional_alert_text(request.comment, "comment")?,
    })
}

fn normalize_optional_required_alert_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_alert_text(value, field_name))
        .transpose()
}

fn normalize_required_alert_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_alert_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_alert_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_alert_text_value(value, field_name))
        .transpose()
}

fn normalize_alert_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_ALERT_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_ALERT_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
