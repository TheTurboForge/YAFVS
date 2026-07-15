// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::{
    errors::ApiError,
    ssh_host_key_pins::{SshHostKeyPin, validate_ssh_host_key_pins},
    target_alive_tests::validate_alive_tests,
    target_host_validation::validate_target_host_lists,
    target_id_validation::{validate_optional_uuid, validate_uuid},
    target_text_validation::{
        normalize_optional_required_target_text, normalize_optional_target_text,
        normalize_required_target_text,
    },
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) alive_tests: Vec<String>,
    pub(crate) allow_simultaneous_ips: bool,
    pub(crate) reverse_lookup_only: bool,
    pub(crate) reverse_lookup_unify: bool,
    pub(crate) port_list_id: String,
    pub(crate) hosts: Vec<String>,
    #[serde(default)]
    pub(crate) exclude_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) credentials: Option<TargetCredentialsCreateRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) alive_tests: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) allow_simultaneous_ips: Option<bool>,
    #[serde(default)]
    pub(crate) reverse_lookup_only: Option<bool>,
    #[serde(default)]
    pub(crate) reverse_lookup_unify: Option<bool>,
    #[serde(default)]
    pub(crate) port_list_id: Option<String>,
    #[serde(default)]
    pub(crate) hosts: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) exclude_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) credentials: Option<TargetCredentialsPatchRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetCredentialLinkPatchRequest {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) port: Option<i32>,
    #[serde(default)]
    pub(crate) host_key_pins: Vec<SshHostKeyPin>,
}

#[derive(Debug)]
pub(crate) enum TargetCredentialPatchFieldRequest {
    Set(TargetCredentialLinkPatchRequest),
    Clear,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetCredentialsPatchRequest {
    #[serde(default, deserialize_with = "deserialize_credential_patch_field")]
    pub(crate) ssh: Option<TargetCredentialPatchFieldRequest>,
    #[serde(default, deserialize_with = "deserialize_credential_patch_field")]
    pub(crate) ssh_elevate: Option<TargetCredentialPatchFieldRequest>,
    #[serde(default, deserialize_with = "deserialize_credential_patch_field")]
    pub(crate) smb: Option<TargetCredentialPatchFieldRequest>,
    #[serde(default, deserialize_with = "deserialize_credential_patch_field")]
    pub(crate) esxi: Option<TargetCredentialPatchFieldRequest>,
    #[serde(default, deserialize_with = "deserialize_credential_patch_field")]
    pub(crate) snmp: Option<TargetCredentialPatchFieldRequest>,
    #[serde(default, deserialize_with = "deserialize_credential_patch_field")]
    pub(crate) krb5: Option<TargetCredentialPatchFieldRequest>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetCredentialsCreateRequest {
    #[serde(default)]
    pub(crate) ssh: Option<TargetCredentialLinkPatchRequest>,
    #[serde(default)]
    pub(crate) ssh_elevate: Option<TargetCredentialLinkPatchRequest>,
    #[serde(default)]
    pub(crate) smb: Option<TargetCredentialLinkPatchRequest>,
    #[serde(default)]
    pub(crate) esxi: Option<TargetCredentialLinkPatchRequest>,
    #[serde(default)]
    pub(crate) snmp: Option<TargetCredentialLinkPatchRequest>,
    #[serde(default)]
    pub(crate) krb5: Option<TargetCredentialLinkPatchRequest>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTargetCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) alive_test: i32,
    pub(crate) allow_simultaneous_ips: i32,
    pub(crate) reverse_lookup_only: i32,
    pub(crate) reverse_lookup_unify: i32,
    pub(crate) port_list_id: String,
    pub(crate) hosts: String,
    pub(crate) exclude_hosts: String,
    pub(crate) credentials: ValidatedTargetCredentialsPatch,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTargetClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTargetPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) alive_test: Option<i32>,
    pub(crate) allow_simultaneous_ips: Option<i32>,
    pub(crate) reverse_lookup_only: Option<i32>,
    pub(crate) reverse_lookup_unify: Option<i32>,
    pub(crate) port_list_id: Option<String>,
    pub(crate) hosts: Option<String>,
    pub(crate) exclude_hosts: Option<String>,
    pub(crate) credentials: ValidatedTargetCredentialsPatch,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedCredentialLinkPatch {
    pub(crate) id: String,
    pub(crate) port: Option<i32>,
    pub(crate) host_key_pins: Vec<SshHostKeyPin>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ValidatedCredentialPatchAction {
    Set(ValidatedCredentialLinkPatch),
    Clear,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ValidatedTargetCredentialsPatch {
    pub(crate) ssh: Option<ValidatedCredentialPatchAction>,
    pub(crate) ssh_elevate: Option<ValidatedCredentialPatchAction>,
    pub(crate) smb: Option<ValidatedCredentialPatchAction>,
    pub(crate) esxi: Option<ValidatedCredentialPatchAction>,
    pub(crate) snmp: Option<ValidatedCredentialPatchAction>,
    pub(crate) krb5: Option<ValidatedCredentialPatchAction>,
}

pub(crate) fn validate_target_clone_request(
    request: TargetCloneRequest,
) -> Result<ValidatedTargetClone, ApiError> {
    Ok(ValidatedTargetClone {
        name: normalize_optional_required_target_text(request.name, "name")?,
        comment: normalize_optional_target_text(request.comment, "comment")?,
    })
}

pub(crate) fn validate_target_create_request(
    request: TargetCreateRequest,
) -> Result<ValidatedTargetCreate, ApiError> {
    let (hosts, exclude_hosts) =
        validate_target_host_lists(Some(request.hosts), request.exclude_hosts)?;
    let alive_test = validate_alive_tests(Some(request.alive_tests))?
        .ok_or_else(|| ApiError::BadRequest("alive_tests is required".to_string()))?;
    Ok(ValidatedTargetCreate {
        name: normalize_required_target_text(request.name, "name")?,
        comment: normalize_optional_target_text(request.comment, "comment")?,
        alive_test,
        allow_simultaneous_ips: i32::from(request.allow_simultaneous_ips),
        reverse_lookup_only: i32::from(request.reverse_lookup_only),
        reverse_lookup_unify: i32::from(request.reverse_lookup_unify),
        port_list_id: validate_uuid(request.port_list_id, "port_list_id")?,
        hosts: hosts.ok_or_else(|| ApiError::BadRequest("hosts is required".to_string()))?,
        exclude_hosts: exclude_hosts.unwrap_or_default(),
        credentials: validate_credentials_create(request.credentials)?,
    })
}

impl ValidatedTargetPatch {
    pub(crate) fn changes_task_in_use_guarded_scan_inputs(&self) -> bool {
        self.allow_simultaneous_ips.is_some()
            || self.reverse_lookup_only.is_some()
            || self.reverse_lookup_unify.is_some()
            || self.port_list_id.is_some()
            || self.hosts.is_some()
    }

    pub(crate) fn changes_credential_links(&self) -> bool {
        self.credentials.has_changes()
    }

    pub(crate) fn changes_target_metadata_or_scan_inputs(&self) -> bool {
        self.name.is_some()
            || self.comment.is_some()
            || self.alive_test.is_some()
            || self.allow_simultaneous_ips.is_some()
            || self.reverse_lookup_only.is_some()
            || self.reverse_lookup_unify.is_some()
            || self.port_list_id.is_some()
            || self.hosts.is_some()
    }
}

impl ValidatedTargetCredentialsPatch {
    pub(crate) fn has_changes(&self) -> bool {
        self.ssh.is_some()
            || self.ssh_elevate.is_some()
            || self.smb.is_some()
            || self.esxi.is_some()
            || self.snmp.is_some()
            || self.krb5.is_some()
    }
}

pub(crate) fn validate_target_patch_request(
    request: TargetPatchRequest,
) -> Result<ValidatedTargetPatch, ApiError> {
    let validated = ValidatedTargetPatch {
        name: normalize_optional_required_target_text(request.name, "name")?,
        comment: normalize_optional_target_text(request.comment, "comment")?,
        alive_test: validate_alive_tests(request.alive_tests)?,
        allow_simultaneous_ips: bool_option_to_int(request.allow_simultaneous_ips),
        reverse_lookup_only: bool_option_to_int(request.reverse_lookup_only),
        reverse_lookup_unify: bool_option_to_int(request.reverse_lookup_unify),
        port_list_id: validate_optional_uuid(request.port_list_id, "port_list_id")?,
        hosts: None,
        exclude_hosts: None,
        credentials: validate_credentials_patch(request.credentials)?,
    };
    let (hosts, exclude_hosts) = validate_target_host_lists(request.hosts, request.exclude_hosts)?;
    let validated = ValidatedTargetPatch {
        hosts,
        exclude_hosts,
        ..validated
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.alive_test.is_none()
        && validated.allow_simultaneous_ips.is_none()
        && validated.reverse_lookup_only.is_none()
        && validated.reverse_lookup_unify.is_none()
        && validated.port_list_id.is_none()
        && validated.hosts.is_none()
        && !validated.credentials.has_changes()
    {
        return Err(ApiError::BadRequest(
            "target patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn validate_credentials_patch(
    request: Option<TargetCredentialsPatchRequest>,
) -> Result<ValidatedTargetCredentialsPatch, ApiError> {
    let Some(request) = request else {
        return Ok(ValidatedTargetCredentialsPatch::default());
    };
    let patch = ValidatedTargetCredentialsPatch {
        ssh: validate_credential_patch_action(request.ssh, "credentials.ssh", true)?,
        ssh_elevate: validate_credential_patch_action(
            request.ssh_elevate,
            "credentials.ssh_elevate",
            false,
        )?,
        smb: validate_credential_patch_action(request.smb, "credentials.smb", false)?,
        esxi: validate_credential_patch_action(request.esxi, "credentials.esxi", false)?,
        snmp: validate_credential_patch_action(request.snmp, "credentials.snmp", false)?,
        krb5: validate_credential_patch_action(request.krb5, "credentials.krb5", false)?,
    };
    if !patch.has_changes() {
        return Err(ApiError::BadRequest(
            "credentials patch must include at least one credential field".to_string(),
        ));
    }
    Ok(patch)
}

fn validate_credentials_create(
    request: Option<TargetCredentialsCreateRequest>,
) -> Result<ValidatedTargetCredentialsPatch, ApiError> {
    let Some(request) = request else {
        return Ok(ValidatedTargetCredentialsPatch::default());
    };
    let credentials = ValidatedTargetCredentialsPatch {
        ssh: validate_credential_create_action(request.ssh, "credentials.ssh", true)?,
        ssh_elevate: validate_credential_create_action(
            request.ssh_elevate,
            "credentials.ssh_elevate",
            false,
        )?,
        smb: validate_credential_create_action(request.smb, "credentials.smb", false)?,
        esxi: validate_credential_create_action(request.esxi, "credentials.esxi", false)?,
        snmp: validate_credential_create_action(request.snmp, "credentials.snmp", false)?,
        krb5: validate_credential_create_action(request.krb5, "credentials.krb5", false)?,
    };
    if !credentials.has_changes() {
        return Err(ApiError::BadRequest(
            "credentials create request must include at least one credential field".to_string(),
        ));
    }
    Ok(credentials)
}

fn validate_credential_create_action(
    request: Option<TargetCredentialLinkPatchRequest>,
    field_name: &str,
    allow_port: bool,
) -> Result<Option<ValidatedCredentialPatchAction>, ApiError> {
    let Some(request) = request else {
        return Ok(None);
    };
    Ok(Some(ValidatedCredentialPatchAction::Set(
        validate_credential_link_request(request, field_name, allow_port)?,
    )))
}

fn validate_credential_patch_action(
    action: Option<TargetCredentialPatchFieldRequest>,
    field_name: &str,
    allow_port: bool,
) -> Result<Option<ValidatedCredentialPatchAction>, ApiError> {
    let Some(action) = action else {
        return Ok(None);
    };
    let request = match action {
        TargetCredentialPatchFieldRequest::Clear => {
            return Ok(Some(ValidatedCredentialPatchAction::Clear));
        }
        TargetCredentialPatchFieldRequest::Set(request) => request,
    };
    Ok(Some(ValidatedCredentialPatchAction::Set(
        validate_credential_link_request(request, field_name, allow_port)?,
    )))
}

fn validate_credential_link_request(
    request: TargetCredentialLinkPatchRequest,
    field_name: &str,
    allow_port: bool,
) -> Result<ValidatedCredentialLinkPatch, ApiError> {
    let port = match (allow_port, request.port) {
        (true, None) => Some(22),
        (true, Some(port)) if (1..=65535).contains(&port) => Some(port),
        (true, Some(_)) => {
            return Err(ApiError::BadRequest(format!(
                "{field_name}.port must be between 1 and 65535"
            )));
        }
        (false, None) => None,
        (false, Some(_)) => {
            return Err(ApiError::BadRequest(format!(
                "{field_name}.port is only supported for ssh"
            )));
        }
    };
    let host_key_pins = if allow_port {
        validate_ssh_host_key_pins(request.host_key_pins, field_name)?
    } else if request.host_key_pins.is_empty() {
        Vec::new()
    } else {
        return Err(ApiError::BadRequest(format!(
            "{field_name}.host_key_pins is only supported for ssh"
        )));
    };
    Ok(ValidatedCredentialLinkPatch {
        id: validate_uuid(request.id, &format!("{field_name}.id"))?,
        port,
        host_key_pins,
    })
}

fn deserialize_credential_patch_field<'de, D>(
    deserializer: D,
) -> Result<Option<TargetCredentialPatchFieldRequest>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let request = Option::<TargetCredentialLinkPatchRequest>::deserialize(deserializer)?;
    Ok(Some(match request {
        Some(request) => TargetCredentialPatchFieldRequest::Set(request),
        None => TargetCredentialPatchFieldRequest::Clear,
    }))
}

fn bool_option_to_int(value: Option<bool>) -> Option<i32> {
    value.map(i32::from)
}
