// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    credential_write_validation::SensitiveBytes,
    errors::ApiError,
    gvmd_control::{
        ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response_bytes,
        request_gvmd_control_response_bytes_with_limit,
    },
};

pub(crate) const MAX_AUTHENTICATION_SETTINGS_BODY_BYTES: usize = 48 * 1024;
const MAX_AUTHENTICATION_SETTINGS_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_PROVIDER_HOST_BYTES: usize = 1024;
const MAX_LDAP_AUTH_DN_BYTES: usize = 4096;
const MAX_CA_CERTIFICATE_BYTES: usize = 32 * 1024;
const MAX_RADIUS_SECRET_BYTES: usize = 4096;
const MAX_CERTIFICATE_FINGERPRINT_BYTES: usize = 256;
const MAX_CERTIFICATE_ISSUER_BYTES: usize = 4096;
const MAX_CERTIFICATE_TIME_BYTES: usize = 128;
const MAX_CERTIFICATE_TIME_STATUS_BYTES: usize = 128;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AuthenticationSettings {
    ldap: LdapAuthenticationSettings,
    radius: RadiusAuthenticationSettings,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct LdapAuthenticationSettings {
    available: bool,
    enabled: bool,
    host: String,
    auth_dn: String,
    allow_plaintext: bool,
    ldaps_only: bool,
    certificate: Option<LdapCertificateMetadata>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct LdapCertificateMetadata {
    sha256_fingerprint: Option<String>,
    issuer: Option<String>,
    activation_time: Option<String>,
    expiration_time: Option<String>,
    time_status: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct RadiusAuthenticationSettings {
    available: bool,
    enabled: bool,
    host: String,
    secret_configured: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LdapAuthenticationSettingsUpdateRequest {
    enabled: bool,
    host: String,
    auth_dn: String,
    allow_plaintext: bool,
    ldaps_only: bool,
    ca_certificate_pem: Option<SensitiveBytes>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RadiusAuthenticationSettingsUpdateRequest {
    enabled: bool,
    host: String,
    secret: Option<SensitiveBytes>,
}

struct ValidatedLdapAuthenticationSettingsUpdate {
    enabled: bool,
    host: String,
    auth_dn: String,
    allow_plaintext: bool,
    ldaps_only: bool,
    ca_certificate_pem: Option<SensitiveBytes>,
}

struct ValidatedRadiusAuthenticationSettingsUpdate {
    enabled: bool,
    host: String,
    secret: Option<SensitiveBytes>,
}

pub(crate) async fn authentication_settings(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<AuthenticationSettings>, ApiError> {
    let operator = require_operator(operator)?;
    Ok(Json(request_authentication_settings(&operator).await?))
}

pub(crate) async fn browser_proxy_authentication_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
) -> Result<Json<AuthenticationSettings>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    Ok(Json(request_authentication_settings(&operator).await?))
}

pub(crate) async fn update_ldap_authentication_settings(
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<LdapAuthenticationSettingsUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = require_operator(operator)?;
    let request = validate_ldap_update(parse_ldap_payload(payload)?)?;
    request_ldap_update(&operator, &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn browser_proxy_update_ldap_authentication_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<LdapAuthenticationSettingsUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    update_ldap_authentication_settings(Some(Extension(operator)), payload).await
}

pub(crate) async fn update_radius_authentication_settings(
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<RadiusAuthenticationSettingsUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = require_operator(operator)?;
    let request = validate_radius_update(parse_radius_payload(payload)?)?;
    request_radius_update(&operator, &request).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn browser_proxy_update_radius_authentication_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<RadiusAuthenticationSettingsUpdateRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    update_radius_authentication_settings(Some(Extension(operator)), payload).await
}

fn require_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    operator
        .map(|Extension(operator)| operator)
        .ok_or(ApiError::Forbidden)
}

fn parse_ldap_payload(
    payload: Result<Json<LdapAuthenticationSettingsUpdateRequest>, JsonRejection>,
) -> Result<LdapAuthenticationSettingsUpdateRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::RequestTooLarge
        } else {
            ApiError::AuthenticationSettingsInvalidRequest
        }
    })
}

fn parse_radius_payload(
    payload: Result<Json<RadiusAuthenticationSettingsUpdateRequest>, JsonRejection>,
) -> Result<RadiusAuthenticationSettingsUpdateRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::RequestTooLarge
        } else {
            ApiError::AuthenticationSettingsInvalidRequest
        }
    })
}

fn validate_ldap_update(
    request: LdapAuthenticationSettingsUpdateRequest,
) -> Result<ValidatedLdapAuthenticationSettingsUpdate, ApiError> {
    validate_plain_text(&request.host, "host", MAX_PROVIDER_HOST_BYTES)?;
    validate_plain_text(&request.auth_dn, "auth_dn", MAX_LDAP_AUTH_DN_BYTES)?;
    if let Some(certificate) = request.ca_certificate_pem.as_ref() {
        validate_multiline_secret(certificate, "ca_certificate_pem", MAX_CA_CERTIFICATE_BYTES)?;
    }
    Ok(ValidatedLdapAuthenticationSettingsUpdate {
        enabled: request.enabled,
        host: request.host,
        auth_dn: request.auth_dn,
        allow_plaintext: request.allow_plaintext,
        ldaps_only: request.ldaps_only,
        ca_certificate_pem: request.ca_certificate_pem,
    })
}

fn validate_radius_update(
    request: RadiusAuthenticationSettingsUpdateRequest,
) -> Result<ValidatedRadiusAuthenticationSettingsUpdate, ApiError> {
    validate_plain_text(&request.host, "host", MAX_PROVIDER_HOST_BYTES)?;
    if let Some(secret) = request.secret.as_ref() {
        validate_secret(secret, "secret", MAX_RADIUS_SECRET_BYTES)?;
    }
    Ok(ValidatedRadiusAuthenticationSettingsUpdate {
        enabled: request.enabled,
        host: request.host,
        secret: request.secret,
    })
}

fn validate_plain_text(value: &str, field: &str, max_bytes: usize) -> Result<(), ApiError> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be at most {max_bytes} UTF-8 bytes without control characters"
        )));
    }
    Ok(())
}

fn validate_secret(value: &SensitiveBytes, field: &str, max_bytes: usize) -> Result<(), ApiError> {
    let text = std::str::from_utf8(value.as_bytes())
        .map_err(|_| ApiError::AuthenticationSettingsInvalidRequest)?;
    if value.as_bytes().is_empty()
        || value.as_bytes().len() > max_bytes
        || text.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must be non-empty UTF-8 text up to {max_bytes} bytes without control characters"
        )));
    }
    Ok(())
}

fn validate_multiline_secret(
    value: &SensitiveBytes,
    field: &str,
    max_bytes: usize,
) -> Result<(), ApiError> {
    let text = std::str::from_utf8(value.as_bytes())
        .map_err(|_| ApiError::AuthenticationSettingsInvalidRequest)?;
    if value.as_bytes().is_empty()
        || value.as_bytes().len() > max_bytes
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\r' | '\n'))
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must be non-empty UTF-8 text up to {max_bytes} bytes without unsupported control characters"
        )));
    }
    Ok(())
}

async fn request_authentication_settings(
    operator: &DirectApiOperator,
) -> Result<AuthenticationSettings, ApiError> {
    let control_secret = gvmd_control_secret()?;
    let frame = authentication_settings_read_command(&control_secret, operator);
    let response = request_gvmd_control_response_bytes_with_limit(
        &gvmd_control_socket_path(),
        &control_secret,
        frame.as_bytes(),
        MAX_AUTHENTICATION_SETTINGS_RESPONSE_BYTES,
    )
    .await
    .map_err(map_control_socket_error)?;
    parse_authentication_settings_response(&response)
}

async fn request_ldap_update(
    operator: &DirectApiOperator,
    request: &ValidatedLdapAuthenticationSettingsUpdate,
) -> Result<(), ApiError> {
    let control_secret = gvmd_control_secret()?;
    let frame = ldap_authentication_settings_update_command(&control_secret, operator, request);
    let response = request_gvmd_control_response_bytes(
        &gvmd_control_socket_path(),
        &control_secret,
        frame.as_bytes(),
    )
    .await
    .map_err(map_control_socket_error)?;
    parse_authentication_settings_write_response(&response)
}

async fn request_radius_update(
    operator: &DirectApiOperator,
    request: &ValidatedRadiusAuthenticationSettingsUpdate,
) -> Result<(), ApiError> {
    let control_secret = gvmd_control_secret()?;
    let frame = radius_authentication_settings_update_command(&control_secret, operator, request);
    let response = request_gvmd_control_response_bytes(
        &gvmd_control_socket_path(),
        &control_secret,
        frame.as_bytes(),
    )
    .await
    .map_err(map_control_socket_error)?;
    parse_authentication_settings_write_response(&response)
}

fn authentication_settings_read_command(
    control_secret: &str,
    operator: &DirectApiOperator,
) -> ScrubbedControlFrame {
    ScrubbedControlFrame::new(
        format!(
            "auth-settings-read {control_secret} {}\n",
            operator.user_uuid()
        )
        .into_bytes(),
    )
}

fn ldap_authentication_settings_update_command(
    control_secret: &str,
    operator: &DirectApiOperator,
    request: &ValidatedLdapAuthenticationSettingsUpdate,
) -> ScrubbedControlFrame {
    let mut frame = Vec::with_capacity(
        192 + encoded_len(request.host.len())
            + encoded_len(request.auth_dn.len())
            + request
                .ca_certificate_pem
                .as_ref()
                .map_or(1, |value| encoded_len(value.as_bytes().len())),
    );
    frame.extend_from_slice(b"auth-settings-ldap-write ");
    frame.extend_from_slice(control_secret.as_bytes());
    frame.push(b' ');
    frame.extend_from_slice(operator.user_uuid().as_bytes());
    append_flag(&mut frame, request.enabled);
    frame.push(b' ');
    append_base64(&mut frame, request.host.as_bytes());
    frame.push(b' ');
    append_base64(&mut frame, request.auth_dn.as_bytes());
    append_flag(&mut frame, request.allow_plaintext);
    append_flag(&mut frame, request.ldaps_only);
    frame.push(b' ');
    append_optional_base64(
        &mut frame,
        request
            .ca_certificate_pem
            .as_ref()
            .map(SensitiveBytes::as_bytes),
    );
    frame.push(b'\n');
    ScrubbedControlFrame::new(frame)
}

fn radius_authentication_settings_update_command(
    control_secret: &str,
    operator: &DirectApiOperator,
    request: &ValidatedRadiusAuthenticationSettingsUpdate,
) -> ScrubbedControlFrame {
    let mut frame = Vec::with_capacity(
        160 + encoded_len(request.host.len())
            + request
                .secret
                .as_ref()
                .map_or(1, |value| encoded_len(value.as_bytes().len())),
    );
    frame.extend_from_slice(b"auth-settings-radius-write ");
    frame.extend_from_slice(control_secret.as_bytes());
    frame.push(b' ');
    frame.extend_from_slice(operator.user_uuid().as_bytes());
    append_flag(&mut frame, request.enabled);
    frame.push(b' ');
    append_base64(&mut frame, request.host.as_bytes());
    frame.push(b' ');
    append_optional_base64(
        &mut frame,
        request.secret.as_ref().map(SensitiveBytes::as_bytes),
    );
    frame.push(b'\n');
    ScrubbedControlFrame::new(frame)
}

fn append_flag(frame: &mut Vec<u8>, value: bool) {
    frame.push(b' ');
    frame.push(if value { b'1' } else { b'0' });
}

fn encoded_len(value_len: usize) -> usize {
    value_len.div_ceil(3) * 4
}

fn append_base64(frame: &mut Vec<u8>, value: &[u8]) {
    if value.is_empty() {
        frame.push(b'-');
        return;
    }
    let start = frame.len();
    frame.resize(start + encoded_len(value.len()), 0);
    let written = STANDARD
        .encode_slice(value, &mut frame[start..])
        .expect("preallocated base64 output must be sufficient");
    frame.truncate(start + written);
}

fn append_optional_base64(frame: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => append_base64(frame, value),
        None => frame.push(b'-'),
    }
}

fn parse_authentication_settings_response(
    response: &[u8],
) -> Result<AuthenticationSettings, ApiError> {
    if !response.starts_with(b"0 settings ") {
        return Err(parse_authentication_settings_control_error(response));
    }
    let fields = response.split(|byte| *byte == b' ').collect::<Vec<_>>();
    if fields.len() != 18 || fields[0] != b"0" || fields[1] != b"settings" {
        return Err(ApiError::ControlFailure);
    }

    let ldap_available = parse_flag(fields[2])?;
    let ldap_enabled = parse_flag(fields[3])?;
    let ldap_host = decode_base64_text(fields[4], MAX_PROVIDER_HOST_BYTES)?;
    let ldap_auth_dn = decode_base64_text(fields[5], MAX_LDAP_AUTH_DN_BYTES)?;
    let allow_plaintext = parse_flag(fields[6])?;
    let ldaps_only = parse_flag(fields[7])?;
    let certificate_present = parse_flag(fields[8])?;
    let certificate = if certificate_present {
        Some(LdapCertificateMetadata {
            sha256_fingerprint: decode_optional_base64_text(
                fields[9],
                MAX_CERTIFICATE_FINGERPRINT_BYTES,
            )?,
            issuer: decode_optional_base64_text(fields[10], MAX_CERTIFICATE_ISSUER_BYTES)?,
            activation_time: decode_optional_base64_text(fields[11], MAX_CERTIFICATE_TIME_BYTES)?,
            expiration_time: decode_optional_base64_text(fields[12], MAX_CERTIFICATE_TIME_BYTES)?,
            time_status: decode_optional_base64_text(
                fields[13],
                MAX_CERTIFICATE_TIME_STATUS_BYTES,
            )?,
        })
    } else {
        if fields[9..14].iter().any(|field| *field != b"-") {
            return Err(ApiError::ControlFailure);
        }
        None
    };
    let radius_available = parse_flag(fields[14])?;
    let radius_enabled = parse_flag(fields[15])?;
    let radius_host = decode_base64_text(fields[16], MAX_PROVIDER_HOST_BYTES)?;
    let radius_secret_configured = parse_flag(fields[17])?;

    Ok(AuthenticationSettings {
        ldap: LdapAuthenticationSettings {
            available: ldap_available,
            enabled: ldap_enabled,
            host: ldap_host,
            auth_dn: ldap_auth_dn,
            allow_plaintext,
            ldaps_only,
            certificate,
        },
        radius: RadiusAuthenticationSettings {
            available: radius_available,
            enabled: radius_enabled,
            host: radius_host,
            secret_configured: radius_secret_configured,
        },
    })
}

fn parse_flag(value: &[u8]) -> Result<bool, ApiError> {
    match value {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(ApiError::ControlFailure),
    }
}

fn decode_optional_base64_text(value: &[u8], max_bytes: usize) -> Result<Option<String>, ApiError> {
    if value == b"-" {
        Ok(None)
    } else {
        decode_base64_text(value, max_bytes).map(Some)
    }
}

fn decode_base64_text(value: &[u8], max_bytes: usize) -> Result<String, ApiError> {
    if value == b"-" {
        return Ok(String::new());
    }
    if value.is_empty() || value.len() > encoded_len(max_bytes) {
        return Err(ApiError::ControlFailure);
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ApiError::ControlFailure)?;
    if decoded.len() > max_bytes || STANDARD.encode(&decoded).as_bytes() != value {
        return Err(ApiError::ControlFailure);
    }
    let text = String::from_utf8(decoded).map_err(|_| ApiError::ControlFailure)?;
    if text.chars().any(char::is_control) {
        return Err(ApiError::ControlFailure);
    }
    Ok(text)
}

fn parse_authentication_settings_write_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 updated" => Ok(()),
        b"1 invalid-auth-dn"
        | b"2 invalid-certificate"
        | b"3 provider-unavailable"
        | b"4 encryption-failed"
        | b"99 permission-denied"
        | b"-2 invalid-request"
        | b"-1 internal-error" => Err(parse_authentication_settings_control_error(response)),
        _ => Err(ApiError::MutationOutcomeIndeterminate),
    }
}

fn parse_authentication_settings_control_error(response: &[u8]) -> ApiError {
    match response {
        b"1 invalid-auth-dn" => ApiError::InvalidAuthDn,
        b"2 invalid-certificate" => ApiError::InvalidCertificate,
        b"3 provider-unavailable" => ApiError::AuthenticationProviderUnavailable,
        b"4 encryption-failed" => ApiError::AuthenticationSettingsEncryptionFailed,
        b"99 permission-denied" => ApiError::AuthenticationSettingsPermissionDenied,
        b"-2 invalid-request" => ApiError::AuthenticationSettingsInvalidRequest,
        b"-1 internal-error" => ApiError::AuthenticationSettingsInternalError,
        _ => ApiError::ControlFailure,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OPERATOR_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn operator() -> DirectApiOperator {
        DirectApiOperator::new(OPERATOR_UUID, Some("operator".to_string())).unwrap()
    }

    fn ldap_request(value: serde_json::Value) -> LdapAuthenticationSettingsUpdateRequest {
        serde_json::from_value(value).unwrap()
    }

    fn radius_request(value: serde_json::Value) -> RadiusAuthenticationSettingsUpdateRequest {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn update_dtos_are_strict_bounded_complete_snapshots() {
        assert!(
            validate_ldap_update(ldap_request(json!({
                "enabled": true,
                "host": "ldap.example",
                "auth_dn": "cn=service,dc=example",
                "allow_plaintext": false,
                "ldaps_only": true
            })))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<LdapAuthenticationSettingsUpdateRequest>(json!({
                "enabled": true,
                "host": "ldap.example",
                "auth_dn": "cn=service",
                "allow_plaintext": false,
                "ldaps_only": true,
                "unexpected": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<LdapAuthenticationSettingsUpdateRequest>(json!({
                "enabled": true,
                "host": "ldap.example",
                "auth_dn": "cn=service",
                "allow_plaintext": false
            }))
            .is_err()
        );
        assert!(
            validate_ldap_update(ldap_request(json!({
                "enabled": false,
                "host": "ldap\n.example",
                "auth_dn": "",
                "allow_plaintext": false,
                "ldaps_only": false
            })))
            .is_err()
        );
        assert!(
            validate_radius_update(radius_request(json!({
                "enabled": true,
                "host": "radius.example",
                "secret": "shared secret"
            })))
            .is_ok()
        );
        assert!(
            validate_radius_update(radius_request(json!({
                "enabled": true,
                "host": "radius.example",
                "secret": ""
            })))
            .is_err()
        );
    }

    #[test]
    fn control_frames_match_the_private_protocol_and_scrub() {
        let read = authentication_settings_read_command(CONTROL_SECRET, &operator());
        assert_eq!(
            read.as_bytes(),
            format!("auth-settings-read {CONTROL_SECRET} {OPERATOR_UUID}\n").as_bytes()
        );

        let ldap = validate_ldap_update(ldap_request(json!({
            "enabled": true,
            "host": "ldap.example",
            "auth_dn": "cn=service",
            "allow_plaintext": true,
            "ldaps_only": false,
            "ca_certificate_pem": "CERT\n"
        })))
        .unwrap();
        let mut frame =
            ldap_authentication_settings_update_command(CONTROL_SECRET, &operator(), &ldap);
        assert_eq!(
            frame.as_bytes(),
            format!(
                "auth-settings-ldap-write {CONTROL_SECRET} {OPERATOR_UUID} 1 bGRhcC5leGFtcGxl Y249c2VydmljZQ== 1 0 Q0VSVAo=\n"
            )
            .as_bytes()
        );
        frame.scrub();
        assert!(frame.as_bytes().iter().all(|byte| *byte == 0));

        let radius = validate_radius_update(radius_request(json!({
            "enabled": false,
            "host": "",
        })))
        .unwrap();
        let frame =
            radius_authentication_settings_update_command(CONTROL_SECRET, &operator(), &radius);
        assert_eq!(
            frame.as_bytes(),
            format!("auth-settings-radius-write {CONTROL_SECRET} {OPERATOR_UUID} 0 - -\n")
                .as_bytes()
        );
    }

    #[test]
    fn empty_required_text_uses_the_canonical_dash_sentinel_round_trip() {
        let ldap = validate_ldap_update(ldap_request(json!({
            "enabled": false,
            "host": "",
            "auth_dn": "",
            "allow_plaintext": false,
            "ldaps_only": false
        })))
        .unwrap();
        let frame = ldap_authentication_settings_update_command(CONTROL_SECRET, &operator(), &ldap);
        assert_eq!(
            frame.as_bytes(),
            format!("auth-settings-ldap-write {CONTROL_SECRET} {OPERATOR_UUID} 0 - - 0 0 -\n")
                .as_bytes()
        );

        let settings =
            parse_authentication_settings_response(b"0 settings 1 0 - - 0 0 0 - - - - - 1 0 - 0")
                .unwrap();
        assert_eq!(settings.ldap.host, "");
        assert_eq!(settings.ldap.auth_dn, "");
        assert_eq!(settings.radius.host, "");
        assert!(settings.ldap.certificate.is_none());
        assert!(!settings.radius.secret_configured);
    }

    #[test]
    fn read_response_is_strict_and_redacted() {
        let encode = |value: &str| STANDARD.encode(value);
        let response = format!(
            "0 settings 1 1 {} {} 0 1 1 {} {} {} {} {} 1 0 {} 1",
            encode("ldap.example"),
            encode("cn=service,dc=example"),
            encode("AA:BB"),
            encode("CN=Example CA"),
            encode("2026-01-01T00:00:00Z"),
            encode("2027-01-01T00:00:00Z"),
            encode("valid"),
            encode("radius.example"),
        );
        let settings = parse_authentication_settings_response(response.as_bytes()).unwrap();
        assert!(settings.ldap.available);
        assert_eq!(settings.ldap.host, "ldap.example");
        assert_eq!(
            settings
                .ldap
                .certificate
                .as_ref()
                .and_then(|certificate| certificate.issuer.as_deref()),
            Some("CN=Example CA")
        );
        assert!(settings.radius.secret_configured);
        let json = serde_json::to_value(settings).unwrap();
        assert!(json.pointer("/ldap/certificate/issuer").is_some());
        assert!(json.pointer("/ldap/ca_certificate_pem").is_none());
        assert!(json.pointer("/radius/secret").is_none());
    }

    #[test]
    fn read_response_rejects_noncanonical_unbounded_or_inconsistent_fields() {
        for response in [
            "0 settings 1 1 bGFkYXA= Y24= 0 0 0 - - - - - 1 0 cmFkaXVz 0 extra",
            "0 settings 1 1 bGFkYXA Y24= 0 0 0 - - - - - 1 0 cmFkaXVz 0",
            "0 settings 1 1  Y24= 0 0 0 - - - - - 1 0 cmFkaXVz 0",
            "0 settings 1 2 bGFkYXA= Y24= 0 0 0 - - - - - 1 0 cmFkaXVz 0",
            "0 settings 1 1 bGFkYXA= Y24= 0 0 0 Zm9v - - - - 1 0 cmFkaXVz 0",
        ] {
            assert!(matches!(
                parse_authentication_settings_response(response.as_bytes()),
                Err(ApiError::ControlFailure)
            ));
        }
        let oversized_host = STANDARD.encode("x".repeat(MAX_PROVIDER_HOST_BYTES + 1));
        let response =
            format!("0 settings 1 1 {oversized_host} Y24= 0 0 0 - - - - - 1 0 cmFkaXVz 0");
        assert!(matches!(
            parse_authentication_settings_response(response.as_bytes()),
            Err(ApiError::ControlFailure)
        ));
    }

    #[test]
    fn every_documented_control_outcome_has_a_distinct_api_mapping() {
        let cases = [
            (
                "1 invalid-auth-dn",
                StatusCode::BAD_REQUEST,
                "invalid_auth_dn",
            ),
            (
                "2 invalid-certificate",
                StatusCode::BAD_REQUEST,
                "invalid_certificate",
            ),
            (
                "3 provider-unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "provider_unavailable",
            ),
            (
                "4 encryption-failed",
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption_failed",
            ),
            (
                "99 permission-denied",
                StatusCode::FORBIDDEN,
                "permission_denied",
            ),
            (
                "-2 invalid-request",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                "-1 internal-error",
                StatusCode::BAD_GATEWAY,
                "internal_error",
            ),
        ];
        for (response, status, code) in cases {
            let error = parse_authentication_settings_write_response(response.as_bytes())
                .expect_err("documented failure must fail");
            assert_eq!(error.status_code(), status);
            assert_eq!(error.code(), code);
        }
        assert!(parse_authentication_settings_write_response(b"0 updated").is_ok());
        let unknown = parse_authentication_settings_write_response(b"unexpected")
            .expect_err("unknown post-dispatch response must be indeterminate");
        assert!(matches!(&unknown, ApiError::MutationOutcomeIndeterminate));
        assert_eq!(unknown.code(), "mutation_outcome_indeterminate");
    }
}
