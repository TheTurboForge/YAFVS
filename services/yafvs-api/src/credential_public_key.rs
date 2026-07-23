// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: components/gvmd/src/gmp.c; components/gvmd/src/manage_sql.c; components/gvmd/src/yafvs_control.c; components/gsad/src/gsad_gmp.c

use axum::{
    Extension,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Response, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
    gvmd_control::{
        ControlSocketError, MAX_CONTROL_REQUEST_BYTES, ScrubbedControlFrame, gvmd_control_secret,
        gvmd_control_socket_path, map_control_socket_error,
        request_gvmd_control_response_bytes_with_limit, validate_gvmd_control_secret,
    },
    path_ids::parse_uuid,
};

pub(crate) const MAX_CREDENTIAL_PUBLIC_KEY_BYTES: usize = 49_146;
pub(crate) const MAX_CREDENTIAL_PUBLIC_KEY_FRAMED_RESPONSE_BYTES: usize = 65_535;
const MAX_CREDENTIAL_PUBLIC_KEY_RESPONSE_BYTES: usize =
    MAX_CREDENTIAL_PUBLIC_KEY_FRAMED_RESPONSE_BYTES - 1;
const CREDENTIAL_PUBLIC_KEY_UNAVAILABLE_MESSAGE: &str = "The credential public key is unavailable.";

pub(crate) async fn credential_public_key(
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Response<Body>, ApiError> {
    let operator = require_credential_public_key_operator(operator)?;
    let credential_id = parse_uuid(&credential_id)?.to_string();
    let control_secret = gvmd_control_secret()?;
    let key = request_credential_public_key(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &credential_id,
    )
    .await?;

    credential_public_key_response(&credential_id, key)
}

pub(crate) async fn browser_proxy_credential_public_key(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    credential_public_key(Path(credential_id), Some(Extension(operator))).await
}

fn require_credential_public_key_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    operator
        .map(|Extension(operator)| operator)
        .ok_or(ApiError::Forbidden)
}

async fn request_credential_public_key(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    credential_uuid: &str,
) -> Result<Vec<u8>, ApiError> {
    let command = credential_public_key_command(control_secret, operator_uuid, credential_uuid)?;
    let response = request_gvmd_control_response_bytes_with_limit(
        socket_path,
        control_secret,
        command.as_bytes(),
        MAX_CREDENTIAL_PUBLIC_KEY_FRAMED_RESPONSE_BYTES,
    )
    .await
    .map_err(map_credential_public_key_control_error)?;
    parse_credential_public_key_response(&response)
}

fn map_credential_public_key_control_error(error: ControlSocketError) -> ApiError {
    match error {
        ControlSocketError::Failure | ControlSocketError::OutcomeIndeterminate => {
            ApiError::ControlFailure
        }
        error => map_control_socket_error(error),
    }
}

fn credential_public_key_command(
    control_secret: &str,
    operator_uuid: &str,
    credential_uuid: &str,
) -> Result<ScrubbedControlFrame, ApiError> {
    validate_gvmd_control_secret(control_secret)?;
    let operator_uuid = parse_uuid(operator_uuid)?.to_string();
    let credential_uuid = parse_uuid(credential_uuid)?.to_string();
    let mut command = Vec::with_capacity(160);
    command.extend_from_slice(b"credential-public-key ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.extend_from_slice(credential_uuid.as_bytes());
    command.push(b'\n');
    if command.len() >= MAX_CONTROL_REQUEST_BYTES {
        return Err(ApiError::RequestTooLarge);
    }
    Ok(ScrubbedControlFrame::new(command))
}

fn parse_credential_public_key_response(response: &[u8]) -> Result<Vec<u8>, ApiError> {
    if response.is_empty() || response.len() > MAX_CREDENTIAL_PUBLIC_KEY_RESPONSE_BYTES {
        return Err(ApiError::ControlFailure);
    }
    match response {
        b"1 not_found" => Err(ApiError::NotFound),
        b"2 unavailable" => Err(ApiError::Conflict(
            CREDENTIAL_PUBLIC_KEY_UNAVAILABLE_MESSAGE.to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        _ => {
            let encoded = response
                .strip_prefix(b"0 key ")
                .filter(|encoded| !encoded.is_empty())
                .ok_or(ApiError::ControlFailure)?;
            let key = STANDARD
                .decode(encoded)
                .map_err(|_| ApiError::ControlFailure)?;
            if key.is_empty() || key.len() > MAX_CREDENTIAL_PUBLIC_KEY_BYTES {
                return Err(ApiError::ControlFailure);
            }
            Ok(key)
        }
    }
}

fn credential_public_key_response(
    credential_id: &str,
    key: Vec<u8>,
) -> Result<Response<Body>, ApiError> {
    let credential_id = parse_uuid(credential_id)?.to_string();
    let content_disposition = HeaderValue::from_str(&format!(
        "attachment; filename=\"credential-{credential_id}.pub\""
    ))
    .map_err(|_| ApiError::Config)?;
    let content_length =
        HeaderValue::from_str(&key.len().to_string()).map_err(|_| ApiError::ControlFailure)?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/key")
        .header(header::CONTENT_DISPOSITION, content_disposition)
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(key))
        .map_err(|_| ApiError::ControlFailure)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::{
        body::to_bytes,
        http::{StatusCode, header},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    use super::*;

    const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OPERATOR_UUID: &str = "12345678-1234-1234-1234-123456789abc";
    const CREDENTIAL_UUID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    #[test]
    fn command_is_exact_canonical_and_scrubbable() {
        let mut command = credential_public_key_command(
            CONTROL_SECRET,
            "12345678-1234-1234-1234-123456789ABC",
            "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
        )
        .unwrap();
        assert_eq!(
            command.as_bytes(),
            format!("credential-public-key {CONTROL_SECRET} {OPERATOR_UUID} {CREDENTIAL_UUID}\n")
                .as_bytes()
        );
        let length = command.as_bytes().len();
        command.scrub();
        assert_eq!(command.as_bytes(), vec![0; length]);
        assert!(credential_public_key_command(CONTROL_SECRET, "invalid", CREDENTIAL_UUID).is_err());
        assert!(credential_public_key_command(CONTROL_SECRET, OPERATOR_UUID, "invalid").is_err());
    }

    #[test]
    fn response_statuses_are_mapped_exactly() {
        assert_eq!(
            parse_credential_public_key_response(b"1 not_found")
                .unwrap_err()
                .status_code(),
            StatusCode::NOT_FOUND
        );
        let unavailable = parse_credential_public_key_response(b"2 unavailable").unwrap_err();
        assert_eq!(unavailable.status_code(), StatusCode::CONFLICT);
        assert_eq!(
            unavailable.public_message(),
            CREDENTIAL_PUBLIC_KEY_UNAVAILABLE_MESSAGE
        );
        assert_eq!(
            parse_credential_public_key_response(b"99 forbidden")
                .unwrap_err()
                .status_code(),
            StatusCode::FORBIDDEN
        );
        for response in [
            b"".as_slice(),
            b"0 key".as_slice(),
            b"0 key ".as_slice(),
            b"0 key !!!".as_slice(),
            b"0 key c3NoLXJzYQ== extra".as_slice(),
            b"0 key c3NoLXJzYQ==\n".as_slice(),
            b"3 internal".as_slice(),
            b"1 not_found extra".as_slice(),
        ] {
            assert!(matches!(
                parse_credential_public_key_response(response),
                Err(ApiError::ControlFailure)
            ));
        }
        assert!(matches!(
            parse_credential_public_key_response(b"0 key "),
            Err(ApiError::ControlFailure)
        ));
    }

    #[test]
    fn response_parser_enforces_decoded_and_raw_bounds() {
        let maximum_key = vec![b'k'; MAX_CREDENTIAL_PUBLIC_KEY_BYTES];
        let maximum_response = format!("0 key {}", STANDARD.encode(&maximum_key));
        assert_eq!(
            maximum_response.len(),
            MAX_CREDENTIAL_PUBLIC_KEY_RESPONSE_BYTES
        );
        assert_eq!(
            parse_credential_public_key_response(maximum_response.as_bytes()).unwrap(),
            maximum_key
        );

        let oversized_key = vec![b'k'; MAX_CREDENTIAL_PUBLIC_KEY_BYTES + 1];
        let oversized_response = format!("0 key {}", STANDARD.encode(oversized_key));
        assert!(matches!(
            parse_credential_public_key_response(oversized_response.as_bytes()),
            Err(ApiError::ControlFailure)
        ));
        assert!(matches!(
            parse_credential_public_key_response(&vec![
                b'x';
                MAX_CREDENTIAL_PUBLIC_KEY_RESPONSE_BYTES + 1
            ]),
            Err(ApiError::ControlFailure)
        ));
    }

    #[tokio::test]
    async fn transport_accepts_exact_framed_limit_and_rejects_oversized_frame() {
        let maximum_key = vec![b'k'; MAX_CREDENTIAL_PUBLIC_KEY_BYTES];
        let maximum_response = format!("0 key {}\n", STANDARD.encode(&maximum_key));
        assert_eq!(
            maximum_response.len(),
            MAX_CREDENTIAL_PUBLIC_KEY_FRAMED_RESPONSE_BYTES
        );
        let key = request_from_test_socket(maximum_response.into_bytes())
            .await
            .unwrap();
        assert_eq!(key, maximum_key);

        let oversized_response = format!(
            "0 key {}\n",
            STANDARD.encode(vec![b'k'; MAX_CREDENTIAL_PUBLIC_KEY_BYTES + 1])
        );
        assert!(oversized_response.len() > MAX_CREDENTIAL_PUBLIC_KEY_FRAMED_RESPONSE_BYTES);
        assert!(matches!(
            request_from_test_socket(oversized_response.into_bytes()).await,
            Err(ApiError::ControlFailure)
        ));
    }

    async fn request_from_test_socket(response: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = std::env::temp_dir().join(format!(
            "yafvs-api-credential-public-key-{}-{nonce}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = vec![0_u8; 256];
            let count = stream.read(&mut command).await.unwrap();
            assert_eq!(
                &command[..count],
                format!(
                    "credential-public-key {CONTROL_SECRET} {OPERATOR_UUID} {CREDENTIAL_UUID}\n"
                )
                .as_bytes()
            );
            stream.write_all(&response).await.unwrap();
        });
        let result = request_credential_public_key(
            socket_path.to_str().unwrap(),
            CONTROL_SECRET,
            OPERATOR_UUID,
            CREDENTIAL_UUID,
        )
        .await;
        server.await.unwrap();
        std::fs::remove_file(socket_path).unwrap();
        result
    }

    #[tokio::test]
    async fn binary_response_has_exact_download_headers_and_body() {
        let key = b"ssh-ed25519 \0binary\xffkey\n".to_vec();
        let response =
            credential_public_key_response("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", key.clone())
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.len(), 6);
        assert_eq!(headers[header::CONTENT_TYPE], "application/key");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"credential-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.pub\""
        );
        assert_eq!(headers[header::CONTENT_LENGTH], key.len().to_string());
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::PRAGMA], "no-cache");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(
            to_bytes(response.into_body(), MAX_CREDENTIAL_PUBLIC_KEY_BYTES)
                .await
                .unwrap(),
            key
        );
    }
}
