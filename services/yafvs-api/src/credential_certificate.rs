// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: behavioral-reimplementation
// YAFVS-Source-Provenance: components/gvmd/src/gmp.c; components/gvmd/src/manage_sql.c; components/gsad/src/gsad_gmp.c

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, Response, header},
};

use crate::{
    app_state::AppState,
    credential_query_sql::credential_certificate_sql,
    errors::ApiError,
    path_ids::parse_uuid,
    scanner_write_validation::{MAX_SCANNER_CA_PUB_BYTES, certificate_pem_is_valid},
};

pub(crate) async fn credential_certificate(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let credential_id = parse_uuid(&credential_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let max_certificate_bytes = MAX_SCANNER_CA_PUB_BYTES as i64;
    let row = client
        .query_opt(
            credential_certificate_sql(),
            &[&credential_id, &max_certificate_bytes],
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                %error,
                credential_id = %credential_id,
                "credential certificate query failed"
            );
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let certificate: String = row.try_get("certificate").map_err(|error| {
        tracing::warn!(
            %error,
            credential_id = %credential_id,
            "credential certificate row was malformed"
        );
        ApiError::Database
    })?;
    if certificate.len() > MAX_SCANNER_CA_PUB_BYTES || !certificate_pem_is_valid(&certificate) {
        tracing::warn!(
            credential_id = %credential_id,
            "stored credential certificate failed bounded PEM validation"
        );
        return Err(ApiError::ControlFailure);
    }
    credential_certificate_response(&credential_id, certificate.into_bytes())
}

fn credential_certificate_response(
    credential_id: &str,
    certificate: Vec<u8>,
) -> Result<Response<Body>, ApiError> {
    let credential_id = parse_uuid(credential_id)?.to_string();
    let content_disposition = HeaderValue::from_str(&format!(
        "attachment; filename=\"credential-{credential_id}.pem\""
    ))
    .map_err(|_| ApiError::Config)?;
    let content_length = HeaderValue::from_str(&certificate.len().to_string())
        .map_err(|_| ApiError::ControlFailure)?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, content_disposition)
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(certificate))
        .map_err(|_| ApiError::ControlFailure)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::to_bytes,
        http::{StatusCode, header},
    };

    use super::*;

    const CREDENTIAL_UUID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    #[tokio::test]
    async fn response_preserves_exact_bytes_and_hardening_headers() {
        let certificate = b"exact certificate bytes\n".to_vec();
        let response =
            credential_certificate_response(CREDENTIAL_UUID, certificate.clone()).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        let expected_filename =
            format!("attachment; filename=\"credential-{CREDENTIAL_UUID}.pem\"");
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            expected_filename.as_str()
        );
        assert_eq!(
            response.headers().get(header::CONTENT_LENGTH).unwrap(),
            certificate.len().to_string().as_str()
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            to_bytes(response.into_body(), MAX_SCANNER_CA_PUB_BYTES)
                .await
                .unwrap(),
            certificate
        );
    }

    #[test]
    fn response_rejects_non_uuid_filename_material() {
        assert!(
            credential_certificate_response("../../credential", Vec::new()).is_err(),
            "response filenames must derive only from canonical UUIDs"
        );
    }
}
