// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    http::{Method, Request, header},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

use crate::{
    authentication_settings::MAX_AUTHENTICATION_SETTINGS_BODY_BYTES,
    direct_api::direct_api_v1_method_is_allowed,
    gvmd_control::{ControlSocketError, request_gvmd_control_response_bytes_with_limit},
    request_shapes::direct_api_request_shape_is_allowed_for_method,
};

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn authentication_settings_direct_routes_have_read_and_write_control_boundaries() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/authentication-settings",
        false,
    ));
    for path in [
        "/api/v1/authentication-settings/ldap",
        "/api/v1/authentication-settings/radius",
    ] {
        assert!(!direct_api_v1_method_is_allowed(&Method::PUT, path, false));
        assert!(direct_api_v1_method_is_allowed(&Method::PUT, path, true));

        let at_limit = Request::builder()
            .method(Method::PUT)
            .uri(path)
            .header(
                header::CONTENT_LENGTH,
                MAX_AUTHENTICATION_SETTINGS_BODY_BYTES.to_string(),
            )
            .body(Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed_for_method(
            &Method::PUT,
            &at_limit,
        ));

        let oversized = Request::builder()
            .method(Method::PUT)
            .uri(path)
            .header(
                header::CONTENT_LENGTH,
                (MAX_AUTHENTICATION_SETTINGS_BODY_BYTES + 1).to_string(),
            )
            .body(Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed_for_method(
            &Method::PUT,
            &oversized,
        ));
    }
}

#[test]
fn direct_and_browser_routes_use_bounded_operator_aware_handlers() {
    let direct_routes = include_str!("direct_api_routes.rs");
    let browser_routes = include_str!("browser_proxy_routes.rs");
    let handlers = include_str!("authentication_settings.rs");

    for required in [
        "/api/v1/authentication-settings",
        "/api/v1/authentication-settings/ldap",
        "/api/v1/authentication-settings/radius",
        "MAX_AUTHENTICATION_SETTINGS_BODY_BYTES",
    ] {
        assert!(
            direct_routes.contains(required),
            "direct routes missing {required}"
        );
        assert!(
            browser_routes.contains(required),
            "browser routes missing {required}"
        );
    }
    for required in [
        "browser_proxy_operator_from_headers(&state, &auth, &headers).await?",
        "SensitiveBytes",
        "ScrubbedControlFrame",
        "request_gvmd_control_response_bytes_with_limit",
    ] {
        assert!(handlers.contains(required), "handlers missing {required}");
    }
    assert!(!handlers.contains("tracing::"));
}

#[test]
fn openapi_declares_redaction_write_only_fields_and_write_control_metadata() {
    let openapi = include_str!("../../../api/openapi/yafvs-v1.yaml");
    let read = openapi
        .split_once("  /authentication-settings:")
        .unwrap()
        .1
        .split_once("  /authentication-settings/ldap:")
        .unwrap()
        .0;
    assert!(read.contains("x-turbovas-exposure: direct-read"));
    assert!(read.contains("$ref: '#/components/schemas/AuthenticationSettings'"));
    assert!(read.contains("never returned"));

    let ldap = openapi
        .split_once("  /authentication-settings/ldap:")
        .unwrap()
        .1
        .split_once("  /authentication-settings/radius:")
        .unwrap()
        .0;
    let radius = openapi
        .split_once("  /authentication-settings/radius:")
        .unwrap()
        .1
        .split_once("  /user-management/users:")
        .unwrap()
        .0;
    for operation in [ldap, radius] {
        for metadata in [
            "x-turbovas-exposure: direct-write",
            "x-turbovas-safety-contract: write-control-v1",
            "x-turbovas-side-effect: account-auth-control",
            "x-turbovas-operator-identity: direct-token-operator",
        ] {
            assert!(operation.contains(metadata), "operation missing {metadata}");
        }
    }

    let schemas = openapi.split_once("    AuthenticationSettings:").unwrap().1;
    for required in [
        "    LdapAuthenticationSettings:",
        "    LdapCertificateMetadata:",
        "    RadiusAuthenticationSettings:",
        "    LdapAuthenticationSettingsUpdateRequest:",
        "    RadiusAuthenticationSettingsUpdateRequest:",
        "secret_configured:",
        "ca_certificate_pem:",
        "secret:",
        "writeOnly: true",
    ] {
        assert!(schemas.contains(required), "schemas missing {required}");
    }
}

#[tokio::test]
async fn oversized_response_after_dispatch_is_indeterminate() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let socket_path = std::env::temp_dir().join(format!(
        "yafvs-api-auth-settings-{}-{nonce}.sock",
        std::process::id(),
    ));
    let listener = UnixListener::bind(&socket_path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 256];
        let count = stream.read(&mut request).await.unwrap();
        assert!(request[..count].ends_with(b"\n"));
        stream
            .write_all(b"0 settings response-exceeds-bound\n")
            .await
            .unwrap();
    });

    let result = request_gvmd_control_response_bytes_with_limit(
        socket_path.to_str().unwrap(),
        CONTROL_SECRET,
        b"auth-settings-read 0123456789abcdef0123456789abcdef 123e4567-e89b-12d3-a456-426614174000\n",
        8,
    )
    .await;
    server.await.unwrap();
    let _ = fs::remove_file(&socket_path);
    assert_eq!(result, Err(ControlSocketError::OutcomeIndeterminate));
}
