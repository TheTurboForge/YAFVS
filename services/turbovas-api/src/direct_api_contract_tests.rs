// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};

use crate::{
    auth::{bearer_token_matches, constant_time_str_eq},
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
    errors::ApiError,
    request_ids::{
        MAX_REQUEST_ID_LENGTH, attach_request_id_header, new_request_id, request_id_from_headers,
        request_id_header_name, request_id_is_valid,
    },
};

#[derive(Debug, PartialEq, Eq)]
struct RegisteredRoute<'a> {
    path: &'a str,
    method: &'a str,
}

struct NativeWriteRouteContract {
    method: &'static str,
    path: &'static str,
    safety_contract: &'static str,
}

const APPROVED_NATIVE_WRITE_ROUTE_CONTRACTS: &[NativeWriteRouteContract] = &[
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/scopes",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/scopes/:scope_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/scopes/:scope_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/tags",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/tags/:tag_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/tags/:tag_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/tags/:tag_id/resources",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/tags/:tag_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/tags/:tag_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/tags/:tag_id/trash",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/report-configs",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/report-configs/:report_config_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/report-configs/:report_config_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/report-configs/:report_config_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/report-configs/:report_config_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/report-configs/:report_config_id/trash",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/scan-configs",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/scan-configs/:scan_config_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/scan-configs/:scan_config_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/scan-configs/:scan_config_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/scan-configs/:scan_config_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/scan-configs/:scan_config_id/trash",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/alerts/:alert_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/credentials/:credential_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/scanners/:scanner_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/targets/:target_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/targets",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/targets/:target_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/targets/:target_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/targets/:target_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/targets/:target_id/trash",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/tasks/:task_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/filters",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/filters/:filter_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/filters/:filter_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/filters/:filter_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/filters/:filter_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/filters/:filter_id/trash",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/port-lists",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/port-lists/:port_list_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/port-lists/:port_list_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/port-lists/:port_list_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/port-lists/:port_list_id/trash",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/port-lists/:port_list_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "patch",
        path: "/api/v1/schedules/:schedule_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/schedules/:schedule_id",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/schedules/:schedule_id/clone",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "post",
        path: "/api/v1/schedules/:schedule_id/restore",
        safety_contract: "write-control-v1",
    },
    NativeWriteRouteContract {
        method: "delete",
        path: "/api/v1/schedules/:schedule_id/trash",
        safety_contract: "write-control-v1",
    },
];

#[test]
fn direct_api_allowlist_tracks_registered_get_routes_and_write_contracts() {
    let source = include_str!("routes.rs");
    let routes = app_route_registration_block(source);
    let api_routes = registered_routes(routes)
        .into_iter()
        .filter(|route| route.path.starts_with("/api/v1/"))
        .collect::<Vec<_>>();
    let internal_only_routes: [&str; 0] = [];

    assert!(api_routes.len() > 40, "expected the native API route table");
    for route in api_routes {
        if route.method == "get" {
            let concrete_path = concrete_direct_api_path(route.path);
            if internal_only_routes.contains(&route.path) {
                assert!(
                    !direct_api_v1_path_is_allowed(&concrete_path),
                    "internal-only route {} must not be direct API allowlisted",
                    route.path
                );
            } else {
                assert!(
                    direct_api_v1_path_is_allowed(&concrete_path),
                    "registered read route {} should be direct API allowlisted as {concrete_path}",
                    route.path
                );
            }
            continue;
        }

        let contract = APPROVED_NATIVE_WRITE_ROUTE_CONTRACTS
            .iter()
            .find(|contract| contract.method == route.method && contract.path == route.path);
        let Some(contract) = contract else {
            panic!(
                "registered native API write/control route {} {} must have an explicit safety contract entry",
                route.method.to_uppercase(),
                route.path
            );
        };
        assert_eq!(
            contract.safety_contract,
            "write-control-v1",
            "write/control route {} {} must use the current safety contract",
            route.method.to_uppercase(),
            route.path
        );
        let concrete_path = concrete_direct_api_path(route.path);
        if route.method != "get" {
            assert!(
                !direct_api_v1_path_is_allowed(&concrete_path),
                "write/control route {} {} must use method-aware direct API gating, not the read allowlist",
                route.method.to_uppercase(),
                route.path
            );
        }
    }
}

#[test]
fn direct_api_write_control_routes_are_direct_only_and_flag_gated() {
    let source = include_str!("routes.rs");
    let internal_routes = registered_routes(app_route_registration_block(source));
    let direct_routes = registered_routes(direct_api_route_registration_block(source));
    let direct_writes = direct_routes
        .iter()
        .filter(|route| route.method != "get")
        .collect::<Vec<_>>();

    assert_eq!(
        direct_writes.len(),
        APPROVED_NATIVE_WRITE_ROUTE_CONTRACTS.len(),
        "direct write/control route count must match explicit safety contracts"
    );
    for contract in APPROVED_NATIVE_WRITE_ROUTE_CONTRACTS {
        let method = contract
            .method
            .to_ascii_uppercase()
            .parse()
            .expect("approved write/control route method must parse");
        assert!(
            !internal_routes
                .iter()
                .any(|route| route.method == contract.method && route.path == contract.path),
            "{} {} must not be registered on the internal/browser router",
            contract.method.to_uppercase(),
            contract.path
        );
        assert!(
            direct_writes
                .iter()
                .any(|route| route.method == contract.method && route.path == contract.path),
            "{} {} must be registered on the direct router when write-control is enabled",
            contract.method.to_uppercase(),
            contract.path
        );

        let concrete_path = concrete_direct_api_path(contract.path);
        assert!(
            !direct_api_v1_method_is_allowed(&method, &concrete_path, false),
            "{} {} must stay denied when direct write-control is disabled",
            contract.method.to_uppercase(),
            contract.path
        );
        assert!(
            direct_api_v1_method_is_allowed(&method, &concrete_path, true),
            "{} {} must be method-allowlisted when direct write-control is enabled",
            contract.method.to_uppercase(),
            contract.path
        );
    }
    assert!(direct_api_route_registration_block(source).contains("if write_control_enabled"));
}

#[test]
fn runtime_accepts_distinct_internal_and_direct_routers() {
    let runtime_source = include_str!("runtime.rs");
    assert!(runtime_source.contains("pub(crate) struct DirectApiListener"));
    assert!(runtime_source.contains("pub(crate) app: Router"));
    assert!(runtime_source.contains("internal_app: Router"));
    assert!(runtime_source.contains("Option<DirectApiListener>"));
    assert!(runtime_source.contains("DirectApiListener { bind, auth, app }"));
    assert!(runtime_source.contains("axum::serve(internal_listener, internal_app)"));
    assert!(runtime_source.contains("axum::serve(direct_listener, direct_app)"));
    assert!(!runtime_source.contains("app.clone().layer"));

    let main_source = include_str!("main.rs");
    assert!(main_source.contains("startup::run().await"));
    assert!(!main_source.contains("DirectApiListener {"));

    let startup_source = include_str!("startup.rs");
    assert!(startup_source.contains("DirectApiListener {"));
    assert!(startup_source.contains("let base_router = native_api_router();"));
    assert!(
        startup_source
            .contains("browser_proxy_native_api_router(base_router.clone(), browser_proxy_auth)")
    );
    assert!(startup_source.contains(".with_state(state.clone())"));
    assert!(startup_source.contains(
        "direct_native_api_router(base_router, auth.write_control_enabled()).with_state(state)"
    ));
    assert!(startup_source.contains("app: direct_app"));
    assert!(!startup_source.contains("app: app.clone()"));
}

fn app_route_registration_block(source: &str) -> &str {
    source
        .split_once("pub(crate) fn native_api_router() -> Router<AppState> {\n    Router::new()")
        .expect("native API router must be registered")
        .1
        .split_once("\n}\n\npub(crate) fn direct_native_api_router")
        .expect("native API router must end before direct router")
        .0
}

fn direct_api_route_registration_block(source: &str) -> &str {
    source
        .split_once("pub(crate) fn direct_native_api_router(")
        .expect("direct API router must be registered")
        .1
        .split_once("\n}\n")
        .expect("direct API router must end")
        .0
}

#[test]
fn direct_api_router_applies_body_limit_to_extractors() {
    let source = include_str!("routes.rs");
    let direct_routes = direct_api_route_registration_block(source);
    assert!(direct_routes.contains("DefaultBodyLimit::max("));
    assert!(direct_routes.contains("MAX_DIRECT_API_WRITE_BODY_BYTES as usize"));
}

#[test]
fn browser_proxy_write_router_is_secret_gated_and_narrow() {
    let source = include_str!("routes.rs");
    let startup_source = include_str!("startup.rs");
    let browser_routes = browser_proxy_route_registration_block(source);
    let registered = registered_routes(browser_routes);
    let mut browser_delete_routes = registered
        .iter()
        .filter(|route| route.method == "delete")
        .map(|route| route.path)
        .collect::<Vec<_>>();
    browser_delete_routes.sort_unstable();
    let mut expected_delete_routes = APPROVED_NATIVE_WRITE_ROUTE_CONTRACTS
        .iter()
        .filter(|contract| contract.method == "delete")
        .map(|contract| contract.path)
        .collect::<Vec<_>>();
    expected_delete_routes.sort_unstable();

    assert!(startup_source.contains("let browser_proxy_auth = browser_proxy_api_config()?;"));
    assert!(browser_routes.contains("let Some(auth) = auth else"));
    assert!(browser_routes.contains("/api/v1/alerts/:alert_id"));
    assert!(browser_routes.contains("/api/v1/filters"));
    assert!(browser_routes.contains("/api/v1/filters/:filter_id"));
    assert!(browser_routes.contains("/api/v1/port-lists"));
    assert!(browser_routes.contains("/api/v1/port-lists/:port_list_id"));
    assert!(browser_routes.contains("/api/v1/report-configs"));
    assert!(browser_routes.contains("/api/v1/report-configs/:report_config_id"));
    assert!(browser_routes.contains("/api/v1/tags"));
    assert!(browser_routes.contains("/api/v1/tags/:tag_id"));
    assert!(browser_routes.contains("/api/v1/filters/:filter_id/clone"));
    assert!(browser_routes.contains("/api/v1/port-lists/:port_list_id/clone"));
    assert!(browser_routes.contains("/api/v1/report-configs/:report_config_id/clone"));
    assert!(browser_routes.contains("/api/v1/scan-configs"));
    assert!(browser_routes.contains("/api/v1/scan-configs/:scan_config_id/clone"));
    assert!(browser_routes.contains("/api/v1/schedules/:schedule_id/clone"));
    assert!(browser_routes.contains("/api/v1/tags/:tag_id/clone"));
    assert!(browser_routes.contains("/api/v1/targets"));
    assert!(browser_routes.contains("/api/v1/targets/:target_id/clone"));
    assert!(browser_routes.contains("/api/v1/filters/:filter_id/restore"));
    assert!(browser_routes.contains("/api/v1/port-lists/:port_list_id/restore"));
    assert!(browser_routes.contains("/api/v1/report-configs/:report_config_id/restore"));
    assert!(browser_routes.contains("/api/v1/scan-configs/:scan_config_id/restore"));
    assert!(browser_routes.contains("/api/v1/schedules/:schedule_id/restore"));
    assert!(browser_routes.contains("/api/v1/tags/:tag_id/restore"));
    assert!(browser_routes.contains("/api/v1/targets/:target_id/restore"));
    assert!(browser_routes.contains("/api/v1/tags/:tag_id/resources"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_alert)"));
    assert!(browser_routes.contains("post(browser_proxy_create_filter)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_filter)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_port_list)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_report_config)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_scan_config)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_schedule)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_scope)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_tag)"));
    assert!(browser_routes.contains("patch(browser_proxy_patch_target)"));
    assert!(browser_routes.contains("post(browser_proxy_create_scope)"));
    assert!(browser_routes.contains("post(browser_proxy_create_tag)"));
    assert!(browser_routes.contains("post(browser_proxy_create_report_config)"));
    assert!(browser_routes.contains("post(browser_proxy_create_target)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_filter)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_port_list)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_report_config)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_scan_config)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_schedule)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_tag)"));
    assert!(browser_routes.contains("post(browser_proxy_clone_target)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_filter)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_port_list)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_report_config)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_scan_config)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_schedule)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_tag)"));
    assert!(browser_routes.contains("post(browser_proxy_restore_target)"));
    assert!(browser_routes.contains("post(browser_proxy_update_tag_resources)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_scope)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_tag)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_tag)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_filter)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_filter)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_port_list)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_port_list)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_report_config)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_report_config)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_scan_config)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_scan_config)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_schedule)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_schedule)"));
    assert!(browser_routes.contains("delete(browser_proxy_delete_target)"));
    assert!(browser_routes.contains("delete(browser_proxy_hard_delete_target)"));
    assert_eq!(browser_delete_routes, expected_delete_routes);
    assert!(browser_routes.contains("DefaultBodyLimit::max("));
    assert!(browser_routes.contains("Extension(auth)"));
    assert!(!browser_routes.contains("patch(patch_"));
    assert!(!browser_routes.contains("delete(delete_"));
    assert!(!browser_routes.contains("delete(hard_delete_"));
    assert!(!browser_routes.contains("/api/v1/targets/:target_id\", post("));
    assert!(!browser_routes.contains("credentials"));
    assert!(!browser_routes.contains("scanner"));
}

fn browser_proxy_route_registration_block(source: &str) -> &str {
    source
        .split_once("pub(crate) fn browser_proxy_native_api_router(")
        .expect("browser proxy router must be registered")
        .1
        .split_once("\n}\n\n#[cfg(test)]")
        .expect("browser proxy router must end before tests")
        .0
}

fn registered_routes(routes: &str) -> Vec<RegisteredRoute<'_>> {
    let mut registered = Vec::new();
    let mut remainder = routes;
    while let Some((_, after_route)) = remainder.split_once(".route(") {
        let Some((_, after_quote)) = after_route.split_once('"') else {
            break;
        };
        let Some((path, after_path)) = after_quote.split_once('"') else {
            break;
        };
        let method = after_path
            .split_once(',')
            .and_then(|(_, after_comma)| after_comma.trim_start().split_once('('))
            .map(|(method, _)| method.trim())
            .unwrap_or("unknown");
        registered.push(RegisteredRoute { path, method });
        remainder = after_path;
    }
    registered
}

fn concrete_direct_api_path(route: &str) -> String {
    route
        .split('/')
        .map(|segment| {
            segment
                .strip_prefix(':')
                .or_else(|| segment.strip_prefix('*'))
                .map(|name| {
                    if name.ends_with("_id") {
                        "12345678-1234-1234-1234-123456789abc".to_string()
                    } else {
                        format!("sample-{name}")
                    }
                })
                .unwrap_or_else(|| segment.to_string())
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn bearer_auth_accepts_only_matching_bearer_token() {
    let mut headers = HeaderMap::new();
    assert!(!bearer_token_matches(&headers, "secret-token"));

    headers.insert(header::AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
    assert!(!bearer_token_matches(&headers, "secret-token"));

    headers.insert(header::AUTHORIZATION, "Basic secret-token".parse().unwrap());
    assert!(!bearer_token_matches(&headers, "secret-token"));

    headers.insert(
        header::AUTHORIZATION,
        "bearer secret-token".parse().unwrap(),
    );
    assert!(bearer_token_matches(&headers, "secret-token"));
}

#[test]
fn constant_time_string_compare_matches_only_equal_bytes() {
    assert!(constant_time_str_eq("secret-token", "secret-token"));
    assert!(!constant_time_str_eq("secret-token", "secret-tokem"));
    assert!(!constant_time_str_eq("secret-token", "secret-token-extra"));
    assert!(!constant_time_str_eq("secret-token-extra", "secret-token"));
    assert!(!constant_time_str_eq("", "secret-token"));
}

#[test]
fn direct_api_method_guard_uses_json_405_contract() {
    let error = ApiError::MethodNotAllowed;
    assert_eq!(error.status_code(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(error.code(), "method_not_allowed");
    assert!(error.public_message().contains("method/path"));
}

#[test]
fn direct_api_request_too_large_uses_json_413_contract() {
    let error = ApiError::RequestTooLarge;
    assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error.code(), "request_too_large");
    assert!(error.public_message().contains("bounded request"));
}

#[test]
fn direct_api_in_flight_cap_uses_json_429_contract() {
    let error = ApiError::TooManyRequests;
    assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error.code(), "too_many_requests");
    assert!(error.public_message().contains("maximum number"));
}

#[test]
fn request_id_accepts_bounded_safe_client_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        request_id_header_name(),
        "client-123_abc.4:5".parse().unwrap(),
    );
    assert_eq!(request_id_from_headers(&headers), "client-123_abc.4:5");
}

#[test]
fn request_id_rejects_unsafe_or_unbounded_client_header() {
    let mut headers = HeaderMap::new();

    headers.insert(request_id_header_name(), "contains space".parse().unwrap());
    assert!(request_id_from_headers(&headers).starts_with("tv-"));

    headers.insert(request_id_header_name(), "../bad".parse().unwrap());
    assert!(request_id_from_headers(&headers).starts_with("tv-"));

    let too_long = "a".repeat(MAX_REQUEST_ID_LENGTH + 1);
    headers.insert(
        request_id_header_name(),
        axum::http::HeaderValue::from_str(&too_long).unwrap(),
    );
    assert!(request_id_from_headers(&headers).starts_with("tv-"));
}

#[test]
fn generated_request_id_is_safe_for_header_contract() {
    let request_id = new_request_id();
    assert!(request_id.starts_with("tv-"));
    assert!(request_id_is_valid(&request_id));
}

#[test]
fn request_id_header_is_attached_to_responses() {
    let mut response = ApiError::Unauthorized.into_response();
    attach_request_id_header(&mut response, "req-123");
    assert_eq!(
        response
            .headers()
            .get(request_id_header_name())
            .and_then(|value| value.to_str().ok()),
        Some("req-123")
    );
}

#[test]
fn unauthorized_error_is_json_contract_shape() {
    assert_eq!(
        ApiError::Unauthorized.status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(ApiError::Unauthorized.code(), "unauthorized");
    assert!(!ApiError::Unauthorized.public_message().contains("secret"));
}
