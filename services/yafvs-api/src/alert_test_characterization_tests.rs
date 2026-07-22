// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const DIRECT_ROUTES: &str = include_str!("direct_api_routes.rs");
const BROWSER_PROXY_ROUTES: &str = include_str!("browser_proxy_routes.rs");
const BROWSER_PROXY_HANDLER: &str = include_str!("browser_proxy_metadata_patch.rs");
const ALERT_TEST: &str = include_str!("alert_test.rs");

#[test]
fn alert_test_remains_an_explicit_real_delivery_action_on_both_write_paths() {
    let operation = OPENAPI
        .split_once("  /alerts/{alert_id}/test:\n")
        .expect("alert test operation must be declared")
        .1
        .split_once("  /alerts/{alert_id}/deliver-report:\n")
        .expect("alert test operation must end before alert deliver-report")
        .0;

    for required in [
        "operationId: postAlertsByAlertIdTest",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: alert-real-delivery-control",
        "summary: Send a real test delivery for an alert",
        "A Start Task alert can start its configured task.",
        "'204':",
        "'409':",
        "'502':",
    ] {
        assert!(
            operation.contains(required),
            "alert test OpenAPI missing {required}"
        );
    }
    assert!(!operation.contains("requestBody:"));
    assert!(!operation.contains("validation"));
    assert!(!operation.contains("preview"));
    assert!(DIRECT_ROUTES.contains("/api/v1/alerts/:alert_id/test"));
    assert!(BROWSER_PROXY_ROUTES.contains("/api/v1/alerts/:alert_id/test"));
    assert!(BROWSER_PROXY_HANDLER.contains("browser_proxy_test_alert"));
    assert!(ALERT_TEST.contains("require_alert_write_operator"));
    assert!(ALERT_TEST.contains("alert-test "));
    assert!(ALERT_TEST.contains("b\"0 tested\""));
}

#[test]
fn alert_create_residual_marker_names_only_unimplemented_delivery_payload_mutation() {
    let create = OPENAPI
        .split_once("  /alerts:\n")
        .expect("alerts collection must be declared")
        .1
        .split_once("  /alerts/{alert_id}:\n")
        .expect("alerts collection must end before detail route")
        .0;
    assert!(create.contains("x-yafvs-inherited-still-owns: delivery-payload-mutations"));
    assert!(!create.contains("alert-test-actions-and-delivery-payload-mutations"));
}
