// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const DIRECT_ROUTES: &str = include_str!("direct_api_routes.rs");
const DIRECT_CONTRACT: &str = include_str!("direct_api_contract.rs");
const BROWSER_PROXY_ROUTES: &str = include_str!("browser_proxy_routes.rs");
const BROWSER_PROXY_HANDLER: &str = include_str!("browser_proxy_metadata_patch.rs");
const DELIVERY: &str = include_str!("alert_deliver_report.rs");

#[test]
fn alert_deliver_report_is_explicit_real_delivery_on_both_authenticated_write_paths() {
    let operation = OPENAPI
        .split_once("  /alerts/{alert_id}/deliver-report:\n")
        .expect("alert deliver-report operation must be declared")
        .1
        .split_once("  /alerts/{alert_id}/export:\n")
        .expect("alert deliver-report operation must end before alert export")
        .0;

    for required in [
        "operationId: postAlertsByAlertIdDeliverReport",
        "x-turbovas-exposure: direct-write",
        "x-turbovas-operator-identity: direct-token-operator",
        "x-turbovas-safety-contract: write-control-v1",
        "x-turbovas-side-effect: alert-report-delivery-control",
        "Sends a real delivery using the alert's configured delivery settings.",
        "A Start Task alert can start its configured task.",
        "report_format_id parameter is ineffective for alert dispatch",
        "$ref: '#/components/schemas/AlertDeliverReportRequest'",
        "'204':",
        "'403':",
        "'404':",
        "'409':",
        "'502':",
    ] {
        assert!(
            operation.contains(required),
            "alert deliver-report OpenAPI missing {required}"
        );
    }
    assert!(!operation.contains("preview"));
    assert!(!operation.contains("report_format_id:"));
    assert!(DIRECT_ROUTES.contains("/api/v1/alerts/:alert_id/deliver-report"));
    assert!(DIRECT_CONTRACT.contains("\"deliver-report\""));
    assert!(BROWSER_PROXY_ROUTES.contains("/api/v1/alerts/:alert_id/deliver-report"));
    assert!(BROWSER_PROXY_HANDLER.contains("browser_proxy_deliver_alert_report"));
    assert!(DELIVERY.contains("require_alert_write_operator"));
    assert!(DELIVERY.contains("alert-deliver-report "));
    assert!(DELIVERY.contains("ScrubbedControlFrame"));
}

#[test]
fn alert_deliver_report_schema_keeps_filter_selectors_exclusive_and_report_format_hidden() {
    let schema = OPENAPI
        .split_once("    AlertDeliverReportRequest:\n")
        .expect("alert deliver-report schema must be declared")
        .1
        .split_once("    AlertEmailCreateRequest:\n")
        .expect("alert deliver-report schema must end before alert email schema")
        .0;
    for required in [
        "additionalProperties: false",
        "required: [report_id]",
        "filter:",
        "filter_id:",
        "not:",
        "required: [filter, filter_id]",
    ] {
        assert!(
            schema.contains(required),
            "alert deliver-report schema missing {required}"
        );
    }
    assert!(!schema.contains("report_format_id:"));
}
