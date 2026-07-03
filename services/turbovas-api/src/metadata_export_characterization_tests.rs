// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const ROUTES_RS: &str = include_str!("read_api_routes.rs");

struct MetadataExportBoundary {
    api_path: &'static str,
    openapi_path: &'static str,
    route_path: &'static str,
    handler: &'static str,
    replaces: &'static str,
    inherited_tail: &'static str,
    schema_ref: &'static str,
}

const EXPORT_BOUNDARIES: &[MetadataExportBoundary] = &[
    MetadataExportBoundary {
        api_path: "/api/v1/filters/12345678-1234-1234-1234-123456789abc/export",
        openapi_path: "/filters/{filter_id}/export",
        route_path: "/api/v1/filters/:filter_id/export",
        handler: "export_filter_metadata",
        replaces: "saved-filter-metadata-export-read",
        inherited_tail: "saved-filter-export-and-alert-linkage",
        schema_ref: "#/components/schemas/FilterAsset",
    },
    MetadataExportBoundary {
        api_path: "/api/v1/tags/12345678-1234-1234-1234-123456789abc/export",
        openapi_path: "/tags/{tag_id}/export",
        route_path: "/api/v1/tags/:tag_id/export",
        handler: "export_tag_metadata",
        replaces: "tag-metadata-export-read",
        inherited_tail: "tag-filter-actions-and-file-export",
        schema_ref: "#/components/schemas/TagAsset",
    },
    MetadataExportBoundary {
        api_path: "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc/export",
        openapi_path: "/port-lists/{port_list_id}/export",
        route_path: "/api/v1/port-lists/:port_list_id/export",
        handler: "export_port_list_metadata",
        replaces: "port-list-metadata-export-read",
        inherited_tail: "port-list-import-export",
        schema_ref: "#/components/schemas/PortListAssetDetail",
    },
    MetadataExportBoundary {
        api_path: "/api/v1/schedules/12345678-1234-1234-1234-123456789abc/export",
        openapi_path: "/schedules/{schedule_id}/export",
        route_path: "/api/v1/schedules/:schedule_id/export",
        handler: "export_schedule_metadata",
        replaces: "schedule-metadata-export-read",
        inherited_tail: "schedule-create-calendar-export",
        schema_ref: "#/components/schemas/ScheduleAssetDetail",
    },
    MetadataExportBoundary {
        api_path: "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/export",
        openapi_path: "/scan-configs/{scan_config_id}/export",
        route_path: "/api/v1/scan-configs/:scan_config_id/export",
        handler: "export_scan_config_metadata",
        replaces: "scan-config-metadata-export-read",
        inherited_tail: "scan-config-preference-selector-mutation-import-export-blank-create",
        schema_ref: "#/components/schemas/ScanConfigAssetDetail",
    },
    MetadataExportBoundary {
        api_path: "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc/export",
        openapi_path: "/report-configs/{report_config_id}/export",
        route_path: "/api/v1/report-configs/:report_config_id/export",
        handler: "export_report_config_metadata",
        replaces: "report-config-metadata-export-read",
        inherited_tail: "report-config-file-export",
        schema_ref: "#/components/schemas/ReportConfigAsset",
    },
];

fn openapi_path_block(path: &str) -> String {
    let marker = format!("  {path}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{path} path block must exist"));
    let tail = &OPENAPI[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("  /") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn residual_metadata_exports_are_scriptable_direct_reads_only() {
    for boundary in EXPORT_BOUNDARIES {
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, boundary.api_path, false),
            "GET {} must remain a direct scriptable metadata export",
            boundary.api_path
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, boundary.api_path, true),
            "GET {} must remain allowed when write-control mode is enabled",
            boundary.api_path
        );
        for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, boundary.api_path, true),
                "{method} {} must stay closed; metadata export must not become mutation/export control",
                boundary.api_path
            );
            assert!(
                !direct_api_v1_method_is_allowed(&method, boundary.api_path, false),
                "{method} {} must stay closed without write-control mode too",
                boundary.api_path
            );
        }
    }
}

#[test]
fn metadata_export_routes_are_explicit_json_metadata_handlers() {
    for boundary in EXPORT_BOUNDARIES {
        assert!(
            ROUTES_RS.contains(boundary.route_path),
            "read_api_routes.rs missing {}",
            boundary.route_path
        );
        assert!(
            ROUTES_RS.contains(boundary.handler),
            "read_api_routes.rs missing handler {}",
            boundary.handler
        );
    }
}

#[test]
fn openapi_keeps_metadata_export_boundaries_distinct_from_inherited_file_exports() {
    for boundary in EXPORT_BOUNDARIES {
        let block = openapi_path_block(boundary.openapi_path);
        for required in [
            "get:",
            "x-turbovas-direct: true",
            "x-turbovas-exposure: direct-read",
            "x-turbovas-maturity: live-read",
            boundary.replaces,
            boundary.inherited_tail,
            boundary.schema_ref,
        ] {
            assert!(
                block.contains(required),
                "{} export block missing {required}",
                boundary.openapi_path
            );
        }
        for forbidden in [
            "x-turbovas-exposure: direct-write",
            "x-turbovas-safety-contract: write-control-v1",
            "post:",
            "patch:",
            "delete:",
        ] {
            assert!(
                !block.contains(forbidden),
                "{} metadata export must not advertise {forbidden}",
                boundary.openapi_path
            );
        }
    }
}
