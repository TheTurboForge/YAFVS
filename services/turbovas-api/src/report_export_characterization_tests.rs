// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const ROUTES_RS: &str = include_str!("read_api_routes.rs");
const EXPORT_PDF: &str =
    include_str!("../../../components/gvm-tools/scripts/export-pdf-report.gmp.py");

#[test]
fn inherited_pdf_export_fetches_report_format_payload_and_decodes_base64() {
    for required in [
        "report_id = args.argv[1]",
        "if len(args.argv) == 3:",
        ".pdf",
        "c402cc3e-b531-11e1-9163-406186ea4fc5",
        "gmp.get_report(",
        "report_id=report_id",
        "report_format_id=pdf_report_format_id",
        "ignore_pagination=True",
        "details=True",
        "report_element = response.find(\"report\")",
        "content = report_element.find(\"report_format\").tail",
        "content.encode(\"ascii\")",
        "b64decode(binary_base64_encoded_pdf)",
        "Path(",
        ".expanduser()",
        ".write_bytes(",
        "Done. PDF created: ",
        "if not content:",
        "Requested report is empty.",
        "file=sys.stderr",
        "sys.exit(1)",
    ] {
        assert!(
            EXPORT_PDF.contains(required),
            "pdf export missing {required}"
        );
    }
}

#[test]
fn native_api_does_not_expose_legacy_rendered_report_format_routes() {
    for path in [
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/export",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/pdf",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/csv",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/xml",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/raw-xml",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "legacy rendered report-format path must remain outside the native API: {path}"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "legacy rendered report-format GET must remain outside the native API: {path}"
        );
    }
    for forbidden in [
        "/reports/{report_id}/export",
        "/reports/{report_id}/pdf",
        "/reports/{report_id}/csv",
        "/reports/{report_id}/xml",
        "report-file-export",
    ] {
        assert!(
            !OPENAPI.contains(forbidden),
            "OpenAPI must not document legacy rendered report-format export: {forbidden}"
        );
        assert!(
            !ROUTES_RS.contains(forbidden),
            "Rust routes must not expose legacy rendered report-format export: {forbidden}"
        );
    }
}
