// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const ROUTES_RS: &str = include_str!("routes.rs");
const EXPORT_PDF: &str =
    include_str!("../../../components/gvm-tools/scripts/export-pdf-report.gmp.py");
const EXPORT_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/export-csv-report.gmp.py");
const EXPORT_XML: &str =
    include_str!("../../../components/gvm-tools/scripts/export-xml-report.gmp.py");

#[test]
fn inherited_pdf_and_csv_exports_fetch_report_format_payloads_and_decode_base64() {
    for (source, label, format_id, extension, done_message) in [
        (
            EXPORT_PDF,
            "pdf",
            "c402cc3e-b531-11e1-9163-406186ea4fc5",
            ".pdf",
            "Done. PDF created: ",
        ),
        (
            EXPORT_CSV,
            "csv",
            "c1645568-627a-11e3-a660-406186ea4fc5",
            ".csv",
            "Done. CSV created: ",
        ),
    ] {
        for required in [
            "report_id = args.argv[1]",
            "if len(args.argv) == 3:",
            extension,
            format_id,
            "gmp.get_report(",
            "report_id=report_id",
            "report_format_id=",
            "ignore_pagination=True",
            "details=True",
            "report_element = response.find(\"report\")",
            "content = report_element.find(\"report_format\").tail",
            "content.encode(\"ascii\")",
            "b64decode(binary_base64_encoded_",
            "Path(",
            ".expanduser()",
            ".write_bytes(",
            done_message,
        ] {
            assert!(
                source.contains(required),
                "{label} export missing {required}"
            );
        }
        for required in [
            "if not content:",
            "Requested report is empty.",
            "file=sys.stderr",
            "sys.exit(1)",
        ] {
            assert!(
                source.contains(required),
                "{label} export must keep inherited empty-report failure behavior: {required}"
            );
        }
    }
}

#[test]
fn inherited_xml_export_serializes_nested_report_xml_without_base64_decoding() {
    for required in [
        "report_id = args.argv[1]",
        "if len(args.argv) == 3:",
        ".xml",
        "5057e5cc-b825-11e4-9d0e-28d24461215b",
        "gmp.get_report(",
        "report_id=report_id",
        "report_format_id=xml_report_format_id",
        "ignore_pagination=True",
        "details=True",
        "report_element = response.find(\"report\")",
        "content = etree.tostring(report_element.find(\"report\"))",
        "dcontent = content.decode(\"utf-8\")",
        "Path(xml_filename).expanduser()",
        "xml_path.write_text(dcontent)",
        "Done. xml created: ",
    ] {
        assert!(
            EXPORT_XML.contains(required),
            "xml export missing {required}"
        );
    }
    for forbidden in ["b64decode", "report_format\").tail", "write_bytes"] {
        assert!(
            !EXPORT_XML.contains(forbidden),
            "xml export must stay plain nested-report XML serialization, not PDF/CSV base64 export: {forbidden}"
        );
    }
}

#[test]
fn native_api_has_no_explicit_report_file_export_route_yet() {
    for path in [
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/export",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/pdf",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/csv",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/xml",
        "/api/v1/reports/12345678-1234-1234-1234-123456789abc/raw-xml",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "report file-export path must stay closed until a native file-export contract lands: {path}"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "report file-export GET must stay closed until a native file-export contract lands: {path}"
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
            "OpenAPI must not document report file export until semantics are explicit: {forbidden}"
        );
        assert!(
            !ROUTES_RS.contains(forbidden),
            "Rust routes must not expose report file export until semantics are explicit: {forbidden}"
        );
    }
}
