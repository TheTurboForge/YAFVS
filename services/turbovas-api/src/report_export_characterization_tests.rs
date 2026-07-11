// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use axum::http::Method;

use crate::direct_api_contract::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const REPORT_ID: &str = "12345678-1234-1234-1234-123456789abc";
const CANONICAL_PDF_REPORT_FORMAT_ID: &str = "c402cc3e-b531-11e1-9163-406186ea4fc5";
const LEGACY_PDF_EXPORT_SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../components/gvm-tools/scripts/export-pdf-report.gmp.py"
);
const ROUTES: &str = include_str!("read_api_routes.rs");
const PDF_SOURCE: &str = include_str!("report_pdf.rs");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");

#[test]
fn native_pdf_contract_replaces_the_inherited_script_characterization() {
    let path = format!("/api/v1/reports/{REPORT_ID}/download");
    assert!(ROUTES.contains("/api/v1/reports/:report_id/download"));
    assert!(direct_api_v1_path_is_allowed(&path));
    assert!(direct_api_v1_method_is_allowed(&Method::GET, &path, false));
    assert!(PDF_SOURCE.contains("CANONICAL_PDF_REPORT_FORMAT_ID"));
    assert!(PDF_SOURCE.contains("PDF_REPORT_SQL"));
    assert!(PDF_SOURCE.contains("PDF_EVIDENCE_SQL"));
    assert!(PDF_SOURCE.contains("pdf_writer"));
    assert!(!PDF_SOURCE.contains("include_str!(\"../../../components/gvm-tools"));
    assert!(!Path::new(LEGACY_PDF_EXPORT_SCRIPT).exists());
}

#[test]
fn native_pdf_contract_keeps_only_the_canonical_format_and_no_legacy_rendering_inputs() {
    let path = OPENAPI
        .split_once("  /reports/{report_id}/download:\n")
        .and_then(|(_, after)| after.split_once("  /reports/{report_id}/results:"))
        .map(|(path, _)| path)
        .expect("OpenAPI native PDF path must be present");
    assert!(OPENAPI.contains(CANONICAL_PDF_REPORT_FORMAT_ID));
    assert!(path.contains("custom report configs, filters, and scripts"));
    assert!(!path.contains("report_config_id"));
    assert!(!path.contains("filter_id"));
    assert!(!PDF_SOURCE.contains("quick_xml"));
    assert!(!PDF_SOURCE.contains("gvmd_control"));
    assert!(!PDF_SOURCE.contains("python-gvm"));
}
