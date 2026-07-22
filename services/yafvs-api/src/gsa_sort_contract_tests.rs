// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{collections::*, query::sort_clause};

fn gsa_native_sort_fields<'a>(source: &'a str, map_name: &str) -> Vec<&'a str> {
    let marker = format!("const {map_name}: Record<string, string> = {{");
    let body = source
        .split_once(&marker)
        .unwrap_or_else(|| panic!("GSA native sort map {map_name} must exist"))
        .1
        .split_once("};")
        .unwrap_or_else(|| panic!("GSA native sort map {map_name} must close"))
        .0;
    body.lines()
        .filter_map(|line| {
            let value = line
                .trim()
                .split_once(':')?
                .1
                .trim()
                .trim_end_matches(',')
                .trim();
            value.strip_prefix('\'')?.strip_suffix('\'')
        })
        .collect()
}

#[test]
fn gsa_native_sort_maps_are_backend_accepted() {
    let checks: &[(&str, &str, &[(&'static str, &'static str)])] = &[
        (
            include_str!("../../../components/gsa/src/gmp/native-api/vulnerabilities.ts"),
            "VULNERABILITY_SORT_FIELDS",
            VULNERABILITY_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/port-lists.ts"),
            "PORT_LIST_SORT_FIELDS",
            PORT_LIST_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/cpes.ts"),
            "CPE_SORT_FIELDS",
            CPE_CATALOG_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/cves.ts"),
            "CVE_SORT_FIELDS",
            CVE_CATALOG_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/report-formats.ts"),
            "REPORT_FORMAT_SORT_FIELDS",
            REPORT_FORMAT_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/dfn-cert-advisories.ts"),
            "DFN_CERT_SORT_FIELDS",
            CERT_ADVISORY_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/filters.ts"),
            "FILTER_SORT_FIELDS",
            FILTER_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/tags.ts"),
            "TAG_SORT_FIELDS",
            TAG_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/hosts.ts"),
            "HOST_SORT_FIELDS",
            HOST_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/targets.ts"),
            "TARGET_SORT_FIELDS",
            TARGET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "REPORT_SORT_FIELDS",
            REPORT_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "APPLICATION_SORT_FIELDS",
            REPORT_APPLICATION_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "OPERATING_SYSTEM_SORT_FIELDS",
            REPORT_OPERATING_SYSTEM_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "TLS_CERTIFICATE_SORT_FIELDS",
            REPORT_TLS_CERTIFICATE_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "CVE_SORT_FIELDS",
            REPORT_CVE_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "ERROR_SORT_FIELDS",
            REPORT_ERROR_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "RESULT_SORT_FIELDS",
            REPORT_RESULT_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "HOST_SORT_FIELDS",
            REPORT_HOST_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/reports.ts"),
            "PORT_SORT_FIELDS",
            REPORT_PORT_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/scan-configs.ts"),
            "SCAN_CONFIG_SORT_FIELDS",
            SCAN_CONFIG_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/tasks.ts"),
            "TASK_SORT_FIELDS",
            TASK_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/nvts.ts"),
            "NVT_SORT_FIELDS",
            NVT_CATALOG_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/alerts.ts"),
            "ALERT_SORT_FIELDS",
            ALERT_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/operating-systems.ts"),
            "OPERATING_SYSTEM_SORT_FIELDS",
            OPERATING_SYSTEM_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/overrides.ts"),
            "OVERRIDE_SORT_FIELDS",
            OVERRIDE_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/scanners.ts"),
            "SCANNER_SORT_FIELDS",
            SCANNER_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/tls-certificates.ts"),
            "TLS_CERTIFICATE_SORT_FIELDS",
            TLS_CERTIFICATE_ASSET_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/cert-bund-advisories.ts"),
            "CERT_BUND_SORT_FIELDS",
            CERT_ADVISORY_SORT_FIELDS,
        ),
        (
            include_str!("../../../components/gsa/src/gmp/native-api/schedules.ts"),
            "SCHEDULE_SORT_FIELDS",
            SCHEDULE_SORT_FIELDS,
        ),
    ];

    assert_eq!(checks.len(), 29, "expected all GSA native sort maps");
    for (source, map_name, rust_fields) in checks {
        for sort_field in gsa_native_sort_fields(source, map_name) {
            assert!(
                sort_clause(sort_field, rust_fields).is_ok(),
                "GSA native sort field {map_name}.{sort_field} must be accepted by the backend sort allowlist"
            );
        }
    }
}
