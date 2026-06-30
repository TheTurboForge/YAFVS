// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};

use crate::{
    alerts::{alert_asset_detail_sql, alert_asset_tasks_sql, alert_assets_sql},
    auth::*,
    collections::*,
    direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed},
    host_assets::host_user_tags_sql,
    operating_systems::operating_system_user_tags_sql,
    port_lists::port_list_user_tags_sql,
    query::sort_clause,
    request_ids::*,
    scan_configs::{scan_config_task_references_sql, scan_config_user_tags_sql},
    scanner_assets::{scanner_task_references_sql, scanner_user_tags_sql},
    schedules::schedule_user_tags_sql,
    scope_payloads::{scope_candidate_hosts_sql, scope_sql},
    scope_report_results::scope_report_results_sql,
    scope_report_retention::scope_report_retention_sources_sql,
    tls_certificates::tls_certificate_user_tags_sql,
    user_tags::catalog_user_tags_sql,
};

use super::*;

struct CollectionContract {
    path: &'static str,
    default_sort: &'static str,
    allowed_sort_fields: &'static [(&'static str, &'static str)],
    filter_fields: &'static [&'static str],
    tie_breakers: &'static [&'static str],
}

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
];

const PRIORITY_COLLECTION_CONTRACTS: &[CollectionContract] = &[
    CollectionContract {
        path: "/api/v1/vulnerabilities",
        default_sort: VULNERABILITY_DEFAULT_SORT,
        allowed_sort_fields: VULNERABILITY_SORT_FIELDS,
        filter_fields: &["id", "name"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/results",
        default_sort: RESULT_DEFAULT_SORT,
        allowed_sort_fields: RESULT_SORT_FIELDS,
        filter_fields: &[
            "id",
            "host",
            "hostname",
            "port",
            "nvt_oid",
            "name",
            "task_name",
            "source_report_name",
        ],
        tie_breakers: &["created_at_unix", "id"],
    },
    CollectionContract {
        path: "/api/v1/reports",
        default_sort: REPORT_DEFAULT_SORT,
        allowed_sort_fields: REPORT_SORT_FIELDS,
        filter_fields: &["uuid", "name", "status", "task_name", "target_name"],
        tie_breakers: &["creation_time", "uuid"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/results",
        default_sort: REPORT_RESULT_DEFAULT_SORT,
        allowed_sort_fields: REPORT_RESULT_SORT_FIELDS,
        filter_fields: &["id", "host", "port", "nvt_oid", "name"],
        tie_breakers: &["created_at_unix", "id"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results",
        default_sort: REPORT_RESULT_DEFAULT_SORT,
        allowed_sort_fields: REPORT_RESULT_SORT_FIELDS,
        filter_fields: &["id", "host", "port", "nvt_oid", "name"],
        tie_breakers: &["created_at_unix", "id"],
    },
];

const REPORT_EVIDENCE_COLLECTION_CONTRACTS: &[CollectionContract] = &[
    CollectionContract {
        path: "/api/v1/reports/{report_id}/hosts",
        default_sort: REPORT_HOST_DEFAULT_SORT,
        allowed_sort_fields: REPORT_HOST_SORT_FIELDS,
        filter_fields: &[
            "host",
            "hostname",
            "best_os_cpe",
            "best_os_txt",
            "authentication_state",
        ],
        tie_breakers: &["host"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/ports",
        default_sort: REPORT_PORT_DEFAULT_SORT,
        allowed_sort_fields: REPORT_PORT_SORT_FIELDS,
        filter_fields: &["port", "protocol"],
        tie_breakers: &["port"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/applications",
        default_sort: REPORT_APPLICATION_DEFAULT_SORT,
        allowed_sort_fields: REPORT_APPLICATION_SORT_FIELDS,
        filter_fields: &["name", "cpe"],
        tie_breakers: &["name"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/operating-systems",
        default_sort: REPORT_OPERATING_SYSTEM_DEFAULT_SORT,
        allowed_sort_fields: REPORT_OPERATING_SYSTEM_SORT_FIELDS,
        filter_fields: &["name", "cpe"],
        tie_breakers: &["name"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/tls-certificates",
        default_sort: REPORT_TLS_CERTIFICATE_DEFAULT_SORT,
        allowed_sort_fields: REPORT_TLS_CERTIFICATE_SORT_FIELDS,
        filter_fields: &["id", "fingerprint_sha256", "subject", "issuer", "serial"],
        tie_breakers: &["id"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/cves",
        default_sort: REPORT_CVE_DEFAULT_SORT,
        allowed_sort_fields: REPORT_CVE_SORT_FIELDS,
        filter_fields: &["id"],
        tie_breakers: &["id"],
    },
    CollectionContract {
        path: "/api/v1/reports/{report_id}/errors",
        default_sort: REPORT_ERROR_DEFAULT_SORT,
        allowed_sort_fields: REPORT_ERROR_SORT_FIELDS,
        filter_fields: &["id", "host", "port", "nvt_oid", "description"],
        tie_breakers: &["id"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts",
        default_sort: SCOPE_REPORT_HOST_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_HOST_SORT_FIELDS,
        filter_fields: &["host", "scope_membership", "authenticated_scan_state"],
        tie_breakers: &["host"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/ports",
        default_sort: SCOPE_REPORT_PORT_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_PORT_SORT_FIELDS,
        filter_fields: &["port", "protocol"],
        tie_breakers: &["port"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/applications",
        default_sort: SCOPE_REPORT_APPLICATION_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_APPLICATION_SORT_FIELDS,
        filter_fields: &["name", "cpe"],
        tie_breakers: &["name"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/operating-systems",
        default_sort: SCOPE_REPORT_OPERATING_SYSTEM_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_OPERATING_SYSTEM_SORT_FIELDS,
        filter_fields: &["name", "cpe"],
        tie_breakers: &["name"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/tls-certificates",
        default_sort: SCOPE_REPORT_TLS_CERTIFICATE_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS,
        filter_fields: &["id", "fingerprint_sha256", "subject", "issuer", "serial"],
        tie_breakers: &["id"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/cves",
        default_sort: SCOPE_REPORT_CVE_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_CVE_SORT_FIELDS,
        filter_fields: &["id"],
        tie_breakers: &["id"],
    },
    CollectionContract {
        path: "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/errors",
        default_sort: SCOPE_REPORT_ERROR_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_ERROR_SORT_FIELDS,
        filter_fields: &["id", "host", "port", "nvt_oid", "description"],
        tie_breakers: &["id"],
    },
];

const SCOPE_TASK_TARGET_COLLECTION_CONTRACTS: &[CollectionContract] = &[
    CollectionContract {
        path: "/api/v1/targets",
        default_sort: TARGET_DEFAULT_SORT,
        allowed_sort_fields: TARGET_SORT_FIELDS,
        filter_fields: &["uuid", "name", "comment", "port_list_name", "hosts"],
        tie_breakers: &["name"],
    },
    CollectionContract {
        path: "/api/v1/tasks",
        default_sort: TASK_DEFAULT_SORT,
        allowed_sort_fields: TASK_SORT_FIELDS,
        filter_fields: &[
            "uuid",
            "name",
            "comment",
            "status",
            "target_name",
            "config_name",
            "scanner_name",
        ],
        tie_breakers: &["name"],
    },
    CollectionContract {
        path: "/api/v1/scopes",
        default_sort: SCOPE_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_SORT_FIELDS,
        filter_fields: &["uuid", "name", "comment", "protection_requirement"],
        tie_breakers: &["uuid"],
    },
    CollectionContract {
        path: "/api/v1/scope-reports",
        default_sort: SCOPE_REPORT_DEFAULT_SORT,
        allowed_sort_fields: SCOPE_REPORT_SORT_FIELDS,
        filter_fields: &["uuid", "scope_uuid", "scope_name"],
        tie_breakers: &["uuid"],
    },
];

const ASSET_CATALOG_COLLECTION_CONTRACTS: &[CollectionContract] = &[
    CollectionContract {
        path: "/api/v1/hosts",
        default_sort: HOST_ASSET_DEFAULT_SORT,
        allowed_sort_fields: HOST_ASSET_SORT_FIELDS,
        filter_fields: &["id", "name", "hostname", "ip", "best_os_cpe", "best_os_txt"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/tls-certificates",
        default_sort: TLS_CERTIFICATE_ASSET_DEFAULT_SORT,
        allowed_sort_fields: TLS_CERTIFICATE_ASSET_SORT_FIELDS,
        filter_fields: &[
            "id",
            "name",
            "subject_dn",
            "issuer_dn",
            "serial",
            "md5_fingerprint",
            "sha256_fingerprint",
        ],
        tie_breakers: &["subject_dn", "id"],
    },
    CollectionContract {
        path: "/api/v1/scanners",
        default_sort: SCANNER_ASSET_DEFAULT_SORT,
        allowed_sort_fields: SCANNER_ASSET_SORT_FIELDS,
        filter_fields: &[
            "id",
            "name",
            "comment",
            "host",
            "credential_name",
            "relay_host",
        ],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/scan-configs",
        default_sort: SCAN_CONFIG_ASSET_DEFAULT_SORT,
        allowed_sort_fields: SCAN_CONFIG_ASSET_SORT_FIELDS,
        filter_fields: &["id", "name", "comment", "owner_name"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/filters",
        default_sort: FILTER_ASSET_DEFAULT_SORT,
        allowed_sort_fields: FILTER_ASSET_SORT_FIELDS,
        filter_fields: &["id", "name", "comment", "filter_type", "term"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/overrides",
        default_sort: OVERRIDE_ASSET_DEFAULT_SORT,
        allowed_sort_fields: OVERRIDE_ASSET_SORT_FIELDS,
        filter_fields: &[
            "id",
            "nvt_id",
            "nvt_name",
            "text",
            "hosts",
            "port",
            "task_name",
        ],
        tie_breakers: &["text", "id"],
    },
    CollectionContract {
        path: "/api/v1/cpes",
        default_sort: CPE_CATALOG_DEFAULT_SORT,
        allowed_sort_fields: CPE_CATALOG_SORT_FIELDS,
        filter_fields: &["id", "name", "title", "cpe_name_id", "comment"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/cves",
        default_sort: CVE_CATALOG_DEFAULT_SORT,
        allowed_sort_fields: CVE_CATALOG_SORT_FIELDS,
        filter_fields: &["id", "description", "cvss_base_vector", "products"],
        tie_breakers: &["id"],
    },
    CollectionContract {
        path: "/api/v1/dfn-cert-advisories",
        default_sort: CERT_ADVISORY_DEFAULT_SORT,
        allowed_sort_fields: CERT_ADVISORY_SORT_FIELDS,
        filter_fields: &["id", "name", "title", "summary", "cves"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/cert-bund-advisories",
        default_sort: CERT_ADVISORY_DEFAULT_SORT,
        allowed_sort_fields: CERT_ADVISORY_SORT_FIELDS,
        filter_fields: &["id", "name", "title", "summary", "cves"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/nvts",
        default_sort: NVT_CATALOG_DEFAULT_SORT,
        allowed_sort_fields: NVT_CATALOG_SORT_FIELDS,
        filter_fields: &["oid", "name", "family", "cve", "qod_type", "solution_type"],
        tie_breakers: &["name", "oid"],
    },
    CollectionContract {
        path: "/api/v1/operating-systems",
        default_sort: OPERATING_SYSTEM_ASSET_DEFAULT_SORT,
        allowed_sort_fields: OPERATING_SYSTEM_ASSET_SORT_FIELDS,
        filter_fields: &["id", "name", "title"],
        tie_breakers: &["name", "id"],
    },
];

const MANAGEMENT_COLLECTION_CONTRACTS: &[CollectionContract] = &[
    CollectionContract {
        path: "/api/v1/alerts",
        default_sort: ALERT_DEFAULT_SORT,
        allowed_sort_fields: ALERT_SORT_FIELDS,
        filter_fields: &[
            "id",
            "name",
            "comment",
            "owner_name",
            "event_type",
            "condition_type",
            "method_type",
            "filter_name",
        ],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/tags",
        default_sort: TAG_DEFAULT_SORT,
        allowed_sort_fields: TAG_SORT_FIELDS,
        filter_fields: &[
            "id",
            "name",
            "comment",
            "owner_name",
            "resource_type",
            "value",
        ],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/tags/{tag_id}/resources",
        default_sort: TAG_RESOURCE_DEFAULT_SORT,
        allowed_sort_fields: TAG_RESOURCE_SORT_FIELDS,
        filter_fields: &["id", "name"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/tags/resource-names/{resource_type}",
        default_sort: TAG_RESOURCE_DEFAULT_SORT,
        allowed_sort_fields: TAG_RESOURCE_SORT_FIELDS,
        filter_fields: &["id", "name"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/port-lists",
        default_sort: PORT_LIST_DEFAULT_SORT,
        allowed_sort_fields: PORT_LIST_SORT_FIELDS,
        filter_fields: &["id", "name", "comment"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/schedules",
        default_sort: SCHEDULE_DEFAULT_SORT,
        allowed_sort_fields: SCHEDULE_SORT_FIELDS,
        filter_fields: &["id", "name", "comment", "timezone"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/report-configs",
        default_sort: REPORT_CONFIG_DEFAULT_SORT,
        allowed_sort_fields: REPORT_CONFIG_SORT_FIELDS,
        filter_fields: &["id", "name", "comment", "report_format_name"],
        tie_breakers: &["name", "id"],
    },
    CollectionContract {
        path: "/api/v1/report-formats",
        default_sort: REPORT_FORMAT_DEFAULT_SORT,
        allowed_sort_fields: REPORT_FORMAT_SORT_FIELDS,
        filter_fields: &["id", "name", "summary", "extension", "content_type"],
        tie_breakers: &["name", "id"],
    },
];

fn sort_field_names(fields: &[(&'static str, &'static str)]) -> Vec<&'static str> {
    fields.iter().map(|(name, _)| *name).collect()
}

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
            include_str!("../../../components/gsa/src/gmp/native-api/report-configs.ts"),
            "REPORT_CONFIG_SORT_FIELDS",
            REPORT_CONFIG_SORT_FIELDS,
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

    assert_eq!(checks.len(), 30, "expected all GSA native sort maps");
    for (source, map_name, rust_fields) in checks {
        for sort_field in gsa_native_sort_fields(source, map_name) {
            assert!(
                sort_clause(sort_field, rust_fields).is_ok(),
                "GSA native sort field {map_name}.{sort_field} must be accepted by the backend sort allowlist"
            );
        }
    }
}

fn assert_collection_contract(contract: &CollectionContract) {
    assert!(
        !contract.filter_fields.is_empty(),
        "{} needs filter fields",
        contract.path
    );
    assert!(
        !contract.tie_breakers.is_empty(),
        "{} needs tie breakers",
        contract.path
    );
    assert!(sort_clause(contract.default_sort, contract.allowed_sort_fields).is_ok());
    assert!(sort_clause("unsupported_field", contract.allowed_sort_fields).is_err());
}

#[test]
fn priority_collection_contracts_define_sort_filter_and_tie_breakers() {
    let paths: Vec<&str> = PRIORITY_COLLECTION_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v1/vulnerabilities",
            "/api/v1/results",
            "/api/v1/reports",
            "/api/v1/reports/{report_id}/results",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results",
        ]
    );
    for contract in PRIORITY_COLLECTION_CONTRACTS {
        assert_collection_contract(contract);
    }
    assert!(sort_field_names(VULNERABILITY_SORT_FIELDS).contains(&"severity"));
    assert!(sort_field_names(RESULT_SORT_FIELDS).contains(&"hostname"));
    assert!(sort_field_names(REPORT_SORT_FIELDS).contains(&"creation_time"));
    assert!(!sort_field_names(REPORT_RESULT_SORT_FIELDS).contains(&"hostname"));
}

#[test]
fn management_collection_contracts_define_sort_filter_and_tie_breakers() {
    let paths: Vec<&str> = MANAGEMENT_COLLECTION_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v1/alerts",
            "/api/v1/tags",
            "/api/v1/tags/{tag_id}/resources",
            "/api/v1/tags/resource-names/{resource_type}",
            "/api/v1/port-lists",
            "/api/v1/schedules",
            "/api/v1/report-configs",
            "/api/v1/report-formats",
        ]
    );
    for contract in MANAGEMENT_COLLECTION_CONTRACTS {
        assert_collection_contract(contract);
    }
    assert!(sort_field_names(ALERT_SORT_FIELDS).contains(&"task_count"));
    assert!(sort_field_names(TAG_SORT_FIELDS).contains(&"resource_type"));
    assert_eq!(
        sort_field_names(TAG_RESOURCE_SORT_FIELDS),
        vec!["id", "name"]
    );
    assert!(sort_field_names(PORT_LIST_SORT_FIELDS).contains(&"total"));
    assert!(sort_field_names(SCHEDULE_SORT_FIELDS).contains(&"next_run"));
    assert!(sort_field_names(REPORT_CONFIG_SORT_FIELDS).contains(&"report_format"));
    assert!(sort_field_names(REPORT_FORMAT_SORT_FIELDS).contains(&"content_type"));
    assert!(sort_clause("-modified", REPORT_FORMAT_SORT_FIELDS).is_ok());
    assert!(sort_clause("created_at", ALERT_SORT_FIELDS).is_err());
}

#[test]
fn asset_catalog_collection_contracts_define_sort_filter_and_tie_breakers() {
    let paths: Vec<&str> = ASSET_CATALOG_COLLECTION_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v1/hosts",
            "/api/v1/tls-certificates",
            "/api/v1/scanners",
            "/api/v1/scan-configs",
            "/api/v1/filters",
            "/api/v1/overrides",
            "/api/v1/cpes",
            "/api/v1/cves",
            "/api/v1/dfn-cert-advisories",
            "/api/v1/cert-bund-advisories",
            "/api/v1/nvts",
            "/api/v1/operating-systems",
        ]
    );
    for contract in ASSET_CATALOG_COLLECTION_CONTRACTS {
        assert_collection_contract(contract);
    }
    assert!(sort_field_names(HOST_ASSET_SORT_FIELDS).contains(&"severity"));
    assert!(sort_field_names(TLS_CERTIFICATE_ASSET_SORT_FIELDS).contains(&"last_seen"));
    assert!(sort_field_names(SCANNER_ASSET_SORT_FIELDS).contains(&"credential"));
    assert!(sort_field_names(SCAN_CONFIG_ASSET_SORT_FIELDS).contains(&"family_count"));
    assert!(sort_field_names(FILTER_ASSET_SORT_FIELDS).contains(&"alert_count"));
    assert!(sort_field_names(OVERRIDE_ASSET_SORT_FIELDS).contains(&"new_severity"));
    assert!(sort_field_names(CPE_CATALOG_SORT_FIELDS).contains(&"cpeNameId"));
    assert!(sort_field_names(CVE_CATALOG_SORT_FIELDS).contains(&"epss_score"));
    assert!(sort_field_names(CERT_ADVISORY_SORT_FIELDS).contains(&"cves"));
    assert!(sort_field_names(NVT_CATALOG_SORT_FIELDS).contains(&"solution_type"));
    assert!(sort_field_names(OPERATING_SYSTEM_ASSET_SORT_FIELDS).contains(&"latest_severity"));
    assert!(sort_clause("created_at", CPE_CATALOG_SORT_FIELDS).is_err());
}

#[test]
fn cve_catalog_detail_reads_reference_context_without_mutation_workflows() {
    let source = include_str!("cve_catalog.rs");
    let cve_source = source;
    let detail_source = source
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog detail handler must exist")
        .1
        .split_once("fn split_catalog_products")
        .expect("CVE catalog detail/reference handlers must precede row helpers")
        .0;
    let list_source = source
        .split_once("async fn cve_catalog(")
        .expect("CVE catalog list handler must exist")
        .1
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog list handler must precede detail handler")
        .0;
    let payload_source = cve_source
        .split_once("struct CatalogCveItem {")
        .expect("CVE catalog payload must exist")
        .1
        .split_once("pub(crate) async fn cve_catalog")
        .expect("CVE catalog payload must precede CVE list handler")
        .0;

    assert!(payload_source.contains("cert_refs: Vec<CatalogCveCertReference>"));
    assert!(payload_source.contains("nvt_refs: Vec<CatalogCveNvtReference>"));
    assert!(payload_source.contains("references: Vec<CatalogCveReference>"));
    assert!(payload_source.contains("configuration_nodes: Option<CatalogCveConfigurationNodes>"));
    assert!(payload_source.contains("epss: Option<CatalogEpssItem>"));
    assert!(detail_source.contains("LEFT JOIN scap.epss_scores e ON e.cve = c.name"));
    assert!(detail_source.contains("item.cert_refs = cve_cert_refs(&client, &cve_id).await?"));
    assert!(detail_source.contains("item.nvt_refs = cve_nvt_refs(&client, &cve_id).await?"));
    assert!(
        detail_source.contains("item.references = cve_references(&client, cve_internal_id).await?")
    );
    assert!(detail_source.contains(
        "item.configuration_nodes = cve_configuration_nodes(&client, cve_internal_id).await?"
    ));
    assert!(detail_source.contains("FROM scap.cve_references"));
    assert!(detail_source.contains("FROM scap.cpe_match_nodes"));
    assert!(detail_source.contains("FROM scap.cpe_match_strings"));
    assert!(detail_source.contains("FROM scap.cpe_matches"));
    assert!(detail_source.contains("FROM cert.cert_bund_cves dc"));
    assert!(detail_source.contains("FROM cert.dfn_cert_cves dc"));
    assert!(detail_source.contains("FROM vt_refs vr"));
    assert!(!list_source.contains("cve_configuration_nodes"));
    assert!(!list_source.contains("cve_references"));
    assert!(!list_source.contains("cve_cert_refs"));
    assert!(!list_source.contains("cve_nvt_refs"));
    for inherited_workflow in ["export", "delete", "modify", "create"] {
        assert!(!detail_source.contains(inherited_workflow));
    }
}

#[test]
fn catalog_detail_user_tags_are_detail_only_active_info_tags() {
    let cve_source = include_str!("cve_catalog.rs");
    let cpe_source = include_str!("cpe_catalog.rs");
    let cve_item_payload = cve_source
        .split_once("struct CatalogCveItem {")
        .expect("CVE catalog payload must exist")
        .1
        .split_once("struct CatalogCveDetail")
        .expect("CVE catalog payload must precede detail payload")
        .0;
    let cpe_item_payload = cpe_source
        .split_once("struct CatalogCpeItem {")
        .expect("CPE catalog payload must exist")
        .1
        .split_once("struct CatalogCpeDetail")
        .expect("CPE catalog payload must precede detail payload")
        .0;
    let cve_detail_source = cve_source
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog detail handler must exist")
        .1
        .split_once("async fn cve_cert_refs")
        .expect("CVE catalog detail handler must precede reference helpers")
        .0;
    let cpe_detail_source = cpe_source
        .split_once("async fn cpe_catalog_detail")
        .expect("CPE catalog detail handler must exist")
        .1
        .split_once("async fn cpe_references")
        .expect("CPE catalog detail handler must precede reference helper")
        .0;
    let cve_list_source = cve_source
        .split_once("async fn cve_catalog(")
        .expect("CVE catalog list handler must exist")
        .1
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog list handler must precede detail handler")
        .0;
    let cpe_list_source = cpe_source
        .split_once("async fn cpe_catalog(")
        .expect("CPE catalog list handler must exist")
        .1
        .split_once("async fn cpe_catalog_detail")
        .expect("CPE catalog list handler must precede detail handler")
        .0;

    assert!(!cve_item_payload.contains("user_tags"));
    assert!(!cpe_item_payload.contains("user_tags"));
    assert!(cve_source.contains("struct CatalogCveDetail"));
    assert!(cpe_source.contains("struct CatalogCpeDetail"));
    assert!(cve_detail_source.contains("catalog_user_tags(&client, \"cve\", &cve_id).await?"));
    assert!(cpe_detail_source.contains("catalog_user_tags_for_aliases_and_row_id("));
    assert!(cpe_detail_source.contains("Some(cpe_internal_id)"));
    assert!(!cve_list_source.contains("catalog_user_tags"));
    assert!(!cpe_list_source.contains("catalog_user_tags"));

    let sql = catalog_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("lower(tr.resource_uuid) = ANY($1::text[])"));
    assert!(sql.contains("tr.resource = $3"));
    assert!(sql.contains("tr.resource_type = $2"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn cpe_catalog_detail_resolves_deprecated_by_by_cpe_name() {
    let source = include_str!("cpe_catalog.rs");
    let cpe_detail_source = source
        .split_once("async fn cpe_catalog_detail")
        .expect("CPE catalog detail handler must exist")
        .1
        .split_once("async fn cpe_references")
        .expect("CPE catalog detail handler must precede reference helper")
        .0;

    assert!(cpe_detail_source.contains("let cpe_name: String = row.get(\"name\");"));
    assert!(cpe_detail_source.contains("let cpe_internal_id: i32 = row.get(\"internal_id\");"));
    assert!(cpe_detail_source.contains("let cpe_uuid: String = row.get(\"id\");"));
    assert!(cpe_detail_source.contains("let cpe_tag_ids = vec![cpe_uuid, cpe_name.clone()];"));
    assert!(cpe_detail_source.contains("FROM scap.cpes_deprecated_by"));
    assert!(cpe_detail_source.contains("WHERE cpe = $1"));
    assert!(cpe_detail_source.contains("&[&cpe_name]"));
    assert!(cpe_detail_source.contains("cpe_references(&client, &cpe_name).await?"));
    assert!(source.contains("FROM scap.cpe_details"));
    assert!(source.contains("WHERE cpe_id = $1"));
    assert!(source.contains("cpe_references_from_details_xml"));
}

#[test]
fn nvt_detail_user_tags_are_detail_only_active_info_tags() {
    let source = include_str!("nvt_catalog.rs");
    let catalog_payload_source = include_str!("nvt_catalog.rs");
    let nvt_item_payload = catalog_payload_source
        .split_once("struct NvtCatalogItem {")
        .expect("NVT catalog item payload must exist")
        .1
        .split_once("struct NvtCatalogDetail")
        .expect("NVT catalog item payload must precede detail payload")
        .0;
    let nvt_detail_source = source
        .split_once("pub(crate) async fn nvt_catalog_detail")
        .expect("NVT catalog detail handler must exist")
        .1
        .split_once("#[derive(Debug, Serialize)]")
        .expect("NVT catalog detail handler must precede payload structs")
        .0;
    let nvt_list_source = source
        .split_once("pub(crate) async fn nvt_catalog(")
        .expect("NVT catalog list handler must exist")
        .1
        .split_once("fn nvt_filter_parts")
        .expect("NVT catalog list handler must precede filter helper")
        .0;

    assert!(!nvt_item_payload.contains("user_tags"));
    assert!(catalog_payload_source.contains("struct NvtCatalogDetail"));
    assert!(nvt_detail_source.contains("catalog_user_tags(&client, \"nvt\", &nvt_id).await?"));
    assert!(!nvt_list_source.contains("catalog_user_tags"));

    let sql = catalog_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("lower(tr.resource_uuid) = ANY($1::text[])"));
    assert!(sql.contains("tr.resource_type = $2"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn cert_advisory_detail_user_tags_use_resolved_uuid_only() {
    let source = include_str!("cert_advisories.rs");
    let payload_source = include_str!("cert_advisories.rs");
    let cert_bund_item_payload = payload_source
        .split_once("struct CertBundAdvisoryItem {")
        .expect("CERT-Bund advisory payload must exist")
        .1
        .split_once("struct CertBundAdvisoryDetail")
        .expect("CERT-Bund advisory payload must precede detail payload")
        .0;
    let dfn_cert_item_payload = payload_source
        .split_once("struct DfnCertAdvisoryItem {")
        .expect("DFN-CERT advisory payload must exist")
        .1
        .split_once("struct DfnCertAdvisoryDetail")
        .expect("DFN-CERT advisory payload must precede detail payload")
        .0;
    let cert_bund_detail_source = source
        .split_once("pub(crate) async fn cert_bund_advisory_detail")
        .expect("CERT-Bund detail handler must exist")
        .1
        .split_once("#[derive(Debug, Serialize)]")
        .expect("CERT-Bund detail handler must precede payload structs")
        .0;
    let dfn_cert_detail_source = source
        .split_once("pub(crate) async fn dfn_cert_advisory_detail")
        .expect("DFN-CERT detail handler must exist")
        .1
        .split_once("pub(crate) async fn cert_bund_advisories")
        .expect("DFN-CERT detail handler must precede CERT-Bund list")
        .0;
    let cert_bund_list_source = source
        .split_once("pub(crate) async fn cert_bund_advisories(")
        .expect("CERT-Bund list handler must exist")
        .1
        .split_once("pub(crate) async fn cert_bund_advisory_detail")
        .expect("CERT-Bund list handler must precede detail handler")
        .0;
    let dfn_cert_list_source = source
        .split_once("pub(crate) async fn dfn_cert_advisories(")
        .expect("DFN-CERT list handler must exist")
        .1
        .split_once("pub(crate) async fn dfn_cert_advisory_detail")
        .expect("DFN-CERT list handler must precede detail handler")
        .0;

    assert!(!cert_bund_item_payload.contains("user_tags"));
    assert!(!dfn_cert_item_payload.contains("user_tags"));
    assert!(payload_source.contains("struct CertBundAdvisoryDetail"));
    assert!(payload_source.contains("struct DfnCertAdvisoryDetail"));
    assert!(cert_bund_detail_source.contains("let id: String = row.get(\"id\");"));
    assert!(dfn_cert_detail_source.contains("let id: String = row.get(\"id\");"));
    assert!(
        cert_bund_detail_source
            .contains("catalog_user_tags(&client, \"cert_bund_adv\", &id).await?")
    );
    assert!(
        dfn_cert_detail_source.contains("catalog_user_tags(&client, \"dfn_cert_adv\", &id).await?")
    );
    assert!(!cert_bund_list_source.contains("catalog_user_tags"));
    assert!(!dfn_cert_list_source.contains("catalog_user_tags"));
}

#[test]
fn report_evidence_collection_contracts_define_sort_filter_and_tie_breakers() {
    let paths: Vec<&str> = REPORT_EVIDENCE_COLLECTION_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v1/reports/{report_id}/hosts",
            "/api/v1/reports/{report_id}/ports",
            "/api/v1/reports/{report_id}/applications",
            "/api/v1/reports/{report_id}/operating-systems",
            "/api/v1/reports/{report_id}/tls-certificates",
            "/api/v1/reports/{report_id}/cves",
            "/api/v1/reports/{report_id}/errors",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/ports",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/applications",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/operating-systems",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/tls-certificates",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/cves",
            "/api/v1/scopes/{scope_id}/reports/{scope_report_id}/errors",
        ]
    );
    for contract in REPORT_EVIDENCE_COLLECTION_CONTRACTS {
        assert_collection_contract(contract);
    }
    assert!(sort_field_names(REPORT_HOST_SORT_FIELDS).contains(&"authentication_state"));
    assert!(sort_field_names(REPORT_PORT_SORT_FIELDS).contains(&"severity"));
    assert!(sort_field_names(REPORT_APPLICATION_SORT_FIELDS).contains(&"occurrences"));
    assert!(sort_field_names(REPORT_TLS_CERTIFICATE_SORT_FIELDS).contains(&"notvalidafter"));
    assert!(sort_field_names(REPORT_CVE_SORT_FIELDS).contains(&"severity"));
    assert!(sort_field_names(REPORT_ERROR_SORT_FIELDS).contains(&"description"));
    assert!(sort_field_names(SCOPE_REPORT_HOST_SORT_FIELDS).contains(&"scope_membership"));
    assert!(sort_field_names(SCOPE_REPORT_PORT_SORT_FIELDS).contains(&"max_severity"));
    assert!(!sort_field_names(SCOPE_REPORT_PORT_SORT_FIELDS).contains(&"severity"));
    assert!(sort_field_names(SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS).contains(&"not_after"));
    assert!(!sort_field_names(SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS).contains(&"dn"));
    assert!(sort_clause("severity", SCOPE_REPORT_CVE_SORT_FIELDS).is_err());
}

#[test]
fn collection_handlers_use_api_query_contract_extractor() {
    let source = [
        include_str!("main.rs"),
        include_str!("alerts.rs"),
        include_str!("nvt_catalog.rs"),
        include_str!("cpe_catalog.rs"),
        include_str!("cve_catalog.rs"),
        include_str!("cert_advisories.rs"),
        include_str!("filters.rs"),
        include_str!("host_asset_payloads.rs"),
        include_str!("host_assets.rs"),
        include_str!("operating_systems.rs"),
        include_str!("overrides.rs"),
        include_str!("port_lists.rs"),
        include_str!("report_applications.rs"),
        include_str!("report_configs.rs"),
        include_str!("report_cves.rs"),
        include_str!("report_errors.rs"),
        include_str!("report_format_payloads.rs"),
        include_str!("report_formats.rs"),
        include_str!("report_hosts.rs"),
        include_str!("report_operating_systems.rs"),
        include_str!("report_payloads.rs"),
        include_str!("report_ports.rs"),
        include_str!("report_tls_certificates.rs"),
        include_str!("result_payloads.rs"),
        include_str!("scan_config_payloads.rs"),
        include_str!("scan_configs.rs"),
        include_str!("scope_payloads.rs"),
        include_str!("scope_report_applications.rs"),
        include_str!("scope_report_cves.rs"),
        include_str!("scope_report_errors.rs"),
        include_str!("scope_reports.rs"),
        include_str!("scope_report_hosts.rs"),
        include_str!("scope_report_operating_systems.rs"),
        include_str!("scope_report_ports.rs"),
        include_str!("scope_report_retention.rs"),
        include_str!("scope_report_results.rs"),
        include_str!("scope_report_tls_certificates.rs"),
        include_str!("scanner_assets.rs"),
        include_str!("schedules.rs"),
        include_str!("tags.rs"),
        include_str!("task_target_payloads.rs"),
        include_str!("task_targets.rs"),
        include_str!("tls_certificates.rs"),
        include_str!("vulnerability_payloads.rs"),
    ]
    .join("\n");
    let expected_collection_count = PRIORITY_COLLECTION_CONTRACTS.len()
        + REPORT_EVIDENCE_COLLECTION_CONTRACTS.len()
        + SCOPE_TASK_TARGET_COLLECTION_CONTRACTS.len()
        + ASSET_CATALOG_COLLECTION_CONTRACTS.len()
        + MANAGEMENT_COLLECTION_CONTRACTS.len();
    let raw_axum_query = concat!("Query", "(query): Query", "<CollectionQuery>");
    let api_query = concat!("ApiQuery", "(query): ApiQuery", "<CollectionQuery>");

    assert_eq!(
        source.matches(raw_axum_query).count(),
        0,
        "collection handlers must not use Axum Query directly"
    );
    assert_eq!(
        source.matches(api_query).count(),
        expected_collection_count,
        "every checked collection contract should use ApiQuery"
    );
}

#[test]
fn scope_report_results_sql_is_source_scoped_and_deduplicated() {
    let sort_sql = sort_clause(REPORT_RESULT_DEFAULT_SORT, REPORT_RESULT_SORT_FIELDS).unwrap();
    let sql = scope_report_results_sql(&sort_sql);

    assert!(sql.contains("WHERE sr.uuid = $1 AND sr.scope_uuid = $2"));
    assert!(sql.contains("JOIN scope_report_sources srs ON srs.scope_report = sr.id"));
    assert!(sql.contains("JOIN selected_hosts sh"));
    assert!(sql.contains("WHERE coalesce(r.severity, 0) != -3.0"));
    assert!(sql.contains("row_number () OVER"));
    assert!(sql.contains("PARTITION BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))"));
    assert!(sql.contains("FROM ranked WHERE rn = 1"));
    assert!(sql.contains("srs.source_report_uuid AS source_report_id"));
    assert!(sql.contains("JOIN results r ON r.report = srs.source_report"));
}

#[test]
fn scope_report_retention_preview_marks_only_non_latest_sources() {
    let sql = scope_report_retention_sources_sql();
    let upper_sql = sql.to_uppercase();

    assert!(sql.contains("WITH latest_completed AS"));
    assert!(sql.contains("SELECT DISTINCT ON (task.target)"));
    assert!(sql.contains("coalesce(task.usage_type, 'scan') = 'scan'"));
    assert!(sql.contains("reports.scan_run_status = 1"));
    assert!(sql.contains("ORDER BY task.target, coalesce(reports.end_time, reports.creation_time) DESC, reports.id DESC"));
    assert!(sql.contains("SELECT srs.source_report, srs.source_report_uuid, srs.target,"));
    assert!(sql.contains("FROM scope_report_sources srs"));
    assert!(sql.contains("(lc.source_report = srs.source_report) AS kept_as_latest"));
    assert!(sql.contains("WHERE srs.scope_report = $1"));
    assert!(sql.contains("SELECT sr.source_report_uuid::text, sr.target_uuid::text"));
    assert!(sql.contains("sr.task_uuid::text, coalesce(sr.task_name, '')::text AS task_name"));
    assert!(sql.contains("coalesce(sr.kept_as_latest, false) AS kept_as_latest"));
    assert!(sql.contains("FROM source_rows sr"));
    assert!(sql.contains("LEFT JOIN results res ON res.report = sr.source_report"));
    assert!(
        sql.contains(
            "GROUP BY sr.source_report_uuid, sr.target_uuid, sr.target_name, sr.task_uuid,"
        )
    );
    assert!(
        sql.find("FROM source_rows sr").unwrap()
            < sql
                .find("LEFT JOIN results res ON res.report = sr.source_report")
                .unwrap()
    );
    assert!(!upper_sql.contains("INSERT"));
    assert!(!upper_sql.contains("UPDATE"));
    assert!(!upper_sql.contains("DELETE"));
    assert!(!direct_api_v1_path_is_allowed(
        "/api/v1/scopes/scope-id/reports/report-id/retention-plan"
    ));
}

#[test]
fn scope_report_retention_plan_remains_dry_run_read_only_preview() {
    let source = include_str!("scope_report_retention.rs");
    let body = source
        .split_once("async fn scope_report_retention_plan(")
        .expect("scope report retention plan handler must exist")
        .1
        .split_once("fn scope_report_retention_sources_sql")
        .expect("retention plan handler must precede retention SQL helper")
        .0;
    let upper_body = body.to_ascii_uppercase();

    assert!(body.contains("mode: \"dry_run_preview\".to_string()"));
    assert!(body.contains("destructive_actions: false"));
    assert!(body.contains("latest_completed_raw_report_retains_full_detail: true"));
    assert!(body.contains("detail_compacted_field: \"detail_compacted\".to_string()"));
    assert!(body.contains("aggregate_only_field: \"aggregate_only\".to_string()"));
    assert!(body.contains("detail_compacted_count: 0"));
    assert!(body.contains("aggregate_only_count: 0"));
    for forbidden in ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP"] {
        assert!(
            !upper_body.contains(forbidden),
            "retention preview handler must stay read-only and non-destructive"
        );
    }
}

#[test]
fn scope_report_metrics_reads_persisted_snapshot_tables_and_not_live_results() {
    let source = include_str!("metrics.rs");
    let start = "pub(crate) async fn scope_report_metrics(";
    let end = "\n}\n\npub(crate) async fn report_metrics";
    let body = source
        .split_once(start)
        .expect("scope_report_metrics handler must exist")
        .1
        .split_once(end)
        .expect("scope_report_metrics handler must precede retention plan")
        .0;
    let upper_body = body.to_ascii_uppercase();

    assert!(body.contains("coalesce(sr.metric_total_system_cvss_load, 0)"));
    assert!(body.contains("coalesce(sr.metric_authenticated_scan_coverage, 0)"));
    assert!(body.contains("SELECT count(*) FROM scope_report_vulnerability_metrics"));
    assert!(body.contains("FROM scope_report_system_metrics"));
    assert!(body.contains("FROM scope_report_vulnerability_metrics"));
    assert!(body.contains("WHERE sr.uuid = $1 AND sr.scope_uuid = $2"));
    assert!(body.contains("ORDER BY cvss_load DESC, host ASC"));
    assert!(body.contains("ORDER BY cvss_load DESC, cvss_score DESC, nvt_name ASC"));
    assert!(!upper_body.contains("JOIN RESULTS"));
    assert!(!upper_body.contains("FROM RESULTS"));
}

#[test]
fn direct_api_allowlist_tracks_registered_get_routes_and_write_contracts() {
    let source = include_str!("routes.rs");
    let routes = app_route_registration_block(source);
    let api_routes = registered_routes(routes)
        .into_iter()
        .filter(|route| route.path.starts_with("/api/v1/"))
        .collect::<Vec<_>>();
    let internal_only_routes = ["/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan"];

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
            .contains("let internal_app = base_router.clone().with_state(state.clone());")
    );
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
fn scope_report_native_routes_remain_get_only_read_paths() {
    let source = include_str!("routes.rs");
    let start = ".route(\"/api/v1/scope-reports\", get(scope_reports))";
    let end = "\n}\n\npub(crate) fn direct_native_api_router";
    let routes = source
        .split_once(start)
        .expect("scope report routes must be registered")
        .1
        .split_once(end)
        .expect("scope report routes must precede app state")
        .0;

    for path in [
        "/api/v1/scope-reports/:scope_report_id",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/results",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/hosts",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/ports",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/applications",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/operating-systems",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/cves",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/tls-certificates",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/errors",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/metrics",
        "/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan",
    ] {
        assert!(routes.contains(path));
    }
    for handler in [
        "get(scope_report_detail)",
        "get(scope_report_results)",
        "get(scope_report_hosts)",
        "get(scope_report_ports)",
        "get(scope_report_applications)",
        "get(scope_report_operating_systems)",
        "get(scope_report_cves)",
        "get(scope_report_tls_certificates)",
        "get(scope_report_errors)",
        "get(scope_report_metrics)",
        "get(scope_report_retention_plan)",
    ] {
        assert!(routes.contains(handler));
    }
    for forbidden in [
        "post(scope_report",
        "put(scope_report",
        "patch(scope_report",
        "delete(scope_report",
        "start_task",
        "resume_task",
    ] {
        assert!(!routes.contains(forbidden));
    }
}

#[test]
fn scope_reports_do_not_trigger_scanner_or_task_control() {
    let source = [
        include_str!("scope_report_results.rs"),
        include_str!("scope_report_applications.rs"),
        include_str!("scope_report_cves.rs"),
        include_str!("scope_report_errors.rs"),
        include_str!("scope_reports.rs"),
        include_str!("scope_report_hosts.rs"),
        include_str!("scope_report_operating_systems.rs"),
        include_str!("scope_report_ports.rs"),
        include_str!("scope_report_tls_certificates.rs"),
        include_str!("scope_report_lookup.rs"),
    ]
    .join("\n");
    let start = "pub(crate) async fn scope_report_results(";
    let end = "\npub(crate) async fn scope_report_exists(";
    let handlers = source
        .split_once(start)
        .expect("scope report handlers must exist")
        .1
        .split_once(end)
        .expect("scope report handlers must precede tests")
        .0;
    let lower_handlers = handlers.to_ascii_lowercase();

    for forbidden in [
        "start_task",
        "resume_task",
        "stop_task",
        "osp_",
        "create_report",
        "insert into reports",
        "update tasks",
        "delete from reports",
    ] {
        assert!(
            !lower_handlers.contains(forbidden),
            "scope report read handlers must not trigger scanner or task control: {forbidden}"
        );
    }
}

#[test]
fn result_rows_expose_nvt_epss_context_without_mutation_workflows() {
    let source = include_str!("result_payloads.rs");
    let result_source = source;
    let scope_report_results_source = include_str!("scope_report_results.rs");
    let result_payload = result_source
        .split_once("pub(crate) struct ResultItem {")
        .expect("result payload struct must exist")
        .1
        .split_once("pub(crate) fn result_from_row")
        .expect("result payload must precede row mapper")
        .0;
    let result_sql_sources = [
        source
            .split_once("async fn results")
            .expect("result list handler must exist")
            .1
            .split_once("async fn result_detail")
            .expect("result list handler must precede result detail")
            .0,
        source
            .split_once("async fn result_detail")
            .expect("result detail handler must exist")
            .1
            .split_once("async fn report_results")
            .expect("result detail handler must precede report result list")
            .0,
        source
            .split_once("async fn report_results")
            .expect("report result list handler must exist")
            .1,
        scope_report_results_source
            .split_once("fn scope_report_results_sql")
            .expect("scope report result SQL helper must exist")
            .1,
    ];
    let row_mapper = result_source
        .split_once("pub(crate) fn result_from_row")
        .expect("result row mapper must exist")
        .1
        .split_once("pub(crate) fn result_override_from_row")
        .expect("result row mapper must precede override row mapper")
        .0;

    for expected in [
        "max_epss: Option<NvtEpssItem>",
        "max_severity: Option<NvtEpssItem>",
        "user_tags: Vec<ReportUserTag>",
        "overrides: Vec<ResultOverrideItem>",
    ] {
        assert!(result_payload.contains(expected));
    }
    for sql_source in result_sql_sources {
        for expected in [
            "n.epss_score",
            "n.epss_percentile",
            "n.epss_cve",
            "n.epss_severity",
            "n.max_epss_score",
            "n.max_epss_percentile",
            "n.max_epss_cve",
            "n.max_epss_severity",
        ] {
            assert!(sql_source.contains(expected));
        }
    }
    assert!(row_mapper.contains("max_epss: nvt_epss_from_row(row)"));
    assert!(row_mapper.contains("max_severity: nvt_max_severity_from_row(row)"));
    assert!(row_mapper.contains("overrides: result_overrides_from_row(row)"));
    assert!(result_sql_sources[0].contains("r.id AS result_internal_id"));
    assert!(result_sql_sources[0].contains("ro.result = p.result_internal_id"));
    assert!(result_sql_sources[0].contains("array_agg(m.id ORDER BY"));
    assert!(result_sql_sources[0].contains("override_active_ints"));
    assert!(result_sql_sources[1].contains("result_user_tags(&client, &result_id)"));
    assert!(result_sql_sources[1].contains("result_effective_overrides(&client, &result_id)"));
    assert!(result_sql_sources[1].contains("tr.resource_type = 'result'"));
    assert!(result_sql_sources[1].contains("coalesce(t.active, 0) = 1"));
    assert!(result_sql_sources[1].contains("FROM result_overrides ro"));
    assert!(result_sql_sources[1].contains("JOIN overrides o ON o.id = ro.override"));
    for list_source in [
        result_sql_sources[0],
        result_sql_sources[2],
        result_sql_sources[3],
    ] {
        assert!(!list_source.contains("result_user_tags"));
        assert!(!list_source.contains("result_effective_overrides"));
    }
    for inherited_workflow in [
        "export",
        "create_override",
        "modify_override",
        "delete_override",
    ] {
        assert!(!result_sql_sources[1].contains(inherited_workflow));
    }
}

#[test]
fn scope_task_target_collection_contracts_define_sort_filter_and_tie_breakers() {
    let paths: Vec<&str> = SCOPE_TASK_TARGET_COLLECTION_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    assert_eq!(
        paths,
        vec![
            "/api/v1/targets",
            "/api/v1/tasks",
            "/api/v1/scopes",
            "/api/v1/scope-reports",
        ]
    );
    for contract in SCOPE_TASK_TARGET_COLLECTION_CONTRACTS {
        assert_collection_contract(contract);
    }
    for sort_field in gsa_native_sort_fields(
        include_str!("../../../components/gsa/src/gmp/native-api/targets.ts"),
        "TARGET_SORT_FIELDS",
    ) {
        assert!(
            sort_clause(sort_field, TARGET_SORT_FIELDS).is_ok(),
            "GSA target native sort field {sort_field} must be accepted by Rust target sort fields"
        );
    }
    assert!(sort_field_names(TARGET_SORT_FIELDS).contains(&"hosts"));
    assert!(sort_field_names(TARGET_SORT_FIELDS).contains(&"port_list"));
    assert!(sort_field_names(TASK_SORT_FIELDS).contains(&"last_report"));
    assert!(sort_field_names(SCOPE_SORT_FIELDS).contains(&"protection_requirement"));
    assert!(sort_field_names(SCOPE_REPORT_SORT_FIELDS).contains(&"latest_evidence_time"));
    assert!(sort_clause("created_at", TARGET_SORT_FIELDS).is_err());
}

#[test]
fn alert_assets_sql_redacts_payload_tables() {
    let sort_sql = sort_clause(ALERT_DEFAULT_SORT, ALERT_SORT_FIELDS).unwrap();
    let sql = alert_assets_sql(&sort_sql);
    assert!(sql.contains("FROM alerts a"));
    assert!(sql.contains("LEFT JOIN users u ON u.id = a.owner"));
    assert!(sql.contains("LEFT JOIN filters f ON f.id = a.filter"));
    assert!(sql.contains("FROM task_alerts ta"));
    assert!(!sql.contains("alert_method_data"));
    assert!(!sql.contains("alert_event_data"));
    assert!(!sql.contains("alert_condition_data"));
    let detail_sql = alert_asset_detail_sql();
    assert!(detail_sql.contains("FROM alerts a"));
    assert!(detail_sql.contains("LEFT JOIN users u ON u.id = a.owner"));
    assert!(detail_sql.contains("LEFT JOIN filters f ON f.id = a.filter"));
    assert!(detail_sql.contains("FROM task_alerts ta"));
    assert!(!detail_sql.contains("alert_method_data"));
    assert!(!detail_sql.contains("alert_event_data"));
    assert!(!detail_sql.contains("alert_condition_data"));
    let tasks_sql = alert_asset_tasks_sql();
    assert!(tasks_sql.contains("FROM alerts a"));
    assert!(tasks_sql.contains("JOIN task_alerts ta ON ta.alert = a.id"));
    assert!(tasks_sql.contains("JOIN tasks t ON t.id = ta.task"));
    assert!(!tasks_sql.contains("alert_method_data"));
    assert!(!tasks_sql.contains("alert_event_data"));
    assert!(!tasks_sql.contains("alert_condition_data"));
}

#[test]
fn operating_system_user_tags_are_active_os_tags_only() {
    let sql = operating_system_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN oss ON oss.id = tr.resource"));
    assert!(sql.contains("tr.resource_type = 'os'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn host_user_tags_are_detail_only_active_host_tags() {
    let payload_source = include_str!("host_asset_payloads.rs");
    let host_list_payload = payload_source
        .split_once("pub(crate) struct HostAssetItem {")
        .expect("host list payload struct must exist")
        .1
        .split_once("pub(crate) struct HostAssetDetailIdentifier")
        .expect("host list payload struct must precede detail identifiers")
        .0;
    let host_detail_payload = payload_source
        .split_once("pub(crate) struct HostAssetDetail {")
        .expect("host detail payload struct must exist")
        .1
        .split_once("fn host_identifier_from_row")
        .expect("host detail payload struct must precede row mapping helpers")
        .0;

    assert!(!host_list_payload.contains("user_tags"));
    assert!(host_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = host_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN hosts ON hosts.id = tr.resource"));
    assert!(sql.contains("lower(hosts.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'host'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn tls_certificate_user_tags_are_active_tls_certificate_tags_only() {
    let sql = tls_certificate_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN tls_certificates ON tls_certificates.id = tr.resource"));
    assert!(sql.contains("lower(tls_certificates.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'tls_certificate'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn tls_certificate_detail_contract_excludes_certificate_bytes() {
    let source = include_str!("tls_certificates.rs");
    let detail_source = source
        .split_once("pub(crate) async fn tls_certificate_asset_detail")
        .expect("TLS certificate detail handler must exist")
        .1
        .split_once("pub(crate) fn tls_certificate_user_tags_sql")
        .expect("TLS certificate detail handler must precede tag helper")
        .0;

    assert!(detail_source.contains("valid_int"));
    assert!(detail_source.contains("trust_int"));
    assert!(detail_source.contains("time_status"));
    assert!(detail_source.contains("host_asset_id"));
    assert!(detail_source.contains("tls_certificate_user_tags"));
    assert!(!detail_source.contains("c.certificate"));
    assert!(!detail_source.contains("certificate_format"));
}

#[test]
fn scanner_user_tags_are_detail_only_active_scanner_tags() {
    let source = include_str!("scanner_assets.rs");
    let scanner_list_payload = source
        .split_once("pub(crate) struct ScannerAssetItem {")
        .expect("scanner list payload struct must exist")
        .1
        .split_once("pub(crate) struct ScannerTaskReference")
        .expect("scanner list payload struct must precede detail references")
        .0;
    let scanner_detail_payload = source
        .split_once("pub(crate) struct ScannerAssetDetail {")
        .expect("scanner detail payload struct must exist")
        .1
        .split_once("pub(crate) fn scanner_asset_from_row")
        .expect("scanner detail payload struct must precede row mapper")
        .0;

    assert!(!scanner_list_payload.contains("user_tags"));
    assert!(scanner_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = scanner_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN scanners ON scanners.id = tr.resource"));
    assert!(sql.contains("lower(scanners.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'scanner'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn scanner_task_references_are_non_hidden_backlinks_only() {
    let sql = scanner_task_references_sql();
    assert!(sql.contains("FROM scanners s"));
    assert!(sql.contains("JOIN tasks t ON t.scanner = s.id"));
    assert!(sql.contains("lower(s.uuid) = lower($1)"));
    assert!(sql.contains("coalesce(t.hidden, 0) = 0"));
    assert!(sql.contains("coalesce(t.usage_type, 'scan') AS usage_type"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("results"));
}

#[test]
fn scanner_detail_contract_excludes_certificate_and_secret_material() {
    let source = include_str!("scanner_assets.rs");
    let detail_source = source
        .split_once("pub(crate) async fn scanner_asset_detail")
        .expect("scanner detail handler must exist")
        .1
        .split_once("pub(crate) fn scanner_task_references_sql")
        .expect("scanner detail handler must precede task-reference helper")
        .0;

    assert!(detail_source.contains("scanner_task_references"));
    assert!(detail_source.contains("scanner_user_tags"));
    assert!(!detail_source.contains("ca_pub"));
    assert!(!detail_source.contains("credential_value"));
    assert!(!detail_source.contains("private_key"));
    assert!(!detail_source.contains("password"));
    assert!(!detail_source.contains("secret"));
    assert!(!detail_source.contains("certificate_info"));
    assert!(!detail_source.contains("send_scanner_info"));
}

#[test]
fn scan_config_user_tags_are_detail_only_active_config_tags() {
    let payload_source = include_str!("scan_config_payloads.rs");
    let scan_config_list_payload = payload_source
        .split_once("pub(crate) struct ScanConfigAssetItem {")
        .expect("scan config list payload struct must exist")
        .1
        .split_once("pub(crate) struct ScanConfigAssetDetail")
        .expect("scan config list payload struct must precede detail payload")
        .0;
    let scan_config_detail_payload = payload_source
        .split_once("pub(crate) struct ScanConfigAssetDetail {")
        .expect("scan config detail payload struct must exist")
        .1
        .split_once("pub(crate) fn scan_config_asset_from_row")
        .expect("scan config detail payload must precede row mapper")
        .0;

    assert!(!scan_config_list_payload.contains("user_tags"));
    assert!(scan_config_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = scan_config_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN configs c ON c.id = tr.resource"));
    assert!(sql.contains("lower(c.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'config'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn scan_config_task_references_are_non_hidden_config_backlinks_only() {
    let sql = scan_config_task_references_sql();
    assert!(sql.contains("FROM configs c"));
    assert!(sql.contains("JOIN tasks t ON t.config = c.id"));
    assert!(sql.contains("lower(c.uuid) = lower($1)"));
    assert!(sql.contains("t.config_location = 0"));
    assert!(sql.contains("coalesce(t.hidden, 0) = 0"));
    assert!(sql.contains("coalesce(t.usage_type, 'scan') AS usage_type"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("results"));
}

#[test]
fn schedule_user_tags_are_detail_only_active_schedule_tags() {
    let source = include_str!("schedules.rs");
    let schedule_list_payload = source
        .split_once("struct ScheduleAssetItem {")
        .expect("schedule list payload struct must exist")
        .1
        .split_once("struct ScheduleAssetDetail")
        .expect("schedule list payload struct must precede detail payload")
        .0;
    let schedule_detail_payload = source
        .split_once("struct ScheduleAssetDetail {")
        .expect("schedule detail payload struct must exist")
        .1
        .split_once("pub(crate) fn schedule_task_from_row")
        .expect("schedule detail payload must precede row mappers")
        .0;

    assert!(!schedule_list_payload.contains("user_tags"));
    assert!(schedule_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = schedule_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN schedules s ON s.id = tr.resource"));
    assert!(sql.contains("lower(s.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'schedule'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn port_list_user_tags_are_detail_only_active_port_list_tags() {
    let source = include_str!("port_lists.rs");
    let port_list_payload = source
        .split_once("struct PortListAssetItem {")
        .expect("port list payload struct must exist")
        .1
        .split_once("struct PortListAssetDetail")
        .expect("port list payload struct must precede detail payload")
        .0;
    let port_list_detail_payload = source
        .split_once("struct PortListAssetDetail {")
        .expect("port list detail payload struct must exist")
        .1
        .split_once("pub(crate) fn port_range_from_row")
        .expect("port list detail payload must precede row mappers")
        .0;

    assert!(!port_list_payload.contains("user_tags"));
    assert!(port_list_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = port_list_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN port_lists pl ON pl.id = tr.resource"));
    assert!(sql.contains("lower(pl.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'port_list'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn scan_config_detail_contract_excludes_preferences_and_secret_material() {
    let source = include_str!("scan_configs.rs");
    let detail_source = source
        .split_once("pub(crate) async fn scan_config_asset_detail")
        .expect("scan config detail handler must exist")
        .1
        .split_once("pub(crate) async fn scan_config_asset_families")
        .expect("scan config detail handler must precede family endpoint")
        .0;

    assert!(detail_source.contains("scan_config_task_references"));
    assert!(detail_source.contains("scan_config_user_tags"));
    assert!(!detail_source.contains("preferences"));
    assert!(!detail_source.contains("nvt_selector"));
    assert!(!detail_source.contains("credential"));
    assert!(!detail_source.contains("password"));
    assert!(!detail_source.contains("secret"));
    assert!(!detail_source.contains("private_key"));
    assert!(!detail_source.contains("export"));
    assert!(!detail_source.contains("xml"));
}

#[test]
fn scope_candidate_hosts_sql_keeps_candidates_out_of_membership() {
    let sql = scope_candidate_hosts_sql();
    assert!(sql.contains("SELECT DISTINCT ON (t.id)"));
    assert!(sql.contains("run_status_name(coalesce(r.scan_run_status, 0)) = 'Done'"));
    assert!(sql.contains("ORDER BY t.id, coalesce(r.end_time, r.creation_time) DESC, r.id DESC"));
    assert!(sql.contains("JOIN scope_targets st ON st.target = t.id"));
    assert!(sql.contains("JOIN report_hosts rh ON rh.report = nr.report"));
    assert!(sql.contains("AND NOT EXISTS"));
    assert!(sql.contains("FROM scope_hosts sh"));
    assert!(sql.contains("WHERE sh.scope = $1 AND lower(h.name) = lower(rh.host)"));
    assert!(!sql.contains("INSERT"));
    assert!(!sql.contains("UPDATE"));
    assert!(!sql.contains("DELETE"));
}

#[test]
fn scope_detail_loads_membership_candidates_and_reports() {
    let source = include_str!("scope_payloads.rs");
    let body = source
        .split_once("async fn scope_detail(")
        .expect("scope detail handler must exist")
        .1
        .split_once("fn scope_sql")
        .expect("scope detail handler must precede scope_sql")
        .0;

    for expected in [
        "let targets = scope_targets(&client, scope_pk, global).await?;",
        "let hosts = scope_hosts(&client, scope_pk, global).await?;",
        "let candidate_hosts = scope_candidate_hosts(&client, scope_pk, global).await?;",
        "let scope_reports = scope_report_references(&client, scope_pk).await?;",
    ] {
        assert!(
            body.contains(expected),
            "missing scope detail load: {expected}"
        );
    }

    assert!(body.contains("scope_from_row("));
    assert!(body.contains("targets,"));
    assert!(body.contains("hosts,"));
    assert!(body.contains("candidate_hosts,"));
    assert!(body.contains("scope_reports,"));
}

#[test]
fn global_scope_membership_queries_include_targets_and_hosts() {
    let sql = scope_sql("true", "name ASC", "");
    assert!(sql.contains("THEN (SELECT count(*) FROM targets)::bigint"));
    assert!(
        sql.contains("ELSE (SELECT count(*) FROM scope_targets st WHERE st.scope = s.id)::bigint")
    );
    assert!(sql.contains("THEN (SELECT count(*) FROM hosts)::bigint"));
    assert!(
        sql.contains("ELSE (SELECT count(*) FROM scope_hosts sh WHERE sh.scope = s.id)::bigint")
    );

    let source = include_str!("scope_payloads.rs");
    let targets_body = source
        .split_once("async fn scope_targets(")
        .expect("scope target helper must exist")
        .1
        .split_once("async fn scope_hosts(")
        .expect("scope target helper must precede scope host helper")
        .0;
    assert!(
        targets_body
            .contains("SELECT uuid, coalesce(name, uuid) FROM targets ORDER BY name, uuid;")
    );
    assert!(targets_body.contains("SELECT target_uuid, coalesce(target_name, target_uuid) FROM scope_targets WHERE scope = $1 ORDER BY target_name, target_uuid;"));

    let hosts_body = source
        .split_once("async fn scope_hosts(")
        .expect("scope host helper must exist")
        .1
        .split_once("fn scope_candidate_hosts_sql")
        .expect("scope host helper must precede candidate host SQL")
        .0;
    assert!(
        hosts_body.contains("SELECT uuid, coalesce(name, uuid) FROM hosts ORDER BY name, uuid;")
    );
    assert!(hosts_body.contains("SELECT host_uuid, coalesce(host_name, host_uuid) FROM scope_hosts WHERE scope = $1 ORDER BY host_name, host_uuid;"));
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
