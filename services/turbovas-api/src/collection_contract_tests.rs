// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{collections::*, query::sort_clause};

struct CollectionContract {
    path: &'static str,
    default_sort: &'static str,
    allowed_sort_fields: &'static [(&'static str, &'static str)],
    filter_fields: &'static [&'static str],
    tie_breakers: &'static [&'static str],
}

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
        path: "/api/v1/credentials",
        default_sort: CREDENTIAL_ASSET_DEFAULT_SORT,
        allowed_sort_fields: CREDENTIAL_ASSET_SORT_FIELDS,
        filter_fields: &["id", "name", "comment", "owner_name", "credential_type"],
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
        filter_fields: &[
            "oid",
            "name",
            "family",
            "category",
            "discovery",
            "cve",
            "qod_type",
            "solution_type",
        ],
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
            "/api/v1/credentials",
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
    assert!(sort_field_names(NVT_CATALOG_SORT_FIELDS).contains(&"category"));
    assert!(sort_field_names(NVT_CATALOG_SORT_FIELDS).contains(&"discovery"));
    assert!(sort_field_names(OPERATING_SYSTEM_ASSET_SORT_FIELDS).contains(&"latest_severity"));
    assert!(sort_clause("created_at", CPE_CATALOG_SORT_FIELDS).is_err());
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
    assert!(sort_field_names(TARGET_SORT_FIELDS).contains(&"hosts"));
    assert!(sort_field_names(TARGET_SORT_FIELDS).contains(&"port_list"));
    assert!(sort_field_names(TASK_SORT_FIELDS).contains(&"last_report"));
    assert!(sort_field_names(SCOPE_SORT_FIELDS).contains(&"protection_requirement"));
    assert!(sort_field_names(SCOPE_REPORT_SORT_FIELDS).contains(&"latest_evidence_time"));
    assert!(sort_clause("created_at", TARGET_SORT_FIELDS).is_err());
}
