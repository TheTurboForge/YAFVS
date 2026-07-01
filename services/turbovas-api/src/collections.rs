// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) const DEFAULT_COLLECTION_PAGE_SIZE: i64 = 50;
pub(crate) const MAX_COLLECTION_PAGE_SIZE: i64 = 500;
pub(crate) const MAX_COLLECTION_FILTER_LENGTH: usize = 4096;
pub(crate) const TAG_RESOURCE_NAME_MAX_PAGE_SIZE: i64 = 200;

pub(crate) const REPORT_DEFAULT_SORT: &str = "-creation_time";
pub(crate) const REPORT_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "uuid"),
    ("name", "name"),
    ("status", "status"),
    ("task", "task_name"),
    ("target", "target_name"),
    ("creation_time", "creation_time"),
    ("scan_start", "scan_start"),
    ("scan_end", "scan_end"),
    ("modification_time", "modification_time"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("host_count", "host_count"),
    ("cve_count", "cve_count"),
    ("severity", "max_severity"),
    ("max_severity", "max_severity"),
    ("critical", "severity_critical"),
    ("high", "severity_high"),
    ("medium", "severity_medium"),
    ("low", "severity_low"),
    ("log", "severity_log"),
    ("false_positive", "severity_false_positive"),
];
pub(crate) const VULNERABILITY_DEFAULT_SORT: &str = "-severity";
pub(crate) const VULNERABILITY_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("oldest", "oldest_result_unix"),
    ("newest", "newest_result_unix"),
    ("severity", "severity"),
    ("qod", "qod"),
    ("results", "result_count"),
    ("hosts", "host_count"),
];
pub(crate) const RESULT_DEFAULT_SORT: &str = "-severity";
pub(crate) const RESULT_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("host", "host"),
    ("hostname", "hostname"),
    ("port", "port"),
    ("nvt_oid", "nvt_oid"),
    ("nvt", "nvt_oid"),
    ("name", "name"),
    ("vulnerability", "name"),
    ("severity", "severity"),
    ("qod", "qod"),
    ("solution_type", "solution_type"),
    ("created", "created_at_unix"),
    ("created_at", "created_at_unix"),
    ("report", "source_report_name"),
    ("task", "task_name"),
];
pub(crate) const REPORT_RESULT_DEFAULT_SORT: &str = "-severity";
pub(crate) const REPORT_RESULT_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("host", "host"),
    ("port", "port"),
    ("nvt_oid", "nvt_oid"),
    ("name", "name"),
    ("severity", "severity"),
    ("qod", "qod"),
    ("created_at", "created_at_unix"),
];
pub(crate) const ALERT_DEFAULT_SORT: &str = "name";
pub(crate) const ALERT_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("event", "event_type"),
    ("condition", "condition_type"),
    ("method", "method_type"),
    ("filter", "filter_name"),
    ("active", "active_int"),
    ("tasks", "task_count"),
    ("task_count", "task_count"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const TAG_DEFAULT_SORT: &str = "name";
pub(crate) const TAG_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("value", "value"),
    ("active", "active_int"),
    ("resource_type", "resource_type"),
    ("resources", "resource_count"),
    ("resource_count", "resource_count"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const TAG_RESOURCE_DEFAULT_SORT: &str = "name";
pub(crate) const TAG_RESOURCE_SORT_FIELDS: &[(&str, &str)] = &[("id", "id"), ("name", "name")];
pub(crate) const PORT_LIST_DEFAULT_SORT: &str = "name";
pub(crate) const PORT_LIST_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("total", "port_count_all"),
    ("tcp", "port_count_tcp"),
    ("udp", "port_count_udp"),
    ("predefined", "predefined_int"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const SCHEDULE_DEFAULT_SORT: &str = "name";
pub(crate) const SCHEDULE_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("first_run", "first_run_unix"),
    ("next_run", "next_run_unix"),
    ("period", "period_seconds"),
    ("duration", "duration_seconds"),
    ("tasks", "task_count"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const REPORT_FORMAT_DEFAULT_SORT: &str = "name";
pub(crate) const REPORT_FORMAT_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("extension", "extension"),
    ("content_type", "content_type"),
    ("trust", "trust_int"),
    ("active", "active_int"),
    ("predefined", "predefined_int"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const REPORT_CONFIG_DEFAULT_SORT: &str = "name";
pub(crate) const REPORT_CONFIG_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("report_format", "report_format_name"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const HOST_ASSET_DEFAULT_SORT: &str = "-severity";
pub(crate) const HOST_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("hostname", "hostname"),
    ("ip", "ip"),
    ("os", "best_os_cpe"),
    ("severity", "severity"),
    ("modified", "modified_at_unix"),
];
pub(crate) const TLS_CERTIFICATE_ASSET_DEFAULT_SORT: &str = "-last_seen";
pub(crate) const TLS_CERTIFICATE_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("subject_dn", "subject_dn"),
    ("subject", "subject_dn"),
    ("issuer_dn", "issuer_dn"),
    ("serial", "serial"),
    ("activates", "activation_time_unix"),
    ("activation_time", "activation_time_unix"),
    ("not_before", "activation_time_unix"),
    ("expires", "expiration_time_unix"),
    ("expiration_time", "expiration_time_unix"),
    ("not_after", "expiration_time_unix"),
    ("last_seen", "last_seen_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const SCANNER_ASSET_DEFAULT_SORT: &str = "name";
pub(crate) const SCANNER_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("host", "host"),
    ("port", "port"),
    ("type", "scanner_type"),
    ("scanner_type", "scanner_type"),
    ("credential", "credential_name"),
    ("modified", "modified_at_unix"),
];
pub(crate) const CREDENTIAL_ASSET_DEFAULT_SORT: &str = "name";
pub(crate) const CREDENTIAL_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("owner", "owner_name"),
    ("type", "credential_type"),
    ("credential_type", "credential_type"),
    ("allow_insecure", "allow_insecure_int"),
    ("targets", "target_count"),
    ("target_count", "target_count"),
    ("scanners", "scanner_count"),
    ("scanner_count", "scanner_count"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const SCAN_CONFIG_ASSET_DEFAULT_SORT: &str = "name";
pub(crate) const SCAN_CONFIG_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("families_total", "family_count"),
    ("family_count", "family_count"),
    ("families_trend", "families_growing"),
    ("nvts_total", "nvt_count"),
    ("nvt_count", "nvt_count"),
    ("nvts_trend", "nvts_growing"),
    ("predefined", "predefined_int"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const FILTER_ASSET_DEFAULT_SORT: &str = "name";
pub(crate) const FILTER_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("term", "term"),
    ("type", "filter_type"),
    ("filter_type", "filter_type"),
    ("alert_count", "alert_count"),
    ("alerts", "alert_count"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const OVERRIDE_ASSET_DEFAULT_SORT: &str = "text";
pub(crate) const OVERRIDE_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("text", "text"),
    ("name", "nvt_name"),
    ("nvt", "nvt_name"),
    ("hosts", "hosts"),
    ("port", "port"),
    ("severity", "severity_sort"),
    ("newSeverity", "new_severity_sort"),
    ("new_severity", "new_severity_sort"),
    ("active", "active_int"),
    ("task_name", "task_name"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
];
pub(crate) const CPE_CATALOG_DEFAULT_SORT: &str = "-modified";
pub(crate) const CPE_CATALOG_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("title", "title"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
    ("severity", "severity"),
    ("cves", "cve_refs"),
    ("cpe_name_id", "cpe_name_id"),
    ("cpeNameId", "cpe_name_id"),
    ("deprecated", "deprecated_int"),
];
pub(crate) const CVE_CATALOG_DEFAULT_SORT: &str = "-severity";
pub(crate) const CVE_CATALOG_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("description", "description"),
    ("published", "published_at_unix"),
    ("modified", "modified_at_unix"),
    ("cvss_base_vector", "cvss_base_vector"),
    ("cvssBaseVector", "cvss_base_vector"),
    ("severity", "severity"),
    ("epss_score", "epss_score"),
    ("epss_percentile", "epss_percentile"),
];
pub(crate) const CERT_ADVISORY_DEFAULT_SORT: &str = "-created";
pub(crate) const CERT_ADVISORY_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("title", "title"),
    ("summary", "summary"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
    ("cves", "cve_refs"),
    ("severity", "severity"),
];
pub(crate) const NVT_CATALOG_DEFAULT_SORT: &str = "-created";
pub(crate) const NVT_CATALOG_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "oid"),
    ("oid", "oid"),
    ("name", "name"),
    ("family", "family"),
    ("category", "category"),
    ("discovery", "discovery"),
    ("created", "created_at_unix"),
    ("modified", "modified_at_unix"),
    ("cve", "cve_refs"),
    ("severity", "severity"),
    ("qod", "qod"),
    ("qod_type", "qod_type"),
    ("solution_type", "solution_type"),
    ("epss_score", "max_epss_score"),
    ("epss_percentile", "max_epss_percentile"),
];
pub(crate) const OPERATING_SYSTEM_ASSET_DEFAULT_SORT: &str = "-latest_severity";
pub(crate) const OPERATING_SYSTEM_ASSET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("title", "title"),
    ("latest_severity", "latest_severity"),
    ("highest_severity", "highest_severity"),
    ("average_severity", "average_severity"),
    ("hosts", "hosts"),
    ("all_hosts", "all_hosts"),
    ("modified", "modified_at_unix"),
];
pub(crate) const REPORT_HOST_DEFAULT_SORT: &str = "host";
pub(crate) const REPORT_HOST_SORT_FIELDS: &[(&str, &str)] = &[
    ("host", "host"),
    ("hostname", "hostname"),
    ("ports_count", "ports_count"),
    ("applications_count", "applications_count"),
    ("distance", "distance"),
    ("authentication_state", "authentication_state"),
    ("start_time", "start_time_unix"),
    ("end_time", "end_time_unix"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("critical", "severity_critical"),
    ("high", "severity_high"),
    ("medium", "severity_medium"),
    ("low", "severity_low"),
    ("log", "severity_log"),
    ("false_positive", "severity_false_positive"),
    ("severity", "max_severity"),
    ("max_severity", "max_severity"),
];
pub(crate) const REPORT_PORT_DEFAULT_SORT: &str = "port";
pub(crate) const REPORT_PORT_SORT_FIELDS: &[(&str, &str)] = &[
    ("port", "port"),
    ("protocol", "protocol"),
    ("host_count", "host_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("severity", "max_severity"),
    ("max_severity", "max_severity"),
];
pub(crate) const REPORT_APPLICATION_DEFAULT_SORT: &str = "name";
pub(crate) const REPORT_APPLICATION_SORT_FIELDS: &[(&str, &str)] = &[
    ("name", "name"),
    ("cpe", "cpe"),
    ("hosts", "host_count"),
    ("host_count", "host_count"),
    ("occurrences", "result_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("severity", "max_severity"),
    ("max_severity", "max_severity"),
];
pub(crate) const REPORT_OPERATING_SYSTEM_DEFAULT_SORT: &str = "name";
pub(crate) const REPORT_OPERATING_SYSTEM_SORT_FIELDS: &[(&str, &str)] = &[
    ("name", "name"),
    ("cpe", "cpe"),
    ("hosts", "host_count"),
    ("host_count", "host_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("severity", "max_severity"),
    ("max_severity", "max_severity"),
];
pub(crate) const REPORT_TLS_CERTIFICATE_DEFAULT_SORT: &str = "-not_after";
pub(crate) const REPORT_TLS_CERTIFICATE_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("fingerprint_sha256", "fingerprint_sha256"),
    ("subject", "subject"),
    ("dn", "subject"),
    ("issuer", "issuer"),
    ("serial", "serial"),
    ("not_before", "not_before_unix"),
    ("notvalidbefore", "not_before_unix"),
    ("not_after", "not_after_unix"),
    ("notvalidafter", "not_after_unix"),
    ("host_count", "host_count"),
    ("port_count", "port_count"),
    ("result_count", "result_count"),
];
pub(crate) const REPORT_CVE_DEFAULT_SORT: &str = "-max_severity";
pub(crate) const REPORT_CVE_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("affected_system_count", "affected_system_count"),
    ("result_count", "result_count"),
    ("severity", "max_severity"),
    ("max_severity", "max_severity"),
];
pub(crate) const REPORT_ERROR_DEFAULT_SORT: &str = "-created_at";
pub(crate) const REPORT_ERROR_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("host", "host"),
    ("port", "port"),
    ("nvt_oid", "nvt_oid"),
    ("description", "description"),
    ("created_at", "created_at_unix"),
];
pub(crate) const TARGET_DEFAULT_SORT: &str = "name";
pub(crate) const TARGET_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "uuid"),
    ("name", "name"),
    ("hosts", "hosts"),
    ("port_list", "port_list_name"),
    ("task_count", "task_count"),
    ("max_hosts", "host_entry_count"),
    ("creation_time", "creation_time"),
    ("modification_time", "modification_time"),
];
pub(crate) const TASK_DEFAULT_SORT: &str = "name";
pub(crate) const TASK_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "uuid"),
    ("name", "name"),
    ("status", "status"),
    ("progress", "progress"),
    ("target", "target_name"),
    ("config", "config_name"),
    ("scanner", "scanner_name"),
    ("schedule", "schedule_name"),
    ("report_count", "report_count_total"),
    ("last_report", "last_report_timestamp"),
    ("max_severity", "max_severity"),
    ("trend", "trend"),
    ("creation_time", "creation_time"),
    ("modification_time", "modification_time"),
];
pub(crate) const SCOPE_DEFAULT_SORT: &str = "name";
pub(crate) const SCOPE_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "uuid"),
    ("name", "name"),
    ("protection_requirement", "protection_requirement"),
    ("target_count", "target_count"),
    ("host_count", "host_count"),
    ("scope_report_count", "scope_report_count"),
    ("creation_time", "creation_time"),
    ("modification_time", "modification_time"),
];
pub(crate) const SCOPE_REPORT_DEFAULT_SORT: &str = "-creation_time";
pub(crate) const SCOPE_REPORT_SORT_FIELDS: &[(&str, &str)] = &[
    ("creation_time", "creation_time"),
    ("modification_time", "modification_time"),
    ("latest_evidence_time", "latest_evidence_time"),
    ("scope_name", "scope_name"),
    ("source_report_count", "source_report_count"),
    ("source_target_count", "source_target_count"),
    ("member_host_count", "member_host_count"),
    ("evidence_host_count", "evidence_host_count"),
    ("missing_host_count", "missing_host_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("max_severity", "max_severity"),
];
pub(crate) const SCOPE_REPORT_HOST_DEFAULT_SORT: &str = "host";
pub(crate) const SCOPE_REPORT_HOST_SORT_FIELDS: &[(&str, &str)] = &[
    ("host", "host"),
    ("scope_membership", "scope_membership"),
    ("source_report_count", "source_report_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("authenticated_scan_state", "authenticated_scan_state"),
];
pub(crate) const SCOPE_REPORT_PORT_DEFAULT_SORT: &str = "port";
pub(crate) const SCOPE_REPORT_PORT_SORT_FIELDS: &[(&str, &str)] = &[
    ("port", "port"),
    ("protocol", "protocol"),
    ("host_count", "host_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("max_severity", "max_severity"),
];
pub(crate) const SCOPE_REPORT_APPLICATION_DEFAULT_SORT: &str = "name";
pub(crate) const SCOPE_REPORT_APPLICATION_SORT_FIELDS: &[(&str, &str)] = &[
    ("name", "name"),
    ("cpe", "cpe"),
    ("host_count", "host_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("max_severity", "max_severity"),
];
pub(crate) const SCOPE_REPORT_OPERATING_SYSTEM_DEFAULT_SORT: &str = "name";
pub(crate) const SCOPE_REPORT_OPERATING_SYSTEM_SORT_FIELDS: &[(&str, &str)] = &[
    ("name", "name"),
    ("cpe", "cpe"),
    ("host_count", "host_count"),
    ("result_count", "result_count"),
    ("vulnerability_count", "vulnerability_count"),
    ("max_severity", "max_severity"),
];
pub(crate) const SCOPE_REPORT_TLS_CERTIFICATE_DEFAULT_SORT: &str = "-not_after";
pub(crate) const SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("fingerprint_sha256", "fingerprint_sha256"),
    ("subject", "subject"),
    ("issuer", "issuer"),
    ("serial", "serial"),
    ("not_before", "not_before_unix"),
    ("not_after", "not_after_unix"),
    ("host_count", "host_count"),
    ("port_count", "port_count"),
    ("result_count", "result_count"),
];
pub(crate) const SCOPE_REPORT_CVE_DEFAULT_SORT: &str = "id";
pub(crate) const SCOPE_REPORT_CVE_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("affected_system_count", "affected_system_count"),
    ("result_count", "result_count"),
    ("max_severity", "max_severity"),
];
pub(crate) const SCOPE_REPORT_ERROR_DEFAULT_SORT: &str = "created_at";
pub(crate) const SCOPE_REPORT_ERROR_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("host", "host"),
    ("port", "port"),
    ("nvt_oid", "nvt_oid"),
    ("created_at", "created_at_unix"),
];
