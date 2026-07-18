// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

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

pub(crate) const REPORT_RAW_RESULT_DEFAULT_SORT: &str = "id";
pub(crate) const REPORT_RAW_RESULT_SORT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("host", "host"),
    ("hostname", "hostname"),
    ("port", "port"),
    ("nvt_oid", "nvt_oid"),
    ("type", "result_type"),
    ("severity", "severity"),
    ("qod", "qod"),
    ("created_at", "created_at_unix"),
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
