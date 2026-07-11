// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    formatters::unix_ts_to_rfc3339,
    row_helpers::{alive_test_labels, boolean_int, csv_values, task_has_active_current_report},
    user_tags::ReportUserTag,
};

#[derive(Debug, Serialize)]
struct TargetReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct PortListReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct CredentialReference {
    id: String,
    name: String,
    credential_type: String,
    port: Option<i64>,
}

#[derive(Debug, Serialize)]
struct TargetCredentials {
    ssh: Option<CredentialReference>,
    ssh_elevate: Option<CredentialReference>,
    smb: Option<CredentialReference>,
    esxi: Option<CredentialReference>,
    snmp: Option<CredentialReference>,
    krb5: Option<CredentialReference>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TargetItem {
    id: String,
    name: String,
    comment: String,
    owner_id: Option<String>,
    hosts: Vec<String>,
    exclude_hosts: Vec<String>,
    max_hosts: i64,
    alive_tests: Vec<String>,
    allow_simultaneous_ips: bool,
    reverse_lookup_only: bool,
    reverse_lookup_unify: bool,
    port_list: Option<PortListReference>,
    credentials: TargetCredentials,
    task_count: i64,
    tasks: Vec<TargetReference>,
    user_tags: Vec<ReportUserTag>,
    creation_time: Option<String>,
    modification_time: Option<String>,
}

#[derive(Debug, Serialize)]
struct TaskReportCount {
    total: i64,
    finished: i64,
}

#[derive(Debug, Serialize)]
struct TaskReportReference {
    id: String,
    timestamp: Option<String>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    severity: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TaskItem {
    id: String,
    name: String,
    comment: String,
    owner_id: Option<String>,
    status: String,
    progress: i64,
    trend: String,
    usage_type: String,
    target: Option<TargetReference>,
    config: Option<TargetReference>,
    scanner: Option<TargetReference>,
    scanner_type: Option<i32>,
    schedule: Option<TargetReference>,
    start_time: Option<String>,
    end_time: Option<String>,
    schedule_next_time: Option<String>,
    schedule_periods: Option<i64>,
    alterable: Option<bool>,
    report_count: TaskReportCount,
    current_report: Option<TaskReportReference>,
    last_report: Option<TaskReportReference>,
    max_severity: f64,
    creation_time: Option<String>,
    modification_time: Option<String>,
}

fn target_reference(id: Option<String>, name: Option<String>) -> Option<TargetReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(TargetReference { id, name })
}

fn port_list_reference(id: Option<String>, name: Option<String>) -> Option<PortListReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(PortListReference { id, name })
}

fn credential_reference(
    row: &Row,
    id_field: &str,
    name_field: &str,
    type_field: &str,
    port_field: &str,
) -> Option<CredentialReference> {
    let id: Option<String> = row.get(id_field);
    id.map(|id| CredentialReference {
        name: row
            .get::<_, Option<String>>(name_field)
            .unwrap_or_else(|| id.clone()),
        credential_type: row
            .get::<_, Option<String>>(type_field)
            .unwrap_or_else(|| "unknown".to_string()),
        port: row.get(port_field),
        id,
    })
}

fn target_credentials(row: &Row) -> TargetCredentials {
    TargetCredentials {
        ssh: credential_reference(
            row,
            "ssh_credential_id",
            "ssh_credential_name",
            "ssh_credential_type",
            "ssh_credential_port",
        ),
        ssh_elevate: credential_reference(
            row,
            "ssh_elevate_credential_id",
            "ssh_elevate_credential_name",
            "ssh_elevate_credential_type",
            "ssh_elevate_credential_port",
        ),
        smb: credential_reference(
            row,
            "smb_credential_id",
            "smb_credential_name",
            "smb_credential_type",
            "smb_credential_port",
        ),
        esxi: credential_reference(
            row,
            "esxi_credential_id",
            "esxi_credential_name",
            "esxi_credential_type",
            "esxi_credential_port",
        ),
        snmp: credential_reference(
            row,
            "snmp_credential_id",
            "snmp_credential_name",
            "snmp_credential_type",
            "snmp_credential_port",
        ),
        krb5: credential_reference(
            row,
            "krb5_credential_id",
            "krb5_credential_name",
            "krb5_credential_type",
            "krb5_credential_port",
        ),
    }
}

fn target_task_references(row: &Row) -> Vec<TargetReference> {
    let ids: Vec<String> = row.get("task_ids");
    let names: Vec<String> = row.get("task_names");
    ids.into_iter()
        .enumerate()
        .map(|(index, id)| TargetReference {
            name: names.get(index).cloned().unwrap_or_else(|| id.clone()),
            id,
        })
        .collect()
}

pub(crate) fn target_from_row(row: &Row) -> TargetItem {
    target_from_row_with_user_tags(row, Vec::new())
}

pub(crate) fn target_from_row_with_user_tags(
    row: &Row,
    user_tags: Vec<ReportUserTag>,
) -> TargetItem {
    let hosts = csv_values(&row.get::<_, String>("hosts"));
    TargetItem {
        id: row.get("uuid"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner_id: row.get("owner_id"),
        max_hosts: row.get("host_entry_count"),
        hosts,
        exclude_hosts: csv_values(&row.get::<_, String>("exclude_hosts")),
        alive_tests: alive_test_labels(row.get("alive_test")),
        allow_simultaneous_ips: boolean_int(row.get("allow_simultaneous_ips")),
        reverse_lookup_only: boolean_int(row.get("reverse_lookup_only")),
        reverse_lookup_unify: boolean_int(row.get("reverse_lookup_unify")),
        port_list: port_list_reference(row.get("port_list_id"), row.get("port_list_name")),
        credentials: target_credentials(row),
        task_count: row.get("task_count"),
        tasks: target_task_references(row),
        user_tags,
        creation_time: unix_ts_to_rfc3339(row.get("creation_time")),
        modification_time: unix_ts_to_rfc3339(row.get("modification_time")),
    }
}

fn task_report_reference(
    row: &Row,
    id_field: &str,
    timestamp_field: &str,
    scan_start_field: &str,
    scan_end_field: &str,
    severity_field: &str,
) -> Option<TaskReportReference> {
    let id: Option<String> = row.get(id_field);
    id.map(|id| TaskReportReference {
        id,
        timestamp: unix_ts_to_rfc3339(row.get(timestamp_field)),
        scan_start: unix_ts_to_rfc3339(row.get(scan_start_field)),
        scan_end: unix_ts_to_rfc3339(row.get(scan_end_field)),
        severity: row.get(severity_field),
    })
}

pub(crate) fn task_from_row(row: &Row) -> TaskItem {
    let status: String = row.get("status");
    let current_report = if task_has_active_current_report(&status) {
        task_report_reference(
            row,
            "current_report_id",
            "current_report_timestamp",
            "current_report_scan_start",
            "current_report_scan_end",
            "current_report_severity",
        )
    } else {
        None
    };
    TaskItem {
        id: row.get("uuid"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner_id: row.get("owner_id"),
        status,
        progress: row.get("progress"),
        trend: row.get("trend"),
        usage_type: row.get("usage_type"),
        target: target_reference(row.get("target_id"), row.get("target_name")),
        config: target_reference(row.get("config_id"), row.get("config_name")),
        scanner: target_reference(row.get("scanner_id"), row.get("scanner_name")),
        scanner_type: row.get("scanner_type"),
        schedule: target_reference(row.get("schedule_id"), row.get("schedule_name")),
        start_time: unix_ts_to_rfc3339(row.get("start_time")),
        end_time: unix_ts_to_rfc3339(row.get("end_time")),
        schedule_next_time: unix_ts_to_rfc3339(row.get("schedule_next_time")),
        schedule_periods: row.get("schedule_periods"),
        alterable: row.get("alterable"),
        report_count: TaskReportCount {
            total: row.get("report_count_total"),
            finished: row.get("report_count_finished"),
        },
        current_report,
        last_report: task_report_reference(
            row,
            "last_report_id",
            "last_report_timestamp",
            "last_report_scan_start",
            "last_report_scan_end",
            "last_report_severity",
        ),
        max_severity: row.get("max_severity"),
        creation_time: unix_ts_to_rfc3339(row.get("creation_time")),
        modification_time: unix_ts_to_rfc3339(row.get("modification_time")),
    }
}
