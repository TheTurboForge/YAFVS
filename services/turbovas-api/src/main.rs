// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, net::SocketAddr};

use axum::{
    Json, Router,
    extract::{Path, State},
    middleware,
    routing::get,
};
use serde::Serialize;
use tokio_postgres::Row;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod app_state;
mod auth;
mod collections;
mod direct_api;
mod errors;
mod feeds;
mod formatters;
mod path_ids;
mod query;
mod report_configs;
mod report_formats;
mod request_ids;
mod request_shapes;
mod row_helpers;
mod tag_resource_helpers;
mod user_tags;

use app_state::{AppState, create_pool, healthz};
use collections::*;
use direct_api::{direct_api_config, require_direct_api_auth};
use errors::ApiError;
use feeds::feeds;
use formatters::*;
use path_ids::*;
use query::*;
use report_configs::*;
use report_formats::*;
use row_helpers::*;
use tag_resource_helpers::*;
use user_tags::*;

#[derive(Debug, Serialize)]
struct ScopeSummary {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct ReportReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct ReportSeverityCounts {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    log: i64,
    false_positive: i64,
}

#[derive(Debug, Serialize)]
struct ReportOwner {
    name: String,
}

#[derive(Debug, Serialize)]
struct ReportItem {
    id: String,
    name: String,
    owner: ReportOwner,
    status: String,
    task: Option<ReportReference>,
    target: Option<ReportReference>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    creation_time: Option<String>,
    modification_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    host_count: i64,
    cve_count: i64,
    severity: ReportSeverityCounts,
    max_severity: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
struct ScopeReportItem {
    id: String,
    name: String,
    status: String,
    scope: ScopeSummary,
    protection_requirement: String,
    source_report_count: i64,
    source_target_count: i64,
    member_host_count: i64,
    evidence_host_count: i64,
    missing_host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    severity: SeverityCounts,
    max_severity: f64,
    latest_evidence_time: Option<String>,
    excluded_candidate_host_count: i64,
    creation_time: Option<String>,
    modification_time: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScopeReportDetail {
    #[serde(flatten)]
    report: ScopeReportItem,
    sources: Vec<ScopeReportSourceItem>,
}

#[derive(Debug, Serialize)]
struct ScopeReportSourceItem {
    id: String,
    source_report_id: String,
    target_id: String,
    target_name: String,
    task_id: String,
    task_name: String,
    scan_end: Option<String>,
    selected: bool,
}

#[derive(Debug, Serialize)]
struct ScopeReportRetentionPolicyPreview {
    mode: String,
    destructive_actions: bool,
    latest_completed_raw_report_retains_full_detail: bool,
    detail_compacted_field: String,
    aggregate_only_field: String,
}

#[derive(Debug, Serialize)]
struct ScopeReportRetentionSummary {
    source_report_count: i64,
    current_full_fidelity_count: i64,
    future_tiered_retention_candidate_count: i64,
    detail_compacted_count: i64,
    aggregate_only_count: i64,
}

#[derive(Debug, Serialize)]
struct ScopeReportRetentionSource {
    source_report_id: String,
    target_id: String,
    target_name: String,
    task_id: String,
    task_name: String,
    scan_start: Option<String>,
    scan_end: Option<String>,
    selected_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    retention_state: String,
    detail_compacted: bool,
    aggregate_only: bool,
    kept_as_latest: bool,
    pinned_by_scope_report: bool,
    future_tiered_retention_candidate: bool,
}

#[derive(Debug, Serialize)]
struct ScopeReportRetentionPlan {
    id: String,
    name: String,
    scope: ScopeSummary,
    generated_at: Option<String>,
    policy: ScopeReportRetentionPolicyPreview,
    summary: ScopeReportRetentionSummary,
    sources: Vec<ScopeReportRetentionSource>,
}

#[derive(Debug, Serialize)]
struct ScopeEntity {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct ScopeCandidateHost {
    id: String,
    name: String,
    target_id: Option<String>,
    target_name: Option<String>,
    source_report_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScopeReportReference {
    id: String,
    name: String,
    creation_time: Option<String>,
    latest_evidence_time: Option<String>,
    source_report_count: i64,
    member_host_count: i64,
    evidence_host_count: i64,
    missing_host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
}

#[derive(Debug, Serialize)]
struct ScopeItem {
    id: String,
    name: String,
    comment: String,
    protection_requirement: String,
    protection_requirement_label: String,
    predefined: bool,
    global: bool,
    creation_time: Option<String>,
    modification_time: Option<String>,
    target_count: i64,
    host_count: i64,
    scope_report_count: i64,
    targets: Vec<ScopeEntity>,
    hosts: Vec<ScopeEntity>,
    candidate_hosts: Vec<ScopeCandidateHost>,
    scope_reports: Vec<ScopeReportReference>,
}

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
struct TargetItem {
    id: String,
    name: String,
    comment: String,
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
struct TaskItem {
    id: String,
    name: String,
    comment: String,
    status: String,
    progress: i64,
    trend: String,
    usage_type: String,
    target: Option<TargetReference>,
    config: Option<TargetReference>,
    scanner: Option<TargetReference>,
    scanner_type: Option<i32>,
    schedule: Option<TargetReference>,
    report_count: TaskReportCount,
    current_report: Option<TaskReportReference>,
    last_report: Option<TaskReportReference>,
    max_severity: f64,
    creation_time: Option<String>,
    modification_time: Option<String>,
}

#[derive(Debug, Serialize)]
struct SeverityCounts {
    high: i64,
    medium: i64,
    low: i64,
    log: i64,
    false_positive: i64,
}

#[derive(Debug, Serialize)]
struct HostItem {
    host: String,
    scope_membership: String,
    source_report_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    authenticated_scan_state: String,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PortItem {
    port: String,
    protocol: String,
    host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ApplicationItem {
    name: String,
    version: String,
    cpe: String,
    host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct OperatingSystemItem {
    name: String,
    cpe: String,
    host_count: i64,
    result_count: i64,
    vulnerability_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CveItem {
    id: String,
    affected_system_count: i64,
    result_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CatalogEpssItem {
    score: f64,
    percentile: f64,
}

#[derive(Debug, Serialize)]
struct CatalogCveCertReference {
    name: String,
    title: String,
    #[serde(rename = "type")]
    cert_type: String,
}

#[derive(Debug, Serialize)]
struct CatalogCveNvtReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct CatalogCveItem {
    id: String,
    name: String,
    comment: String,
    description: String,
    cvss_base_vector: String,
    severity: f64,
    products: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cert_refs: Vec<CatalogCveCertReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nvt_refs: Vec<CatalogCveNvtReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss: Option<CatalogEpssItem>,
    published_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct CatalogCveDetail {
    #[serde(flatten)]
    item: CatalogCveItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct ScanConfigFamilyItem {
    name: String,
    nvt_count: i64,
    max_nvt_count: i64,
    growing: i32,
}

#[derive(Serialize)]
struct ScanConfigFamiliesPayload {
    scan_config_id: String,
    family_count: i64,
    families_growing: i32,
    families: Vec<ScanConfigFamilyItem>,
}

#[derive(Serialize)]
struct TlsCertificateSourceLocation {
    id: String,
    host_ip: String,
    port: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_asset_id: Option<String>,
}

#[derive(Serialize)]
struct TlsCertificateSourceOrigin {
    id: String,
    origin_type: String,
    origin_id: String,
    origin_data: String,
}

#[derive(Serialize)]
struct TlsCertificateSourceItem {
    id: String,
    timestamp: Option<String>,
    tls_versions: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<TlsCertificateSourceLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<TlsCertificateSourceOrigin>,
}

#[derive(Serialize)]
struct TlsCertificateAssetDetail {
    #[serde(flatten)]
    asset: TlsCertificateAssetItem,
    sources: Vec<TlsCertificateSourceItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
struct CatalogCpeCveItem {
    id: String,
    severity: f64,
}

#[derive(Debug, Serialize)]
struct CatalogCpeItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    cpe_name_id: String,
    deprecated: bool,
    deprecated_by: Option<String>,
    severity: f64,
    cve_refs: i64,
    cves: Vec<CatalogCpeCveItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct CatalogCpeDetail {
    #[serde(flatten)]
    item: CatalogCpeItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
struct DfnCertAdvisoryItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    summary: String,
    severity: f64,
    cve_refs: i64,
    cves: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct DfnCertAdvisoryDetail {
    #[serde(flatten)]
    item: DfnCertAdvisoryItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
struct CertBundAdvisoryItem {
    id: String,
    name: String,
    comment: String,
    title: String,
    summary: String,
    severity: f64,
    cve_refs: i64,
    cves: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertBundAdvisoryDetail {
    #[serde(flatten)]
    item: CertBundAdvisoryItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
struct NvtEpssItem {
    score: f64,
    percentile: f64,
    cve: String,
    severity: f64,
}

#[derive(Debug, Serialize)]
struct NvtCatalogItem {
    id: String,
    oid: String,
    name: String,
    family: String,
    severity: f64,
    qod: i64,
    qod_type: String,
    solution_type: String,
    solution_method: String,
    solution: String,
    tags: String,
    cve_refs: i64,
    cves: Vec<String>,
    cert_refs: Vec<String>,
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct NvtCatalogDetail {
    #[serde(flatten)]
    catalog: NvtCatalogItem,
    comment: String,
    summary: String,
    insight: String,
    affected: String,
    impact: String,
    detection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Debug, Serialize)]
struct TlsCertificateItem {
    id: String,
    fingerprint_sha256: String,
    subject: String,
    issuer: String,
    serial: String,
    not_before: Option<String>,
    not_after: Option<String>,
    host_count: i64,
    port_count: i64,
    result_count: i64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResultOverrideNvtReference {
    id: String,
    name: String,
    #[serde(rename = "type")]
    nvt_type: String,
}

#[derive(Debug, Serialize)]
struct ResultOverrideItem {
    id: String,
    nvt: ResultOverrideNvtReference,
    text: String,
    text_excerpt: bool,
    hosts: String,
    port: String,
    severity: Option<f64>,
    new_severity: Option<f64>,
    active: bool,
    end_time: Option<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ResultItem {
    id: String,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_asset_id: Option<String>,
    hostname: Option<String>,
    port: String,
    nvt_oid: String,
    name: String,
    nvt_family: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cves: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cert_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    description_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution: Option<String>,
    severity: f64,
    qod: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_nvt_version: Option<String>,
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<ReportReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ReportReference>,
    source_report_id: String,
    raw_evidence_href: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    overrides: Vec<ResultOverrideItem>,
}

#[derive(Serialize)]
struct VulnerabilityItem {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    oldest_result: Option<String>,
    newest_result: Option<String>,
    severity: f64,
    qod: i64,
    result_count: i64,
    host_count: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cves: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cert_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution: Option<String>,
}

#[derive(Serialize)]
struct OperatingSystemAssetItem {
    id: String,
    name: String,
    title: String,
    latest_severity: Option<f64>,
    highest_severity: Option<f64>,
    average_severity: Option<f64>,
    hosts: i64,
    all_hosts: i64,
    created_at: Option<String>,
    modified_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct ScheduleTaskReference {
    id: String,
    name: String,
    usage_type: String,
}

#[derive(Serialize)]
struct ScheduleAssetItem {
    id: String,
    name: String,
    comment: String,
    icalendar: String,
    timezone: String,
    timezone_abbrev: Option<String>,
    task_count: i64,
    tasks: Vec<ScheduleTaskReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct ScheduleAssetDetail {
    #[serde(flatten)]
    asset: ScheduleAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct TrashcanSummaryItem {
    resource_type: String,
    title: String,
    count: i64,
}

#[derive(Serialize)]
struct TrashcanSummary {
    items: Vec<TrashcanSummaryItem>,
    total: i64,
}

#[derive(Serialize)]
struct ScannerAssetCredential {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct ScannerAssetItem {
    id: String,
    name: String,
    comment: String,
    host: String,
    port: i64,
    scanner_type: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<ScannerAssetCredential>,
    relay_host: Option<String>,
    relay_port: i64,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct ScannerTaskReference {
    id: String,
    name: String,
    usage_type: String,
}

#[derive(Serialize)]
struct ScannerAssetDetail {
    #[serde(flatten)]
    asset: ScannerAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tasks: Vec<ScannerTaskReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct ScanConfigOwner {
    name: String,
}

#[derive(Serialize)]
struct ScanConfigTrendCount {
    total: i64,
    trend: i32,
}

#[derive(Serialize)]
struct ScanConfigTaskReference {
    id: String,
    name: String,
    usage_type: String,
}

#[derive(Serialize)]
struct ScanConfigAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: ScanConfigOwner,
    family_count: i64,
    families_growing: i32,
    nvt_count: i64,
    nvts_growing: i32,
    families: ScanConfigTrendCount,
    nvts: ScanConfigTrendCount,
    predefined: bool,
    deprecated: bool,
    writable: bool,
    in_use: bool,
    orphan: bool,
    trash: bool,
    usage_type: String,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct ScanConfigAssetDetail {
    #[serde(flatten)]
    asset: ScanConfigAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tasks: Vec<ScanConfigTaskReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct FilterAlertReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct FilterAssetItem {
    id: String,
    name: String,
    comment: String,
    filter_type: String,
    term: String,
    alert_count: i64,
    alerts: Vec<FilterAlertReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct AlertOwner {
    name: String,
}

#[derive(Serialize)]
struct AlertReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct AlertTypeLabel {
    #[serde(rename = "type")]
    type_name: String,
}

#[derive(Serialize)]
struct AlertAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: AlertOwner,
    active: bool,
    in_use: bool,
    task_count: i64,
    event: AlertTypeLabel,
    condition: AlertTypeLabel,
    method: AlertTypeLabel,
    method_data_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<AlertReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tasks: Vec<AlertReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct TagOwner {
    name: String,
}

#[derive(Serialize)]
struct TagResourceCount {
    total: i64,
}

#[derive(Serialize)]
struct TagResourcesSummary {
    #[serde(rename = "type")]
    resource_type: String,
    count: TagResourceCount,
}

#[derive(Serialize)]
struct TagAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: TagOwner,
    resource_type: String,
    resource_count: i64,
    resources: TagResourcesSummary,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    writable: bool,
    in_use: bool,
    orphan: bool,
    trash: bool,
    permissions: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct TagResourceItem {
    id: String,
    #[serde(rename = "type")]
    resource_type: String,
    name: String,
}

#[derive(Serialize)]
struct TagResourceCollection {
    tag_id: String,
    resource_type: String,
    page: PageInfo,
    items: Vec<TagResourceItem>,
}

#[derive(Serialize)]
struct OverrideOwner {
    name: String,
}

#[derive(Serialize)]
struct OverrideNvtReference {
    id: String,
    name: String,
    #[serde(rename = "type")]
    nvt_type: String,
}

#[derive(Serialize)]
struct OverrideTaskReference {
    id: String,
    name: String,
    trash: bool,
}

#[derive(Serialize)]
struct OverrideReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct OverrideAssetItem {
    id: String,
    owner: OverrideOwner,
    nvt: OverrideNvtReference,
    text: String,
    text_excerpt: bool,
    hosts: String,
    port: String,
    severity: Option<f64>,
    new_severity: Option<f64>,
    writable: bool,
    in_use: bool,
    orphan: bool,
    active: bool,
    end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<OverrideTaskReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<OverrideReference>,
    permissions: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct PortRangeItem {
    id: String,
    protocol: String,
    start: i64,
    end: i64,
    comment: String,
}

#[derive(Serialize)]
struct PortCountItem {
    all: i64,
    tcp: i64,
    udp: i64,
}

#[derive(Serialize)]
struct PortListTargetReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct PortListAssetItem {
    id: String,
    name: String,
    comment: String,
    port_count: PortCountItem,
    port_ranges: Vec<PortRangeItem>,
    targets: Vec<PortListTargetReference>,
    predefined: bool,
    deprecated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct PortListAssetDetail {
    #[serde(flatten)]
    asset: PortListAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct HostIdentifierItem {
    id: String,
    name: String,
    value: String,
    source_type: String,
    source_id: String,
    source_data: String,
}

#[derive(Serialize)]
struct HostAssetItem {
    id: String,
    name: String,
    comment: String,
    hostname: Option<String>,
    ip: Option<String>,
    best_os_cpe: Option<String>,
    best_os_txt: Option<String>,
    severity: f64,
    identifiers: Vec<HostIdentifierItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct HostAssetDetailIdentifier {
    id: String,
    name: String,
    value: String,
    source_type: String,
    source_id: String,
    source_data: String,
    source_data_truncated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct HostAssetOperatingSystemItem {
    id: String,
    name: String,
    comment: String,
    operating_system_id: String,
    operating_system_name: String,
    title: String,
    source_type: String,
    source_id: String,
    source_data: String,
    source_data_truncated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct HostAssetDetailItem {
    name: String,
    value: String,
    value_truncated: bool,
    source_type: String,
    source_id: String,
    detail_source_type: String,
    detail_source_name: String,
    detail_source_description: String,
    detail_source_description_truncated: bool,
}

#[derive(Serialize)]
struct HostAssetDetail {
    asset: HostAssetItem,
    identifiers: Vec<HostAssetDetailIdentifier>,
    operating_systems: Vec<HostAssetOperatingSystemItem>,
    details: Vec<HostAssetDetailItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

#[derive(Serialize)]
struct TlsCertificateAssetItem {
    id: String,
    name: String,
    comment: String,
    subject_dn: String,
    issuer_dn: String,
    serial: String,
    md5_fingerprint: String,
    sha256_fingerprint: String,
    activation_time: Option<String>,
    expiration_time: Option<String>,
    last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_status: Option<String>,
    source_host_count: i64,
    source_port_count: i64,
    source_count: i64,
    in_use: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReportHostItem {
    host: String,
    hostname: Option<String>,
    best_os_cpe: Option<String>,
    best_os_txt: Option<String>,
    ports_count: i64,
    applications_count: i64,
    distance: Option<i64>,
    authentication_state: String,
    start_time: Option<String>,
    end_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    severity: ReportSeverityCounts,
    max_severity: f64,
    source_report_id: String,
}

#[derive(Debug, Serialize)]
struct ErrorMessageItem {
    id: String,
    host: String,
    port: String,
    nvt_oid: String,
    description: String,
    source_report_id: String,
    created_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct MetricsSummary {
    total_system_cvss_load: f64,
    average_system_cvss_load: f64,
    authenticated_scan_coverage_percent: f64,
    alive_system_count: i64,
    vulnerability_count: i64,
    authenticated_system_count: i64,
    authentication_failed_system_count: i64,
    no_credential_path_system_count: i64,
    unknown_authentication_system_count: i64,
}

#[derive(Debug, Serialize)]
struct MetricsSystem {
    host: String,
    cvss_load: f64,
    max_cvss: f64,
    vulnerability_count: i64,
    authentication_state: String,
    source_report_count: i64,
}

#[derive(Debug, Serialize)]
struct MetricsVulnerability {
    nvt_oid: String,
    name: String,
    cvss_score: f64,
    affected_system_count: i64,
    cvss_load: f64,
    average_contribution: f64,
    source_report_count: i64,
}

#[derive(Debug, Serialize)]
struct MetricsPayload {
    id: String,
    summary: MetricsSummary,
    systems: Vec<MetricsSystem>,
    vulnerabilities: Vec<MetricsVulnerability>,
}

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState {
        pool: create_pool()?,
    };
    let direct_api = direct_api_config()?;
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/results", get(results))
        .route("/api/v1/results/:result_id", get(result_detail))
        .route("/api/v1/vulnerabilities", get(vulnerabilities))
        .route("/api/v1/cpes", get(cpe_catalog))
        .route("/api/v1/cpes/*cpe_id", get(cpe_catalog_detail))
        .route("/api/v1/cves", get(cve_catalog))
        .route("/api/v1/cves/:cve_id", get(cve_catalog_detail))
        .route("/api/v1/cert-bund-advisories", get(cert_bund_advisories))
        .route(
            "/api/v1/cert-bund-advisories/*advisory_id",
            get(cert_bund_advisory_detail),
        )
        .route("/api/v1/dfn-cert-advisories", get(dfn_cert_advisories))
        .route(
            "/api/v1/dfn-cert-advisories/*advisory_id",
            get(dfn_cert_advisory_detail),
        )
        .route("/api/v1/nvts", get(nvt_catalog))
        .route("/api/v1/nvts/:nvt_id", get(nvt_catalog_detail))
        .route("/api/v1/operating-systems", get(operating_system_assets))
        .route(
            "/api/v1/operating-systems/:os_id",
            get(operating_system_asset_detail),
        )
        .route("/api/v1/hosts", get(host_assets))
        .route("/api/v1/hosts/:host_id", get(host_asset_detail))
        .route("/api/v1/tls-certificates", get(tls_certificate_assets))
        .route(
            "/api/v1/tls-certificates/:certificate_id",
            get(tls_certificate_asset_detail),
        )
        .route("/api/v1/scanners", get(scanner_assets))
        .route("/api/v1/scanners/:scanner_id", get(scanner_asset_detail))
        .route("/api/v1/scan-configs", get(scan_config_assets))
        .route(
            "/api/v1/scan-configs/:scan_config_id",
            get(scan_config_asset_detail),
        )
        .route(
            "/api/v1/scan-configs/:scan_config_id/families",
            get(scan_config_asset_families),
        )
        .route("/api/v1/filters", get(filter_assets))
        .route("/api/v1/filters/:filter_id", get(filter_asset_detail))
        .route("/api/v1/feeds", get(feeds))
        .route("/api/v1/alerts", get(alert_assets))
        .route("/api/v1/alerts/:alert_id", get(alert_asset_detail))
        .route("/api/v1/tags", get(tag_assets))
        .route(
            "/api/v1/tags/resource-names/:resource_type",
            get(tag_resource_names),
        )
        .route("/api/v1/tags/:tag_id/resources", get(tag_asset_resources))
        .route("/api/v1/tags/:tag_id", get(tag_asset_detail))
        .route("/api/v1/overrides", get(override_assets))
        .route("/api/v1/overrides/:override_id", get(override_asset_detail))
        .route("/api/v1/port-lists", get(port_list_assets))
        .route(
            "/api/v1/port-lists/:port_list_id",
            get(port_list_asset_detail),
        )
        .route("/api/v1/schedules", get(schedule_assets))
        .route("/api/v1/schedules/:schedule_id", get(schedule_asset_detail))
        .route("/api/v1/report-configs", get(report_config_assets))
        .route(
            "/api/v1/report-configs/:report_config_id",
            get(report_config_asset_detail),
        )
        .route("/api/v1/report-formats", get(report_format_assets))
        .route(
            "/api/v1/report-formats/:report_format_id",
            get(report_format_asset_detail),
        )
        .route("/api/v1/trashcan/summary", get(trashcan_summary))
        .route("/api/v1/reports", get(reports))
        .route("/api/v1/reports/:report_id", get(report_detail))
        .route("/api/v1/reports/:report_id/results", get(report_results))
        .route("/api/v1/reports/:report_id/hosts", get(report_hosts))
        .route("/api/v1/reports/:report_id/ports", get(report_ports))
        .route(
            "/api/v1/reports/:report_id/applications",
            get(report_applications),
        )
        .route(
            "/api/v1/reports/:report_id/operating-systems",
            get(report_operating_systems),
        )
        .route("/api/v1/reports/:report_id/cves", get(report_cves))
        .route(
            "/api/v1/reports/:report_id/tls-certificates",
            get(report_tls_certificates),
        )
        .route("/api/v1/reports/:report_id/errors", get(report_errors))
        .route("/api/v1/scopes", get(scopes))
        .route("/api/v1/scopes/:scope_id", get(scope_detail))
        .route("/api/v1/targets", get(targets))
        .route("/api/v1/targets/:target_id", get(target_detail))
        .route("/api/v1/tasks", get(tasks))
        .route("/api/v1/tasks/:task_id", get(task_detail))
        .route("/api/v1/scope-reports", get(scope_reports))
        .route(
            "/api/v1/scope-reports/:scope_report_id",
            get(scope_report_detail),
        )
        .route("/api/v1/reports/:report_id/metrics", get(report_metrics))
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/results",
            get(scope_report_results),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/hosts",
            get(scope_report_hosts),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/ports",
            get(scope_report_ports),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/applications",
            get(scope_report_applications),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/operating-systems",
            get(scope_report_operating_systems),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/cves",
            get(scope_report_cves),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/tls-certificates",
            get(scope_report_tls_certificates),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/errors",
            get(scope_report_errors),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/metrics",
            get(scope_report_metrics),
        )
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan",
            get(scope_report_retention_plan),
        )
        .with_state(state);

    let bind = env_string("TURBOVAS_API_BIND").unwrap_or_else(|| "0.0.0.0:9080".to_string());
    let internal_listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|_| ApiError::Config)?;
    let internal_addr: SocketAddr = internal_listener
        .local_addr()
        .map_err(|_| ApiError::Config)?;
    tracing::info!(addr = %internal_addr, "starting turbovas-api internal listener");

    if let Some((direct_bind, auth)) = direct_api {
        let direct_listener = tokio::net::TcpListener::bind(&direct_bind)
            .await
            .map_err(|_| ApiError::Config)?;
        let direct_addr: SocketAddr = direct_listener.local_addr().map_err(|_| ApiError::Config)?;
        tracing::info!(addr = %direct_addr, "starting turbovas-api direct authenticated listener");
        let direct_app = app.clone().layer(middleware::from_fn_with_state(
            auth,
            require_direct_api_auth,
        ));
        tokio::try_join!(
            axum::serve(internal_listener, app).with_graceful_shutdown(shutdown_signal()),
            axum::serve(direct_listener, direct_app).with_graceful_shutdown(shutdown_signal()),
        )
        .map(|_| ())
        .map_err(|_| ApiError::Config)
    } else {
        axum::serve(internal_listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|_| ApiError::Config)
    }
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn reports(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_SORT_FIELDS)?;
    let sql = raw_report_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(status) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(task_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(target_name, '')) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "raw report list")
            .await?;
    let items = rows.iter().map(report_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn host_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<HostAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, HOST_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, HOST_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH latest_ip AS (
             SELECT DISTINCT ON (host)
                    host, uuid, value, source_type, source_id, source_data
               FROM host_identifiers
              WHERE name = 'ip'
              ORDER BY host, modification_time DESC, id DESC
         ),
         latest_hostname AS (
             SELECT DISTINCT ON (host)
                    host, name, uuid, value, source_type, source_id, source_data
               FROM host_identifiers
              WHERE name IN ('hostname', 'DNS-via-TargetDefinition')
              ORDER BY host,
                       CASE WHEN name = 'hostname' THEN 0 ELSE 1 END,
                       modification_time DESC,
                       id DESC
         ),
         latest_best_os_cpe AS (
             SELECT DISTINCT ON (host) host, value
               FROM host_details
              WHERE name = 'best_os_cpe'
              ORDER BY host, id DESC
         ),
         latest_best_os_txt AS (
             SELECT DISTINCT ON (host) host, value
               FROM host_details
              WHERE name = 'best_os_txt'
              ORDER BY host, id DESC
         ),
         latest_severity AS (
             SELECT DISTINCT ON (host)
                    host,
                    round(CAST(severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities
              ORDER BY host, creation_time DESC, id DESC
         ),
         host_rows AS (
             SELECT h.uuid AS id,
                    coalesce(h.name, '') AS name,
                    coalesce(h.comment, '') AS comment,
                    nullif(lh.value, '') AS hostname,
                    nullif(li.value, '') AS ip,
                    nullif(lbo.value, '') AS best_os_cpe,
                    nullif(lbt.value, '') AS best_os_txt,
                    coalesce(ls.severity, 0)::double precision AS severity,
                    coalesce(h.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(h.modification_time, 0)::bigint AS modified_at_unix,
                    li.uuid AS ip_identifier_id,
                    li.source_type AS ip_source_type,
                    li.source_id AS ip_source_id,
                    left(coalesce(li.source_data, ''), 512) AS ip_source_data,
                    lh.name AS hostname_identifier_name,
                    lh.uuid AS hostname_identifier_id,
                    lh.source_type AS hostname_source_type,
                    lh.source_id AS hostname_source_id,
                    left(coalesce(lh.source_data, ''), 512) AS hostname_source_data
               FROM hosts h
               LEFT JOIN latest_ip li ON li.host = h.id
               LEFT JOIN latest_hostname lh ON lh.host = h.id
               LEFT JOIN latest_best_os_cpe lbo ON lbo.host = h.id
               LEFT JOIN latest_best_os_txt lbt ON lbt.host = h.id
               LEFT JOIN latest_severity ls ON ls.host = h.id
         ),
         filtered AS (
             SELECT * FROM host_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(ip, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(best_os_cpe, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(best_os_txt, '')) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "host asset list")
            .await?;
    let items = rows.iter().map(host_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn host_asset_detail(
    State(state): State<AppState>,
    Path(host_id): Path<String>,
) -> Result<Json<HostAssetDetail>, ApiError> {
    parse_uuid(&host_id)?;
    let host_id = host_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"WITH latest_ip AS (
                 SELECT DISTINCT ON (host)
                        host, uuid, value, source_type, source_id, source_data
                   FROM host_identifiers
                  WHERE name = 'ip'
                  ORDER BY host, modification_time DESC, id DESC
             ),
             latest_hostname AS (
                 SELECT DISTINCT ON (host)
                        host, name, uuid, value, source_type, source_id, source_data
                   FROM host_identifiers
                  WHERE name IN ('hostname', 'DNS-via-TargetDefinition')
                  ORDER BY host,
                           CASE WHEN name = 'hostname' THEN 0 ELSE 1 END,
                           modification_time DESC,
                           id DESC
             ),
             latest_best_os_cpe AS (
                 SELECT DISTINCT ON (host) host, value
                   FROM host_details
                  WHERE name = 'best_os_cpe'
                  ORDER BY host, id DESC
             ),
             latest_best_os_txt AS (
                 SELECT DISTINCT ON (host) host, value
                   FROM host_details
                  WHERE name = 'best_os_txt'
                  ORDER BY host, id DESC
             ),
             latest_severity AS (
                 SELECT DISTINCT ON (host)
                        host,
                        round(CAST(severity AS numeric), 1)::double precision AS severity
                   FROM host_max_severities
                  ORDER BY host, creation_time DESC, id DESC
             )
             SELECT h.uuid AS id,
                    coalesce(h.name, '') AS name,
                    coalesce(h.comment, '') AS comment,
                    nullif(lh.value, '') AS hostname,
                    nullif(li.value, '') AS ip,
                    nullif(lbo.value, '') AS best_os_cpe,
                    nullif(lbt.value, '') AS best_os_txt,
                    coalesce(ls.severity, 0)::double precision AS severity,
                    coalesce(h.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(h.modification_time, 0)::bigint AS modified_at_unix,
                    li.uuid AS ip_identifier_id,
                    li.source_type AS ip_source_type,
                    li.source_id AS ip_source_id,
                    li.source_data AS ip_source_data,
                    lh.name AS hostname_identifier_name,
                    lh.uuid AS hostname_identifier_id,
                    lh.source_type AS hostname_source_type,
                    lh.source_id AS hostname_source_id,
                    lh.source_data AS hostname_source_data
               FROM hosts h
               LEFT JOIN latest_ip li ON li.host = h.id
               LEFT JOIN latest_hostname lh ON lh.host = h.id
               LEFT JOIN latest_best_os_cpe lbo ON lbo.host = h.id
               LEFT JOIN latest_best_os_txt lbt ON lbt.host = h.id
               LEFT JOIN latest_severity ls ON ls.host = h.id
              WHERE h.uuid = $1
              LIMIT 1;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let identifier_rows = client
        .query(
            r#"SELECT hi.uuid AS id,
                    coalesce(hi.name, '') AS name,
                    coalesce(hi.value, '') AS value,
                    coalesce(hi.source_type, '') AS source_type,
                    coalesce(hi.source_id, '') AS source_id,
                    left(coalesce(hi.source_data, ''), 512) AS source_data,
                    (length(coalesce(hi.source_data, '')) > 512) AS source_data_truncated,
                    coalesce(hi.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(hi.modification_time, 0)::bigint AS modified_at_unix
               FROM hosts h
               JOIN host_identifiers hi ON hi.host = h.id
              WHERE h.uuid = $1
                AND hi.name IN ('ip', 'hostname', 'DNS-via-TargetDefinition', 'MAC', 'OS')
              ORDER BY CASE hi.name
                         WHEN 'ip' THEN 0
                         WHEN 'hostname' THEN 1
                         WHEN 'DNS-via-TargetDefinition' THEN 2
                         WHEN 'MAC' THEN 3
                         WHEN 'OS' THEN 4
                         ELSE 5
                       END,
                       hi.modification_time DESC NULLS LAST,
                       hi.id DESC;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset identifier detail query failed");
            ApiError::Database
        })?;
    let operating_system_rows = client
        .query(
            r#"SELECT ho.uuid AS id,
                    coalesce(ho.name, '') AS name,
                    coalesce(ho.comment, '') AS comment,
                    oss.uuid AS operating_system_id,
                    oss.name AS operating_system_name,
                    coalesce(cpe_title(oss.name), '') AS title,
                    coalesce(ho.source_type, '') AS source_type,
                    coalesce(ho.source_id, '') AS source_id,
                    left(coalesce(ho.source_data, ''), 512) AS source_data,
                    (length(coalesce(ho.source_data, '')) > 512) AS source_data_truncated,
                    coalesce(ho.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(ho.modification_time, 0)::bigint AS modified_at_unix
               FROM hosts h
               JOIN host_oss ho ON ho.host = h.id
               JOIN oss ON oss.id = ho.os
              WHERE h.uuid = $1
              ORDER BY ho.modification_time DESC NULLS LAST, ho.id DESC;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset operating-system detail query failed");
            ApiError::Database
        })?;
    let detail_rows = client
        .query(
            r#"WITH latest_details AS (
                 SELECT DISTINCT ON (hd.name)
                        coalesce(hd.name, '') AS name,
                        left(coalesce(hd.value, ''), 4096) AS value,
                        (length(coalesce(hd.value, '')) > 4096) AS value_truncated,
                        coalesce(hd.source_type, '') AS source_type,
                        coalesce(hd.source_id, '') AS source_id,
                        coalesce(hd.detail_source_type, '') AS detail_source_type,
                        coalesce(hd.detail_source_name, '') AS detail_source_name,
                        left(coalesce(hd.detail_source_description, ''), 1024) AS detail_source_description,
                        (length(coalesce(hd.detail_source_description, '')) > 1024) AS detail_source_description_truncated
                   FROM hosts h
                   JOIN host_details hd ON hd.host = h.id
                  WHERE h.uuid = $1
                    AND hd.name IN ('best_os_cpe', 'best_os_txt', 'traceroute')
                  ORDER BY hd.name, hd.id DESC
             )
             SELECT * FROM latest_details
              ORDER BY CASE name
                         WHEN 'best_os_cpe' THEN 0
                         WHEN 'best_os_txt' THEN 1
                         WHEN 'traceroute' THEN 2
                         ELSE 3
                       END;"#,
            &[&host_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host asset safe detail query failed");
            ApiError::Database
        })?;
    let user_tags = host_user_tags(&client, &host_id).await?;
    Ok(Json(HostAssetDetail {
        asset: host_asset_from_row(&row),
        identifiers: identifier_rows
            .iter()
            .map(host_asset_detail_identifier_from_row)
            .collect(),
        operating_systems: operating_system_rows
            .iter()
            .map(host_asset_operating_system_from_row)
            .collect(),
        details: detail_rows
            .iter()
            .map(host_asset_detail_item_from_row)
            .collect(),
        user_tags,
    }))
}

fn host_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN hosts ON hosts.id = tr.resource
        WHERE lower(hosts.uuid) = lower($1)
          AND tr.resource_type = 'host'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn host_user_tags(
    client: &tokio_postgres::Client,
    host_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(host_user_tags_sql(), &[&host_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "host user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn tls_certificate_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, TLS_CERTIFICATE_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TLS_CERTIFICATE_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH tls_rows AS (
             SELECT c.uuid AS id,
                    coalesce(nullif(c.subject_dn, ''), c.uuid) AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.subject_dn, '') AS subject_dn,
                    coalesce(c.issuer_dn, '') AS issuer_dn,
                    coalesce(c.serial, '') AS serial,
                    coalesce(c.md5_fingerprint, '') AS md5_fingerprint,
                    coalesce(c.sha256_fingerprint, '') AS sha256_fingerprint,
                    coalesce(c.activation_time, 0)::bigint AS activation_time_unix,
                    coalesce(c.expiration_time, 0)::bigint AS expiration_time_unix,
                    coalesce(max(src.timestamp), 0)::bigint AS last_seen_unix,
                    count(DISTINCT lower(loc.host_ip))::bigint AS source_host_count,
                    count(DISTINCT loc.port)::bigint AS source_port_count,
                    count(DISTINCT src.uuid)::bigint AS source_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM tls_certificates c
               LEFT JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
              GROUP BY c.id, c.uuid, c.subject_dn, c.comment, c.issuer_dn,
                       c.serial, c.md5_fingerprint, c.sha256_fingerprint,
                       c.activation_time, c.expiration_time,
                       c.creation_time, c.modification_time
         ),
         filtered AS (
             SELECT * FROM tls_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(subject_dn) LIKE '%' || lower($1) || '%'
                     OR lower(issuer_dn) LIKE '%' || lower($1) || '%'
                     OR lower(serial) LIKE '%' || lower($1) || '%'
                     OR lower(md5_fingerprint) LIKE '%' || lower($1) || '%'
                     OR lower(sha256_fingerprint) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, subject_dn ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tls_certificate_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn tls_certificate_asset_detail(
    State(state): State<AppState>,
    Path(certificate_id): Path<String>,
) -> Result<Json<TlsCertificateAssetDetail>, ApiError> {
    parse_uuid(&certificate_id)?;
    let certificate_id = certificate_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.uuid AS id,
                    coalesce(nullif(c.subject_dn, ''), c.uuid) AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.subject_dn, '') AS subject_dn,
                    coalesce(c.issuer_dn, '') AS issuer_dn,
                    coalesce(c.serial, '') AS serial,
                    coalesce(c.md5_fingerprint, '') AS md5_fingerprint,
                    coalesce(c.sha256_fingerprint, '') AS sha256_fingerprint,
                    coalesce(c.activation_time, 0)::bigint AS activation_time_unix,
                    coalesce(c.expiration_time, 0)::bigint AS expiration_time_unix,
                    CAST (((coalesce(c.expiration_time, 0) >= m_now()
                             OR coalesce(c.expiration_time, 0) = -1)
                            AND (coalesce(c.activation_time, 0) <= m_now()
                                 OR coalesce(c.activation_time, 0) = -1)) AS integer) AS valid_int,
                    coalesce(c.trust, 0)::integer AS trust_int,
                    (CASE WHEN (coalesce(c.activation_time, 0) = -1)
                                OR (coalesce(c.expiration_time, 0) = 1)
                          THEN 'unknown'
                          WHEN (coalesce(c.expiration_time, 0) < m_now()
                                AND coalesce(c.expiration_time, 0) != 0)
                          THEN 'expired'
                          WHEN (coalesce(c.activation_time, 0) > m_now())
                          THEN 'inactive'
                          ELSE 'valid' END) AS time_status,
                    coalesce(max(src.timestamp), 0)::bigint AS last_seen_unix,
                    count(DISTINCT lower(loc.host_ip))::bigint AS source_host_count,
                    count(DISTINCT loc.port)::bigint AS source_port_count,
                    count(DISTINCT src.uuid)::bigint AS source_count,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM tls_certificates c
               LEFT JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
              WHERE c.uuid = $1
              GROUP BY c.id, c.uuid, c.subject_dn, c.comment, c.issuer_dn,
                       c.serial, c.md5_fingerprint, c.sha256_fingerprint,
                       c.activation_time, c.expiration_time,
                       c.creation_time, c.modification_time
              LIMIT 1;"#,
            &[&certificate_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let source_rows = client
        .query(
            r#"SELECT src.uuid AS id,
                    coalesce(src.timestamp, 0)::bigint AS timestamp_unix,
                    coalesce(src.tls_versions, '') AS tls_versions,
                    loc.uuid AS location_id,
                    coalesce(loc.host_ip, '') AS location_host_ip,
                    coalesce(loc.port, '') AS location_port,
                    host_asset.uuid AS host_asset_id,
                    origin.uuid AS origin_uuid,
                    coalesce(origin.origin_type, '') AS origin_type,
                    coalesce(origin.origin_id, '') AS origin_resource_id,
                    coalesce(origin.origin_data, '') AS origin_data
               FROM tls_certificates c
               JOIN tls_certificate_sources src ON src.tls_certificate = c.id
               LEFT JOIN tls_certificate_locations loc ON loc.id = src.location
               LEFT JOIN tls_certificate_origins origin ON origin.id = src.origin
               LEFT JOIN LATERAL (
                    SELECT h.uuid
                      FROM host_identifiers hi
                      JOIN hosts h ON h.id = hi.host
                     WHERE hi.name = 'ip'
                       AND hi.value = loc.host_ip
                       AND hi.source_id = origin.origin_id
                     ORDER BY hi.modification_time DESC NULLS LAST, hi.id DESC
                     LIMIT 1
               ) host_asset ON true
              WHERE c.uuid = $1
              ORDER BY src.timestamp DESC NULLS LAST, src.uuid ASC;"#,
            &[&certificate_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate asset source query failed");
            ApiError::Database
        })?;
    let user_tags = tls_certificate_user_tags(&client, &certificate_id).await?;
    Ok(Json(TlsCertificateAssetDetail {
        asset: tls_certificate_asset_from_row(&row),
        sources: source_rows
            .iter()
            .map(tls_certificate_source_from_row)
            .collect(),
        user_tags,
    }))
}

fn tls_certificate_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN tls_certificates ON tls_certificates.id = tr.resource
        WHERE lower(tls_certificates.uuid) = lower($1)
          AND tr.resource_type = 'tls_certificate'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn tls_certificate_user_tags(
    client: &tokio_postgres::Client,
    certificate_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(tls_certificate_user_tags_sql(), &[&certificate_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "TLS certificate user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn scanner_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScannerAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCANNER_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCANNER_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH scanner_rows AS (
             SELECT s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.host, '') AS host,
                    coalesce(s.port, 0)::bigint AS port,
                    coalesce(s.type, 0)::bigint AS scanner_type,
                    nullif(c.uuid, '') AS credential_id,
                    nullif(c.name, '') AS credential_name,
                    nullif(s.relay_host, '') AS relay_host,
                    coalesce(s.relay_port, 0)::bigint AS relay_port,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix
               FROM scanners s
               LEFT JOIN credentials c ON c.id = s.credential
         ),
         filtered AS (
             SELECT * FROM scanner_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(host) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(credential_name, '')) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(relay_host, '')) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(scanner_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scanner_asset_detail(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let scanner_id = parse_uuid(&scanner_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT s.uuid AS id,
                      coalesce(s.name, '') AS name,
                      coalesce(s.comment, '') AS comment,
                      coalesce(s.host, '') AS host,
                      coalesce(s.port, 0)::bigint AS port,
                      coalesce(s.type, 0)::bigint AS scanner_type,
                      nullif(c.uuid, '') AS credential_id,
                      nullif(c.name, '') AS credential_name,
                      nullif(s.relay_host, '') AS relay_host,
                      coalesce(s.relay_port, 0)::bigint AS relay_port,
                      coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(s.modification_time, 0)::bigint AS modified_at_unix
                 FROM scanners s
            LEFT JOIN credentials c ON c.id = s.credential
                WHERE s.uuid = $1
                LIMIT 1;"#,
            &[&scanner_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let tasks = scanner_task_references(&client, &scanner_id).await?;
    let user_tags = scanner_user_tags(&client, &scanner_id).await?;
    Ok(Json(ScannerAssetDetail {
        asset: scanner_asset_from_row(&row),
        tasks,
        user_tags,
    }))
}

fn scanner_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM scanners s
         JOIN tasks t ON t.scanner = s.id
        WHERE lower(s.uuid) = lower($1)
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scanner_task_references(
    client: &tokio_postgres::Client,
    scanner_id: &str,
) -> Result<Vec<ScannerTaskReference>, ApiError> {
    let rows = client
        .query(scanner_task_references_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ScannerTaskReference {
            id: row.get("id"),
            name: row.get("name"),
            usage_type: row.get("usage_type"),
        })
        .collect())
}

fn scanner_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN scanners ON scanners.id = tr.resource
        WHERE lower(scanners.uuid) = lower($1)
          AND tr.resource_type = 'scanner'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scanner_user_tags(
    client: &tokio_postgres::Client,
    scanner_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scanner_user_tags_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

fn scan_config_asset_from_row(row: &Row) -> ScanConfigAssetItem {
    let family_count = row.get("family_count");
    let families_growing = row.get("families_growing");
    let nvt_count = row.get("nvt_count");
    let nvts_growing = row.get("nvts_growing");

    ScanConfigAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: ScanConfigOwner {
            name: row.get("owner_name"),
        },
        family_count,
        families_growing,
        nvt_count,
        nvts_growing,
        families: ScanConfigTrendCount {
            total: family_count,
            trend: families_growing,
        },
        nvts: ScanConfigTrendCount {
            total: nvt_count,
            trend: nvts_growing,
        },
        predefined: row.get::<_, i32>("predefined_int") != 0,
        deprecated: row.get::<_, i32>("deprecated_int") != 0,
        writable: row.get::<_, i32>("predefined_int") == 0,
        in_use: row.get::<_, i32>("in_use_int") != 0,
        orphan: false,
        trash: false,
        usage_type: row.get("usage_type"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

async fn scan_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScanConfigAssetItem>>, ApiError> {
    let predefined_filter = query.predefined.clone().unwrap_or_default();
    if !matches!(predefined_filter.as_str(), "" | "0" | "1") {
        return Err(ApiError::BadRequest("invalid predefined filter".into()));
    }
    let params = normalize_collection_query(query, SCAN_CONFIG_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCAN_CONFIG_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH scan_config_rows AS (
             SELECT c.id AS internal_id,
                    c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.family_count, 0)::bigint AS family_count,
                    coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                    coalesce(c.families_growing, 0)::integer AS families_growing,
                    coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                    coalesce(c.predefined, 0)::integer AS predefined_int,
                    coalesce(c.usage_type, 'scan') AS usage_type,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM tasks t
                        WHERE t.config = c.id
                          AND t.config_location = 0
                          AND t.hidden = 0
                    ) THEN 1 ELSE 0 END AS in_use_int,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM deprecated_feed_data d
                        WHERE d.type = 'config' AND d.uuid = c.uuid
                    ) THEN 1 ELSE 0 END AS deprecated_int,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM configs c
          LEFT JOIN users u ON u.id = c.owner
              WHERE coalesce(c.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM scan_config_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND predefined_int = 1)
                     OR ($4 = '0' AND predefined_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &predefined_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(scan_config_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scan_config_asset_detail(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    parse_uuid(&scan_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.id AS internal_id,
                      c.uuid AS id,
                      coalesce(c.name, '') AS name,
                      coalesce(c.comment, '') AS comment,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(c.family_count, 0)::bigint AS family_count,
                      coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                      coalesce(c.families_growing, 0)::integer AS families_growing,
                      coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                      coalesce(c.predefined, 0)::integer AS predefined_int,
                      coalesce(c.usage_type, 'scan') AS usage_type,
                      CASE WHEN EXISTS (
                         SELECT 1 FROM tasks t
                          WHERE t.config = c.id
                            AND t.config_location = 0
                            AND t.hidden = 0
                      ) THEN 1 ELSE 0 END AS in_use_int,
                      CASE WHEN EXISTS (
                         SELECT 1 FROM deprecated_feed_data d
                          WHERE d.type = 'config' AND d.uuid = c.uuid
                      ) THEN 1 ELSE 0 END AS deprecated_int,
                      coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                 FROM configs c
            LEFT JOIN users u ON u.id = c.owner
                WHERE c.uuid = $1
                  AND coalesce(c.usage_type, 'scan') = 'scan'
                LIMIT 1;"#,
            &[&scan_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    let tasks = scan_config_task_references(&client, &scan_config_id).await?;
    let user_tags = scan_config_user_tags(&client, &scan_config_id).await?;
    Ok(Json(ScanConfigAssetDetail {
        asset: scan_config_asset_from_row(&row),
        tasks,
        user_tags,
    }))
}

fn scan_config_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM configs c
         JOIN tasks t ON t.config = c.id
        WHERE lower(c.uuid) = lower($1)
          AND t.config_location = 0
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scan_config_task_references(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ScanConfigTaskReference>, ApiError> {
    let rows = client
        .query(scan_config_task_references_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ScanConfigTaskReference {
            id: row.get("id"),
            name: row.get("name"),
            usage_type: row.get("usage_type"),
        })
        .collect())
}

fn scan_config_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN configs c ON c.id = tr.resource
        WHERE lower(c.uuid) = lower($1)
          AND tr.resource_type = 'config'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scan_config_user_tags(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scan_config_user_tags_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn scan_config_asset_families(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigFamiliesPayload>, ApiError> {
    parse_uuid(&scan_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            r#"WITH config_row AS (
                    SELECT c.uuid AS scan_config_id,
                           coalesce(c.nvt_selector, '') AS nvt_selector,
                           coalesce(c.family_count, 0)::bigint AS family_count,
                           coalesce(c.families_growing, 0)::integer AS families_growing
                      FROM configs c
                     WHERE c.uuid = $1
                       AND coalesce(c.usage_type, 'scan') = 'scan'
                     LIMIT 1
                ),
                all_mode_families AS (
                    SELECT DISTINCT n.family
                      FROM nvts n
                      JOIN config_row c ON c.families_growing <> 0
                     WHERE n.family != 'Credentials'
                    EXCEPT
                    SELECT DISTINCT ns.family
                      FROM nvt_selectors ns
                      JOIN config_row c ON c.families_growing <> 0
                     WHERE ns.name = c.nvt_selector
                       AND ns.type = 1
                       AND ns.exclude = 1
                    UNION
                    SELECT DISTINCT ns.family
                      FROM nvt_selectors ns
                      JOIN config_row c ON c.families_growing <> 0
                     WHERE ns.name = c.nvt_selector
                       AND ns.type = 2
                       AND ns.exclude = 0
                ),
                static_mode_families AS (
                    SELECT DISTINCT ns.family
                      FROM nvt_selectors ns
                      JOIN config_row c ON c.families_growing = 0
                     WHERE ns.name = c.nvt_selector
                       AND ns.type IN (1, 2)
                       AND ns.family != 'Credentials'
                ),
                family_rows AS (
                    SELECT family FROM all_mode_families
                    UNION
                    SELECT family FROM static_mode_families
                ),
                family_state AS (
                    SELECT c.scan_config_id,
                           c.family_count,
                           c.families_growing,
                           f.family AS name,
                           CASE
                             WHEN c.families_growing <> 0 THEN
                               CASE WHEN EXISTS (
                                      SELECT 1 FROM nvt_selectors ns
                                       WHERE ns.name = c.nvt_selector
                                         AND ns.type = 1
                                         AND ns.family_or_nvt = f.family
                                         AND ns.exclude = 1
                                    ) THEN 0 ELSE 1 END
                             ELSE
                               CASE WHEN EXISTS (
                                      SELECT 1 FROM nvt_selectors ns
                                       WHERE ns.name = c.nvt_selector
                                         AND ns.type = 1
                                         AND ns.family_or_nvt = f.family
                                         AND ns.exclude = 0
                                    ) THEN 1 ELSE 0 END
                           END AS growing,
                           (SELECT count(*)::bigint
                              FROM nvts n
                             WHERE n.family = f.family) AS max_nvt_count
                      FROM config_row c
                      JOIN family_rows f ON f.family IS NOT NULL AND f.family != ''
                )
                SELECT scan_config_id,
                       family_count,
                       families_growing,
                       name,
                       growing::integer AS growing,
                       CASE
                         WHEN growing <> 0 THEN
                           max_nvt_count -
                           (SELECT count(*)::bigint
                              FROM nvt_selectors ns
                              JOIN config_row c ON true
                             WHERE ns.name = c.nvt_selector
                               AND ns.exclude = 1
                               AND ns.type = 2
                               AND ns.family = family_state.name)
                         ELSE
                           (SELECT count(*)::bigint
                              FROM nvt_selectors ns
                              JOIN config_row c ON true
                             WHERE ns.name = c.nvt_selector
                               AND ns.exclude = 0
                               AND ns.type = 2
                               AND ns.family = family_state.name)
                       END AS nvt_count,
                       max_nvt_count
                  FROM family_state
                 ORDER BY lower(name), name;"#,
            &[&scan_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config family query failed");
            ApiError::Database
        })?;

    if rows.is_empty() {
        let exists = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM configs WHERE uuid = $1 AND coalesce(usage_type, 'scan') = 'scan');",
                &[&scan_config_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "scan config family existence query failed");
                ApiError::Database
            })?
            .get::<_, bool>(0);
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    let (family_count, families_growing) = rows
        .first()
        .map(|row| {
            (
                row.get::<_, i64>("family_count"),
                row.get::<_, i32>("families_growing"),
            )
        })
        .unwrap_or((0, 0));
    let families = rows
        .iter()
        .map(|row| ScanConfigFamilyItem {
            name: row.get("name"),
            nvt_count: row.get("nvt_count"),
            max_nvt_count: row.get("max_nvt_count"),
            growing: row.get("growing"),
        })
        .collect();

    Ok(Json(ScanConfigFamiliesPayload {
        scan_config_id,
        family_count,
        families_growing,
        families,
    }))
}

async fn filter_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<FilterAssetItem>>, ApiError> {
    let filter_type = query
        .filter_type
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    let params = normalize_collection_query(query, FILTER_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, FILTER_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH filter_rows AS (
             SELECT f.uuid AS id,
                    coalesce(f.name, '') AS name,
                    coalesce(f.comment, '') AS comment,
                    coalesce(f.type, '') AS filter_type,
                    coalesce(f.term, '') AS term,
                    coalesce(f.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(f.modification_time, 0)::bigint AS modified_at_unix,
                    (
                      SELECT count(DISTINCT alert_id)::bigint
                        FROM (
                          SELECT a.id AS alert_id
                            FROM alerts a
                           WHERE a.filter = f.id
                          UNION
                          SELECT acd.alert AS alert_id
                            FROM alert_condition_data acd
                           WHERE acd.name = 'filter_id'
                             AND acd.data = f.uuid
                        ) alert_refs
                    ) AS alert_count
               FROM filters f
         ),
         filtered AS (
             SELECT * FROM filter_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(filter_type) LIKE '%' || lower($1) || '%'
                     OR lower(term) LIKE '%' || lower($1) || '%')
                AND ($2 = '' OR lower(filter_type) = lower($2))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $3 OFFSET $4;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &filter_type,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| filter_asset_from_row(row, Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn filter_asset_detail(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    parse_uuid(&filter_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT f.id AS internal_id,
                      f.uuid AS id,
                      coalesce(f.name, '') AS name,
                      coalesce(f.comment, '') AS comment,
                      coalesce(f.type, '') AS filter_type,
                      coalesce(f.term, '') AS term,
                      coalesce(f.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(f.modification_time, 0)::bigint AS modified_at_unix,
                      (
                        SELECT count(DISTINCT alert_id)::bigint
                          FROM (
                            SELECT a.id AS alert_id
                              FROM alerts a
                             WHERE a.filter = f.id
                            UNION
                            SELECT acd.alert AS alert_id
                              FROM alert_condition_data acd
                             WHERE acd.name = 'filter_id'
                               AND acd.data = f.uuid
                          ) alert_refs
                      ) AS alert_count
                 FROM filters f
                WHERE f.uuid = $1
                LIMIT 1;"#,
            &[&filter_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let alerts = client
        .query(
            r#"SELECT DISTINCT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alerts a
                WHERE a.filter = $1
                UNION
               SELECT DISTINCT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alert_condition_data acd
                 JOIN alerts a ON a.id = acd.alert
                WHERE acd.name = 'filter_id'
                  AND acd.data = $2
                ORDER BY name ASC, id ASC;"#,
            &[&row.get::<_, i32>("internal_id"), &filter_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "filter alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(filter_alert_from_row)
        .collect();
    Ok(Json(filter_asset_from_row(&row, alerts)))
}

fn alert_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"WITH alert_rows AS (
             SELECT a.uuid AS id,
                    coalesce(a.name, '') AS name,
                    coalesce(a.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(a.active, 0)::integer AS active_int,
                    CASE coalesce(a.event, 0)::integer
                      WHEN 1 THEN 'Task run status changed'
                      WHEN 2 THEN 'New SecInfo arrived'
                      WHEN 3 THEN 'Updated SecInfo arrived'
                      ELSE 'Internal Error'
                    END AS event_type,
                    CASE coalesce(a.condition, 0)::integer
                      WHEN 1 THEN 'Always'
                      WHEN 2 THEN 'Severity at least'
                      WHEN 3 THEN 'Severity changed'
                      WHEN 4 THEN 'Filter count at least'
                      WHEN 5 THEN 'Filter count changed'
                      ELSE 'Internal Error'
                    END AS condition_type,
                    CASE coalesce(a.method, 0)::integer
                      WHEN 1 THEN 'Email'
                      WHEN 2 THEN 'HTTP Get'
                      WHEN 3 THEN 'Sourcefire Connector'
                      WHEN 4 THEN 'Start Task'
                      WHEN 5 THEN 'Syslog'
                      WHEN 6 THEN 'verinice Connector'
                      WHEN 7 THEN 'Send'
                      WHEN 8 THEN 'SCP'
                      WHEN 9 THEN 'SNMP'
                      WHEN 10 THEN 'SMB'
                      WHEN 11 THEN 'TippingPoint SMS'
                      WHEN 12 THEN 'Alemba vFire'
                      ELSE 'Internal Error'
                    END AS method_type,
                    f.uuid AS filter_id,
                    coalesce(f.name, '') AS filter_name,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM task_alerts ta
                        JOIN tasks t ON t.id = ta.task
                       WHERE ta.alert = a.id
                         AND coalesce(t.hidden, 0) = 0
                    ), 0)::bigint AS task_count,
                    coalesce(a.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(a.modification_time, 0)::bigint AS modified_at_unix
               FROM alerts a
          LEFT JOIN users u ON u.id = a.owner
          LEFT JOIN filters f ON f.id = a.filter
         ),
         filtered AS (
             SELECT * FROM alert_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(event_type) LIKE '%' || lower($1) || '%'
                     OR lower(condition_type) LIKE '%' || lower($1) || '%'
                     OR lower(method_type) LIKE '%' || lower($1) || '%'
                     OR lower(filter_name) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

async fn alert_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<AlertAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, ALERT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, ALERT_SORT_FIELDS)?;
    let sql = alert_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "alert asset list")
            .await?;
    let items = rows.iter().map(alert_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

fn alert_asset_detail_sql() -> &'static str {
    r#"SELECT a.uuid AS id,
              coalesce(a.name, '') AS name,
              coalesce(a.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              coalesce(a.active, 0)::integer AS active_int,
              CASE coalesce(a.event, 0)::integer
                WHEN 1 THEN 'Task run status changed'
                WHEN 2 THEN 'New SecInfo arrived'
                WHEN 3 THEN 'Updated SecInfo arrived'
                ELSE 'Internal Error'
              END AS event_type,
              CASE coalesce(a.condition, 0)::integer
                WHEN 1 THEN 'Always'
                WHEN 2 THEN 'Severity at least'
                WHEN 3 THEN 'Severity changed'
                WHEN 4 THEN 'Filter count at least'
                WHEN 5 THEN 'Filter count changed'
                ELSE 'Internal Error'
              END AS condition_type,
              CASE coalesce(a.method, 0)::integer
                WHEN 1 THEN 'Email'
                WHEN 2 THEN 'HTTP Get'
                WHEN 3 THEN 'Sourcefire Connector'
                WHEN 4 THEN 'Start Task'
                WHEN 5 THEN 'Syslog'
                WHEN 6 THEN 'verinice Connector'
                WHEN 7 THEN 'Send'
                WHEN 8 THEN 'SCP'
                WHEN 9 THEN 'SNMP'
                WHEN 10 THEN 'SMB'
                WHEN 11 THEN 'TippingPoint SMS'
                WHEN 12 THEN 'Alemba vFire'
                ELSE 'Internal Error'
              END AS method_type,
              f.uuid AS filter_id,
              coalesce(f.name, '') AS filter_name,
              coalesce((
                SELECT count(*)::bigint
                  FROM task_alerts ta
                  JOIN tasks t ON t.id = ta.task
                 WHERE ta.alert = a.id
                   AND coalesce(t.hidden, 0) = 0
              ), 0)::bigint AS task_count,
              coalesce(a.creation_time, 0)::bigint AS created_at_unix,
              coalesce(a.modification_time, 0)::bigint AS modified_at_unix
         FROM alerts a
    LEFT JOIN users u ON u.id = a.owner
    LEFT JOIN filters f ON f.id = a.filter
        WHERE a.uuid = $1
        LIMIT 1;"#
}

fn alert_asset_tasks_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name
         FROM alerts a
         JOIN task_alerts ta ON ta.alert = a.id
         JOIN tasks t ON t.id = ta.task
        WHERE a.uuid = $1
          AND coalesce(t.hidden, 0) = 0
        ORDER BY name ASC, id ASC;"#
}

async fn alert_asset_detail(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let alert_id = parse_uuid(&alert_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(alert_asset_detail_sql(), &[&alert_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let task_rows = client
        .query(alert_asset_tasks_sql(), &[&alert_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "alert asset task reference query failed");
            ApiError::Database
        })?;
    let tasks = task_rows
        .iter()
        .map(|row| AlertReference {
            id: row.get("id"),
            name: row.get("name"),
        })
        .collect();
    let mut item = alert_asset_from_row(&row);
    item.tasks = tasks;
    Ok(Json(item))
}

async fn tag_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TagAssetItem>>, ApiError> {
    let active_filter = query.active.clone().unwrap_or_default();
    let resource_type_filter = query.resource_type.clone().unwrap_or_default();
    let value_filter = query.value.clone().unwrap_or_default();
    let params = normalize_collection_query(query, TAG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TAG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH tag_rows AS (
             SELECT t.uuid AS id,
                    coalesce(t.name, '') AS name,
                    coalesce(t.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(t.resource_type, '') AS resource_type,
                    coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
                    coalesce(t.active, 0)::integer AS active_int,
                    coalesce(t.value, '') AS value,
                    coalesce(t.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(t.modification_time, 0)::bigint AS modified_at_unix
               FROM tags t
          LEFT JOIN users u ON u.id = t.owner
         ),
         filtered AS (
             SELECT * FROM tag_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(resource_type) LIKE '%' || lower($1) || '%'
                     OR lower(value) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND active_int = 1)
                     OR ($4 = '0' AND active_int = 0))
                AND ($5 = '' OR lower(resource_type) = lower($5))
                AND ($6 = '' OR lower(value) LIKE '%' || lower($6) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &active_filter,
                &resource_type_filter,
                &value_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tag_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn tag_asset_detail(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
) -> Result<Json<TagAssetItem>, ApiError> {
    parse_uuid(&tag_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.comment, '') AS comment,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(t.resource_type, '') AS resource_type,
                      coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
                      coalesce(t.active, 0)::integer AS active_int,
                      coalesce(t.value, '') AS value,
                      coalesce(t.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(t.modification_time, 0)::bigint AS modified_at_unix
                 FROM tags t
            LEFT JOIN users u ON u.id = t.owner
                WHERE t.uuid = $1
                LIMIT 1;"#,
            &[&tag_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(tag_asset_from_row(&row)))
}

async fn tag_asset_resources(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<TagResourceCollection>, ApiError> {
    let tag_id = parse_uuid(&tag_id)?.to_string();
    let params = normalize_collection_query(query, TAG_RESOURCE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TAG_RESOURCE_SORT_FIELDS)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tag_row = client
        .query_opt(
            r#"SELECT id, uuid, coalesce(resource_type, '') AS resource_type
                 FROM tags
                WHERE uuid = $1
                LIMIT 1;"#,
            &[&tag_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag lookup for resource expansion failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let tag_internal_id: i32 = tag_row.get("id");
    let resource_type = normalize_tag_resource_type(tag_row.get("resource_type"));
    let sql = tag_resource_collection_sql(&resource_type, &sort_sql)?;
    let rows = client
        .query(
            &sql,
            &[
                &tag_internal_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, %resource_type, "tag resource query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tag_resource_from_row).collect();
    Ok(Json(TagResourceCollection {
        tag_id,
        resource_type,
        page: params.page_info(total),
        items,
    }))
}

async fn tag_resource_names(
    State(state): State<AppState>,
    Path(resource_type): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TagResourceItem>>, ApiError> {
    let resource_type = normalize_tag_resource_type(resource_type);
    let params = normalize_collection_query(query, TAG_RESOURCE_DEFAULT_SORT)?;
    if params.page_size > TAG_RESOURCE_NAME_MAX_PAGE_SIZE {
        return Err(ApiError::BadRequest(format!(
            "page_size must be between 1 and {TAG_RESOURCE_NAME_MAX_PAGE_SIZE}"
        )));
    }
    let sort_sql = sort_clause(&params.sort, TAG_RESOURCE_SORT_FIELDS)?;
    let (filter, exact_id_filter) = tag_resource_name_filter(&params.filter);
    let sql = tag_resource_name_collection_sql(&resource_type, &sort_sql)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[&filter, &exact_id_filter, &params.page_size, &params.offset],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, %resource_type, "tag resource-name query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tag_resource_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn override_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OverrideAssetItem>>, ApiError> {
    let active_filter = query.active.clone().unwrap_or_default();
    let text_filter = query.text.clone().unwrap_or_default();
    let task_name_filter = query.task_name.clone().unwrap_or_default();
    let params = normalize_collection_query(query, OVERRIDE_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, OVERRIDE_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH override_rows AS (
             SELECT o.uuid AS id,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(o.nvt, '') AS nvt_id,
                    CASE
                      WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                      ELSE coalesce(n.name, o.nvt, '')
                    END AS nvt_name,
                    CASE
                      WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                      ELSE 'nvt'
                    END AS nvt_type,
                    coalesce(o.text, '') AS text,
                    coalesce(o.hosts, '') AS hosts,
                    coalesce(o.port, '') AS port,
                    o.severity::double precision AS severity,
                    coalesce(o.severity, -9999)::double precision AS severity_sort,
                    o.new_severity::double precision AS new_severity,
                    coalesce(o.new_severity, -9999)::double precision AS new_severity_sort,
                    coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(o.end_time, 0)::bigint AS end_time_unix,
                    CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int,
                    t.uuid AS task_id,
                    coalesce(t.name, '') AS task_name,
                    r.uuid AS result_id,
                    coalesce(r.uuid, '') AS result_name,
                    CASE
                      WHEN ((coalesce(o.task, 0) <> 0 AND t.uuid IS NULL)
                            OR (coalesce(o.result, 0) <> 0 AND r.uuid IS NULL))
                      THEN 1 ELSE 0
                    END AS orphan_int
               FROM overrides o
          LEFT JOIN users u ON u.id = o.owner
          LEFT JOIN nvts n ON n.oid = o.nvt
          LEFT JOIN tasks t ON t.id = o.task
          LEFT JOIN results r ON r.id = o.result
         ),
         filtered AS (
             SELECT * FROM override_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_id) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_name) LIKE '%' || lower($1) || '%'
                     OR lower(text) LIKE '%' || lower($1) || '%'
                     OR lower(hosts) LIKE '%' || lower($1) || '%'
                     OR lower(port) LIKE '%' || lower($1) || '%'
                     OR lower(task_name) LIKE '%' || lower($1) || '%')
                AND ($4 = '' OR lower(text) LIKE '%' || lower($4) || '%')
                AND ($5 = '' OR lower(task_name) LIKE '%' || lower($5) || '%')
                AND ($6 = ''
                     OR ($6 = '1' AND active_int = 1)
                     OR ($6 = '0' AND active_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, text ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &text_filter,
                &task_name_filter,
                &active_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "override asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(override_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn override_asset_detail(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    parse_uuid(&override_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT o.uuid AS id,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(o.nvt, '') AS nvt_id,
                      CASE
                        WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                        ELSE coalesce(n.name, o.nvt, '')
                      END AS nvt_name,
                      CASE
                        WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                        ELSE 'nvt'
                      END AS nvt_type,
                      coalesce(o.text, '') AS text,
                      coalesce(o.hosts, '') AS hosts,
                      coalesce(o.port, '') AS port,
                      o.severity::double precision AS severity,
                      o.new_severity::double precision AS new_severity,
                      coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce(o.end_time, 0)::bigint AS end_time_unix,
                      CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int,
                      t.uuid AS task_id,
                      coalesce(t.name, '') AS task_name,
                      r.uuid AS result_id,
                      coalesce(r.uuid, '') AS result_name,
                      CASE
                        WHEN ((coalesce(o.task, 0) <> 0 AND t.uuid IS NULL)
                              OR (coalesce(o.result, 0) <> 0 AND r.uuid IS NULL))
                        THEN 1 ELSE 0
                      END AS orphan_int
                 FROM overrides o
            LEFT JOIN users u ON u.id = o.owner
            LEFT JOIN nvts n ON n.oid = o.nvt
            LEFT JOIN tasks t ON t.id = o.task
            LEFT JOIN results r ON r.id = o.result
                WHERE o.uuid = $1
                LIMIT 1;"#,
            &[&override_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "override asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(override_asset_from_row(&row)))
}

async fn port_list_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortListAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, PORT_LIST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, PORT_LIST_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH port_list_rows AS (
             SELECT pl.id AS internal_id,
                    pl.uuid AS id,
                    coalesce(pl.name, '') AS name,
                    coalesce(pl.comment, '') AS comment,
                    coalesce(pl.predefined, 0)::integer AS predefined_int,
                    0::integer AS deprecated_int,
                    coalesce(pl.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(pl.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                    ), 0)::bigint AS port_count_all,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                         AND pr.type = 0
                    ), 0)::bigint AS port_count_tcp,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                         AND pr.type = 1
                    ), 0)::bigint AS port_count_udp
               FROM port_lists pl
         ),
         filtered AS (
             SELECT * FROM port_list_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| port_list_asset_from_row(row, Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn port_list_asset_detail(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    parse_uuid(&port_list_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT pl.id AS internal_id,
                      pl.uuid AS id,
                      coalesce(pl.name, '') AS name,
                      coalesce(pl.comment, '') AS comment,
                      coalesce(pl.predefined, 0)::integer AS predefined_int,
                      0::integer AS deprecated_int,
                      coalesce(pl.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(pl.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce((
                        SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                          FROM port_ranges pr
                         WHERE pr.port_list = pl.id
                      ), 0)::bigint AS port_count_all,
                      coalesce((
                        SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                          FROM port_ranges pr
                         WHERE pr.port_list = pl.id
                           AND pr.type = 0
                      ), 0)::bigint AS port_count_tcp,
                      coalesce((
                        SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                          FROM port_ranges pr
                         WHERE pr.port_list = pl.id
                           AND pr.type = 1
                      ), 0)::bigint AS port_count_udp
                 FROM port_lists pl
                WHERE pl.uuid = $1
                LIMIT 1;"#,
            &[&port_list_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let ranges = client
        .query(
            r#"SELECT pr.uuid AS id,
                      CASE WHEN pr.type = 1 THEN 'udp' ELSE 'tcp' END AS protocol,
                      coalesce(pr.start, 0)::bigint AS start,
                      coalesce(pr."end", pr.start, 0)::bigint AS "end",
                      coalesce(pr.comment, '') AS comment
                 FROM port_ranges pr
                WHERE pr.port_list = $1
                ORDER BY pr.type ASC, pr.start ASC, pr."end" ASC, pr.uuid ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list range query failed");
            ApiError::Database
        })?
        .iter()
        .map(port_range_from_row)
        .collect();
    let targets = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name
                 FROM targets t
                WHERE t.port_list = $1
                ORDER BY name ASC, id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list target backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(port_list_target_from_row)
        .collect();
    let user_tags = port_list_user_tags(&client, &port_list_id).await?;
    Ok(Json(PortListAssetDetail {
        asset: port_list_asset_from_row(&row, ranges, targets),
        user_tags,
    }))
}

fn port_list_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN port_lists pl ON pl.id = tr.resource
        WHERE lower(pl.uuid) = lower($1)
          AND tr.resource_type = 'port_list'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn port_list_user_tags(
    client: &tokio_postgres::Client,
    port_list_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(port_list_user_tags_sql(), &[&port_list_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn schedule_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScheduleAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCHEDULE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCHEDULE_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH schedule_rows AS (
             SELECT s.id AS internal_id,
                    s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.icalendar, '') AS icalendar,
                    coalesce(s.timezone, 'UTC') AS timezone,
                    coalesce(s.first_time, 0)::bigint AS first_run_unix,
                    coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                    coalesce(s.period, 0)::bigint AS period_seconds,
                    coalesce(s.duration, 0)::bigint AS duration_seconds,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM tasks t
                       WHERE t.schedule = s.id
                         AND t.hidden = 0
                    ), 0)::bigint AS task_count
               FROM schedules s
         ),
         filtered AS (
             SELECT * FROM schedule_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(timezone) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| schedule_asset_from_row(row, Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn schedule_asset_detail(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    parse_uuid(&schedule_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT s.id AS internal_id,
                      s.uuid AS id,
                      coalesce(s.name, '') AS name,
                      coalesce(s.comment, '') AS comment,
                      coalesce(s.icalendar, '') AS icalendar,
                      coalesce(s.timezone, 'UTC') AS timezone,
                      coalesce(s.first_time, 0)::bigint AS first_run_unix,
                      coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                      coalesce(s.period, 0)::bigint AS period_seconds,
                      coalesce(s.duration, 0)::bigint AS duration_seconds,
                      coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce((
                        SELECT count(*)::bigint
                          FROM tasks t
                         WHERE t.schedule = s.id
                           AND t.hidden = 0
                      ), 0)::bigint AS task_count
                 FROM schedules s
                WHERE s.uuid = $1
                LIMIT 1;"#,
            &[&schedule_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let tasks = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.usage_type, 'scan') AS usage_type
                 FROM tasks t
                WHERE t.schedule = $1
                  AND t.hidden = 0
                ORDER BY name ASC, id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule task backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(schedule_task_from_row)
        .collect();
    let user_tags = schedule_user_tags(&client, &schedule_id).await?;
    Ok(Json(ScheduleAssetDetail {
        asset: schedule_asset_from_row(&row, tasks),
        user_tags,
    }))
}

fn schedule_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN schedules s ON s.id = tr.resource
        WHERE lower(s.uuid) = lower($1)
          AND tr.resource_type = 'schedule'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn schedule_user_tags(
    client: &tokio_postgres::Client,
    schedule_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(schedule_user_tags_sql(), &[&schedule_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn report_format_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportFormatAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_FORMAT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_FORMAT_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH report_format_rows AS (
             SELECT rf.id AS internal_id,
                    rf.uuid AS id,
                    coalesce(rf.name, '') AS name,
                    coalesce(rf.summary, '') AS summary,
                    coalesce(rf.description, '') AS description,
                    coalesce(rf.extension, '') AS extension,
                    coalesce(rf.content_type, '') AS content_type,
                    coalesce(rf.report_type, '') AS report_type,
                    coalesce(rf.trust, 3)::integer AS trust_int,
                    coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                    coalesce(rf.flags & 1, 0)::integer AS active_int,
                    coalesce(rf.predefined, 0)::integer AS predefined_int,
                    (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                    (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                    coalesce((SELECT count(DISTINCT a.id)::bigint
                                FROM alerts a
                                JOIN alert_method_data amd ON amd.alert = a.id
                               WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                    coalesce((SELECT count(DISTINCT rc.id)::bigint
                                FROM report_configs rc
                               WHERE rc.report_format_id = rf.uuid), 0)::bigint AS report_config_count,
                    coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
               FROM report_formats rf
         ),
         filtered AS (
             SELECT * FROM report_format_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR lower(extension) LIKE '%' || lower($1) || '%'
                     OR lower(content_type) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| report_format_asset_from_row(row, Vec::new(), Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_format_asset_detail(
    State(state): State<AppState>,
    Path(report_format_id): Path<String>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    parse_uuid(&report_format_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT rf.id AS internal_id,
                      rf.uuid AS id,
                      coalesce(rf.name, '') AS name,
                      coalesce(rf.summary, '') AS summary,
                      coalesce(rf.description, '') AS description,
                      coalesce(rf.extension, '') AS extension,
                      coalesce(rf.content_type, '') AS content_type,
                      coalesce(rf.report_type, '') AS report_type,
                      coalesce(rf.trust, 3)::integer AS trust_int,
                      coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                      coalesce(rf.flags & 1, 0)::integer AS active_int,
                      coalesce(rf.predefined, 0)::integer AS predefined_int,
                      (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                      (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                      coalesce((SELECT count(DISTINCT a.id)::bigint
                                  FROM alerts a
                                  JOIN alert_method_data amd ON amd.alert = a.id
                                 WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                      coalesce((SELECT count(DISTINCT rc.id)::bigint
                                  FROM report_configs rc
                                 WHERE rc.report_format_id = rf.uuid), 0)::bigint AS report_config_count,
                      coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
                 FROM report_formats rf
                WHERE rf.uuid = $1
                LIMIT 1;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let alerts = client
        .query(
            r#"SELECT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alerts a
                 JOIN alert_method_data amd ON amd.alert = a.id
                WHERE amd.data = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let report_configs = client
        .query(
            r#"SELECT rc.uuid AS id,
                      coalesce(rc.name, '') AS name
                 FROM report_configs rc
                WHERE rc.report_format_id = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format config backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let mut params = Vec::new();
    for param_row in client
        .query(
            r#"SELECT rfp.id AS internal_id,
                      coalesce(rfp.name, '') AS name,
                      coalesce(rfp.type, 100)::integer AS type_int,
                      coalesce(rfp.value, '') AS value,
                      coalesce(rfp.fallback, '') AS fallback,
                      rfp.type_min AS min,
                      rfp.type_max AS max
                 FROM report_format_params rfp
                WHERE rfp.report_format = $1
                ORDER BY name ASC, internal_id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format params query failed");
            ApiError::Database
        })?
    {
        let param_id: i32 = param_row.get("internal_id");
        let options = client
            .query(
                r#"SELECT coalesce(value, '') AS value
                     FROM report_format_param_options
                    WHERE report_format_param = $1
                    ORDER BY value ASC;"#,
                &[&param_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report format param options query failed");
                ApiError::Database
            })?
            .iter()
            .map(report_format_param_option_from_row)
            .collect();
        params.push(report_format_param_from_row(&param_row, options));
    }

    Ok(Json(report_format_asset_from_row(
        &row,
        alerts,
        report_configs,
        params,
    )))
}

async fn report_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportConfigAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_CONFIG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_CONFIG_SORT_FIELDS)?;
    let sql = format!(
        r#"SELECT count(*) OVER()::bigint AS total,
                  rc.id::bigint AS internal_id,
                  rc.uuid AS id,
                  coalesce(rc.name, '') AS name,
                  coalesce(rc.comment, '') AS comment,
                  coalesce(u.name, '') AS owner_name,
                  coalesce(rc.report_format_id, '') AS report_format_id,
                  coalesce(rf.id, 0)::bigint AS report_format_rowid,
                  coalesce(rf.name, '') AS report_format_name,
                  CASE WHEN coalesce(rf.name, '') = '' THEN 1 ELSE 0 END AS orphan,
                  coalesce(rc.creation_time, 0)::bigint AS created_at_unix,
                  coalesce(rc.modification_time, 0)::bigint AS modified_at_unix
             FROM report_configs rc
        LEFT JOIN users u ON u.id = rc.owner
        LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id
            WHERE ($1 = ''
                   OR lower(rc.uuid) LIKE '%' || lower($1) || '%'
                   OR lower(rc.name) LIKE '%' || lower($1) || '%'
                   OR lower(rc.comment) LIKE '%' || lower($1) || '%'
                   OR lower(rf.name) LIKE '%' || lower($1) || '%')
         ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let mut items = Vec::new();
    for row in &rows {
        items.push(report_config_asset_from_row(&client, row).await?);
    }
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_config_asset_detail(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    parse_uuid(&report_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT rc.id::bigint AS internal_id,
                      rc.uuid AS id,
                      coalesce(rc.name, '') AS name,
                      coalesce(rc.comment, '') AS comment,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(rc.report_format_id, '') AS report_format_id,
                      coalesce(rf.id, 0)::bigint AS report_format_rowid,
                      coalesce(rf.name, '') AS report_format_name,
                      CASE WHEN coalesce(rf.name, '') = '' THEN 1 ELSE 0 END AS orphan,
                      coalesce(rc.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(rc.modification_time, 0)::bigint AS modified_at_unix
                 FROM report_configs rc
            LEFT JOIN users u ON u.id = rc.owner
            LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id
                WHERE rc.uuid = $1
                LIMIT 1;"#,
            &[&report_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(report_config_asset_from_row(&client, &row).await?))
}

async fn trashcan_summary(
    State(state): State<AppState>,
) -> Result<Json<TrashcanSummary>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            r#"SELECT resource_type, title, item_count
                 FROM (
                   SELECT 1 AS sort_order, 'alerts'::text AS resource_type, 'Alerts'::text AS title, count(*)::bigint AS item_count FROM alerts_trash
                   UNION ALL
                   SELECT 2 AS sort_order, 'scan_configs'::text AS resource_type, 'Scan Configs'::text AS title, count(*)::bigint AS item_count FROM configs_trash
                   UNION ALL
                   SELECT 3 AS sort_order, 'credentials'::text AS resource_type, 'Credentials'::text AS title, count(*)::bigint AS item_count FROM credentials_trash
                   UNION ALL
                   SELECT 4 AS sort_order, 'filters'::text AS resource_type, 'Filters'::text AS title, count(*)::bigint AS item_count FROM filters_trash
                   UNION ALL
                   SELECT 5 AS sort_order, 'overrides'::text AS resource_type, 'Overrides'::text AS title, count(*)::bigint AS item_count FROM overrides_trash
                   UNION ALL
                   SELECT 6 AS sort_order, 'port_lists'::text AS resource_type, 'Port Lists'::text AS title, count(*)::bigint AS item_count FROM port_lists_trash
                   UNION ALL
                   SELECT 7 AS sort_order, 'report_configs'::text AS resource_type, 'Report Configs'::text AS title, count(*)::bigint AS item_count FROM report_configs_trash
                   UNION ALL
                   SELECT 8 AS sort_order, 'report_formats'::text AS resource_type, 'Report Formats'::text AS title, count(*)::bigint AS item_count FROM report_formats_trash
                   UNION ALL
                   SELECT 9 AS sort_order, 'scanners'::text AS resource_type, 'Scanners'::text AS title, count(*)::bigint AS item_count FROM scanners_trash
                   UNION ALL
                   SELECT 10 AS sort_order, 'schedules'::text AS resource_type, 'Schedules'::text AS title, count(*)::bigint AS item_count FROM schedules_trash
                   UNION ALL
                   SELECT 11 AS sort_order, 'tags'::text AS resource_type, 'Tags'::text AS title, count(*)::bigint AS item_count FROM tags_trash
                   UNION ALL
                   SELECT 12 AS sort_order, 'targets'::text AS resource_type, 'Targets'::text AS title, count(*)::bigint AS item_count FROM targets_trash
                   UNION ALL
                   SELECT 13 AS sort_order, 'tasks'::text AS resource_type, 'Tasks'::text AS title, count(*)::bigint AS item_count FROM tasks WHERE hidden = 2
                 ) trash_counts
                ORDER BY sort_order ASC;"#,
            &[],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "trashcan summary query failed");
            ApiError::Database
        })?;
    let items: Vec<TrashcanSummaryItem> = rows
        .iter()
        .map(|row| TrashcanSummaryItem {
            resource_type: row.get("resource_type"),
            title: row.get("title"),
            count: row.get("item_count"),
        })
        .collect();
    let total = items.iter().map(|item| item.count).sum();
    Ok(Json(TrashcanSummary { items, total }))
}

async fn vulnerabilities(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<VulnerabilityItem>>, ApiError> {
    let params = normalize_collection_query(query, VULNERABILITY_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, VULNERABILITY_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH vulnerability_rows AS (
             SELECT coalesce(nullif(r.nvt, ''), r.uuid::text) AS id,
                    coalesce(max(nullif(n.name, '')), max(nullif(r.nvt, '')), 'Unknown vulnerability') AS name,
                    max(nullif(n.family, '')) AS family,
                    max(n.cve) AS cve_text,
                    max(n.epss_score::double precision) AS epss_score,
                    max(n.epss_percentile::double precision) AS epss_percentile,
                    max(n.epss_cve) AS epss_cve,
                    max(n.epss_severity::double precision) AS epss_severity,
                    max(n.max_epss_score::double precision) AS max_epss_score,
                    max(n.max_epss_percentile::double precision) AS max_epss_percentile,
                    max(n.max_epss_cve) AS max_epss_cve,
                    max(n.max_epss_severity::double precision) AS max_epss_severity,
                    max(nullif(n.summary, '')) AS summary,
                    max(nullif(n.insight, '')) AS insight,
                    max(nullif(n.affected, '')) AS affected,
                    max(nullif(n.impact, '')) AS impact,
                    max(nullif(n.detection, '')) AS detection,
                    max(nullif(n.solution_type, '')) AS solution_type,
                    max(nullif(n.solution, '')) AS solution,
                    min(coalesce(r.date, 0))::bigint AS oldest_result_unix,
                    max(coalesce(r.date, 0))::bigint AS newest_result_unix,
                    max(coalesce(r.severity, 0))::double precision AS severity,
                    max(coalesce(r.qod, 0))::bigint AS qod,
                    count(*)::bigint AS result_count,
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS host_count
               FROM results r
               JOIN reports rep ON rep.id = r.report
               LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
               LEFT JOIN nvts n ON n.oid = r.nvt
              WHERE coalesce(r.severity, 0) > 0
                AND coalesce(nullif(r.nvt, ''), '') <> ''
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
                AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
              GROUP BY coalesce(nullif(r.nvt, ''), r.uuid::text)
         ),
         filtered AS (
             SELECT * FROM vulnerability_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%')
         ),
         page_rows AS (
             SELECT count(*) OVER()::bigint AS total, * FROM filtered
              ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3
         ),
         page_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs
               FROM page_rows p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.id
               ) refs ON true
         )
         SELECT * FROM page_with_refs;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "vulnerability list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "vulnerability list")
            .await?;
    let items = rows.iter().map(vulnerability_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn cpe_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CatalogCpeItem>>, ApiError> {
    let params = normalize_collection_query(query, CPE_CATALOG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CPE_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH cpe_rows AS (
             SELECT c.uuid AS id,
                    c.name AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.title, '') AS title,
                    coalesce(c.cpe_name_id, '') AS cpe_name_id,
                    coalesce(c.deprecated, 0)::integer AS deprecated_int,
                    coalesce(c.severity, 0)::double precision AS severity,
                    coalesce(c.cve_refs, 0)::bigint AS cve_refs,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM scap.cpes c
         ),
         filtered AS (
             SELECT * FROM cpe_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%'
                     OR lower(cpe_name_id) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| catalog_cpe_from_row(row, Vec::new(), None))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn cpe_catalog_detail(
    State(state): State<AppState>,
    Path(cpe_id): Path<String>,
) -> Result<Json<CatalogCpeDetail>, ApiError> {
    let cpe_id = cpe_id.strip_prefix('/').unwrap_or(&cpe_id).to_string();
    validate_cpe_id(&cpe_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.uuid AS id,
                      c.name AS name,
                      coalesce(c.comment, '') AS comment,
                      coalesce(c.title, '') AS title,
                      coalesce(c.cpe_name_id, '') AS cpe_name_id,
                      coalesce(c.deprecated, 0)::integer AS deprecated_int,
                      coalesce(c.severity, 0)::double precision AS severity,
                      coalesce(c.cve_refs, 0)::bigint AS cve_refs,
                      coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                 FROM scap.cpes c
                WHERE c.uuid = $1 OR c.name = $1
                LIMIT 1;"#,
            &[&cpe_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let cves = client
        .query(
            r#"SELECT cv.name AS id,
                      coalesce(cv.severity, 0)::double precision AS severity
                 FROM scap.cves cv
                 JOIN scap.affected_products ap ON ap.cve = cv.id
                 JOIN scap.cpes c ON c.id = ap.cpe
                WHERE c.uuid = $1 OR c.name = $1
                ORDER BY severity DESC, cv.name ASC;"#,
            &[&cpe_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog CVE reference query failed");
            ApiError::Database
        })?
        .iter()
        .map(catalog_cpe_cve_from_row)
        .collect();
    let deprecated_by = client
        .query_opt(
            r#"SELECT deprecated_by
                 FROM scap.cpes_deprecated_by
                WHERE cpe = $1
                ORDER BY deprecated_by
                LIMIT 1;"#,
            &[&cpe_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog deprecated-by query failed");
            ApiError::Database
        })?
        .map(|row| row.get("deprecated_by"));

    let user_tags = catalog_user_tags(&client, "cpe", &cpe_id).await?;
    Ok(Json(CatalogCpeDetail {
        item: catalog_cpe_from_row(&row, cves, deprecated_by),
        user_tags,
    }))
}

async fn cve_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CatalogCveItem>>, ApiError> {
    let params = normalize_collection_query(query, CVE_CATALOG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CVE_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH cve_rows AS (
             SELECT c.name AS id,
                    c.name AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(c.description, '') AS description,
                    coalesce(c.cvss_vector, '') AS cvss_base_vector,
                    coalesce(c.severity, 0)::double precision AS severity,
                    coalesce(c.products, '') AS products,
                    e.epss::double precision AS epss_score,
                    e.percentile::double precision AS epss_percentile,
                    coalesce(c.creation_time, 0)::bigint AS published_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM scap.cves c
               LEFT JOIN scap.epss_scores e ON e.cve = c.name
         ),
         filtered AS (
             SELECT * FROM cve_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(description) LIKE '%' || lower($1) || '%'
                     OR lower(cvss_base_vector) LIKE '%' || lower($1) || '%'
                     OR lower(products) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(catalog_cve_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn cve_catalog_detail(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
) -> Result<Json<CatalogCveDetail>, ApiError> {
    validate_cve_id(&cve_id)?;
    let sql = r#"SELECT c.name AS id,
                        c.name AS name,
                        coalesce(c.comment, '') AS comment,
                        coalesce(c.description, '') AS description,
                        coalesce(c.cvss_vector, '') AS cvss_base_vector,
                        coalesce(c.severity, 0)::double precision AS severity,
                        coalesce(c.products, '') AS products,
                        e.epss::double precision AS epss_score,
                        e.percentile::double precision AS epss_percentile,
                        coalesce(c.creation_time, 0)::bigint AS published_at_unix,
                        coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                   FROM scap.cves c
                   LEFT JOIN scap.epss_scores e ON e.cve = c.name
                  WHERE lower(c.name) = lower($1)
                  LIMIT 1;"#;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(sql, &[&cve_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = catalog_cve_from_row(&row);
    item.cert_refs = cve_cert_refs(&client, &cve_id).await?;
    item.nvt_refs = cve_nvt_refs(&client, &cve_id).await?;
    let user_tags = catalog_user_tags(&client, "cve", &cve_id).await?;
    Ok(Json(CatalogCveDetail { item, user_tags }))
}

async fn cve_cert_refs(
    client: &tokio_postgres::Client,
    cve_id: &str,
) -> Result<Vec<CatalogCveCertReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT *
                 FROM (
                       SELECT 'CERT-Bund'::text AS cert_type,
                              d.name AS name,
                              coalesce(d.title, '') AS title
                         FROM cert.cert_bund_cves dc
                         JOIN cert.cert_bund_advs d ON d.id = dc.adv_id
                        WHERE lower(dc.cve_name) = lower($1)
                        UNION ALL
                       SELECT 'DFN-CERT'::text AS cert_type,
                              d.name AS name,
                              coalesce(d.title, '') AS title
                         FROM cert.dfn_cert_cves dc
                         JOIN cert.dfn_cert_advs d ON d.id = dc.adv_id
                        WHERE lower(dc.cve_name) = lower($1)
                      ) refs
                ORDER BY cert_type ASC, name ASC;"#,
            &[&cve_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog CERT reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveCertReference {
            cert_type: row.get("cert_type"),
            name: row.get("name"),
            title: row.get("title"),
        })
        .collect())
}

async fn cve_nvt_refs(
    client: &tokio_postgres::Client,
    cve_id: &str,
) -> Result<Vec<CatalogCveNvtReference>, ApiError> {
    let rows = client
        .query(
            r#"SELECT DISTINCT n.oid AS id,
                              coalesce(nullif(n.name, ''), n.oid) AS name
                 FROM vt_refs vr
                 JOIN nvts n ON n.oid = vr.vt_oid
                WHERE lower(vr.ref_id) = lower($1)
                  AND lower(vr.type) IN ('cve', 'cve_id')
                ORDER BY name ASC, id ASC;"#,
            &[&cve_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CVE catalog NVT reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| CatalogCveNvtReference {
            id: row.get("id"),
            name: row.get("name"),
        })
        .collect())
}

async fn dfn_cert_advisories(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<DfnCertAdvisoryItem>>, ApiError> {
    let params = normalize_collection_query(query, CERT_ADVISORY_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CERT_ADVISORY_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH advisory_rows AS (
             SELECT d.uuid AS id,
                    d.name AS name,
                    coalesce(d.comment, '') AS comment,
                    coalesce(d.title, '') AS title,
                    coalesce(d.summary, '') AS summary,
                    coalesce(d.severity, 0)::double precision AS severity,
                    coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                    coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(array_agg(dc.cve_name ORDER BY dc.cve_name)
                      FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
               FROM cert.dfn_cert_advs d
               LEFT JOIN cert.dfn_cert_cves dc ON dc.adv_id = d.id
              GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                       d.severity, d.cve_refs, d.creation_time,
                       d.modification_time
         ),
         filtered AS (
             SELECT * FROM advisory_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR EXISTS (
                         SELECT 1 FROM unnest(cves) AS cve_name
                          WHERE lower(cve_name) LIKE '%' || lower($1) || '%'))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "DFN-CERT advisory list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(dfn_cert_advisory_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn dfn_cert_advisory_detail(
    State(state): State<AppState>,
    Path(advisory_id): Path<String>,
) -> Result<Json<DfnCertAdvisoryDetail>, ApiError> {
    validate_advisory_id(&advisory_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT d.uuid AS id,
                      d.name AS name,
                      coalesce(d.comment, '') AS comment,
                      coalesce(d.title, '') AS title,
                      coalesce(d.summary, '') AS summary,
                      coalesce(d.severity, 0)::double precision AS severity,
                      coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                      coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce(array_agg(dc.cve_name ORDER BY dc.cve_name)
                        FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
                 FROM cert.dfn_cert_advs d
                 LEFT JOIN cert.dfn_cert_cves dc ON dc.adv_id = d.id
                WHERE d.uuid = $1 OR d.name = $1
                GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                         d.severity, d.cve_refs, d.creation_time,
                         d.modification_time;"#,
            &[&advisory_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "DFN-CERT advisory detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let id: String = row.get("id");
    let user_tags = catalog_user_tags(&client, "dfn_cert_adv", &id).await?;
    Ok(Json(DfnCertAdvisoryDetail {
        item: dfn_cert_advisory_from_row(&row),
        user_tags,
    }))
}

async fn cert_bund_advisories(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CertBundAdvisoryItem>>, ApiError> {
    let params = normalize_collection_query(query, CERT_ADVISORY_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, CERT_ADVISORY_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH advisory_rows AS (
             SELECT d.uuid AS id,
                    d.name AS name,
                    coalesce(d.comment, '') AS comment,
                    coalesce(d.title, '') AS title,
                    coalesce(d.summary, '') AS summary,
                    coalesce(d.severity, 0)::double precision AS severity,
                    coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                    coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce(array_agg(dc.cve_name::text ORDER BY dc.cve_name)
                      FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
               FROM cert.cert_bund_advs d
               LEFT JOIN cert.cert_bund_cves dc ON dc.adv_id = d.id
              GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                       d.severity, d.cve_refs, d.creation_time,
                       d.modification_time
         ),
         filtered AS (
             SELECT * FROM advisory_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR EXISTS (
                         SELECT 1 FROM unnest(cves) AS cve_name
                          WHERE lower(cve_name) LIKE '%' || lower($1) || '%'))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CERT-Bund advisory list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(cert_bund_advisory_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn cert_bund_advisory_detail(
    State(state): State<AppState>,
    Path(advisory_id): Path<String>,
) -> Result<Json<CertBundAdvisoryDetail>, ApiError> {
    validate_advisory_id(&advisory_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT d.uuid AS id,
                      d.name AS name,
                      coalesce(d.comment, '') AS comment,
                      coalesce(d.title, '') AS title,
                      coalesce(d.summary, '') AS summary,
                      coalesce(d.severity, 0)::double precision AS severity,
                      coalesce(d.cve_refs, 0)::bigint AS cve_refs,
                      coalesce(d.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(d.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce(array_agg(dc.cve_name::text ORDER BY dc.cve_name)
                        FILTER (WHERE dc.cve_name IS NOT NULL), ARRAY[]::text[]) AS cves
                 FROM cert.cert_bund_advs d
                 LEFT JOIN cert.cert_bund_cves dc ON dc.adv_id = d.id
                WHERE d.uuid = $1 OR d.name = $1
                GROUP BY d.uuid, d.name, d.comment, d.title, d.summary,
                         d.severity, d.cve_refs, d.creation_time,
                         d.modification_time;"#,
            &[&advisory_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CERT-Bund advisory detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let id: String = row.get("id");
    let user_tags = catalog_user_tags(&client, "cert_bund_adv", &id).await?;
    Ok(Json(CertBundAdvisoryDetail {
        item: cert_bund_advisory_from_row(&row),
        user_tags,
    }))
}

async fn nvt_catalog(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<NvtCatalogItem>>, ApiError> {
    let params = normalize_collection_query(query, NVT_CATALOG_DEFAULT_SORT)?;
    let (filter_mode, filter_value) = nvt_filter_parts(&params.filter);
    let sort_sql = sort_clause(&params.sort, NVT_CATALOG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH filtered AS (
             SELECT n.oid AS id,
                    n.oid AS oid,
                    coalesce(n.name, '') AS name,
                    coalesce(n.family, '') AS family,
                    coalesce(n.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(n.modification_time, 0)::bigint AS modified_at_unix,
                    CASE
                      WHEN coalesce(n.cvss_base, '') ~ '^-?[0-9]+(\.[0-9]+)?$'
                      THEN n.cvss_base::double precision
                      ELSE 0::double precision
                    END AS severity,
                    coalesce(n.qod, 0)::bigint AS qod,
                    coalesce(n.qod_type, '') AS qod_type,
                    coalesce(n.solution_type, '') AS solution_type,
                    coalesce(n.solution_method, '') AS solution_method,
                    coalesce(n.solution, '') AS solution,
                    coalesce(n.tag, '') AS tags,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    coalesce(n.epss_cve, '') AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    coalesce(n.max_epss_cve, '') AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity
               FROM nvts n
              WHERE ($2 = ''
                     OR ($1 = 'family' AND lower(n.family) = lower($2))
                     OR ($1 = 'name' AND lower(n.name) LIKE '%' || lower($2) || '%')
                     OR ($1 = 'cve' AND lower(coalesce(n.cve, '')) LIKE '%' || lower($2) || '%')
                     OR ($1 = 'qod_type' AND lower(coalesce(n.qod_type, '')) = lower($2))
                     OR ($1 = 'solution_type' AND lower(coalesce(n.solution_type, '')) = lower($2))
                     OR ($1 = 'search'
                         AND (lower(n.oid) LIKE '%' || lower($2) || '%'
                              OR lower(n.name) LIKE '%' || lower($2) || '%'
                              OR lower(n.family) LIKE '%' || lower($2) || '%'
                              OR lower(coalesce(n.cve, '')) LIKE '%' || lower($2) || '%')))
         ),
         page_rows AS (
             SELECT count(*) OVER()::bigint AS total, * FROM filtered
              ORDER BY {sort_sql}, name ASC, oid ASC LIMIT $3 OFFSET $4
         ),
         page_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs
               FROM page_rows p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.oid
               ) refs ON true
         )
         SELECT *, cardinality(cves)::bigint AS cve_refs FROM page_with_refs;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &filter_mode,
                &filter_value,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "NVT catalog list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(nvt_catalog_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

fn nvt_filter_parts(raw: &str) -> (&'static str, String) {
    for key in ["family", "name", "cve", "qod_type", "solution_type"] {
        if let Some(value) = raw.strip_prefix(&format!("{key}=")) {
            return (key, value.trim_matches('"').to_string());
        }
    }
    ("search", raw.to_string())
}

async fn nvt_catalog_detail(
    State(state): State<AppState>,
    Path(nvt_id): Path<String>,
) -> Result<Json<NvtCatalogDetail>, ApiError> {
    validate_nvt_oid(&nvt_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"WITH nvt_row AS (
             SELECT n.oid AS id,
                    n.oid AS oid,
                    coalesce(n.name, '') AS name,
                    coalesce(n.comment, '') AS comment,
                    coalesce(n.summary, '') AS summary,
                    coalesce(n.insight, '') AS insight,
                    coalesce(n.affected, '') AS affected,
                    coalesce(n.impact, '') AS impact,
                    coalesce(n.detection, '') AS detection,
                    coalesce(n.family, '') AS family,
                    coalesce(n.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(n.modification_time, 0)::bigint AS modified_at_unix,
                    CASE
                      WHEN coalesce(n.cvss_base, '') ~ '^-?[0-9]+(\.[0-9]+)?$'
                      THEN n.cvss_base::double precision
                      ELSE 0::double precision
                    END AS severity,
                    coalesce(n.qod, 0)::bigint AS qod,
                    coalesce(n.qod_type, '') AS qod_type,
                    coalesce(n.solution_type, '') AS solution_type,
                    coalesce(n.solution_method, '') AS solution_method,
                    coalesce(n.solution, '') AS solution,
                    coalesce(n.tag, '') AS tags,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    coalesce(n.epss_cve, '') AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    coalesce(n.max_epss_cve, '') AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity
               FROM nvts n
              WHERE n.oid = $1
         ),
         row_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs
               FROM nvt_row p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.oid
               ) refs ON true
         )
         SELECT *, cardinality(cves)::bigint AS cve_refs FROM row_with_refs;"#,
            &[&nvt_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "NVT catalog detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let user_tags = catalog_user_tags(&client, "nvt", &nvt_id).await?;
    Ok(Json(nvt_catalog_detail_from_row(&row, user_tags)))
}

async fn operating_system_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, OPERATING_SYSTEM_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, OPERATING_SYSTEM_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH latest_best_os AS (
             SELECT DISTINCT ON (hd.host)
                    hd.host, hd.value AS cpe
               FROM host_details hd
              WHERE hd.name = 'best_os_cpe'
              ORDER BY hd.host, hd.id DESC
         ),
         latest_host_severity AS (
             SELECT DISTINCT ON (hms.host)
                    hms.host,
                    round(CAST(hms.severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities hms
              ORDER BY hms.host, hms.creation_time DESC
         ),
         os_rows AS (
             SELECT oss.uuid AS id,
                    oss.name AS name,
                    coalesce(cpe_title(oss.name), '') AS title,
                    (
                      SELECT lhs.severity
                        FROM host_oss ho_latest
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_latest.host
                       WHERE ho_latest.os = oss.id
                       ORDER BY ho_latest.creation_time DESC
                       LIMIT 1
                    ) AS latest_severity,
                    (
                      SELECT max(lhs.severity)
                        FROM host_oss ho_highest
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_highest.host
                       WHERE ho_highest.os = oss.id
                    ) AS highest_severity,
                    (
                      SELECT round(CAST(avg(lhs.severity) AS numeric), 2)::double precision
                        FROM host_oss ho_average
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_average.host
                       WHERE ho_average.os = oss.id
                    ) AS average_severity,
                    (
                      SELECT count(DISTINCT lbo.host)::bigint
                        FROM latest_best_os lbo
                       WHERE lbo.cpe = oss.name
                    ) AS hosts,
                    (
                      SELECT count(DISTINCT ho_all.host)::bigint
                        FROM host_oss ho_all
                       WHERE ho_all.os = oss.id
                    ) AS all_hosts,
                    coalesce(oss.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(oss.modification_time, 0)::bigint AS modified_at_unix
               FROM oss
         ),
         filtered AS (
             SELECT * FROM os_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(operating_system_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn operating_system_asset_detail(
    State(state): State<AppState>,
    Path(os_id): Path<String>,
) -> Result<Json<OperatingSystemAssetItem>, ApiError> {
    parse_uuid(&os_id)?;
    let os_id = os_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"WITH latest_best_os AS (
             SELECT DISTINCT ON (hd.host)
                    hd.host, hd.value AS cpe
               FROM host_details hd
              WHERE hd.name = 'best_os_cpe'
              ORDER BY hd.host, hd.id DESC
         ),
         latest_host_severity AS (
             SELECT DISTINCT ON (hms.host)
                    hms.host,
                    round(CAST(hms.severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities hms
              ORDER BY hms.host, hms.creation_time DESC
         )
         SELECT oss.uuid AS id,
                oss.name AS name,
                coalesce(cpe_title(oss.name), '') AS title,
                (
                  SELECT lhs.severity
                    FROM host_oss ho_latest
                    LEFT JOIN latest_host_severity lhs ON lhs.host = ho_latest.host
                   WHERE ho_latest.os = oss.id
                   ORDER BY ho_latest.creation_time DESC
                   LIMIT 1
                ) AS latest_severity,
                (
                  SELECT max(lhs.severity)
                    FROM host_oss ho_highest
                    LEFT JOIN latest_host_severity lhs ON lhs.host = ho_highest.host
                   WHERE ho_highest.os = oss.id
                ) AS highest_severity,
                (
                  SELECT round(CAST(avg(lhs.severity) AS numeric), 2)::double precision
                    FROM host_oss ho_average
                    LEFT JOIN latest_host_severity lhs ON lhs.host = ho_average.host
                   WHERE ho_average.os = oss.id
                ) AS average_severity,
                (
                  SELECT count(DISTINCT lbo.host)::bigint
                    FROM latest_best_os lbo
                   WHERE lbo.cpe = oss.name
                ) AS hosts,
                (
                  SELECT count(DISTINCT ho_all.host)::bigint
                    FROM host_oss ho_all
                   WHERE ho_all.os = oss.id
                ) AS all_hosts,
                coalesce(oss.creation_time, 0)::bigint AS created_at_unix,
                coalesce(oss.modification_time, 0)::bigint AS modified_at_unix
           FROM oss
          WHERE oss.uuid = $1
          LIMIT 1;"#,
            &[&os_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = operating_system_asset_from_row(&row);
    item.user_tags = operating_system_user_tags(&client, &os_id).await?;
    Ok(Json(item))
}

fn operating_system_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN oss ON oss.id = tr.resource
        WHERE lower(oss.uuid) = lower($1)
          AND tr.resource_type = 'os'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn operating_system_user_tags(
    client: &tokio_postgres::Client,
    os_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(operating_system_user_tags_sql(), &[&os_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn report_ports(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_PORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_PORT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         port_rows AS (\n\
             SELECT coalesce(r.port, '') AS port,\n\
                    CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                         THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                         ELSE '' END AS protocol,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                AND coalesce(r.port, '') <> ''\n\
              GROUP BY coalesce(r.port, ''),\n\
                       CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                            THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                            ELSE '' END\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM port_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(protocol) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, port ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report port query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(port_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_applications(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ApplicationItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_APPLICATION_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_APPLICATION_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         app_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    sr.uuid AS source_report_id,\n\
                    rh.id AS report_host,\n\
                    rhd.source_name AS detection_oid,\n\
                    rhd.value AS name\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
               JOIN report_host_details rhd ON rhd.report_host = rh.id\n\
              WHERE rhd.name = 'App'\n\
                AND coalesce(rhd.value, '') <> ''\n\
                AND coalesce(rhd.source_name, '') <> ''\n\
                AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, sr.uuid,\n\
                       rh.id, rhd.source_name, rhd.value\n\
         ),\n\
         result_detection AS (\n\
             SELECT r.uuid AS result_id,\n\
                    r.report AS source_report,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(nullif(by_location.value, ''), by_generic.value, '') AS detection_oid,\n\
                    coalesce(nullif(r.path, ''),\n\
                             CASE WHEN coalesce(r.port, '') <> ''\n\
                                    AND coalesce(r.port, '') NOT LIKE 'general/%'\n\
                                  THEN r.port ELSE NULL END,\n\
                             detected_at.value, '') AS detection_location\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               JOIN report_hosts rh\n\
                 ON rh.report = r.report\n\
                AND lower(rh.host) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
               LEFT JOIN report_host_details detected_at\n\
                 ON detected_at.report_host = rh.id\n\
                AND detected_at.source_name = r.nvt\n\
                AND detected_at.name = 'detected_at'\n\
               LEFT JOIN report_host_details by_location\n\
                 ON by_location.report_host = rh.id\n\
                AND by_location.source_name = r.nvt\n\
                AND by_location.name = 'detected_by@' || coalesce(nullif(r.path, ''),\n\
                     CASE WHEN coalesce(r.port, '') <> ''\n\
                            AND coalesce(r.port, '') NOT LIKE 'general/%'\n\
                          THEN r.port ELSE NULL END,\n\
                     detected_at.value, '')\n\
               LEFT JOIN report_host_details by_generic\n\
                 ON by_generic.report_host = rh.id\n\
                AND by_generic.source_name = r.nvt\n\
                AND by_generic.name = 'detected_by'\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         app_result_matches AS (\n\
             SELECT ai.name,\n\
                    ai.host_key,\n\
                    ai.source_report_id,\n\
                    rd.result_id,\n\
                    rd.nvt_oid,\n\
                    rd.severity\n\
               FROM app_instances ai\n\
               LEFT JOIN result_detection rd\n\
                 ON rd.source_report = ai.source_report\n\
                AND rd.host_key = ai.host_key\n\
                AND rd.detection_oid = ai.detection_oid\n\
               LEFT JOIN report_host_details app_location\n\
                 ON app_location.report_host = ai.report_host\n\
                AND app_location.source_name = ai.detection_oid\n\
                AND app_location.name = ai.name\n\
                AND app_location.value = rd.detection_location\n\
              WHERE rd.result_id IS NULL OR app_location.id IS NOT NULL\n\
         ),\n\
         application_rows AS (\n\
             SELECT ai.name,\n\
                    ''::text AS version,\n\
                    CASE WHEN lower(ai.name) LIKE 'cpe:%' THEN ai.name ELSE '' END AS cpe,\n\
                    count(DISTINCT ai.host_key)::bigint AS host_count,\n\
                    count(DISTINCT arm.result_id)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(arm.nvt_oid, ''), arm.result_id))\n\
                      FILTER (WHERE coalesce(arm.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(arm.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT ai.source_report_id), NULL) AS source_report_ids\n\
               FROM app_instances ai\n\
               LEFT JOIN app_result_matches arm\n\
                 ON arm.name = ai.name\n\
                AND arm.host_key = ai.host_key\n\
                AND arm.source_report_id = ai.source_report_id\n\
              GROUP BY ai.name\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM application_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(name) LIKE '%' || lower($2) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report application query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(application_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_operating_systems(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_OPERATING_SYSTEM_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_OPERATING_SYSTEM_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         os_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    sr.uuid AS source_report_id,\n\
                    coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown') AS name,\n\
                    coalesce(os_cpe.value, '') AS cpe\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
               LEFT JOIN report_host_details os_cpe\n\
                 ON os_cpe.report_host = rh.id AND os_cpe.name = 'best_os_cpe'\n\
               LEFT JOIN report_host_details os_txt\n\
                 ON os_txt.report_host = rh.id AND os_txt.name = 'best_os_txt'\n\
              WHERE coalesce(os_txt.value, os_cpe.value, '') <> ''\n\
                AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, sr.uuid,\n\
                       coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown'),\n\
                       coalesce(os_cpe.value, '')\n\
         ),\n\
         operating_system_rows AS (\n\
             SELECT oi.name,\n\
                    oi.cpe,\n\
                    count(DISTINCT oi.host_key)::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(r.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT oi.source_report_id), NULL) AS source_report_ids\n\
               FROM os_instances oi\n\
               LEFT JOIN results r\n\
                 ON r.report = oi.source_report\n\
                AND lower(coalesce(nullif(r.host, ''), r.hostname, '')) = oi.host_key\n\
                AND coalesce(r.severity, 0) != -3.0\n\
              GROUP BY oi.name, oi.cpe\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM operating_system_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(name) LIKE '%' || lower($2) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report operating-system query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(operating_system_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_tls_certificates(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_TLS_CERTIFICATE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_TLS_CERTIFICATE_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_report sr\n\
               JOIN report_hosts rh ON rh.report = sr.id\n\
              WHERE coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
         ),\n\
         tls_rows AS (\n\
             SELECT c.uuid AS id,\n\
                    coalesce(c.sha256_fingerprint, '') AS fingerprint_sha256,\n\
                    coalesce(c.subject_dn, '') AS subject,\n\
                    coalesce(c.issuer_dn, '') AS issuer,\n\
                    coalesce(c.serial, '') AS serial,\n\
                    coalesce(c.activation_time, 0)::bigint AS not_before_unix,\n\
                    coalesce(c.expiration_time, 0)::bigint AS not_after_unix,\n\
                    count(DISTINCT lower(loc.host_ip))::bigint AS host_count,\n\
                    count(DISTINCT loc.port)::bigint AS port_count,\n\
                    count(DISTINCT src.uuid)::bigint AS result_count,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN tls_certificate_origins origin\n\
                 ON origin.origin_type = 'Report'\n\
                AND origin.origin_id = sr.uuid\n\
               JOIN tls_certificate_sources src ON src.origin = origin.id\n\
               JOIN tls_certificates c ON c.id = src.tls_certificate\n\
               JOIN tls_certificate_locations loc ON loc.id = src.location\n\
               JOIN selected_hosts sh ON sh.host_key = lower(loc.host_ip)\n\
              GROUP BY c.uuid, c.sha256_fingerprint, c.subject_dn, c.issuer_dn,\n\
                       c.serial, c.activation_time, c.expiration_time\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM tls_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(fingerprint_sha256) LIKE '%' || lower($2) || '%'\n\
                     OR lower(subject) LIKE '%' || lower($2) || '%'\n\
                     OR lower(issuer) LIKE '%' || lower($2) || '%'\n\
                     OR lower(serial) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report TLS certificate query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(tls_certificate_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_cves(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CveItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_CVE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_CVE_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         cve_rows AS (\n\
             SELECT vr.ref_id AS id,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS affected_system_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT sr.uuid), NULL) AS source_report_ids\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               JOIN vt_refs vr ON vr.vt_oid = r.nvt AND vr.type = 'cve'\n\
              WHERE coalesce(r.severity, 0) > 0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY vr.ref_id\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM cve_rows\n\
              WHERE ($2 = '' OR lower(id) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report CVE query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(cve_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_errors(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ErrorMessageItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_ERROR_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_ERROR_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         error_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.description, '') AS description,\n\
                    sr.uuid AS source_report_id,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
              WHERE (r.type = 'Error Message' OR coalesce(r.severity, 0) = -3)\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM error_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(host) LIKE '%' || lower($2) || '%'\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($2) || '%'\n\
                     OR lower(description) LIKE '%' || lower($2) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $3 OFFSET $4;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report error-message query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(error_message_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_detail(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<ReportItem>, ApiError> {
    parse_uuid(&report_id)?;
    let sql = raw_report_sql("lower(uuid) = lower($1)", "creation_time DESC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&report_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut report = report_from_row(&row);
    report.user_tags = report_user_tags(&client, &report_id).await?;
    Ok(Json(report))
}

async fn results(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    let params = normalize_collection_query(query, RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, RESULT_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH result_rows AS (
             SELECT r.uuid AS id,
                    r.id AS result_internal_id,
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
                    h.uuid AS host_asset_id,
                    nullif(r.hostname, '') AS hostname,
                    coalesce(r.port, '') AS port,
                    coalesce(r.nvt, '') AS nvt_oid,
                    coalesce(n.name, r.nvt, '') AS name,
                    nullif(n.family, '') AS nvt_family,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    n.epss_cve AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    n.max_epss_cve AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity,
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,
                    nullif(n.solution_type, '') AS solution_type,
                    nullif(n.solution, '') AS solution,
                    coalesce(r.severity, 0)::double precision AS severity,
                    coalesce(r.qod, 0)::bigint AS qod,
                    nullif(r.nvt_version, '') AS scan_nvt_version,
                    coalesce(r.date, 0)::bigint AS created_at_unix,
                    rep.uuid AS source_report_id,
                    coalesce(nullif(t.name, ''), rep.uuid) AS source_report_name,
                    t.uuid AS task_id,
                    t.name AS task_name
               FROM results r
               JOIN reports rep ON rep.id = r.report
               LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
               LEFT JOIN hosts h ON lower(h.name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))
               LEFT JOIN nvts n ON n.oid = r.nvt
              WHERE coalesce(r.severity, 0) != -3.0
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
                AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
         ),
         filtered AS (
             SELECT * FROM result_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(host) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($1) || '%'
                     OR lower(port) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_oid) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(task_name, '')) LIKE '%' || lower($1) || '%'
                     OR lower(source_report_name) LIKE '%' || lower($1) || '%')
         ),
         page_rows AS (
             SELECT count(*) OVER()::bigint AS total, * FROM filtered
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $2 OFFSET $3
         ),
         page_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs,
                    coalesce(active_overrides.override_ids, ARRAY[]::text[]) AS override_ids,
                    coalesce(active_overrides.override_nvt_ids, ARRAY[]::text[]) AS override_nvt_ids,
                    coalesce(active_overrides.override_nvt_names, ARRAY[]::text[]) AS override_nvt_names,
                    coalesce(active_overrides.override_nvt_types, ARRAY[]::text[]) AS override_nvt_types,
                    coalesce(active_overrides.override_texts, ARRAY[]::text[]) AS override_texts,
                    coalesce(active_overrides.override_hosts, ARRAY[]::text[]) AS override_hosts,
                    coalesce(active_overrides.override_ports, ARRAY[]::text[]) AS override_ports,
                    coalesce(active_overrides.override_severities, ARRAY[]::double precision[]) AS override_severities,
                    coalesce(active_overrides.override_new_severities, ARRAY[]::double precision[]) AS override_new_severities,
                    coalesce(active_overrides.override_created_at_unix, ARRAY[]::bigint[]) AS override_created_at_unix,
                    coalesce(active_overrides.override_modified_at_unix, ARRAY[]::bigint[]) AS override_modified_at_unix,
                    coalesce(active_overrides.override_end_time_unix, ARRAY[]::bigint[]) AS override_end_time_unix,
                    coalesce(active_overrides.override_active_ints, ARRAY[]::integer[]) AS override_active_ints
               FROM page_rows p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.nvt_oid
               ) refs ON true
               LEFT JOIN LATERAL (
                   SELECT array_agg(m.id ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_ids,
                          array_agg(m.nvt_id ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_ids,
                          array_agg(m.nvt_name ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_names,
                          array_agg(m.nvt_type ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_types,
                          array_agg(m.text ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_texts,
                          array_agg(m.hosts ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_hosts,
                          array_agg(m.port ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_ports,
                          array_agg(m.severity ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_severities,
                          array_agg(m.new_severity ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_new_severities,
                          array_agg(m.created_at_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_created_at_unix,
                          array_agg(m.modified_at_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_modified_at_unix,
                          array_agg(m.end_time_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_end_time_unix,
                          array_agg(m.active_int ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_active_ints
                     FROM (
                         SELECT DISTINCT ON (o.id)
                                o.uuid AS id,
                                coalesce(o.nvt, '') AS nvt_id,
                                CASE
                                  WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                                  ELSE coalesce(n.name, o.nvt, '')
                                END AS nvt_name,
                                CASE
                                  WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                                  ELSE 'nvt'
                                END AS nvt_type,
                                coalesce(o.text, '') AS text,
                                coalesce(o.hosts, '') AS hosts,
                                coalesce(o.port, '') AS port,
                                o.severity::double precision AS severity,
                                o.new_severity::double precision AS new_severity,
                                coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                                coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                                coalesce(o.end_time, 0)::bigint AS end_time_unix,
                                CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int
                           FROM result_overrides ro
                           JOIN overrides o ON o.id = ro.override
                      LEFT JOIN nvts n ON n.oid = o.nvt
                          WHERE ro.result = p.result_internal_id
                          ORDER BY o.id, coalesce(o.modification_time, o.creation_time, 0) DESC, o.uuid ASC
                     ) m
               ) active_overrides ON true
         )
         SELECT * FROM page_with_refs;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "result list")
            .await?;
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn result_detail(
    State(state): State<AppState>,
    Path(result_id): Path<String>,
) -> Result<Json<ResultItem>, ApiError> {
    parse_uuid(&result_id)?;
    let sql = r#"SELECT r.uuid AS id,
                         lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
                         h.uuid AS host_asset_id,
                         nullif(r.hostname, '') AS hostname,
                         coalesce(r.port, '') AS port,
                         coalesce(r.nvt, '') AS nvt_oid,
                         coalesce(n.name, r.nvt, '') AS name,
                         nullif(n.family, '') AS nvt_family,
                         n.epss_score::double precision AS epss_score,
                         n.epss_percentile::double precision AS epss_percentile,
                         n.epss_cve AS epss_cve,
                         n.epss_severity::double precision AS epss_severity,
                         n.max_epss_score::double precision AS max_epss_score,
                         n.max_epss_percentile::double precision AS max_epss_percentile,
                         n.max_epss_cve AS max_epss_cve,
                         n.max_epss_severity::double precision AS max_epss_severity,
                         CASE
                           WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                           THEN refs.cves
                           WHEN coalesce(n.cve, '') <> ''
                           THEN regexp_split_to_array(n.cve, '\\s*,\\s*')
                           ELSE ARRAY[]::text[]
                         END AS cves,
                         coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                         coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs,
                         nullif(r.description, '') AS description,
                         nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,
                         nullif(n.summary, '') AS summary,
                         nullif(n.insight, '') AS insight,
                         nullif(n.affected, '') AS affected,
                         nullif(n.impact, '') AS impact,
                         nullif(n.detection, '') AS detection,
                         nullif(n.solution_type, '') AS solution_type,
                         nullif(n.solution, '') AS solution,
                         coalesce(r.severity, 0)::double precision AS severity,
                         coalesce(r.qod, 0)::bigint AS qod,
                         nullif(r.nvt_version, '') AS scan_nvt_version,
                         coalesce(r.date, 0)::bigint AS created_at_unix,
                         rep.uuid AS source_report_id,
                         coalesce(nullif(t.name, ''), rep.uuid) AS source_report_name,
                         t.uuid AS task_id,
                         t.name AS task_name
                    FROM results r
                    JOIN reports rep ON rep.id = r.report
                    LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
                    LEFT JOIN hosts h ON lower(h.name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))
                    LEFT JOIN nvts n ON n.oid = r.nvt
                    LEFT JOIN LATERAL (
                        SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                                 FILTER (WHERE vr.ref_id IS NOT NULL
                                         AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                               array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                                 FILTER (WHERE vr.ref_id IS NOT NULL
                                         AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                               array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                                 FILTER (WHERE vr.ref_id IS NOT NULL
                                         AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                          FROM vt_refs vr
                         WHERE vr.vt_oid = r.nvt
                    ) refs ON true
                   WHERE lower(r.uuid) = lower($1)
                     AND coalesce(r.severity, 0) != -3.0
                     AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
                     AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
                   LIMIT 1;"#;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(sql, &[&result_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = result_from_row(&row);
    item.user_tags = result_user_tags(&client, &result_id).await?;
    item.overrides = result_effective_overrides(&client, &result_id).await?;
    Ok(Json(item))
}

async fn result_user_tags(
    client: &tokio_postgres::Client,
    result_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.value, '') AS value,
                      coalesce(t.comment, '') AS comment
                 FROM tags t
                 JOIN tag_resources tr ON tr.tag = t.id
                 JOIN results r ON r.id = tr.resource
                WHERE lower(r.uuid) = lower($1)
                  AND tr.resource_type = 'result'
                  AND tr.resource_location = 0
                  AND coalesce(t.active, 0) = 1
                ORDER BY t.name ASC, t.uuid ASC;"#,
            &[&result_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn result_effective_overrides(
    client: &tokio_postgres::Client,
    result_id: &str,
) -> Result<Vec<ResultOverrideItem>, ApiError> {
    let rows = client
        .query(
            r#"WITH matched AS (
                 SELECT DISTINCT ON (o.id)
                        o.uuid AS id,
                        coalesce(o.nvt, '') AS nvt_id,
                        CASE
                          WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                          ELSE coalesce(n.name, o.nvt, '')
                        END AS nvt_name,
                        CASE
                          WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                          ELSE 'nvt'
                        END AS nvt_type,
                        coalesce(o.text, '') AS text,
                        coalesce(o.hosts, '') AS hosts,
                        coalesce(o.port, '') AS port,
                        o.severity::double precision AS severity,
                        o.new_severity::double precision AS new_severity,
                        coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                        coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                        coalesce(o.end_time, 0)::bigint AS end_time_unix,
                        CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int
                   FROM result_overrides ro
                   JOIN results r ON r.id = ro.result
                   JOIN overrides o ON o.id = ro.override
              LEFT JOIN nvts n ON n.oid = o.nvt
                  WHERE lower(r.uuid) = lower($1)
                  ORDER BY o.id, coalesce(o.modification_time, o.creation_time, 0) DESC, o.uuid ASC
             )
             SELECT * FROM matched
              ORDER BY modified_at_unix DESC, created_at_unix DESC, id ASC;"#,
            &[&result_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result effective-override query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(result_override_from_row).collect())
}

async fn report_results(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_RESULT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         result_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    nullif(r.hostname, '') AS hostname,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
                    nullif(n.family, '') AS nvt_family,\n\
                    n.cve AS cve_text,\n\
                    n.epss_score::double precision AS epss_score,\n\
                    n.epss_percentile::double precision AS epss_percentile,\n\
                    n.epss_cve AS epss_cve,\n\
                    n.epss_severity::double precision AS epss_severity,\n\
                    n.max_epss_score::double precision AS max_epss_score,\n\
                    n.max_epss_percentile::double precision AS max_epss_percentile,\n\
                    n.max_epss_cve AS max_epss_cve,\n\
                    n.max_epss_severity::double precision AS max_epss_severity,\n\
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(r.qod, 0)::bigint AS qod,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix,\n\
                    sr.uuid AS source_report_id\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               LEFT JOIN nvts n ON n.oid = r.nvt\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM result_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(host) LIKE '%' || lower($2) || '%'\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($2) || '%'\n\
                     OR lower(name) LIKE '%' || lower($2) || '%')\n\
         ),\n\
         page_rows AS (\n\
             SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $3 OFFSET $4\n\
         ),\n\
         page_with_refs AS (\n\
             SELECT p.*,\n\
                    CASE\n\
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0\n\
                      THEN refs.cves\n\
                      WHEN coalesce(p.cve_text, '') <> ''\n\
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')\n\
                      ELSE ARRAY[]::text[]\n\
                    END AS cves,\n\
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,\n\
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs\n\
               FROM page_rows p\n\
               LEFT JOIN LATERAL (\n\
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs\n\
                     FROM vt_refs vr\n\
                    WHERE vr.vt_oid = p.nvt_oid\n\
               ) refs ON true\n\
         )\n\
         SELECT * FROM page_with_refs;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report result query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_hosts(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportHostItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_HOST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_HOST_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH selected_report AS (
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)
         ),
         host_base AS (
             SELECT rh.id AS report_host_id,
                    lower(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host_key,
                    coalesce(nullif(rh.host, ''), rh.hostname, '') AS host,
                    nullif(rh.hostname, '') AS hostname,
                    coalesce(rh.start_time, 0)::bigint AS start_time_unix,
                    coalesce(rh.end_time, 0)::bigint AS end_time_unix,
                    sr.uuid AS source_report_id
               FROM selected_report sr
               JOIN report_hosts rh ON rh.report = sr.id
              WHERE coalesce(nullif(rh.host, ''), rh.hostname, '') <> ''
         ),
         detail_rows AS (
             SELECT hb.report_host_id,
                    nullif(max(rhd.value) FILTER (WHERE rhd.name = 'best_os_cpe'), '') AS best_os_cpe,
                    nullif(max(rhd.value) FILTER (WHERE rhd.name = 'best_os_txt'), '') AS best_os_txt,
                    count(*) FILTER (WHERE rhd.name = 'App')::bigint AS applications_count,
                    max(CASE WHEN rhd.name = 'distance' AND rhd.value ~ '^[0-9]+$' THEN rhd.value::bigint ELSE NULL END) AS distance,
                    bool_or((lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                            AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%success%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%succeeded%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%logged in%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%valid credential%')) AS auth_success,
                    bool_or((lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                             OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')
                            AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%fail%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%denied%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%invalid%'
                                 OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%refused%')) AS auth_failure,
                    bool_or(lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'
                            OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'
                            OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%') AS has_credential_path
               FROM host_base hb
               LEFT JOIN report_host_details rhd ON rhd.report_host = hb.report_host_id
              GROUP BY hb.report_host_id
         ),
         result_counts AS (
             SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,
                    count(*)::bigint AS result_count,
                    count(DISTINCT nullif(r.nvt, '')) FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,
                    count(DISTINCT nullif(r.port, ''))::bigint AS ports_count,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 9.0)::bigint AS severity_critical,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 7.0 AND coalesce(r.severity, 0) < 9.0)::bigint AS severity_high,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) >= 4.0 AND coalesce(r.severity, 0) < 7.0)::bigint AS severity_medium,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) > 0.0 AND coalesce(r.severity, 0) < 4.0)::bigint AS severity_low,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) = 0.0)::bigint AS severity_log,
                    count(*) FILTER (WHERE coalesce(r.severity, 0) = -1.0)::bigint AS severity_false_positive,
                    coalesce(max(r.severity) FILTER (WHERE coalesce(r.severity, 0) > 0), 0)::double precision AS max_severity
               FROM selected_report sr
               JOIN results r ON r.report = sr.id
              WHERE coalesce(r.severity, 0) != -3.0
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
              GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))
         ),
         rows AS (
             SELECT hb.host, hb.hostname, dr.best_os_cpe, dr.best_os_txt,
                    coalesce(rc.ports_count, 0)::bigint AS ports_count,
                    coalesce(dr.applications_count, 0)::bigint AS applications_count,
                    dr.distance,
                    CASE WHEN coalesce(dr.auth_success, false) THEN 'authenticated'
                         WHEN coalesce(dr.auth_failure, false) THEN 'authentication_failed'
                         WHEN coalesce(dr.has_credential_path, false) THEN 'unknown'
                         ELSE 'no_credential_path' END AS authentication_state,
                    hb.start_time_unix, hb.end_time_unix,
                    coalesce(rc.result_count, 0)::bigint AS result_count,
                    coalesce(rc.vulnerability_count, 0)::bigint AS vulnerability_count,
                    coalesce(rc.severity_critical, 0)::bigint AS severity_critical,
                    coalesce(rc.severity_high, 0)::bigint AS severity_high,
                    coalesce(rc.severity_medium, 0)::bigint AS severity_medium,
                    coalesce(rc.severity_low, 0)::bigint AS severity_low,
                    coalesce(rc.severity_log, 0)::bigint AS severity_log,
                    coalesce(rc.severity_false_positive, 0)::bigint AS severity_false_positive,
                    coalesce(rc.max_severity, 0)::double precision AS max_severity,
                    hb.source_report_id
               FROM host_base hb
               LEFT JOIN detail_rows dr ON dr.report_host_id = hb.report_host_id
               LEFT JOIN result_counts rc ON rc.host_key = hb.host_key
         ),
         filtered AS (
             SELECT * FROM rows
              WHERE ($2 = ''
                     OR lower(host) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(best_os_cpe, '')) LIKE '%' || lower($2) || '%'
                     OR lower(coalesce(best_os_txt, '')) LIKE '%' || lower($2) || '%'
                     OR lower(authentication_state) LIKE '%' || lower($2) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, host ASC LIMIT $3 OFFSET $4;"#
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report host query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(report_host_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn targets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TargetItem>>, ApiError> {
    let params = normalize_collection_query(query, TARGET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TARGET_SORT_FIELDS)?;
    let sql = target_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(comment) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(port_list_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(hosts) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(target_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn target_detail(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> Result<Json<TargetItem>, ApiError> {
    parse_uuid(&target_id)?;
    let sql = target_sql("lower(uuid) = lower($1)", "name ASC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&target_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(target_from_row(&row)))
}

fn target_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH base AS (
             SELECT t.id AS target_pk,
                    t.uuid,
                    t.name,
                    coalesce(t.comment, '') AS comment,
                    coalesce(t.hosts, '') AS hosts,
                    coalesce(t.exclude_hosts, '') AS exclude_hosts,
                    coalesce(t.alive_test, 0)::bigint AS alive_test,
                    coalesce(t.allow_simultaneous_ips, 0)::int AS allow_simultaneous_ips,
                    coalesce(t.reverse_lookup_only, 0)::int AS reverse_lookup_only,
                    coalesce(t.reverse_lookup_unify, 0)::int AS reverse_lookup_unify,
                    pl.uuid AS port_list_id,
                    pl.name AS port_list_name,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_port,
                    coalesce(t.creation_time, 0)::bigint AS creation_time,
                    coalesce(t.modification_time, 0)::bigint AS modification_time,
                    CASE WHEN coalesce(t.hosts, '') = '' THEN 0::bigint
                         ELSE cardinality(string_to_array(t.hosts, ','))::bigint END AS host_entry_count,
                    count(task.id)::bigint AS task_count,
                    coalesce(array_agg(task.uuid ORDER BY task.name) FILTER (WHERE task.id IS NOT NULL), ARRAY[]::text[]) AS task_ids,
                    coalesce(array_agg(task.name ORDER BY task.name) FILTER (WHERE task.id IS NOT NULL), ARRAY[]::text[]) AS task_names
               FROM targets t
               LEFT JOIN port_lists pl ON pl.id = t.port_list
               LEFT JOIN tasks task
                 ON task.target = t.id
                AND coalesce(task.hidden, 0) = 0
                AND coalesce(task.usage_type, 'scan') = 'scan'
              GROUP BY t.id, t.uuid, t.name, t.comment, t.hosts, t.exclude_hosts,
                       t.alive_test, t.allow_simultaneous_ips, t.reverse_lookup_only,
                       t.reverse_lookup_unify, pl.uuid, pl.name,
                       t.creation_time, t.modification_time
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total, *
           FROM filtered
          ORDER BY {sort_sql}, name ASC {limit_clause};"#
    )
}

async fn tasks(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TaskItem>>, ApiError> {
    let params = normalize_collection_query(query, TASK_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TASK_SORT_FIELDS)?;
    let sql = task_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(comment) LIKE '%' || lower($1) || '%'\n\
            OR lower(status) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(target_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(config_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(scanner_name, '')) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(task_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn task_detail(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskItem>, ApiError> {
    parse_uuid(&task_id)?;
    let sql = task_sql("lower(uuid) = lower($1)", "name ASC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&task_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(task_from_row(&row)))
}

fn task_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH report_rollup AS (
             SELECT r.task,
                    count(DISTINCT r.id)::bigint AS report_count_total,
                    count(DISTINCT r.id) FILTER (WHERE run_status_name(coalesce(r.scan_run_status, 0)) = 'Done')::bigint AS report_count_finished,
                    coalesce(max(res.severity) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity
               FROM reports r
               LEFT JOIN results res ON res.report = r.id
              GROUP BY r.task
         ),
         report_rows AS (
             SELECT r.task,
                    r.id AS report_pk,
                    r.uuid,
                    coalesce(r.creation_time, 0)::bigint AS timestamp,
                    coalesce(r.start_time, 0)::bigint AS scan_start,
                    coalesce(r.end_time, 0)::bigint AS scan_end,
                    coalesce(max(res.severity) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS severity,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 9.0)::bigint AS critical_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 7.0 AND coalesce(res.severity, 0) < 9.0)::bigint AS high_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 4.0 AND coalesce(res.severity, 0) < 7.0)::bigint AS medium_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) > 0 AND coalesce(res.severity, 0) < 4.0)::bigint AS low_count,
                    run_status_name(coalesce(r.scan_run_status, 0)) AS status,
                    row_number() OVER (PARTITION BY r.task ORDER BY coalesce(nullif(r.end_time, 0), nullif(r.start_time, 0), nullif(r.creation_time, 0), 0) DESC, r.id DESC) AS latest_rank,
                    CASE WHEN run_status_name(coalesce(r.scan_run_status, 0)) = 'Done' THEN 1 ELSE 0 END AS is_finished
               FROM reports r
               LEFT JOIN results res ON res.report = r.id
              GROUP BY r.task, r.id, r.uuid, r.creation_time, r.start_time, r.end_time, r.scan_run_status
         ),
         finished_report_rows AS (
             SELECT *, row_number() OVER (PARTITION BY task ORDER BY coalesce(nullif(scan_end, 0), nullif(scan_start, 0), nullif(timestamp, 0), 0) DESC, report_pk DESC) AS finished_rank
               FROM report_rows
              WHERE is_finished = 1
         ),
         latest_report AS (
             SELECT * FROM report_rows WHERE latest_rank = 1
         ),
         latest_finished_report AS (
             SELECT * FROM finished_report_rows WHERE finished_rank = 1
         ),
         second_latest_finished_report AS (
             SELECT * FROM finished_report_rows WHERE finished_rank = 2
         ),
         base AS (
             SELECT task.id AS task_pk,
                    task.uuid,
                    task.name,
                    coalesce(task.comment, '') AS comment,
                    run_status_name(coalesce(task.run_status, 0)) AS status,
                    CASE WHEN run_status_name(coalesce(task.run_status, 0)) = 'Done' THEN 100::bigint
                         WHEN latest_report.report_pk IS NOT NULL THEN coalesce(report_progress(latest_report.report_pk), 0)::bigint
                         ELSE 0::bigint END AS progress,
                    CASE
                      WHEN coalesce(report_rollup.report_count_finished, 0) <= 1 THEN ''
                      WHEN run_status_name(coalesce(task.run_status, 0)) = 'Running' OR target.id IS NULL THEN ''
                      WHEN latest_finished_report.severity > second_latest_finished_report.severity THEN 'up'
                      WHEN second_latest_finished_report.severity > latest_finished_report.severity THEN 'down'
                      WHEN (CASE WHEN latest_finished_report.critical_count > 0 THEN 5
                                 WHEN latest_finished_report.high_count > 0 THEN 4
                                 WHEN latest_finished_report.medium_count > 0 THEN 3
                                 WHEN latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END)
                         > (CASE WHEN second_latest_finished_report.critical_count > 0 THEN 5
                                 WHEN second_latest_finished_report.high_count > 0 THEN 4
                                 WHEN second_latest_finished_report.medium_count > 0 THEN 3
                                 WHEN second_latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END) THEN 'up'
                      WHEN (CASE WHEN second_latest_finished_report.critical_count > 0 THEN 5
                                 WHEN second_latest_finished_report.high_count > 0 THEN 4
                                 WHEN second_latest_finished_report.medium_count > 0 THEN 3
                                 WHEN second_latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END)
                         > (CASE WHEN latest_finished_report.critical_count > 0 THEN 5
                                 WHEN latest_finished_report.high_count > 0 THEN 4
                                 WHEN latest_finished_report.medium_count > 0 THEN 3
                                 WHEN latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END) THEN 'down'
                      WHEN latest_finished_report.critical_count > 0 THEN
                        CASE WHEN latest_finished_report.critical_count > second_latest_finished_report.critical_count THEN 'more'
                             WHEN latest_finished_report.critical_count < second_latest_finished_report.critical_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.high_count > 0 THEN
                        CASE WHEN latest_finished_report.high_count > second_latest_finished_report.high_count THEN 'more'
                             WHEN latest_finished_report.high_count < second_latest_finished_report.high_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.medium_count > 0 THEN
                        CASE WHEN latest_finished_report.medium_count > second_latest_finished_report.medium_count THEN 'more'
                             WHEN latest_finished_report.medium_count < second_latest_finished_report.medium_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.low_count > 0 THEN
                        CASE WHEN latest_finished_report.low_count > second_latest_finished_report.low_count THEN 'more'
                             WHEN latest_finished_report.low_count < second_latest_finished_report.low_count THEN 'less'
                             ELSE 'same' END
                      ELSE 'same'
                    END AS trend,
                    coalesce(task.usage_type, 'scan') AS usage_type,
                    target.uuid AS target_id,
                    target.name AS target_name,
                    config.uuid AS config_id,
                    config.name AS config_name,
                    scanner.uuid AS scanner_id,
                    scanner.name AS scanner_name,
                    scanner.type AS scanner_type,
                    schedule.uuid AS schedule_id,
                    schedule.name AS schedule_name,
                    coalesce(report_rollup.report_count_total, 0)::bigint AS report_count_total,
                    coalesce(report_rollup.report_count_finished, 0)::bigint AS report_count_finished,
                    latest_report.uuid AS current_report_id,
                    latest_report.timestamp AS current_report_timestamp,
                    latest_report.scan_start AS current_report_scan_start,
                    latest_report.scan_end AS current_report_scan_end,
                    latest_report.severity AS current_report_severity,
                    latest_finished_report.uuid AS last_report_id,
                    latest_finished_report.timestamp AS last_report_timestamp,
                    latest_finished_report.scan_start AS last_report_scan_start,
                    latest_finished_report.scan_end AS last_report_scan_end,
                    latest_finished_report.severity AS last_report_severity,
                    coalesce(report_rollup.max_severity, 0)::double precision AS max_severity,
                    coalesce(task.creation_time, 0)::bigint AS creation_time,
                    coalesce(task.modification_time, 0)::bigint AS modification_time
               FROM tasks task
               LEFT JOIN targets target ON target.id = task.target
               LEFT JOIN configs config ON config.id = task.config
               LEFT JOIN scanners scanner ON scanner.id = task.scanner
               LEFT JOIN schedules schedule ON schedule.id = task.schedule
               LEFT JOIN report_rollup ON report_rollup.task = task.id
               LEFT JOIN latest_report ON latest_report.task = task.id
               LEFT JOIN latest_finished_report ON latest_finished_report.task = task.id
               LEFT JOIN second_latest_finished_report ON second_latest_finished_report.task = task.id
              WHERE coalesce(task.hidden, 0) = 0
                AND coalesce(task.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total, *
           FROM filtered
          ORDER BY {sort_sql}, name ASC {limit_clause};"#
    )
}

async fn scopes(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScopeItem>>, ApiError> {
    let params = normalize_collection_query(query, SCOPE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_SORT_FIELDS)?;
    let sql = scope_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(comment, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(protection_requirement) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope list query failed");
            ApiError::Database
        })?;
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| scope_from_row(row, Vec::new(), Vec::new(), Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_detail(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
) -> Result<Json<ScopeItem>, ApiError> {
    parse_uuid(&scope_id)?;
    let sql = scope_sql("lower(uuid) = lower($1)", "is_global DESC, name ASC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&scope_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let scope_pk: i32 = row.get(1);
    let is_global: i32 = row.get(7);
    let global = is_global != 0;
    let targets = scope_targets(&client, scope_pk, global).await?;
    let hosts = scope_hosts(&client, scope_pk, global).await?;
    let candidate_hosts = scope_candidate_hosts(&client, scope_pk, global).await?;
    let scope_reports = scope_report_references(&client, scope_pk).await?;
    Ok(Json(scope_from_row(
        &row,
        targets,
        hosts,
        candidate_hosts,
        scope_reports,
    )))
}

fn scope_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH base AS (
             SELECT s.id AS scope_pk,
                    s.uuid,
                    s.name,
                    coalesce(s.comment, '') AS comment,
                    s.protection_requirement,
                    coalesce(s.predefined, 0)::int AS predefined,
                    coalesce(s.is_global, 0)::int AS is_global,
                    coalesce(s.creation_time, 0)::bigint AS creation_time,
                    coalesce(s.modification_time, 0)::bigint AS modification_time,
                    CASE WHEN coalesce(s.is_global, 0) = 1
                         THEN (SELECT count(*) FROM targets)::bigint
                         ELSE (SELECT count(*) FROM scope_targets st WHERE st.scope = s.id)::bigint END AS target_count,
                    CASE WHEN coalesce(s.is_global, 0) = 1
                         THEN (SELECT count(*) FROM hosts)::bigint
                         ELSE (SELECT count(*) FROM scope_hosts sh WHERE sh.scope = s.id)::bigint END AS host_count,
                    (SELECT count(*) FROM scope_reports sr WHERE sr.scope = s.id)::bigint AS scope_report_count
               FROM scopes s
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total,
                scope_pk, uuid, name, comment, protection_requirement,
                predefined, is_global, creation_time, modification_time,
                target_count, host_count, scope_report_count
           FROM filtered
          ORDER BY {sort_sql}, uuid ASC {limit_clause};"#,
    )
}

async fn scope_targets(
    client: &tokio_postgres::Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeEntity>, ApiError> {
    let sql = if global {
        "SELECT uuid, coalesce(name, uuid) FROM targets ORDER BY name, uuid;"
    } else {
        "SELECT target_uuid, coalesce(target_name, target_uuid) FROM scope_targets WHERE scope = $1 ORDER BY target_name, target_uuid;"
    };
    let rows = if global {
        client.query(sql, &[]).await
    } else {
        client.query(sql, &[&scope_pk]).await
    }
    .map_err(|error| {
        tracing::warn!(%error, "scope targets query failed");
        ApiError::Database
    })?;
    Ok(rows.iter().map(scope_entity_from_row).collect())
}

async fn scope_hosts(
    client: &tokio_postgres::Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeEntity>, ApiError> {
    let sql = if global {
        "SELECT uuid, coalesce(name, uuid) FROM hosts ORDER BY name, uuid;"
    } else {
        "SELECT host_uuid, coalesce(host_name, host_uuid) FROM scope_hosts WHERE scope = $1 ORDER BY host_name, host_uuid;"
    };
    let rows = if global {
        client.query(sql, &[]).await
    } else {
        client.query(sql, &[&scope_pk]).await
    }
    .map_err(|error| {
        tracing::warn!(%error, "scope hosts query failed");
        ApiError::Database
    })?;
    Ok(rows.iter().map(scope_entity_from_row).collect())
}

fn scope_candidate_hosts_sql() -> &'static str {
    "WITH newest_reports AS (\n\
         SELECT DISTINCT ON (t.id) t.id AS target, r.id AS report, r.uuid AS report_uuid\n\
           FROM targets t\n\
           JOIN scope_targets st ON st.target = t.id\n\
           JOIN tasks task ON task.target = t.id\n\
           JOIN reports r ON r.task = task.id\n\
          WHERE st.scope = $1\n\
            AND coalesce(task.usage_type, 'scan') = 'scan'\n\
            AND run_status_name(coalesce(r.scan_run_status, 0)) = 'Done'\n\
          ORDER BY t.id, coalesce(r.end_time, r.creation_time) DESC, r.id DESC\n\
     )\n\
     SELECT DISTINCT rh.host::text, st.target_uuid::text, coalesce(st.target_name, st.target_uuid)::text, nr.report_uuid::text\n\
       FROM scope_targets st\n\
       JOIN newest_reports nr ON nr.target = st.target\n\
       JOIN report_hosts rh ON rh.report = nr.report\n\
      WHERE st.scope = $1\n\
        AND coalesce(rh.host, '') <> ''\n\
        AND NOT EXISTS (\n\
            SELECT 1 FROM scope_hosts sh\n\
            JOIN hosts h ON h.id = sh.host\n\
            WHERE sh.scope = $1 AND lower(h.name) = lower(rh.host)\n\
        )\n\
      ORDER BY rh.host, st.target_uuid;"
}

async fn scope_candidate_hosts(
    client: &tokio_postgres::Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeCandidateHost>, ApiError> {
    if global {
        return Ok(Vec::new());
    }
    let rows = client
        .query(scope_candidate_hosts_sql(), &[&scope_pk])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope candidate hosts query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(scope_candidate_host_from_row).collect())
}

async fn scope_report_references(
    client: &tokio_postgres::Client,
    scope_pk: i32,
) -> Result<Vec<ScopeReportReference>, ApiError> {
    let rows = client
        .query(
            "SELECT uuid, scope_name, creation_time::bigint, latest_evidence_time::bigint,\n\
                    source_report_count::bigint, member_host_count::bigint,\n\
                    evidence_host_count::bigint, missing_host_count::bigint,\n\
                    result_count::bigint, vulnerability_count::bigint,\n\
                    max_severity::double precision\n\
               FROM scope_reports\n\
              WHERE scope = $1\n\
              ORDER BY creation_time DESC, id DESC;",
            &[&scope_pk],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report references query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(scope_report_reference_from_row).collect())
}

fn raw_report_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH base AS (
             SELECT r.id AS report_pk,
                    r.uuid,
                    coalesce(nullif(t.name, ''), r.uuid) AS name,
                    coalesce(u.name, '') AS owner_name,
                    t.uuid AS task_uuid,
                    t.name AS task_name,
                    tg.uuid AS target_uuid,
                    tg.name AS target_name,
                    run_status_name(coalesce(r.scan_run_status, 0)) AS status,
                    coalesce(r.creation_time, 0)::bigint AS creation_time,
                    coalesce(r.start_time, 0)::bigint AS scan_start,
                    coalesce(r.end_time, 0)::bigint AS scan_end,
                    coalesce(r.modification_time, 0)::bigint AS modification_time
               FROM reports r
               LEFT JOIN tasks t ON t.id = r.task
               LEFT JOIN users u ON u.id = r.owner
               LEFT JOIN targets tg ON tg.id = t.target
              WHERE (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
         ),
         result_agg AS (
             SELECT b.report_pk,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) != -3.0)::bigint AS result_count,
                    count(DISTINCT nullif(res.nvt, '')) FILTER (WHERE coalesce(res.severity, 0) != -3.0)::bigint AS vulnerability_count,
                    coalesce(max(coalesce(res.severity, 0)) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) >= 9.0)::bigint AS severity_critical,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) >= 7.0 AND coalesce(res.severity, 0) < 9.0)::bigint AS severity_high,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) >= 4.0 AND coalesce(res.severity, 0) < 7.0)::bigint AS severity_medium,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) > 0.0 AND coalesce(res.severity, 0) < 4.0)::bigint AS severity_low,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) = 0.0)::bigint AS severity_log,
                    count(res.id) FILTER (WHERE coalesce(res.severity, 0) = -1.0)::bigint AS severity_false_positive
               FROM base b
               LEFT JOIN results res ON res.report = b.report_pk
              GROUP BY b.report_pk
         ),
         host_agg AS (
             SELECT b.report_pk,
                    count(DISTINCT lower(rh.host)) FILTER (WHERE coalesce(rh.host, '') <> '')::bigint AS host_count
               FROM base b
               LEFT JOIN report_hosts rh ON rh.report = b.report_pk
              GROUP BY b.report_pk
         ),
         cve_agg AS (
             SELECT b.report_pk,
                    count(DISTINCT lower(vr.ref_id)) FILTER (WHERE coalesce(vr.ref_id, '') <> '')::bigint AS cve_count
               FROM base b
               LEFT JOIN results res ON res.report = b.report_pk AND coalesce(res.severity, 0) > 0
               LEFT JOIN vt_refs vr ON vr.vt_oid = res.nvt AND lower(vr.type) = 'cve'
              GROUP BY b.report_pk
         ),
         joined AS (
             SELECT b.uuid, b.name, b.owner_name, b.task_uuid, b.task_name, b.target_uuid, b.target_name,
                    b.status, b.creation_time, b.scan_start, b.scan_end, b.modification_time,
                    coalesce(ra.result_count, 0)::bigint AS result_count,
                    coalesce(ra.vulnerability_count, 0)::bigint AS vulnerability_count,
                    coalesce(ha.host_count, 0)::bigint AS host_count,
                    coalesce(ca.cve_count, 0)::bigint AS cve_count,
                    coalesce(ra.max_severity, 0)::double precision AS max_severity,
                    coalesce(ra.severity_critical, 0)::bigint AS severity_critical,
                    coalesce(ra.severity_high, 0)::bigint AS severity_high,
                    coalesce(ra.severity_medium, 0)::bigint AS severity_medium,
                    coalesce(ra.severity_low, 0)::bigint AS severity_low,
                    coalesce(ra.severity_log, 0)::bigint AS severity_log,
                    coalesce(ra.severity_false_positive, 0)::bigint AS severity_false_positive
               FROM base b
               LEFT JOIN result_agg ra ON ra.report_pk = b.report_pk
               LEFT JOIN host_agg ha ON ha.report_pk = b.report_pk
               LEFT JOIN cve_agg ca ON ca.report_pk = b.report_pk
         ),
         filtered AS (
             SELECT * FROM joined WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total,
                uuid, name, owner_name, task_uuid, task_name, target_uuid, target_name, status,
                creation_time, scan_start, scan_end, modification_time,
                result_count, vulnerability_count, host_count, cve_count, max_severity,
                severity_critical, severity_high, severity_medium, severity_low,
                severity_log, severity_false_positive
           FROM filtered
          ORDER BY {sort_sql}, creation_time DESC, uuid DESC {limit_clause};"#,
    )
}

async fn report_user_tags(
    client: &tokio_postgres::Client,
    report_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.value, '') AS value,
                      coalesce(t.comment, '') AS comment
                 FROM tags t
                 JOIN tag_resources tr ON tr.tag = t.id
                 JOIN reports r ON r.id = tr.resource
                WHERE lower(r.uuid) = lower($1)
                  AND tr.resource_type = 'report'
                  AND tr.resource_location = 0
                  AND coalesce(t.active, 0) = 1
                ORDER BY t.name ASC, t.uuid ASC;"#,
            &[&report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn scope_report_results(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, REPORT_RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_RESULT_SORT_FIELDS)?;
    let sql = scope_report_results_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report result query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

fn scope_report_results_sql(sort_sql: &str) -> String {
    format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         ranked AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    nullif(r.hostname, '') AS hostname,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
                    nullif(n.family, '') AS nvt_family,\n\
                    n.cve AS cve_text,\n\
                    n.epss_score::double precision AS epss_score,\n\
                    n.epss_percentile::double precision AS epss_percentile,\n\
                    n.epss_cve AS epss_cve,\n\
                    n.epss_severity::double precision AS epss_severity,\n\
                    n.max_epss_score::double precision AS max_epss_score,\n\
                    n.max_epss_percentile::double precision AS max_epss_percentile,\n\
                    n.max_epss_cve AS max_epss_cve,\n\
                    n.max_epss_severity::double precision AS max_epss_severity,\n\
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(r.qod, 0)::bigint AS qod,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    row_number () OVER (\n\
                      PARTITION BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                                   coalesce(r.nvt, ''), coalesce(r.port, '')\n\
                      ORDER BY coalesce(r.severity, 0) DESC, coalesce(r.date, 0) DESC, r.id DESC\n\
                    ) AS rn\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
               LEFT JOIN nvts n ON n.oid = r.nvt\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         result_rows AS (\n\
             SELECT id, host, hostname, port, nvt_oid, name, nvt_family, cve_text, epss_score, epss_percentile, epss_cve, epss_severity, max_epss_score, max_epss_percentile, max_epss_cve, max_epss_severity, description_excerpt, severity, qod, created_at_unix, source_report_id\n\
               FROM ranked WHERE rn = 1\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM result_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($3) || '%'\n\
                     OR lower(name) LIKE '%' || lower($3) || '%')\n\
         ),\n\
         page_rows AS (\n\
             SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $4 OFFSET $5\n\
         ),\n\
         page_with_refs AS (\n\
             SELECT p.*,\n\
                    CASE\n\
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0\n\
                      THEN refs.cves\n\
                      WHEN coalesce(p.cve_text, '') <> ''\n\
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')\n\
                      ELSE ARRAY[]::text[]\n\
                    END AS cves,\n\
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,\n\
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs\n\
               FROM page_rows p\n\
               LEFT JOIN LATERAL (\n\
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs\n\
                     FROM vt_refs vr\n\
                    WHERE vr.vt_oid = p.nvt_oid\n\
               ) refs ON true\n\
         )\n\
         SELECT * FROM page_with_refs;"
    )
}

async fn scope_report_metrics(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
) -> Result<Json<MetricsPayload>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let summary_row = client
        .query_opt(
            "SELECT sr.id, sr.uuid,\n\
                    coalesce(sr.metric_total_system_cvss_load, 0)::double precision AS total_system_cvss_load,\n\
                    coalesce(sr.metric_average_system_cvss_load, 0)::double precision AS average_system_cvss_load,\n\
                    coalesce(sr.metric_authenticated_scan_coverage, 0)::double precision AS authenticated_scan_coverage_percent,\n\
                    coalesce(sr.metric_alive_system_count, 0)::bigint AS alive_system_count,\n\
                    (SELECT count(*) FROM scope_report_vulnerability_metrics srvm WHERE srvm.scope_report = sr.id)::bigint AS vulnerability_count,\n\
                    coalesce(sr.metric_authenticated_system_count, 0)::bigint AS authenticated_system_count,\n\
                    coalesce(sr.metric_auth_failed_system_count, 0)::bigint AS authentication_failed_system_count,\n\
                    coalesce(sr.metric_no_credential_path_system_count, 0)::bigint AS no_credential_path_system_count,\n\
                    coalesce(sr.metric_unknown_authentication_system_count, 0)::bigint AS unknown_authentication_system_count\n\
               FROM scope_reports sr\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2;",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report metrics summary query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = summary_row.get(0);
    let systems_rows = client
        .query(
            "SELECT host, cvss_load, max_cvss, vulnerability_count::bigint, authentication_state, source_report_count::bigint\n\
               FROM scope_report_system_metrics\n\
              WHERE scope_report = $1\n\
              ORDER BY cvss_load DESC, host ASC;",
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report metrics systems query failed");
            ApiError::Database
        })?;
    let vulnerability_rows = client
        .query(
            "SELECT nvt_oid, nvt_name, cvss_score, affected_system_count::bigint, cvss_load, average_contribution, source_report_count::bigint\n\
               FROM scope_report_vulnerability_metrics\n\
              WHERE scope_report = $1\n\
              ORDER BY cvss_load DESC, cvss_score DESC, nvt_name ASC;",
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report metrics vulnerabilities query failed");
            ApiError::Database
        })?;
    Ok(Json(MetricsPayload {
        id: summary_row.get(1),
        summary: metrics_summary_from_row(&summary_row),
        systems: systems_rows.iter().map(metrics_system_from_row).collect(),
        vulnerabilities: vulnerability_rows
            .iter()
            .map(metrics_vulnerability_from_row)
            .collect(),
    }))
}

async fn scope_report_retention_plan(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
) -> Result<Json<ScopeReportRetentionPlan>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let report_row = client
        .query_opt(
            "SELECT id, uuid, scope_uuid, scope_name, creation_time::bigint\n\
               FROM scope_reports\n\
              WHERE uuid = $1 AND scope_uuid = $2;",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report retention plan header query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = report_row.get(0);
    let source_rows = client
        .query(scope_report_retention_sources_sql(), &[&internal_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report retention plan source query failed");
            ApiError::Database
        })?;
    let sources: Vec<_> = source_rows
        .iter()
        .map(scope_report_retention_source_from_row)
        .collect();
    let source_report_count = sources.len() as i64;
    let current_full_fidelity_count = sources
        .iter()
        .filter(|source| source.kept_as_latest)
        .count() as i64;
    let future_tiered_retention_candidate_count = sources
        .iter()
        .filter(|source| source.future_tiered_retention_candidate)
        .count() as i64;
    let scope_name: String = report_row.get(3);
    Ok(Json(ScopeReportRetentionPlan {
        id: report_row.get(1),
        name: format!("{scope_name} scope report retention plan"),
        scope: ScopeSummary {
            id: report_row.get(2),
            name: scope_name,
        },
        generated_at: unix_ts_to_rfc3339(report_row.get(4)),
        policy: ScopeReportRetentionPolicyPreview {
            mode: "dry_run_preview".to_string(),
            destructive_actions: false,
            latest_completed_raw_report_retains_full_detail: true,
            detail_compacted_field: "detail_compacted".to_string(),
            aggregate_only_field: "aggregate_only".to_string(),
        },
        summary: ScopeReportRetentionSummary {
            source_report_count,
            current_full_fidelity_count,
            future_tiered_retention_candidate_count,
            detail_compacted_count: 0,
            aggregate_only_count: 0,
        },
        sources,
    }))
}

fn scope_report_retention_sources_sql() -> &'static str {
    "WITH latest_completed AS (\n\
         SELECT DISTINCT ON (task.target)\n\
                task.target AS target, reports.id AS source_report\n\
           FROM reports\n\
           JOIN tasks task ON task.id = reports.task\n\
          WHERE coalesce(task.usage_type, 'scan') = 'scan'\n\
            AND reports.scan_run_status = 1\n\
          ORDER BY task.target, coalesce(reports.end_time, reports.creation_time) DESC, reports.id DESC\n\
     ),\n\
     source_rows AS (\n\
         SELECT srs.source_report, srs.source_report_uuid, srs.target,\n\
                srs.target_uuid, srs.target_name, srs.task_uuid, srs.task_name,\n\
                srs.scan_start::bigint, srs.scan_end::bigint, srs.selected_time::bigint,\n\
                (lc.source_report = srs.source_report) AS kept_as_latest\n\
           FROM scope_report_sources srs\n\
           LEFT JOIN latest_completed lc ON lc.target = srs.target\n\
          WHERE srs.scope_report = $1\n\
     )\n\
     SELECT sr.source_report_uuid::text, sr.target_uuid::text,\n\
            coalesce(nullif(sr.target_name, ''), sr.target_uuid)::text AS target_name,\n\
            sr.task_uuid::text, coalesce(sr.task_name, '')::text AS task_name,\n\
            coalesce(sr.scan_start, 0)::bigint AS scan_start,\n\
            coalesce(sr.scan_end, 0)::bigint AS scan_end,\n\
            coalesce(sr.selected_time, 0)::bigint AS selected_time,\n\
            count(res.id) FILTER (WHERE coalesce(res.severity, 0) != -3.0)::bigint AS result_count,\n\
            count(DISTINCT nullif(res.nvt, '')) FILTER (WHERE coalesce(res.severity, 0) > 0)::bigint AS vulnerability_count,\n\
            coalesce(max(coalesce(res.severity, 0)) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity,\n\
            coalesce(sr.kept_as_latest, false) AS kept_as_latest\n\
       FROM source_rows sr\n\
       LEFT JOIN results res ON res.report = sr.source_report\n\
      GROUP BY sr.source_report_uuid, sr.target_uuid, sr.target_name, sr.task_uuid,\n\
               sr.task_name, sr.scan_start, sr.scan_end, sr.selected_time, sr.kept_as_latest\n\
      ORDER BY target_name ASC, sr.target_uuid ASC, scan_end DESC, sr.source_report_uuid ASC;"
}

async fn report_metrics(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<MetricsPayload>, ApiError> {
    parse_uuid(&report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let report_row = client
        .query_opt(
            "SELECT id, uuid FROM reports WHERE uuid = $1;",
            &[&report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report metrics report lookup failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = report_row.get(0);

    let system_rows = client
        .query(
            "WITH source_reports AS (\n\
                 SELECT r.id AS source_report, t.target AS target\n\
                   FROM reports r JOIN tasks t ON t.id = r.task\n\
                  WHERE r.id = $1\n\
             ),\n\
             alive AS (\n\
                 SELECT lower(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host_key,\n\
                        min(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host,\n\
                        count(DISTINCT rh.report)::bigint AS source_report_count,\n\
                        bool_or(EXISTS (SELECT 1 FROM targets_login_data tld\n\
                                         WHERE tld.target = sr.target\n\
                                           AND coalesce(tld.credential, 0) > 0)) AS has_credential_path,\n\
                        bool_or(EXISTS (\n\
                          SELECT 1 FROM report_host_details rhd\n\
                           WHERE rhd.report_host = rh.id\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%success%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%succeeded%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%logged in%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%valid credential%')\n\
                        )) AS auth_success,\n\
                        bool_or(EXISTS (\n\
                          SELECT 1 FROM report_host_details rhd\n\
                           WHERE rhd.report_host = rh.id\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%fail%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%denied%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%invalid%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%refused%')\n\
                        )) AS auth_failure\n\
                   FROM report_hosts rh\n\
                   JOIN source_reports sr ON sr.source_report = rh.report\n\
                  WHERE coalesce(nullif(rh.host, ''), rh.hostname, '') <> ''\n\
                  GROUP BY lower(coalesce(nullif(rh.host, ''), rh.hostname, ''))\n\
             ),\n\
             vuln_by_system AS (\n\
                 SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                        coalesce(nullif(r.nvt, ''), 'unknown') AS nvt_oid,\n\
                        max(coalesce(r.severity, 0))::double precision AS cvss_score\n\
                   FROM results r\n\
                   JOIN source_reports sr ON sr.source_report = r.report\n\
                  WHERE coalesce(r.severity, 0) > 0\n\
                    AND coalesce(r.severity, 0) != -3.0\n\
                    AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                  GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                           coalesce(nullif(r.nvt, ''), 'unknown')\n\
             ),\n\
             system_load AS (\n\
                 SELECT host_key, sum(cvss_score)::double precision AS cvss_load,\n\
                        max(cvss_score)::double precision AS max_cvss,\n\
                        count(*)::bigint AS vulnerability_count\n\
                   FROM vuln_by_system GROUP BY host_key\n\
             )\n\
             SELECT alive.host::text,\n\
                    coalesce(system_load.cvss_load, 0)::double precision,\n\
                    coalesce(system_load.max_cvss, 0)::double precision,\n\
                    coalesce(system_load.vulnerability_count, 0)::bigint,\n\
                    CASE WHEN alive.auth_success THEN 'authenticated'\n\
                         WHEN alive.auth_failure THEN 'authentication_failed'\n\
                         WHEN alive.has_credential_path THEN 'unknown'\n\
                         ELSE 'no_credential_path' END::text,\n\
                    alive.source_report_count::bigint\n\
               FROM alive LEFT JOIN system_load USING (host_key)\n\
              ORDER BY coalesce(system_load.cvss_load, 0) DESC, alive.host ASC;",
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report metrics systems query failed");
            ApiError::Database
        })?;
    let systems: Vec<MetricsSystem> = system_rows.iter().map(metrics_system_from_row).collect();
    let alive_system_count = systems.len() as i64;

    let vulnerability_rows = client
        .query(
            "WITH source_reports AS (\n\
                 SELECT r.id AS source_report, t.target AS target\n\
                   FROM reports r JOIN tasks t ON t.id = r.task\n\
                  WHERE r.id = $1\n\
             ),\n\
             deduped_results AS (\n\
                 SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                        coalesce(nullif(r.nvt, ''), 'unknown') AS nvt_oid,\n\
                        max(coalesce(n.name, r.nvt, 'Unknown vulnerability')) AS nvt_name,\n\
                        max(coalesce(r.severity, 0))::double precision AS cvss_score,\n\
                        r.report AS source_report\n\
                   FROM results r\n\
                   JOIN source_reports sr ON sr.source_report = r.report\n\
                   LEFT JOIN nvts n ON n.oid = r.nvt\n\
                  WHERE coalesce(r.severity, 0) > 0\n\
                    AND coalesce(r.severity, 0) != -3.0\n\
                    AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                  GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                           coalesce(nullif(r.nvt, ''), 'unknown'), r.report\n\
             ),\n\
             vuln_by_system AS (\n\
                 SELECT host_key, nvt_oid, max(nvt_name) AS nvt_name,\n\
                        max(cvss_score)::double precision AS cvss_score\n\
                   FROM deduped_results\n\
                  GROUP BY host_key, nvt_oid\n\
             ),\n\
             vuln_sources AS (\n\
                 SELECT nvt_oid, count(DISTINCT source_report)::bigint AS source_report_count\n\
                   FROM deduped_results\n\
                  GROUP BY nvt_oid\n\
             )\n\
             SELECT v.nvt_oid::text, max(v.nvt_name)::text,\n\
                    max(v.cvss_score)::double precision,\n\
                    count(DISTINCT v.host_key)::bigint,\n\
                    (max(v.cvss_score) * count(DISTINCT v.host_key))::double precision,\n\
                    CASE WHEN $2::bigint > 0\n\
                         THEN ((max(v.cvss_score) * count(DISTINCT v.host_key)) / $2::double precision)::double precision\n\
                         ELSE 0::double precision END,\n\
                    coalesce(max(vs.source_report_count), 0)::bigint\n\
               FROM vuln_by_system v\n\
               LEFT JOIN vuln_sources vs ON vs.nvt_oid = v.nvt_oid\n\
              GROUP BY v.nvt_oid\n\
              ORDER BY (max(v.cvss_score) * count(DISTINCT v.host_key)) DESC,\n\
                       max(v.cvss_score) DESC, max(v.nvt_name) ASC;",
            &[&internal_id, &alive_system_count],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report metrics vulnerabilities query failed");
            ApiError::Database
        })?;
    let vulnerabilities: Vec<MetricsVulnerability> = vulnerability_rows
        .iter()
        .map(metrics_vulnerability_from_row)
        .collect();
    Ok(Json(MetricsPayload {
        id: report_row.get(1),
        summary: summarize_metrics(&systems, vulnerabilities.len() as i64),
        systems,
        vulnerabilities,
    }))
}

async fn scope_report_errors(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ErrorMessageItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_ERROR_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_ERROR_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         error_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    coalesce(r.port, '') AS port,\n\
                    r.nvt AS nvt_oid,\n\
                    coalesce(r.description, '') AS description,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE (r.type = 'Error Message' OR coalesce(r.severity, 0) = -3)\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM error_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($3) || '%'\n\
                     OR lower(description) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report error-message query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(error_message_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_reports(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScopeReportItem>>, ApiError> {
    let params = normalize_collection_query(query, SCOPE_REPORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_SORT_FIELDS)?;
    let sql = format!(
        "WITH filtered AS (\n\
           SELECT sr.id, sr.scope, sr.uuid, sr.scope_uuid, sr.scope_name, sr.protection_requirement,\n\
                  sr.source_report_count::bigint, sr.source_target_count::bigint,\n\
                  sr.member_host_count::bigint, sr.evidence_host_count::bigint,\n\
                  sr.missing_host_count::bigint, sr.result_count::bigint,\n\
                  sr.vulnerability_count::bigint, sr.max_severity::double precision,\n\
                  sr.latest_evidence_time::bigint, sr.excluded_candidate_host_count::bigint,\n\
                  sr.creation_time::bigint, sr.modification_time::bigint,\n\
                  coalesce(s.is_global, 0)::int AS is_global\n\
             FROM scope_reports sr\n\
             JOIN scopes s ON s.id = sr.scope\n\
            WHERE ($1 = '' OR lower(sr.uuid) = lower($1)\n\
                   OR lower(sr.scope_uuid) = lower($1)\n\
                   OR lower(sr.scope_name) LIKE '%' || lower($1) || '%')\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT f.id AS scope_report_id, lower(rh.host) AS host_key\n\
               FROM filtered f\n\
               JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE f.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY f.id, lower(rh.host)\n\
             UNION\n\
             SELECT f.id AS scope_report_id, lower(h.name) AS host_key\n\
               FROM filtered f\n\
               JOIN scope_hosts sh ON sh.scope = f.scope AND f.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY f.id, lower(h.name)\n\
         ),\n\
         ranked_results AS (\n\
             SELECT f.id AS scope_report_id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    row_number () OVER (\n\
                      PARTITION BY f.id, lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                                   coalesce(r.nvt, ''), coalesce(r.port, '')\n\
                      ORDER BY coalesce(r.severity, 0) DESC, coalesce(r.date, 0) DESC, r.id DESC\n\
                    ) AS rn\n\
               FROM filtered f\n\
               JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.scope_report_id = f.id\n\
                                      AND sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         severity_counts AS (\n\
             SELECT scope_report_id,\n\
                    count(*) FILTER (WHERE severity >= 7.0)::bigint AS severity_high,\n\
                    count(*) FILTER (WHERE severity >= 4.0 AND severity < 7.0)::bigint AS severity_medium,\n\
                    count(*) FILTER (WHERE severity > 0.0 AND severity < 4.0)::bigint AS severity_low,\n\
                    count(*) FILTER (WHERE severity = 0.0)::bigint AS severity_log,\n\
                    count(*) FILTER (WHERE severity = -1.0)::bigint AS severity_false_positive\n\
               FROM ranked_results\n\
              WHERE rn = 1\n\
              GROUP BY scope_report_id\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total,\n\
                f.uuid, f.scope_uuid, f.scope_name, f.protection_requirement,\n\
                f.source_report_count, f.source_target_count, f.member_host_count,\n\
                f.evidence_host_count, f.missing_host_count, f.result_count,\n\
                f.vulnerability_count, f.max_severity, f.latest_evidence_time,\n\
                f.excluded_candidate_host_count, f.creation_time, f.modification_time,\n\
                coalesce(sc.severity_high, 0)::bigint,\n\
                coalesce(sc.severity_medium, 0)::bigint,\n\
                coalesce(sc.severity_low, 0)::bigint,\n\
                coalesce(sc.severity_log, 0)::bigint,\n\
                coalesce(sc.severity_false_positive, 0)::bigint\n\
           FROM filtered f\n\
           LEFT JOIN severity_counts sc ON sc.scope_report_id = f.id\n\
          ORDER BY {sort_sql}, uuid DESC LIMIT $2 OFFSET $3;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report query failed");
            ApiError::Database
        })?;
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(scope_report_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_detail(
    State(state): State<AppState>,
    Path(scope_report_id): Path<String>,
) -> Result<Json<ScopeReportDetail>, ApiError> {
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            "WITH selected_scope_report AS (\n\
               SELECT sr.id, sr.scope, sr.uuid, sr.scope_uuid, sr.scope_name, sr.protection_requirement,\n\
                      sr.source_report_count::bigint, sr.source_target_count::bigint,\n\
                      sr.member_host_count::bigint, sr.evidence_host_count::bigint,\n\
                      sr.missing_host_count::bigint, sr.result_count::bigint,\n\
                      sr.vulnerability_count::bigint, sr.max_severity::double precision,\n\
                      sr.latest_evidence_time::bigint, sr.excluded_candidate_host_count::bigint,\n\
                      sr.creation_time::bigint, sr.modification_time::bigint,\n\
                      coalesce(s.is_global, 0)::int AS is_global\n\
                 FROM scope_reports sr\n\
                 JOIN scopes s ON s.id = sr.scope\n\
                WHERE lower(sr.uuid) = lower($1)\n\
             ),\n\
             selected_hosts AS (\n\
                 SELECT f.id AS scope_report_id, lower(rh.host) AS host_key\n\
                   FROM selected_scope_report f\n\
                   JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
                   JOIN report_hosts rh ON rh.report = srs.source_report\n\
                  WHERE f.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
                  GROUP BY f.id, lower(rh.host)\n\
                 UNION\n\
                 SELECT f.id AS scope_report_id, lower(h.name) AS host_key\n\
                   FROM selected_scope_report f\n\
                   JOIN scope_hosts sh ON sh.scope = f.scope AND f.is_global = 0\n\
                   JOIN hosts h ON h.id = sh.host\n\
                  WHERE coalesce(h.name, '') <> ''\n\
                  GROUP BY f.id, lower(h.name)\n\
             ),\n\
             ranked_results AS (\n\
                 SELECT f.id AS scope_report_id,\n\
                        lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                        coalesce(r.nvt, '') AS nvt_oid,\n\
                        coalesce(r.port, '') AS port,\n\
                        coalesce(r.severity, 0)::double precision AS severity,\n\
                        row_number () OVER (\n\
                          PARTITION BY f.id, lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                                       coalesce(r.nvt, ''), coalesce(r.port, '')\n\
                          ORDER BY coalesce(r.severity, 0) DESC, coalesce(r.date, 0) DESC, r.id DESC\n\
                        ) AS rn\n\
                   FROM selected_scope_report f\n\
                   JOIN scope_report_sources srs ON srs.scope_report = f.id\n\
                   JOIN results r ON r.report = srs.source_report\n\
                   JOIN selected_hosts sh ON sh.scope_report_id = f.id\n\
                                          AND sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
                  WHERE coalesce(r.severity, 0) != -3.0\n\
                    AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
             ),\n\
             severity_counts AS (\n\
                 SELECT scope_report_id,\n\
                        count(*) FILTER (WHERE severity >= 7.0)::bigint AS severity_high,\n\
                        count(*) FILTER (WHERE severity >= 4.0 AND severity < 7.0)::bigint AS severity_medium,\n\
                        count(*) FILTER (WHERE severity > 0.0 AND severity < 4.0)::bigint AS severity_low,\n\
                        count(*) FILTER (WHERE severity = 0.0)::bigint AS severity_log,\n\
                        count(*) FILTER (WHERE severity = -1.0)::bigint AS severity_false_positive\n\
                   FROM ranked_results\n\
                  WHERE rn = 1\n\
                  GROUP BY scope_report_id\n\
             )\n\
             SELECT 1::bigint AS total,\n\
                    f.uuid, f.scope_uuid, f.scope_name, f.protection_requirement,\n\
                    f.source_report_count, f.source_target_count, f.member_host_count,\n\
                    f.evidence_host_count, f.missing_host_count, f.result_count,\n\
                    f.vulnerability_count, f.max_severity, f.latest_evidence_time,\n\
                    f.excluded_candidate_host_count, f.creation_time, f.modification_time,\n\
                    coalesce(sc.severity_high, 0)::bigint,\n\
                    coalesce(sc.severity_medium, 0)::bigint,\n\
                    coalesce(sc.severity_low, 0)::bigint,\n\
                    coalesce(sc.severity_log, 0)::bigint,\n\
                    coalesce(sc.severity_false_positive, 0)::bigint\n\
               FROM selected_scope_report f\n\
               LEFT JOIN severity_counts sc ON sc.scope_report_id = f.id;",
            &[&scope_report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let sources = client
        .query(
            "SELECT srs.id::bigint AS id,\n\
                    coalesce(srs.source_report_uuid, '') AS source_report_id,\n\
                    coalesce(srs.target_uuid, '') AS target_id,\n\
                    coalesce(srs.target_name, '') AS target_name,\n\
                    coalesce(srs.task_uuid, '') AS task_id,\n\
                    coalesce(srs.task_name, '') AS task_name,\n\
                    srs.scan_end::bigint AS scan_end\n\
               FROM scope_report_sources srs\n\
               JOIN scope_reports sr ON sr.id = srs.scope_report\n\
              WHERE lower(sr.uuid) = lower($1)\n\
              ORDER BY lower(coalesce(srs.target_name, '')), srs.target_uuid, srs.source_report_uuid;",
            &[&scope_report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report source query failed");
            ApiError::Database
        })?;

    Ok(Json(ScopeReportDetail {
        report: scope_report_from_row(&row),
        sources: sources.iter().map(scope_report_source_from_row).collect(),
    }))
}

async fn scope_report_hosts(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<HostItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_HOST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_HOST_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         member_hosts AS (\n\
             SELECT lower(h.name) AS host_key, min(h.name) AS host\n\
               FROM selected_scope_report sr\n\
               JOIN hosts h ON sr.is_global = 1\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key, min(h.name) AS host\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         evidence_hosts AS (\n\
             SELECT lower(rh.host) AS host_key, min(rh.host) AS host,\n\
                    count(DISTINCT srs.source_report)::bigint AS source_report_count,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
         ),\n\
         result_counts AS (\n\
             SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    count(DISTINCT (coalesce(r.nvt, ''), coalesce(r.port, '')))::bigint AS result_count\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
         ),\n\
         host_rows AS (\n\
             SELECT coalesce(m.host_key, e.host_key) AS host_key,\n\
                    coalesce(m.host, e.host) AS host,\n\
                    m.host_key IS NOT NULL AS is_member,\n\
                    e.host_key IS NOT NULL AS has_evidence,\n\
                    coalesce(e.source_report_count, 0)::bigint AS source_report_count,\n\
                    coalesce(e.source_report_ids, ARRAY[]::text[]) AS source_report_ids\n\
               FROM member_hosts m\n\
               FULL OUTER JOIN evidence_hosts e ON e.host_key = m.host_key\n\
         ),\n\
         rows AS (\n\
             SELECT hr.host,\n\
                    CASE\n\
                      WHEN sr.is_global = 1 THEN 'organization'\n\
                      WHEN hr.is_member THEN 'member'\n\
                      ELSE 'candidate'\n\
                    END AS scope_membership,\n\
                    hr.source_report_count,\n\
                    coalesce(rc.result_count, 0)::bigint AS result_count,\n\
                    coalesce(srm.vulnerability_count, 0)::bigint AS vulnerability_count,\n\
                    coalesce(nullif(srm.authentication_state, ''), 'unknown') AS authenticated_scan_state,\n\
                    hr.source_report_ids\n\
               FROM selected_scope_report sr\n\
               CROSS JOIN host_rows hr\n\
               LEFT JOIN result_counts rc ON rc.host_key = hr.host_key\n\
               LEFT JOIN scope_report_system_metrics srm\n\
                 ON srm.scope_report = sr.id AND lower(srm.host) = hr.host_key\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM rows\n\
              WHERE ($3 = '' OR lower(host) LIKE '%' || lower($3) || '%'\n\
                     OR lower(scope_membership) LIKE '%' || lower($3) || '%'\n\
                     OR lower(authenticated_scan_state) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, host ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report host query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(host_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_ports(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_PORT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_PORT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         port_rows AS (\n\
             SELECT coalesce(r.port, '') AS port,\n\
                    CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                         THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                         ELSE '' END AS protocol,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                AND coalesce(r.port, '') <> ''\n\
              GROUP BY coalesce(r.port, ''),\n\
                       CASE WHEN position('/' in coalesce(r.port, '')) > 0\n\
                            THEN split_part(coalesce(r.port, ''), '/', 2)\n\
                            ELSE '' END\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM port_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(port) LIKE '%' || lower($3) || '%'\n\
                     OR lower(protocol) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, port ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report port query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(port_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_applications(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ApplicationItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_APPLICATION_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_APPLICATION_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         app_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    rh.id AS report_host,\n\
                    rhd.source_name AS detection_oid,\n\
                    rhd.value AS name\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(rh.host)\n\
               JOIN report_host_details rhd ON rhd.report_host = rh.id\n\
              WHERE rhd.name = 'App'\n\
                AND coalesce(rhd.value, '') <> ''\n\
                AND coalesce(rhd.source_name, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, srs.source_report_uuid,\n\
                       rh.id, rhd.source_name, rhd.value\n\
         ),\n\
         result_detection AS (\n\
             SELECT r.uuid AS result_id,\n\
                    r.report AS source_report,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(nullif(by_location.value, ''), by_generic.value, '') AS detection_oid,\n\
                    coalesce(nullif(r.path, ''),\n\
                             CASE WHEN coalesce(r.port, '') <> ''\n\
                                    AND coalesce(r.port, '') NOT LIKE 'general/%'\n\
                                  THEN r.port ELSE NULL END,\n\
                             detected_at.value, '') AS detection_location\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN report_hosts rh\n\
                 ON rh.report = r.report\n\
                AND lower(rh.host) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
               JOIN selected_hosts sh ON sh.host_key = lower(rh.host)\n\
               LEFT JOIN report_host_details detected_at\n\
                 ON detected_at.report_host = rh.id\n\
                AND detected_at.source_name = r.nvt\n\
                AND detected_at.name = 'detected_at'\n\
               LEFT JOIN report_host_details by_location\n\
                 ON by_location.report_host = rh.id\n\
                AND by_location.source_name = r.nvt\n\
                AND by_location.name = 'detected_by@' || coalesce(nullif(r.path, ''),\n\
                     CASE WHEN coalesce(r.port, '') <> ''\n\
                            AND coalesce(r.port, '') NOT LIKE 'general/%'\n\
                          THEN r.port ELSE NULL END,\n\
                     detected_at.value, '')\n\
               LEFT JOIN report_host_details by_generic\n\
                 ON by_generic.report_host = rh.id\n\
                AND by_generic.source_name = r.nvt\n\
                AND by_generic.name = 'detected_by'\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         app_result_matches AS (\n\
             SELECT ai.name,\n\
                    ai.host_key,\n\
                    ai.source_report_id,\n\
                    rd.result_id,\n\
                    rd.nvt_oid,\n\
                    rd.severity\n\
               FROM app_instances ai\n\
               LEFT JOIN result_detection rd\n\
                 ON rd.source_report = ai.source_report\n\
                AND rd.host_key = ai.host_key\n\
                AND rd.detection_oid = ai.detection_oid\n\
               LEFT JOIN report_host_details app_location\n\
                 ON app_location.report_host = ai.report_host\n\
                AND app_location.source_name = ai.detection_oid\n\
                AND app_location.name = ai.name\n\
                AND app_location.value = rd.detection_location\n\
              WHERE rd.result_id IS NULL OR app_location.id IS NOT NULL\n\
         ),\n\
         application_rows AS (\n\
             SELECT ai.name,\n\
                    ''::text AS version,\n\
                    CASE WHEN lower(ai.name) LIKE 'cpe:%' THEN ai.name ELSE '' END AS cpe,\n\
                    count(DISTINCT ai.host_key)::bigint AS host_count,\n\
                    count(DISTINCT arm.result_id)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(arm.nvt_oid, ''), arm.result_id))\n\
                      FILTER (WHERE coalesce(arm.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(arm.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT ai.source_report_id), NULL) AS source_report_ids\n\
               FROM app_instances ai\n\
               LEFT JOIN app_result_matches arm\n\
                 ON arm.name = ai.name\n\
                AND arm.host_key = ai.host_key\n\
                AND arm.source_report_id = ai.source_report_id\n\
              GROUP BY ai.name\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM application_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(name) LIKE '%' || lower($3) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report application query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(application_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_operating_systems(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_OPERATING_SYSTEM_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_OPERATING_SYSTEM_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         os_instances AS (\n\
             SELECT lower(rh.host) AS host_key,\n\
                    rh.report AS source_report,\n\
                    srs.source_report_uuid AS source_report_id,\n\
                    coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown') AS name,\n\
                    coalesce(os_cpe.value, '') AS cpe\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(rh.host)\n\
               LEFT JOIN report_host_details os_cpe\n\
                 ON os_cpe.report_host = rh.id AND os_cpe.name = 'best_os_cpe'\n\
               LEFT JOIN report_host_details os_txt\n\
                 ON os_txt.report_host = rh.id AND os_txt.name = 'best_os_txt'\n\
              WHERE coalesce(os_txt.value, os_cpe.value, '') <> ''\n\
              GROUP BY lower(rh.host), rh.report, srs.source_report_uuid,\n\
                       coalesce(nullif(os_txt.value, ''), nullif(os_cpe.value, ''), 'Unknown'),\n\
                       coalesce(os_cpe.value, '')\n\
         ),\n\
         operating_system_rows AS (\n\
             SELECT oi.name,\n\
                    oi.cpe,\n\
                    count(DISTINCT oi.host_key)::bigint AS host_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    count(DISTINCT coalesce(nullif(r.nvt, ''), r.uuid::text))\n\
                      FILTER (WHERE coalesce(r.severity, 0) > 0)::bigint AS vulnerability_count,\n\
                    coalesce(max(coalesce(r.severity, 0)), 0)::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT oi.source_report_id), NULL) AS source_report_ids\n\
               FROM os_instances oi\n\
               LEFT JOIN results r\n\
                 ON r.report = oi.source_report\n\
                AND lower(coalesce(nullif(r.host, ''), r.hostname, '')) = oi.host_key\n\
                AND coalesce(r.severity, 0) != -3.0\n\
              GROUP BY oi.name, oi.cpe\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM operating_system_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(name) LIKE '%' || lower($3) || '%'\n\
                     OR lower(cpe) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, name ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report operating-system query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(operating_system_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_tls_certificates(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_TLS_CERTIFICATE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_TLS_CERTIFICATE_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         tls_rows AS (\n\
             SELECT c.uuid AS id,\n\
                    coalesce(c.sha256_fingerprint, '') AS fingerprint_sha256,\n\
                    coalesce(c.subject_dn, '') AS subject,\n\
                    coalesce(c.issuer_dn, '') AS issuer,\n\
                    coalesce(c.serial, '') AS serial,\n\
                    coalesce(c.activation_time, 0)::bigint AS not_before_unix,\n\
                    coalesce(c.expiration_time, 0)::bigint AS not_after_unix,\n\
                    count(DISTINCT lower(loc.host_ip))::bigint AS host_count,\n\
                    count(DISTINCT loc.port)::bigint AS port_count,\n\
                    count(DISTINCT src.uuid)::bigint AS result_count,\n\
                    array_remove(array_agg(DISTINCT origin.origin_id), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN tls_certificate_origins origin\n\
                 ON origin.origin_type = 'Report'\n\
                AND origin.origin_id = srs.source_report_uuid\n\
               JOIN tls_certificate_sources src ON src.origin = origin.id\n\
               JOIN tls_certificates c ON c.id = src.tls_certificate\n\
               JOIN tls_certificate_locations loc ON loc.id = src.location\n\
               JOIN selected_hosts sh ON sh.host_key = lower(loc.host_ip)\n\
              GROUP BY c.uuid, c.sha256_fingerprint, c.subject_dn, c.issuer_dn,\n\
                       c.serial, c.activation_time, c.expiration_time\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM tls_rows\n\
              WHERE ($3 = ''\n\
                     OR lower(id) LIKE '%' || lower($3) || '%'\n\
                     OR lower(fingerprint_sha256) LIKE '%' || lower($3) || '%'\n\
                     OR lower(subject) LIKE '%' || lower($3) || '%'\n\
                     OR lower(issuer) LIKE '%' || lower($3) || '%'\n\
                     OR lower(serial) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report TLS certificate query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(tls_certificate_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_cves(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<CveItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, SCOPE_REPORT_CVE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCOPE_REPORT_CVE_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_scope_report AS (\n\
             SELECT sr.id, sr.scope, coalesce(s.is_global, 0)::int AS is_global\n\
               FROM scope_reports sr\n\
               JOIN scopes s ON s.id = sr.scope\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2\n\
         ),\n\
         selected_hosts AS (\n\
             SELECT lower(rh.host) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN report_hosts rh ON rh.report = srs.source_report\n\
              WHERE sr.is_global = 1 AND coalesce(rh.host, '') <> ''\n\
              GROUP BY lower(rh.host)\n\
             UNION\n\
             SELECT lower(h.name) AS host_key\n\
               FROM selected_scope_report sr\n\
               JOIN scope_hosts sh ON sh.scope = sr.scope AND sr.is_global = 0\n\
               JOIN hosts h ON h.id = sh.host\n\
              WHERE coalesce(h.name, '') <> ''\n\
              GROUP BY lower(h.name)\n\
         ),\n\
         cve_rows AS (\n\
             SELECT vr.ref_id AS id,\n\
                    count(DISTINCT lower(coalesce(nullif(r.host, ''), r.hostname, '')))::bigint AS affected_system_count,\n\
                    count(DISTINCT r.uuid)::bigint AS result_count,\n\
                    max(coalesce(r.severity, 0))::double precision AS max_severity,\n\
                    array_remove(array_agg(DISTINCT srs.source_report_uuid), NULL) AS source_report_ids\n\
               FROM selected_scope_report sr\n\
               JOIN scope_report_sources srs ON srs.scope_report = sr.id\n\
               JOIN results r ON r.report = srs.source_report\n\
               JOIN selected_hosts sh ON sh.host_key = lower(coalesce(nullif(r.host, ''), r.hostname, ''))\n\
               JOIN vt_refs vr ON vr.vt_oid = r.nvt AND vr.type = 'cve'\n\
              WHERE coalesce(r.severity, 0) > 0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
              GROUP BY vr.ref_id\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM cve_rows\n\
              WHERE ($3 = '' OR lower(id) LIKE '%' || lower($3) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, id ASC LIMIT $4 OFFSET $5;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &scope_report_id,
                &scope_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report CVE query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !scope_report_exists(&client, &scope_report_id, &scope_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(cve_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn scope_report_exists(
    client: &tokio_postgres::Client,
    scope_report_id: &str,
    scope_id: &str,
) -> Result<bool, ApiError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM scope_reports WHERE uuid = $1 AND scope_uuid = $2);",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(row.get::<_, bool>(0))
}

async fn raw_report_exists(
    client: &tokio_postgres::Client,
    report_id: &str,
) -> Result<bool, ApiError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM reports WHERE lower(uuid) = lower($1));",
            &[&report_id],
        )
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(row.get::<_, bool>(0))
}

fn host_identifier_from_row(
    row: &Row,
    id_field: &str,
    name: &str,
    value: Option<String>,
    source_type_field: &str,
    source_id_field: &str,
    source_data_field: &str,
) -> Option<HostIdentifierItem> {
    let id: Option<String> = row.get(id_field);
    let value = value?;
    id.map(|id| HostIdentifierItem {
        id,
        name: name.to_string(),
        value,
        source_type: row
            .get::<_, Option<String>>(source_type_field)
            .unwrap_or_default(),
        source_id: row
            .get::<_, Option<String>>(source_id_field)
            .unwrap_or_default(),
        source_data: row
            .get::<_, Option<String>>(source_data_field)
            .unwrap_or_default(),
    })
}

fn host_asset_from_row(row: &Row) -> HostAssetItem {
    let hostname: Option<String> = row.get("hostname");
    let ip: Option<String> = row.get("ip");
    let hostname_identifier_name: Option<String> = row.get("hostname_identifier_name");
    let mut identifiers = Vec::new();
    if let Some(identifier) = host_identifier_from_row(
        row,
        "ip_identifier_id",
        "ip",
        ip.clone(),
        "ip_source_type",
        "ip_source_id",
        "ip_source_data",
    ) {
        identifiers.push(identifier);
    }
    if let Some(identifier) = host_identifier_from_row(
        row,
        "hostname_identifier_id",
        hostname_identifier_name.as_deref().unwrap_or("hostname"),
        hostname.clone(),
        "hostname_source_type",
        "hostname_source_id",
        "hostname_source_data",
    ) {
        identifiers.push(identifier);
    }
    HostAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        hostname,
        ip,
        best_os_cpe: row.get("best_os_cpe"),
        best_os_txt: row.get("best_os_txt"),
        severity: row.get("severity"),
        identifiers,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn host_asset_detail_identifier_from_row(row: &Row) -> HostAssetDetailIdentifier {
    HostAssetDetailIdentifier {
        id: row.get("id"),
        name: row.get("name"),
        value: row.get("value"),
        source_type: row.get("source_type"),
        source_id: row.get("source_id"),
        source_data: row.get("source_data"),
        source_data_truncated: row.get("source_data_truncated"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn host_asset_operating_system_from_row(row: &Row) -> HostAssetOperatingSystemItem {
    HostAssetOperatingSystemItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        operating_system_id: row.get("operating_system_id"),
        operating_system_name: row.get("operating_system_name"),
        title: row.get("title"),
        source_type: row.get("source_type"),
        source_id: row.get("source_id"),
        source_data: row.get("source_data"),
        source_data_truncated: row.get("source_data_truncated"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn host_asset_detail_item_from_row(row: &Row) -> HostAssetDetailItem {
    HostAssetDetailItem {
        name: row.get("name"),
        value: row.get("value"),
        value_truncated: row.get("value_truncated"),
        source_type: row.get("source_type"),
        source_id: row.get("source_id"),
        detail_source_type: row.get("detail_source_type"),
        detail_source_name: row.get("detail_source_name"),
        detail_source_description: row.get("detail_source_description"),
        detail_source_description_truncated: row.get("detail_source_description_truncated"),
    }
}

fn vulnerability_from_row(row: &Row) -> VulnerabilityItem {
    VulnerabilityItem {
        id: row.get("id"),
        name: row.get("name"),
        family: optional_row_string(row, "family"),
        oldest_result: unix_ts_to_rfc3339(row.get("oldest_result_unix")),
        newest_result: unix_ts_to_rfc3339(row.get("newest_result_unix")),
        severity: row.get("severity"),
        qod: row.get("qod"),
        result_count: row.get("result_count"),
        host_count: row.get("host_count"),
        cves: optional_row_strings(row, "cves"),
        cert_refs: optional_row_strings(row, "cert_refs"),
        xrefs: optional_row_strings(row, "xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        summary: optional_row_string(row, "summary"),
        insight: optional_row_string(row, "insight"),
        affected: optional_row_string(row, "affected"),
        impact: optional_row_string(row, "impact"),
        detection: optional_row_string(row, "detection"),
        solution_type: optional_row_string(row, "solution_type"),
        solution: optional_row_string(row, "solution"),
    }
}

fn operating_system_asset_from_row(row: &Row) -> OperatingSystemAssetItem {
    OperatingSystemAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        title: row.get("title"),
        latest_severity: row.get("latest_severity"),
        highest_severity: row.get("highest_severity"),
        average_severity: row.get("average_severity"),
        hosts: row.get("hosts"),
        all_hosts: row.get("all_hosts"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        user_tags: Vec::new(),
    }
}

fn report_reference(id: Option<String>, name: Option<String>) -> Option<ReportReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(ReportReference { id, name })
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

fn target_from_row(row: &Row) -> TargetItem {
    let hosts = csv_values(&row.get::<_, String>("hosts"));
    TargetItem {
        id: row.get("uuid"),
        name: row.get("name"),
        comment: row.get("comment"),
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

fn task_from_row(row: &Row) -> TaskItem {
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
        status,
        progress: row.get("progress"),
        trend: row.get("trend"),
        usage_type: row.get("usage_type"),
        target: target_reference(row.get("target_id"), row.get("target_name")),
        config: target_reference(row.get("config_id"), row.get("config_name")),
        scanner: target_reference(row.get("scanner_id"), row.get("scanner_name")),
        scanner_type: row.get("scanner_type"),
        schedule: target_reference(row.get("schedule_id"), row.get("schedule_name")),
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

fn report_from_row(row: &Row) -> ReportItem {
    ReportItem {
        id: row.get(1),
        name: row.get(2),
        owner: ReportOwner { name: row.get(3) },
        task: report_reference(row.get(4), row.get(5)),
        target: report_reference(row.get(6), row.get(7)),
        status: row.get(8),
        creation_time: unix_ts_to_rfc3339(row.get(9)),
        scan_start: unix_ts_to_rfc3339(row.get(10)),
        scan_end: unix_ts_to_rfc3339(row.get(11)),
        modification_time: unix_ts_to_rfc3339(row.get(12)),
        result_count: row.get(13),
        vulnerability_count: row.get(14),
        host_count: row.get(15),
        cve_count: row.get(16),
        max_severity: row.get(17),
        severity: ReportSeverityCounts {
            critical: row.get(18),
            high: row.get(19),
            medium: row.get(20),
            low: row.get(21),
            log: row.get(22),
            false_positive: row.get(23),
        },
        user_tags: Vec::new(),
    }
}

fn scope_from_row(
    row: &Row,
    targets: Vec<ScopeEntity>,
    hosts: Vec<ScopeEntity>,
    candidate_hosts: Vec<ScopeCandidateHost>,
    scope_reports: Vec<ScopeReportReference>,
) -> ScopeItem {
    let protection = row.get::<_, String>(5);
    let predefined: i32 = row.get(6);
    let global: i32 = row.get(7);
    ScopeItem {
        id: row.get(2),
        name: row.get(3),
        comment: row.get(4),
        protection_requirement: protection.clone(),
        protection_requirement_label: normalize_protection_requirement(&protection),
        predefined: predefined != 0,
        global: global != 0,
        creation_time: unix_ts_to_rfc3339(row.get(8)),
        modification_time: unix_ts_to_rfc3339(row.get(9)),
        target_count: row.get(10),
        host_count: row.get(11),
        scope_report_count: row.get(12),
        targets,
        hosts,
        candidate_hosts,
        scope_reports,
    }
}

fn scope_entity_from_row(row: &Row) -> ScopeEntity {
    ScopeEntity {
        id: row.get(0),
        name: row.get(1),
    }
}

fn scope_candidate_host_from_row(row: &Row) -> ScopeCandidateHost {
    let name: String = row.get(0);
    ScopeCandidateHost {
        id: name.clone(),
        name,
        target_id: row.get(1),
        target_name: row.get(2),
        source_report_id: row.get(3),
    }
}

fn scope_report_reference_from_row(row: &Row) -> ScopeReportReference {
    let scope_name: String = row.get(1);
    ScopeReportReference {
        id: row.get(0),
        name: format!("{scope_name} scope report"),
        creation_time: unix_ts_to_rfc3339(row.get(2)),
        latest_evidence_time: unix_ts_to_rfc3339(row.get(3)),
        source_report_count: row.get(4),
        member_host_count: row.get(5),
        evidence_host_count: row.get(6),
        missing_host_count: row.get(7),
        result_count: row.get(8),
        vulnerability_count: row.get(9),
        max_severity: row.get(10),
    }
}

fn scope_report_from_row(row: &Row) -> ScopeReportItem {
    let scope_name: String = row.get(3);
    ScopeReportItem {
        id: row.get(1),
        name: format!("{scope_name} scope report"),
        status: "Done".to_string(),
        scope: ScopeSummary {
            id: row.get(2),
            name: scope_name,
        },
        protection_requirement: normalize_protection_requirement(&row.get::<_, String>(4)),
        source_report_count: row.get(5),
        source_target_count: row.get(6),
        member_host_count: row.get(7),
        evidence_host_count: row.get(8),
        missing_host_count: row.get(9),
        result_count: row.get(10),
        vulnerability_count: row.get(11),
        max_severity: row.get(12),
        severity: SeverityCounts {
            high: row.get(17),
            medium: row.get(18),
            low: row.get(19),
            log: row.get(20),
            false_positive: row.get(21),
        },
        latest_evidence_time: unix_ts_to_rfc3339(row.get(13)),
        excluded_candidate_host_count: row.get(14),
        creation_time: unix_ts_to_rfc3339(row.get(15)),
        modification_time: unix_ts_to_rfc3339(row.get(16)),
    }
}

fn scope_report_source_from_row(row: &Row) -> ScopeReportSourceItem {
    let id: i64 = row.get("id");
    ScopeReportSourceItem {
        id: id.to_string(),
        source_report_id: row.get("source_report_id"),
        target_id: row.get("target_id"),
        target_name: row.get("target_name"),
        task_id: row.get("task_id"),
        task_name: row.get("task_name"),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        selected: true,
    }
}

fn scope_report_retention_source_from_row(row: &Row) -> ScopeReportRetentionSource {
    let kept_as_latest: bool = row.get("kept_as_latest");
    ScopeReportRetentionSource {
        source_report_id: row.get("source_report_uuid"),
        target_id: row.get("target_uuid"),
        target_name: row.get("target_name"),
        task_id: row.get("task_uuid"),
        task_name: row.get("task_name"),
        scan_start: unix_ts_to_rfc3339(row.get("scan_start")),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        selected_time: unix_ts_to_rfc3339(row.get("selected_time")),
        result_count: row.get("result_count"),
        vulnerability_count: row.get("vulnerability_count"),
        max_severity: row.get("max_severity"),
        retention_state: if kept_as_latest {
            "current_full_fidelity".to_string()
        } else {
            "future_tiered_retention_candidate".to_string()
        },
        detail_compacted: false,
        aggregate_only: false,
        kept_as_latest,
        pinned_by_scope_report: true,
        future_tiered_retention_candidate: !kept_as_latest,
    }
}

fn host_from_row(row: &Row) -> HostItem {
    HostItem {
        host: row.get(1),
        scope_membership: row.get(2),
        source_report_count: row.get(3),
        result_count: row.get(4),
        vulnerability_count: row.get(5),
        authenticated_scan_state: normalize_authentication_state(&row.get::<_, String>(6)),
        source_report_ids: row.get(7),
    }
}

fn port_from_row(row: &Row) -> PortItem {
    PortItem {
        port: row.get(1),
        protocol: row.get(2),
        host_count: row.get(3),
        result_count: row.get(4),
        vulnerability_count: row.get(5),
        max_severity: row.get(6),
        source_report_ids: row.get(7),
    }
}

fn application_from_row(row: &Row) -> ApplicationItem {
    ApplicationItem {
        name: row.get(1),
        version: row.get(2),
        cpe: row.get(3),
        host_count: row.get(4),
        result_count: row.get(5),
        vulnerability_count: row.get(6),
        max_severity: row.get(7),
        source_report_ids: row.get(8),
    }
}

fn operating_system_from_row(row: &Row) -> OperatingSystemItem {
    OperatingSystemItem {
        name: row.get(1),
        cpe: row.get(2),
        host_count: row.get(3),
        result_count: row.get(4),
        vulnerability_count: row.get(5),
        max_severity: row.get(6),
        source_report_ids: row.get(7),
    }
}

fn cve_from_row(row: &Row) -> CveItem {
    CveItem {
        id: row.get(1),
        affected_system_count: row.get(2),
        result_count: row.get(3),
        max_severity: row.get(4),
        source_report_ids: row.get(5),
    }
}

fn split_catalog_products(value: String) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|product| !product.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn catalog_cve_from_row(row: &Row) -> CatalogCveItem {
    let epss_score: Option<f64> = row.get("epss_score");
    let epss_percentile: Option<f64> = row.get("epss_percentile");
    CatalogCveItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        description: row.get("description"),
        cvss_base_vector: row.get("cvss_base_vector"),
        severity: row.get("severity"),
        products: split_catalog_products(row.get("products")),
        cert_refs: Vec::new(),
        nvt_refs: Vec::new(),
        epss: epss_score
            .zip(epss_percentile)
            .map(|(score, percentile)| CatalogEpssItem { score, percentile }),
        published_at: unix_ts_to_rfc3339(row.get("published_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn catalog_cpe_cve_from_row(row: &Row) -> CatalogCpeCveItem {
    CatalogCpeCveItem {
        id: row.get("id"),
        severity: row.get("severity"),
    }
}

fn catalog_cpe_from_row(
    row: &Row,
    cves: Vec<CatalogCpeCveItem>,
    deprecated_by: Option<String>,
) -> CatalogCpeItem {
    let deprecated_int: i32 = row.get("deprecated_int");
    CatalogCpeItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        cpe_name_id: row.get("cpe_name_id"),
        deprecated: deprecated_int != 0,
        deprecated_by,
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn dfn_cert_advisory_from_row(row: &Row) -> DfnCertAdvisoryItem {
    DfnCertAdvisoryItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        summary: row.get("summary"),
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn cert_bund_advisory_from_row(row: &Row) -> CertBundAdvisoryItem {
    CertBundAdvisoryItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        title: row.get("title"),
        summary: row.get("summary"),
        severity: row.get("severity"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn nvt_catalog_from_row(row: &Row) -> NvtCatalogItem {
    NvtCatalogItem {
        id: row.get("id"),
        oid: row.get("oid"),
        name: row.get("name"),
        family: row.get("family"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        qod_type: row.get("qod_type"),
        solution_type: row.get("solution_type"),
        solution_method: row.get("solution_method"),
        solution: row.get("solution"),
        tags: row.get("tags"),
        cve_refs: row.get("cve_refs"),
        cves: row.get("cves"),
        cert_refs: row.get("cert_refs"),
        xrefs: row.get("xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
        updated_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn nvt_catalog_detail_from_row(row: &Row, user_tags: Vec<ReportUserTag>) -> NvtCatalogDetail {
    NvtCatalogDetail {
        catalog: nvt_catalog_from_row(row),
        comment: row.get("comment"),
        summary: row.get("summary"),
        insight: row.get("insight"),
        affected: row.get("affected"),
        impact: row.get("impact"),
        detection: row.get("detection"),
        user_tags,
    }
}

fn nvt_epss_from_row(row: &Row) -> Option<NvtEpssItem> {
    let score = row.get::<_, Option<f64>>("max_epss_score")?;
    Some(NvtEpssItem {
        score,
        percentile: row
            .get::<_, Option<f64>>("max_epss_percentile")
            .unwrap_or(0.0),
        cve: row
            .get::<_, Option<String>>("max_epss_cve")
            .unwrap_or_default(),
        severity: row
            .get::<_, Option<f64>>("max_epss_severity")
            .unwrap_or(0.0),
    })
}

fn nvt_max_severity_from_row(row: &Row) -> Option<NvtEpssItem> {
    let score = row.get::<_, Option<f64>>("epss_score")?;
    Some(NvtEpssItem {
        score,
        percentile: row.get::<_, Option<f64>>("epss_percentile").unwrap_or(0.0),
        cve: row.get::<_, Option<String>>("epss_cve").unwrap_or_default(),
        severity: row.get::<_, Option<f64>>("epss_severity").unwrap_or(0.0),
    })
}

fn tls_certificate_asset_from_row(row: &Row) -> TlsCertificateAssetItem {
    let source_count = row.get("source_count");
    TlsCertificateAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        subject_dn: row.get("subject_dn"),
        issuer_dn: row.get("issuer_dn"),
        serial: row.get("serial"),
        md5_fingerprint: row.get("md5_fingerprint"),
        sha256_fingerprint: row.get("sha256_fingerprint"),
        activation_time: unix_ts_to_rfc3339(row.get("activation_time_unix")),
        expiration_time: unix_ts_to_rfc3339(row.get("expiration_time_unix")),
        last_seen: unix_ts_to_rfc3339(row.get("last_seen_unix")),
        valid: row
            .try_get::<_, Option<i32>>("valid_int")
            .ok()
            .flatten()
            .map(boolean_int),
        trust: row
            .try_get::<_, Option<i32>>("trust_int")
            .ok()
            .flatten()
            .map(boolean_int),
        time_status: optional_row_string(row, "time_status"),
        source_host_count: row.get("source_host_count"),
        source_port_count: row.get("source_port_count"),
        source_count,
        in_use: source_count > 0,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn tls_certificate_source_from_row(row: &Row) -> TlsCertificateSourceItem {
    let location_id: Option<String> = row.get("location_id");
    let origin_uuid: Option<String> = row.get("origin_uuid");
    TlsCertificateSourceItem {
        id: row.get("id"),
        timestamp: unix_ts_to_rfc3339(row.get("timestamp_unix")),
        tls_versions: row.get("tls_versions"),
        location: location_id.map(|id| TlsCertificateSourceLocation {
            id,
            host_ip: row
                .get::<_, Option<String>>("location_host_ip")
                .unwrap_or_default(),
            port: row
                .get::<_, Option<String>>("location_port")
                .unwrap_or_default(),
            host_asset_id: row.get("host_asset_id"),
        }),
        origin: origin_uuid.map(|id| TlsCertificateSourceOrigin {
            id,
            origin_type: row
                .get::<_, Option<String>>("origin_type")
                .unwrap_or_default(),
            origin_id: row
                .get::<_, Option<String>>("origin_resource_id")
                .unwrap_or_default(),
            origin_data: row
                .get::<_, Option<String>>("origin_data")
                .unwrap_or_default(),
        }),
    }
}

fn scanner_asset_from_row(row: &Row) -> ScannerAssetItem {
    let credential_id: Option<String> = row.get("credential_id");
    let credential_name: Option<String> = row.get("credential_name");
    ScannerAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        host: row.get("host"),
        port: row.get("port"),
        scanner_type: row.get("scanner_type"),
        credential: credential_id.map(|id| ScannerAssetCredential {
            id,
            name: credential_name.unwrap_or_default(),
        }),
        relay_host: row.get("relay_host"),
        relay_port: row.get("relay_port"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn filter_alert_from_row(row: &Row) -> FilterAlertReference {
    FilterAlertReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

fn filter_asset_from_row(row: &Row, alerts: Vec<FilterAlertReference>) -> FilterAssetItem {
    FilterAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        filter_type: row.get("filter_type"),
        term: row.get("term"),
        alert_count: row.get("alert_count"),
        alerts,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn alert_asset_from_row(row: &Row) -> AlertAssetItem {
    let filter_id: Option<String> = row.get("filter_id");
    let filter = filter_id.map(|id| AlertReference {
        name: row
            .get::<_, Option<String>>("filter_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        id,
    });
    let task_count: i64 = row.get("task_count");

    AlertAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: AlertOwner {
            name: row.get("owner_name"),
        },
        active: row.get::<_, i32>("active_int") != 0,
        in_use: task_count > 0,
        task_count,
        event: AlertTypeLabel {
            type_name: row.get("event_type"),
        },
        condition: AlertTypeLabel {
            type_name: row.get("condition_type"),
        },
        method: AlertTypeLabel {
            type_name: row.get("method_type"),
        },
        method_data_redacted: true,
        filter,
        tasks: Vec::new(),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn tag_asset_from_row(row: &Row) -> TagAssetItem {
    let resource_type: String = row.get("resource_type");
    let resource_count: i64 = row.get("resource_count");
    let raw_value: String = row.get("value");
    let value = if raw_value.trim().is_empty() {
        None
    } else {
        Some(raw_value)
    };
    TagAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: TagOwner {
            name: row.get("owner_name"),
        },
        resource_type: resource_type.clone(),
        resource_count,
        resources: TagResourcesSummary {
            resource_type,
            count: TagResourceCount {
                total: resource_count,
            },
        },
        active: row.get::<_, i32>("active_int") != 0,
        value,
        writable: true,
        in_use: false,
        orphan: false,
        trash: false,
        permissions: vec![
            "get_tags".to_string(),
            "modify_tag".to_string(),
            "delete_tag".to_string(),
            "create_tag".to_string(),
        ],
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn tag_resource_from_row(row: &Row) -> TagResourceItem {
    TagResourceItem {
        id: row.get("id"),
        resource_type: row.get("resource_type"),
        name: row.get("name"),
    }
}

fn override_asset_from_row(row: &Row) -> OverrideAssetItem {
    let task_id: Option<String> = row.get("task_id");
    let task = task_id.map(|id| OverrideTaskReference {
        name: row
            .get::<_, Option<String>>("task_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        trash: false,
        id,
    });
    let result_id: Option<String> = row.get("result_id");
    let result = result_id.map(|id| OverrideReference {
        name: row
            .get::<_, Option<String>>("result_name")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        id,
    });

    OverrideAssetItem {
        id: row.get("id"),
        owner: OverrideOwner {
            name: row.get("owner_name"),
        },
        nvt: OverrideNvtReference {
            id: row.get("nvt_id"),
            name: row.get("nvt_name"),
            nvt_type: row.get("nvt_type"),
        },
        text: row.get("text"),
        text_excerpt: false,
        hosts: row.get("hosts"),
        port: row.get("port"),
        severity: row.get("severity"),
        new_severity: row.get("new_severity"),
        writable: true,
        in_use: false,
        orphan: row.get::<_, i32>("orphan_int") != 0,
        active: row.get::<_, i32>("active_int") != 0,
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        task,
        result,
        permissions: vec![
            "get_overrides".to_string(),
            "modify_override".to_string(),
            "delete_override".to_string(),
            "create_override".to_string(),
        ],
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn port_range_from_row(row: &Row) -> PortRangeItem {
    PortRangeItem {
        id: row.get("id"),
        protocol: row.get("protocol"),
        start: row.get("start"),
        end: row.get("end"),
        comment: row.get("comment"),
    }
}

fn port_list_target_from_row(row: &Row) -> PortListTargetReference {
    PortListTargetReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

fn port_list_asset_from_row(
    row: &Row,
    port_ranges: Vec<PortRangeItem>,
    targets: Vec<PortListTargetReference>,
) -> PortListAssetItem {
    PortListAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        port_count: PortCountItem {
            all: row.get("port_count_all"),
            tcp: row.get("port_count_tcp"),
            udp: row.get("port_count_udp"),
        },
        port_ranges,
        targets,
        predefined: row.get::<_, i32>("predefined_int") != 0,
        deprecated: row.get::<_, i32>("deprecated_int") != 0,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn schedule_task_from_row(row: &Row) -> ScheduleTaskReference {
    ScheduleTaskReference {
        id: row.get("id"),
        name: row.get("name"),
        usage_type: row.get("usage_type"),
    }
}

fn schedule_asset_from_row(row: &Row, tasks: Vec<ScheduleTaskReference>) -> ScheduleAssetItem {
    ScheduleAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        icalendar: row.get("icalendar"),
        timezone: row.get("timezone"),
        timezone_abbrev: None,
        task_count: row.get("task_count"),
        tasks,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn tls_certificate_from_row(row: &Row) -> TlsCertificateItem {
    TlsCertificateItem {
        id: row.get(1),
        fingerprint_sha256: row.get(2),
        subject: row.get(3),
        issuer: row.get(4),
        serial: row.get(5),
        not_before: unix_ts_to_rfc3339(row.get(6)),
        not_after: unix_ts_to_rfc3339(row.get(7)),
        host_count: row.get(8),
        port_count: row.get(9),
        result_count: row.get(10),
        source_report_ids: row.get(11),
    }
}

fn result_from_row(row: &Row) -> ResultItem {
    let id: String = row.get("id");
    let source_report_id: String = row.get("source_report_id");
    ResultItem {
        raw_evidence_href: format!("/result/{id}"),
        id,
        host: row.get("host"),
        host_asset_id: optional_row_string(row, "host_asset_id"),
        hostname: row.get("hostname"),
        port: row.get("port"),
        nvt_oid: row.get("nvt_oid"),
        name: row.get("name"),
        nvt_family: row.get("nvt_family"),
        cves: optional_row_strings(row, "cves"),
        cert_refs: optional_row_strings(row, "cert_refs"),
        xrefs: optional_row_strings(row, "xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        description: optional_row_string(row, "description"),
        description_excerpt: row.get("description_excerpt"),
        summary: optional_row_string(row, "summary"),
        insight: optional_row_string(row, "insight"),
        affected: optional_row_string(row, "affected"),
        impact: optional_row_string(row, "impact"),
        detection: optional_row_string(row, "detection"),
        solution_type: optional_row_string(row, "solution_type"),
        solution: optional_row_string(row, "solution"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        scan_nvt_version: optional_row_string(row, "scan_nvt_version"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        report: report_reference(
            optional_row_string(row, "source_report_id"),
            optional_row_string(row, "source_report_name"),
        ),
        task: report_reference(
            optional_row_string(row, "task_id"),
            optional_row_string(row, "task_name"),
        ),
        source_report_id,
        user_tags: Vec::new(),
        overrides: result_overrides_from_row(row),
    }
}

fn result_overrides_from_row(row: &Row) -> Vec<ResultOverrideItem> {
    let ids = optional_row_strings(row, "override_ids");
    let nvt_ids = optional_row_strings(row, "override_nvt_ids");
    let nvt_names = optional_row_strings(row, "override_nvt_names");
    let nvt_types = optional_row_strings(row, "override_nvt_types");
    let texts = optional_row_strings(row, "override_texts");
    let hosts = optional_row_strings(row, "override_hosts");
    let ports = optional_row_strings(row, "override_ports");
    let severities = row
        .try_get::<_, Vec<Option<f64>>>("override_severities")
        .unwrap_or_default();
    let new_severities = row
        .try_get::<_, Vec<Option<f64>>>("override_new_severities")
        .unwrap_or_default();
    let created_at = row
        .try_get::<_, Vec<i64>>("override_created_at_unix")
        .unwrap_or_default();
    let modified_at = row
        .try_get::<_, Vec<i64>>("override_modified_at_unix")
        .unwrap_or_default();
    let end_times = row
        .try_get::<_, Vec<i64>>("override_end_time_unix")
        .unwrap_or_default();
    let active_ints = row
        .try_get::<_, Vec<i32>>("override_active_ints")
        .unwrap_or_default();

    ids.into_iter()
        .enumerate()
        .map(|(index, id)| ResultOverrideItem {
            id,
            nvt: ResultOverrideNvtReference {
                id: nvt_ids.get(index).cloned().unwrap_or_default(),
                name: nvt_names.get(index).cloned().unwrap_or_default(),
                nvt_type: nvt_types
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| "nvt".to_string()),
            },
            text: texts.get(index).cloned().unwrap_or_default(),
            text_excerpt: false,
            hosts: hosts.get(index).cloned().unwrap_or_default(),
            port: ports.get(index).cloned().unwrap_or_default(),
            severity: severities.get(index).copied().unwrap_or(None),
            new_severity: new_severities.get(index).copied().unwrap_or(None),
            active: active_ints.get(index).copied().unwrap_or_default() != 0,
            end_time: unix_ts_to_rfc3339(end_times.get(index).copied().unwrap_or_default()),
            created_at: unix_ts_to_rfc3339(created_at.get(index).copied().unwrap_or_default()),
            modified_at: unix_ts_to_rfc3339(modified_at.get(index).copied().unwrap_or_default()),
        })
        .collect()
}

fn result_override_from_row(row: &Row) -> ResultOverrideItem {
    ResultOverrideItem {
        id: row.get("id"),
        nvt: ResultOverrideNvtReference {
            id: row.get("nvt_id"),
            name: row.get("nvt_name"),
            nvt_type: row.get("nvt_type"),
        },
        text: row.get("text"),
        text_excerpt: false,
        hosts: row.get("hosts"),
        port: row.get("port"),
        severity: row.get("severity"),
        new_severity: row.get("new_severity"),
        active: row.get::<_, i32>("active_int") != 0,
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

fn report_host_from_row(row: &Row) -> ReportHostItem {
    ReportHostItem {
        host: row.get("host"),
        hostname: row.get("hostname"),
        best_os_cpe: row.get("best_os_cpe"),
        best_os_txt: row.get("best_os_txt"),
        ports_count: row.get("ports_count"),
        applications_count: row.get("applications_count"),
        distance: row.get("distance"),
        authentication_state: normalize_authentication_state(
            &row.get::<_, String>("authentication_state"),
        ),
        start_time: unix_ts_to_rfc3339(row.get("start_time_unix")),
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        result_count: row.get("result_count"),
        vulnerability_count: row.get("vulnerability_count"),
        severity: ReportSeverityCounts {
            critical: row.get("severity_critical"),
            high: row.get("severity_high"),
            medium: row.get("severity_medium"),
            low: row.get("severity_low"),
            log: row.get("severity_log"),
            false_positive: row.get("severity_false_positive"),
        },
        max_severity: row.get("max_severity"),
        source_report_id: row.get("source_report_id"),
    }
}

fn error_message_from_row(row: &Row) -> ErrorMessageItem {
    ErrorMessageItem {
        id: row.get(1),
        host: row.get(2),
        port: row.get(3),
        nvt_oid: row.get(4),
        description: row.get(5),
        source_report_id: row.get(6),
        created_at: unix_ts_to_rfc3339(row.get(7)),
    }
}

fn metrics_summary_from_row(row: &Row) -> MetricsSummary {
    MetricsSummary {
        total_system_cvss_load: row.get(2),
        average_system_cvss_load: row.get(3),
        authenticated_scan_coverage_percent: row.get(4),
        alive_system_count: row.get(5),
        vulnerability_count: row.get(6),
        authenticated_system_count: row.get(7),
        authentication_failed_system_count: row.get(8),
        no_credential_path_system_count: row.get(9),
        unknown_authentication_system_count: row.get(10),
    }
}

fn metrics_system_from_row(row: &Row) -> MetricsSystem {
    MetricsSystem {
        host: row.get(0),
        cvss_load: row.get(1),
        max_cvss: row.get(2),
        vulnerability_count: row.get(3),
        authentication_state: normalize_authentication_state(&row.get::<_, String>(4)),
        source_report_count: row.get(5),
    }
}

fn metrics_vulnerability_from_row(row: &Row) -> MetricsVulnerability {
    MetricsVulnerability {
        nvt_oid: row.get(0),
        name: row.get(1),
        cvss_score: row.get(2),
        affected_system_count: row.get(3),
        cvss_load: row.get(4),
        average_contribution: row.get(5),
        source_report_count: row.get(6),
    }
}

fn summarize_metrics(systems: &[MetricsSystem], vulnerability_count: i64) -> MetricsSummary {
    let alive_system_count = systems.len() as i64;
    let total_system_cvss_load = systems.iter().map(|system| system.cvss_load).sum::<f64>();
    let authenticated_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Authenticated")
        .count() as i64;
    let authentication_failed_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Authentication Failed")
        .count() as i64;
    let no_credential_path_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "No Credential Path")
        .count() as i64;
    let unknown_authentication_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Unknown")
        .count() as i64;
    MetricsSummary {
        total_system_cvss_load,
        average_system_cvss_load: if alive_system_count > 0 {
            total_system_cvss_load / alive_system_count as f64
        } else {
            0.0
        },
        authenticated_scan_coverage_percent: if alive_system_count > 0 {
            (100.0 * authenticated_system_count as f64) / alive_system_count as f64
        } else {
            0.0
        },
        alive_system_count,
        vulnerability_count,
        authenticated_system_count,
        authentication_failed_system_count,
        no_credential_path_system_count,
        unknown_authentication_system_count,
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        extract::Request,
        http::{HeaderMap, StatusCode, header},
        response::IntoResponse,
    };

    use crate::{
        auth::*, direct_api::direct_api_v1_path_is_allowed, request_ids::*, request_shapes::*,
    };

    use super::*;

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
        let source = include_str!("main.rs");
        let detail_source = source
            .split_once("async fn cve_catalog_detail")
            .expect("CVE catalog detail handler must exist")
            .1
            .split_once("async fn dfn_cert_advisories")
            .expect("CVE catalog detail handler must precede advisory handlers")
            .0;
        let list_source = source
            .split_once("async fn cve_catalog(")
            .expect("CVE catalog list handler must exist")
            .1
            .split_once("async fn cve_catalog_detail")
            .expect("CVE catalog list handler must precede detail handler")
            .0;
        let payload_source = source
            .split_once("struct CatalogCveItem {")
            .expect("CVE catalog payload must exist")
            .1
            .split_once("struct CatalogCpeCveItem")
            .expect("CVE catalog payload must precede CPE CVE payload")
            .0;

        assert!(payload_source.contains("cert_refs: Vec<CatalogCveCertReference>"));
        assert!(payload_source.contains("nvt_refs: Vec<CatalogCveNvtReference>"));
        assert!(payload_source.contains("epss: Option<CatalogEpssItem>"));
        assert!(detail_source.contains("LEFT JOIN scap.epss_scores e ON e.cve = c.name"));
        assert!(detail_source.contains("item.cert_refs = cve_cert_refs(&client, &cve_id).await?"));
        assert!(detail_source.contains("item.nvt_refs = cve_nvt_refs(&client, &cve_id).await?"));
        assert!(detail_source.contains("FROM cert.cert_bund_cves dc"));
        assert!(detail_source.contains("FROM cert.dfn_cert_cves dc"));
        assert!(detail_source.contains("FROM vt_refs vr"));
        assert!(!list_source.contains("cve_cert_refs"));
        assert!(!list_source.contains("cve_nvt_refs"));
        for inherited_workflow in ["export", "delete", "modify", "create"] {
            assert!(!detail_source.contains(inherited_workflow));
        }
    }

    #[test]
    fn catalog_detail_user_tags_are_detail_only_active_info_tags() {
        let source = include_str!("main.rs");
        let cve_item_payload = source
            .split_once("struct CatalogCveItem {")
            .expect("CVE catalog payload must exist")
            .1
            .split_once("struct CatalogCveDetail")
            .expect("CVE catalog payload must precede detail payload")
            .0;
        let cpe_item_payload = source
            .split_once("struct CatalogCpeItem {")
            .expect("CPE catalog payload must exist")
            .1
            .split_once("struct CatalogCpeDetail")
            .expect("CPE catalog payload must precede detail payload")
            .0;
        let cve_detail_source = source
            .split_once("async fn cve_catalog_detail")
            .expect("CVE catalog detail handler must exist")
            .1
            .split_once("async fn cve_cert_refs")
            .expect("CVE catalog detail handler must precede reference helpers")
            .0;
        let cpe_detail_source = source
            .split_once("async fn cpe_catalog_detail")
            .expect("CPE catalog detail handler must exist")
            .1
            .split_once("async fn cve_catalog")
            .expect("CPE catalog detail handler must precede CVE catalog list")
            .0;
        let cve_list_source = source
            .split_once("async fn cve_catalog(")
            .expect("CVE catalog list handler must exist")
            .1
            .split_once("async fn cve_catalog_detail")
            .expect("CVE catalog list handler must precede detail handler")
            .0;
        let cpe_list_source = source
            .split_once("async fn cpe_catalog(")
            .expect("CPE catalog list handler must exist")
            .1
            .split_once("async fn cpe_catalog_detail")
            .expect("CPE catalog list handler must precede detail handler")
            .0;

        assert!(!cve_item_payload.contains("user_tags"));
        assert!(!cpe_item_payload.contains("user_tags"));
        assert!(source.contains("struct CatalogCveDetail"));
        assert!(source.contains("struct CatalogCpeDetail"));
        assert!(cve_detail_source.contains("catalog_user_tags(&client, \"cve\", &cve_id).await?"));
        assert!(cpe_detail_source.contains("catalog_user_tags(&client, \"cpe\", &cpe_id).await?"));
        assert!(!cve_list_source.contains("catalog_user_tags"));
        assert!(!cpe_list_source.contains("catalog_user_tags"));

        let sql = catalog_user_tags_sql();
        assert!(sql.contains("FROM tags t"));
        assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
        assert!(sql.contains("lower(tr.resource_uuid) = lower($1)"));
        assert!(sql.contains("tr.resource_type = $2"));
        assert!(sql.contains("coalesce(t.active, 0) = 1"));
        assert!(!sql.contains("credential"));
        assert!(!sql.contains("reports"));
        assert!(!sql.contains("results"));
    }

    #[test]
    fn nvt_detail_user_tags_are_detail_only_active_info_tags() {
        let source = include_str!("main.rs");
        let nvt_item_payload = source
            .split_once("struct NvtCatalogItem {")
            .expect("NVT catalog item payload must exist")
            .1
            .split_once("struct NvtCatalogDetail")
            .expect("NVT catalog item payload must precede detail payload")
            .0;
        let nvt_detail_source = source
            .split_once("async fn nvt_catalog_detail")
            .expect("NVT catalog detail handler must exist")
            .1
            .split_once("async fn operating_system_assets")
            .expect("NVT catalog detail handler must precede asset handlers")
            .0;
        let nvt_list_source = source
            .split_once("async fn nvt_catalog(")
            .expect("NVT catalog list handler must exist")
            .1
            .split_once("fn nvt_filter_parts")
            .expect("NVT catalog list handler must precede filter helper")
            .0;

        assert!(!nvt_item_payload.contains("user_tags"));
        assert!(source.contains("struct NvtCatalogDetail"));
        assert!(nvt_detail_source.contains("catalog_user_tags(&client, \"nvt\", &nvt_id).await?"));
        assert!(!nvt_list_source.contains("catalog_user_tags"));

        let sql = catalog_user_tags_sql();
        assert!(sql.contains("FROM tags t"));
        assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
        assert!(sql.contains("lower(tr.resource_uuid) = lower($1)"));
        assert!(sql.contains("tr.resource_type = $2"));
        assert!(sql.contains("coalesce(t.active, 0) = 1"));
        assert!(!sql.contains("credential"));
        assert!(!sql.contains("reports"));
        assert!(!sql.contains("results"));
    }

    #[test]
    fn cert_advisory_detail_user_tags_use_resolved_uuid_only() {
        let source = include_str!("main.rs");
        let cert_bund_item_payload = source
            .split_once("struct CertBundAdvisoryItem {")
            .expect("CERT-Bund advisory payload must exist")
            .1
            .split_once("struct CertBundAdvisoryDetail")
            .expect("CERT-Bund advisory payload must precede detail payload")
            .0;
        let dfn_cert_item_payload = source
            .split_once("struct DfnCertAdvisoryItem {")
            .expect("DFN-CERT advisory payload must exist")
            .1
            .split_once("struct DfnCertAdvisoryDetail")
            .expect("DFN-CERT advisory payload must precede detail payload")
            .0;
        let cert_bund_detail_source = source
            .split_once("async fn cert_bund_advisory_detail")
            .expect("CERT-Bund detail handler must exist")
            .1
            .split_once("async fn nvt_catalog")
            .expect("CERT-Bund detail handler must precede NVT catalog")
            .0;
        let dfn_cert_detail_source = source
            .split_once("async fn dfn_cert_advisory_detail")
            .expect("DFN-CERT detail handler must exist")
            .1
            .split_once("async fn cert_bund_advisories")
            .expect("DFN-CERT detail handler must precede CERT-Bund list")
            .0;
        let cert_bund_list_source = source
            .split_once("async fn cert_bund_advisories(")
            .expect("CERT-Bund list handler must exist")
            .1
            .split_once("async fn cert_bund_advisory_detail")
            .expect("CERT-Bund list handler must precede detail handler")
            .0;
        let dfn_cert_list_source = source
            .split_once("async fn dfn_cert_advisories(")
            .expect("DFN-CERT list handler must exist")
            .1
            .split_once("async fn dfn_cert_advisory_detail")
            .expect("DFN-CERT list handler must precede detail handler")
            .0;

        assert!(!cert_bund_item_payload.contains("user_tags"));
        assert!(!dfn_cert_item_payload.contains("user_tags"));
        assert!(source.contains("struct CertBundAdvisoryDetail"));
        assert!(source.contains("struct DfnCertAdvisoryDetail"));
        assert!(cert_bund_detail_source.contains("let id: String = row.get(\"id\");"));
        assert!(dfn_cert_detail_source.contains("let id: String = row.get(\"id\");"));
        assert!(
            cert_bund_detail_source
                .contains("catalog_user_tags(&client, \"cert_bund_adv\", &id).await?")
        );
        assert!(
            dfn_cert_detail_source
                .contains("catalog_user_tags(&client, \"dfn_cert_adv\", &id).await?")
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
        let source = include_str!("main.rs");
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
        assert!(sql.contains(
            "GROUP BY sr.source_report_uuid, sr.target_uuid, sr.target_name, sr.task_uuid,"
        ));
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
        let source = include_str!("main.rs");
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
        let source = include_str!("main.rs");
        let start = "async fn scope_report_metrics(";
        let end = "\n}\n\nasync fn scope_report_retention_plan";
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
    fn direct_api_allowlist_tracks_registered_read_routes() {
        let source = include_str!("main.rs");
        let routes = app_route_registration_block(source);
        let api_routes = registered_route_paths(routes)
            .into_iter()
            .filter(|path| path.starts_with("/api/v1/"))
            .collect::<Vec<_>>();
        let internal_only_routes =
            ["/api/v1/scopes/:scope_id/reports/:scope_report_id/retention-plan"];

        assert!(api_routes.len() > 40, "expected the native API route table");
        for forbidden_method in ["post(", "put(", "patch(", "delete("] {
            assert!(
                !routes.contains(forbidden_method),
                "registered native API routes must remain read-only"
            );
        }
        for route in api_routes {
            let concrete_path = concrete_direct_api_path(route);
            if internal_only_routes.contains(&route) {
                assert!(
                    !direct_api_v1_path_is_allowed(&concrete_path),
                    "internal-only route {route} must not be direct API allowlisted"
                );
            } else {
                assert!(
                    direct_api_v1_path_is_allowed(&concrete_path),
                    "registered read route {route} should be direct API allowlisted as {concrete_path}"
                );
            }
        }
    }

    fn app_route_registration_block(source: &str) -> &str {
        source
            .split_once("let app = Router::new()")
            .expect("native API router must be registered")
            .1
            .split_once("\n        .with_state(state);")
            .expect("native API router must attach app state")
            .0
    }

    fn registered_route_paths(routes: &str) -> Vec<&str> {
        let mut paths = Vec::new();
        let mut remainder = routes;
        while let Some((_, after_route)) = remainder.split_once(".route(") {
            let Some((_, after_quote)) = after_route.split_once('"') else {
                break;
            };
            let Some((path, after_path)) = after_quote.split_once('"') else {
                break;
            };
            paths.push(path);
            remainder = after_path;
        }
        paths
    }

    fn concrete_direct_api_path(route: &str) -> String {
        route
            .split('/')
            .map(|segment| {
                segment
                    .strip_prefix(':')
                    .or_else(|| segment.strip_prefix('*'))
                    .map(|name| format!("sample-{name}"))
                    .unwrap_or_else(|| segment.to_string())
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    #[test]
    fn scope_report_native_routes_remain_get_only_read_paths() {
        let source = include_str!("main.rs");
        let start = ".route(\"/api/v1/scope-reports\", get(scope_reports))";
        let end = "\n        .with_state(state);";
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
    fn scope_report_handlers_do_not_trigger_scanner_or_task_control() {
        let source = include_str!("main.rs");
        let start = "async fn scope_report_results(";
        let end = "\n}\n\nfn scope_report_from_row";
        let handlers = source
            .split_once(start)
            .expect("scope report handlers must exist")
            .1
            .split_once(end)
            .expect("scope report handlers must precede row mapping helpers")
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
        let source = include_str!("main.rs");
        let result_payload = source
            .split_once("struct ResultItem {")
            .expect("result payload struct must exist")
            .1
            .split_once("struct VulnerabilityItem")
            .expect("result payload must precede vulnerability payload")
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
                .1
                .split_once("async fn report_hosts")
                .expect("report result list handler must precede report host list")
                .0,
            source
                .split_once("fn scope_report_results_sql")
                .expect("scope report result SQL helper must exist")
                .1
                .split_once("async fn scope_report_metrics")
                .expect("scope report result SQL helper must precede metrics")
                .0,
        ];
        let row_mapper = source
            .split_once("fn result_from_row")
            .expect("result row mapper must exist")
            .1
            .split_once("fn report_host_from_row")
            .expect("result row mapper must precede report host mapper")
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
        let source = include_str!("main.rs");
        let host_list_payload = source
            .split_once("struct HostAssetItem {")
            .expect("host list payload struct must exist")
            .1
            .split_once("struct HostAssetDetailIdentifier")
            .expect("host list payload struct must precede detail identifiers")
            .0;
        let host_detail_payload = source
            .split_once("struct HostAssetDetail {")
            .expect("host detail payload struct must exist")
            .1
            .split_once("struct TlsCertificateAssetItem")
            .expect("host detail payload struct must precede TLS asset struct")
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
        let source = include_str!("main.rs");
        let detail_source = source
            .split_once("async fn tls_certificate_asset_detail")
            .expect("TLS certificate detail handler must exist")
            .1
            .split_once("async fn scanner_assets")
            .expect("TLS certificate detail handler must precede scanner assets")
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
        let source = include_str!("main.rs");
        let scanner_list_payload = source
            .split_once("struct ScannerAssetItem {")
            .expect("scanner list payload struct must exist")
            .1
            .split_once("struct ScannerTaskReference")
            .expect("scanner list payload struct must precede detail references")
            .0;
        let scanner_detail_payload = source
            .split_once("struct ScannerAssetDetail {")
            .expect("scanner detail payload struct must exist")
            .1
            .split_once("struct ScanConfigOwner")
            .expect("scanner detail payload struct must precede scan config owner")
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
        let source = include_str!("main.rs");
        let detail_source = source
            .split_once("async fn scanner_asset_detail")
            .expect("scanner detail handler must exist")
            .1
            .split_once("fn scan_config_asset_from_row")
            .expect("scanner detail handler must precede scan config assets")
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
        let source = include_str!("main.rs");
        let scan_config_list_payload = source
            .split_once("struct ScanConfigAssetItem {")
            .expect("scan config list payload struct must exist")
            .1
            .split_once("struct ScanConfigAssetDetail")
            .expect("scan config list payload struct must precede detail payload")
            .0;
        let scan_config_detail_payload = source
            .split_once("struct ScanConfigAssetDetail {")
            .expect("scan config detail payload struct must exist")
            .1
            .split_once("struct FilterAlertReference")
            .expect("scan config detail payload must precede filter structs")
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
        let source = include_str!("main.rs");
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
            .split_once("struct TrashcanSummaryItem")
            .expect("schedule detail payload must precede trashcan structs")
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
        let source = include_str!("main.rs");
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
            .split_once("struct HostIdentifierItem")
            .expect("port list detail payload must precede host structs")
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
        let source = include_str!("main.rs");
        let detail_source = source
            .split_once("async fn scan_config_asset_detail")
            .expect("scan config detail handler must exist")
            .1
            .split_once("async fn scan_config_asset_families")
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
        assert!(
            sql.contains("ORDER BY t.id, coalesce(r.end_time, r.creation_time) DESC, r.id DESC")
        );
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
        let source = include_str!("main.rs");
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
        assert!(sql.contains(
            "ELSE (SELECT count(*) FROM scope_targets st WHERE st.scope = s.id)::bigint"
        ));
        assert!(sql.contains("THEN (SELECT count(*) FROM hosts)::bigint"));
        assert!(
            sql.contains(
                "ELSE (SELECT count(*) FROM scope_hosts sh WHERE sh.scope = s.id)::bigint"
            )
        );

        let source = include_str!("main.rs");
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
            hosts_body
                .contains("SELECT uuid, coalesce(name, uuid) FROM hosts ORDER BY name, uuid;")
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
        assert!(error.public_message().contains("GET"));
    }

    #[test]
    fn direct_api_request_too_large_uses_json_413_contract() {
        let error = ApiError::RequestTooLarge;
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.code(), "request_too_large");
        assert!(error.public_message().contains("bounded read-only"));
    }

    #[test]
    fn direct_api_in_flight_cap_uses_json_429_contract() {
        let error = ApiError::TooManyRequests;
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.code(), "too_many_requests");
        assert!(error.public_message().contains("maximum number"));
    }

    #[test]
    fn direct_api_bearer_token_requires_bounded_printable_secret() {
        assert!(direct_api_bearer_token_is_acceptable(
            "0123456789abcdef0123456789abcdef"
        ));
        assert!(direct_api_bearer_token_is_acceptable(
            &"A".repeat(MAX_DIRECT_API_BEARER_TOKEN_LENGTH)
        ));
        assert!(!direct_api_bearer_token_is_acceptable("short-token"));
        assert!(!direct_api_bearer_token_is_acceptable(
            &"A".repeat(MAX_DIRECT_API_BEARER_TOKEN_LENGTH + 1)
        ));
        assert!(!direct_api_bearer_token_is_acceptable(
            "0123456789abcdef 123456789abcdef"
        ));
        assert!(!direct_api_bearer_token_is_acceptable(
            "0123456789abcdef0123456789abcde\n"
        ));
    }

    #[test]
    fn direct_api_path_classifier_uses_positive_scriptable_allowlist() {
        assert!(direct_api_v1_path_is_allowed("/api/v1/reports"));
        assert!(direct_api_v1_path_is_allowed(
            "/api/v1/reports/report-id/results"
        ));
        assert!(direct_api_v1_path_is_allowed("/api/v1/feeds"));
        assert!(direct_api_v1_path_is_allowed(
            "/api/v1/tags/resource-names/alert"
        ));
        assert!(direct_api_v1_path_is_allowed(
            "/api/v1/cpes/cpe:/a:example:thing/1.0"
        ));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes///"));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes/."));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes/.."));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/cpes/foo/../bar"));
        assert!(!direct_api_v1_path_is_allowed(
            "/api/v1/cert-bund-advisories/.."
        ));
        assert!(direct_api_v1_path_is_allowed(
            "/api/v1/scopes/scope-id/reports/report-id/metrics"
        ));
        assert!(direct_api_v1_path_is_allowed(
            "/api/v1/scope-reports/scope-report-id"
        ));
        assert!(!direct_api_v1_path_is_allowed(
            "/api/v1/scopes/scope-id/reports/report-id/retention-plan"
        ));
        assert!(!direct_api_v1_path_is_allowed(
            "/api/v1/scopes//reports/report-id/results"
        ));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/reports//results"));
        assert!(!direct_api_v1_path_is_allowed(
            "/api/v1/scopes/scope-id/reports/scope-report-id"
        ));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/internal-preview"));
        assert!(!direct_api_v1_path_is_allowed("/api/v1/reports/id/raw-xml"));
    }

    #[test]
    fn direct_api_request_shape_rejects_bodies_and_oversized_queries() {
        let allowed = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed(&allowed));

        let explicit_empty_body = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::CONTENT_LENGTH, "0")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(direct_api_request_shape_is_allowed(&explicit_empty_body));

        let body = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::CONTENT_LENGTH, "1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&body));

        let chunked = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::TRANSFER_ENCODING, "chunked")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&chunked));

        let malformed_length = Request::builder()
            .uri("/api/v1/reports?page_size=1")
            .header(header::CONTENT_LENGTH, "not-a-number")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&malformed_length));

        let oversized_query = format!(
            "/api/v1/reports?filter={}",
            "a".repeat(MAX_DIRECT_API_QUERY_BYTES)
        );
        let oversized = Request::builder()
            .uri(oversized_query)
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!direct_api_request_shape_is_allowed(&oversized));
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
}
