// SPDX-FileCopyrightText: 2026 TurboVAS contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{env, net::SocketAddr};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_postgres::{Config as PgConfig, NoTls, Row};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    pool: Pool,
}

#[derive(Debug, Deserialize)]
struct CollectionQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    sort: Option<String>,
    filter: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    database: &'static str,
}

#[derive(Debug, Serialize)]
struct PageInfo {
    page: i64,
    page_size: i64,
    total: i64,
    sort: String,
    filter: String,
}

#[derive(Debug, Serialize)]
struct Collection<T> {
    page: PageInfo,
    items: Vec<T>,
}

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
struct ReportItem {
    id: String,
    name: String,
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
    description_excerpt: Option<String>,
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
}

#[derive(Serialize)]
struct VulnerabilityItem {
    id: String,
    name: String,
    oldest_result: Option<String>,
    newest_result: Option<String>,
    severity: f64,
    qod: i64,
    result_count: i64,
    host_count: i64,
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

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("resource not found")]
    NotFound,
    #[error("database error")]
    Database,
    #[error("configuration error")]
    Config,
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Database | Self::Config => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::NotFound => "not_found",
            Self::Database => "database_error",
            Self::Config => "configuration_error",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::BadRequest(message) => message.clone(),
            Self::NotFound => "The requested resource was not found.".to_string(),
            Self::Database => "The database query failed.".to_string(),
            Self::Config => "The API service is not configured correctly.".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorBody {
            error: ErrorPayload {
                code: self.code().to_string(),
                message: self.public_message(),
            },
        };
        (status, Json(body)).into_response()
    }
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
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/results", get(results))
        .route("/api/v1/vulnerabilities", get(vulnerabilities))
        .route("/api/v1/operating-systems", get(operating_system_assets))
        .route("/api/v1/hosts", get(host_assets))
        .route("/api/v1/tls-certificates", get(tls_certificate_assets))
        .route("/api/v1/scanners", get(scanner_assets))
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
        .with_state(state);

    let bind = env::var("TURBOVAS_API_BIND").unwrap_or_else(|_| "0.0.0.0:9080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|_| ApiError::Config)?;
    let addr: SocketAddr = listener.local_addr().map_err(|_| ApiError::Config)?;
    tracing::info!(%addr, "starting turbovas-api");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| ApiError::Config)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn create_pool() -> Result<Pool, ApiError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| ApiError::Config)?;
    let pg_config: PgConfig = database_url.parse().map_err(|_| ApiError::Config)?;
    let manager = Manager::from_config(
        pg_config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(8)
        .build()
        .map_err(|_| ApiError::Config)
}

async fn healthz(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    client
        .query_one("SELECT 1;", &[])
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(Json(HealthResponse {
        status: "ok",
        database: "ok",
    }))
}

async fn reports(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ReportItem>>, ApiError> {
    let params = normalize_collection_query(query, "-creation_time")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(report_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn host_assets(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<HostAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, "-severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("name", "name"),
            ("hostname", "hostname"),
            ("ip", "ip"),
            ("os", "best_os_cpe"),
            ("severity", "severity"),
            ("modified", "modified_at_unix"),
        ],
    )?;
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
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(host_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn tls_certificate_assets(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, "-last_seen")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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

async fn scanner_assets(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ScannerAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("name", "name"),
            ("host", "host"),
            ("port", "port"),
            ("type", "scanner_type"),
            ("scanner_type", "scanner_type"),
            ("credential", "credential_name"),
            ("modified", "modified_at_unix"),
        ],
    )?;
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

async fn vulnerabilities(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<VulnerabilityItem>>, ApiError> {
    let params = normalize_collection_query(query, "-severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("name", "name"),
            ("oldest", "oldest_result_unix"),
            ("newest", "newest_result_unix"),
            ("severity", "severity"),
            ("qod", "qod"),
            ("results", "result_count"),
            ("hosts", "host_count"),
        ],
    )?;
    let sql = format!(
        r#"WITH vulnerability_rows AS (
             SELECT coalesce(nullif(r.nvt, ''), r.uuid::text) AS id,
                    coalesce(max(nullif(n.name, '')), max(nullif(r.nvt, '')), 'Unknown vulnerability') AS name,
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
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "vulnerability list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(vulnerability_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn operating_system_assets(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, "-latest_severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("name", "name"),
            ("title", "title"),
            ("latest_severity", "latest_severity"),
            ("highest_severity", "highest_severity"),
            ("average_severity", "average_severity"),
            ("hosts", "hosts"),
            ("all_hosts", "all_hosts"),
            ("modified", "modified_at_unix"),
        ],
    )?;
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

async fn report_ports(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "port")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("port", "port"),
            ("protocol", "protocol"),
            ("host_count", "host_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("severity", "max_severity"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ApplicationItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("name", "name"),
            ("cpe", "cpe"),
            ("hosts", "host_count"),
            ("host_count", "host_count"),
            ("occurrences", "result_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("severity", "max_severity"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("name", "name"),
            ("cpe", "cpe"),
            ("hosts", "host_count"),
            ("host_count", "host_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("severity", "max_severity"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "-not_after")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<CveItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "-max_severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("affected_system_count", "affected_system_count"),
            ("result_count", "result_count"),
            ("severity", "max_severity"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ErrorMessageItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "-created_at")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("host", "host"),
            ("port", "port"),
            ("nvt_oid", "nvt_oid"),
            ("description", "description"),
            ("created_at", "created_at_unix"),
        ],
    )?;
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
    Ok(Json(report_from_row(&row)))
}

async fn results(
    State(state): State<AppState>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    let params = normalize_collection_query(query, "-severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
    let sql = format!(
        r#"WITH result_rows AS (
             SELECT r.uuid AS id,
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
                    h.uuid AS host_asset_id,
                    nullif(r.hostname, '') AS hostname,
                    coalesce(r.port, '') AS port,
                    coalesce(r.nvt, '') AS nvt_oid,
                    coalesce(n.name, r.nvt, '') AS name,
                    nullif(n.family, '') AS nvt_family,
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
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

async fn report_results(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "-severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("host", "host"),
            ("port", "port"),
            ("nvt_oid", "nvt_oid"),
            ("name", "name"),
            ("severity", "severity"),
            ("qod", "qod"),
            ("created_at", "created_at_unix"),
        ],
    )?;
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
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $3 OFFSET $4;"
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ReportHostItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, "host")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<TargetItem>>, ApiError> {
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "uuid"),
            ("name", "name"),
            ("port_list", "port_list_name"),
            ("task_count", "task_count"),
            ("max_hosts", "host_entry_count"),
            ("creation_time", "creation_time"),
            ("modification_time", "modification_time"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<TaskItem>>, ApiError> {
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ScopeItem>>, ApiError> {
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "uuid"),
            ("name", "name"),
            ("protection_requirement", "protection_requirement"),
            ("target_count", "target_count"),
            ("host_count", "host_count"),
            ("scope_report_count", "scope_report_count"),
            ("creation_time", "creation_time"),
            ("modification_time", "modification_time"),
        ],
    )?;
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

async fn scope_candidate_hosts(
    client: &tokio_postgres::Client,
    scope_pk: i32,
    global: bool,
) -> Result<Vec<ScopeCandidateHost>, ApiError> {
    if global {
        return Ok(Vec::new());
    }
    let rows = client
        .query(
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
              ORDER BY rh.host, st.target_uuid;",
            &[&scope_pk],
        )
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
             SELECT b.uuid, b.name, b.task_uuid, b.task_name, b.target_uuid, b.target_name,
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
                uuid, name, task_uuid, task_name, target_uuid, target_name, status,
                creation_time, scan_start, scan_end, modification_time,
                result_count, vulnerability_count, host_count, cve_count, max_severity,
                severity_critical, severity_high, severity_medium, severity_low,
                severity_log, severity_false_positive
           FROM filtered
          ORDER BY {sort_sql}, creation_time DESC, uuid DESC {limit_clause};"#,
    )
}

async fn scope_report_results(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "-severity")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("host", "host"),
            ("port", "port"),
            ("nvt_oid", "nvt_oid"),
            ("name", "name"),
            ("severity", "severity"),
            ("qod", "qod"),
            ("created_at", "created_at_unix"),
        ],
    )?;
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
         ranked AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    nullif(r.hostname, '') AS hostname,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
                    nullif(n.family, '') AS nvt_family,\n\
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
             SELECT id, host, hostname, port, nvt_oid, name, nvt_family, description_excerpt, severity, qod, created_at_unix, source_report_id\n\
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
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
          ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $4 OFFSET $5;"
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ErrorMessageItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "created_at")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("host", "host"),
            ("port", "port"),
            ("nvt_oid", "nvt_oid"),
            ("created_at", "created_at_unix"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ScopeReportItem>>, ApiError> {
    let params = normalize_collection_query(query, "-creation_time")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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

async fn scope_report_hosts(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<HostItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "host")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("host", "host"),
            ("scope_membership", "scope_membership"),
            ("source_report_count", "source_report_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("authenticated_scan_state", "authenticated_scan_state"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<PortItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "port")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("port", "port"),
            ("protocol", "protocol"),
            ("host_count", "host_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<ApplicationItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("name", "name"),
            ("cpe", "cpe"),
            ("host_count", "host_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "name")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("name", "name"),
            ("cpe", "cpe"),
            ("host_count", "host_count"),
            ("result_count", "result_count"),
            ("vulnerability_count", "vulnerability_count"),
            ("max_severity", "max_severity"),
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<TlsCertificateItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "-not_after")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
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
        ],
    )?;
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
    Query(query): Query<CollectionQuery>,
) -> Result<Json<Collection<CveItem>>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let params = normalize_collection_query(query, "id")?;
    let sort_sql = sort_clause(
        &params.sort,
        &[
            ("id", "id"),
            ("affected_system_count", "affected_system_count"),
            ("result_count", "result_count"),
            ("max_severity", "max_severity"),
        ],
    )?;
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

#[derive(Debug)]
struct NormalizedQuery {
    page: i64,
    page_size: i64,
    offset: i64,
    sort: String,
    filter: String,
}

impl NormalizedQuery {
    fn page_info(&self, total: i64) -> PageInfo {
        PageInfo {
            page: self.page,
            page_size: self.page_size,
            total,
            sort: self.sort.clone(),
            filter: self.filter.clone(),
        }
    }
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

fn vulnerability_from_row(row: &Row) -> VulnerabilityItem {
    VulnerabilityItem {
        id: row.get("id"),
        name: row.get("name"),
        oldest_result: unix_ts_to_rfc3339(row.get("oldest_result_unix")),
        newest_result: unix_ts_to_rfc3339(row.get("newest_result_unix")),
        severity: row.get("severity"),
        qod: row.get("qod"),
        result_count: row.get("result_count"),
        host_count: row.get("host_count"),
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
    }
}

fn normalize_collection_query(
    query: CollectionQuery,
    default_sort: &str,
) -> Result<NormalizedQuery, ApiError> {
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(50);
    if page < 1 {
        return Err(ApiError::BadRequest(
            "page must be greater than or equal to 1".to_string(),
        ));
    }
    if !(1..=500).contains(&page_size) {
        return Err(ApiError::BadRequest(
            "page_size must be between 1 and 500".to_string(),
        ));
    }
    let sort = query
        .sort
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_sort.to_string());
    let filter = query.filter.unwrap_or_default();
    Ok(NormalizedQuery {
        page,
        page_size,
        offset: (page - 1) * page_size,
        sort,
        filter,
    })
}

fn sort_clause(sort: &str, allowed: &[(&str, &str)]) -> Result<String, ApiError> {
    let (direction, field) = if let Some(field) = sort.strip_prefix('-') {
        ("DESC", field)
    } else {
        ("ASC", sort)
    };
    allowed
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, column)| format!("{column} {direction}"))
        .ok_or_else(|| ApiError::BadRequest(format!("unsupported sort field: {field}")))
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::BadRequest("path id must be a UUID".to_string()))
}

fn report_reference(id: Option<String>, name: Option<String>) -> Option<ReportReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(ReportReference { id, name })
}

fn optional_row_string(row: &Row, name: &str) -> Option<String> {
    row.try_get::<_, Option<String>>(name).ok().flatten()
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

fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn alive_test_labels(value: i64) -> Vec<String> {
    let label = match value {
        0 => "Scan Config Default",
        1 => "ICMP Ping",
        2 => "TCP-ACK Service Ping",
        3 => "TCP-SYN Service Ping",
        4 => "ARP Ping",
        5 => "Consider Alive",
        _ => "Unknown",
    };
    vec![label.to_string()]
}

fn boolean_int(value: i32) -> bool {
    value != 0
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

fn task_has_active_current_report(status: &str) -> bool {
    matches!(
        status,
        "Requested" | "Queued" | "Running" | "Processing" | "Stop Requested"
    )
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
        task: report_reference(row.get(3), row.get(4)),
        target: report_reference(row.get(5), row.get(6)),
        status: row.get(7),
        creation_time: unix_ts_to_rfc3339(row.get(8)),
        scan_start: unix_ts_to_rfc3339(row.get(9)),
        scan_end: unix_ts_to_rfc3339(row.get(10)),
        modification_time: unix_ts_to_rfc3339(row.get(11)),
        result_count: row.get(12),
        vulnerability_count: row.get(13),
        host_count: row.get(14),
        cve_count: row.get(15),
        max_severity: row.get(16),
        severity: ReportSeverityCounts {
            critical: row.get(17),
            high: row.get(18),
            medium: row.get(19),
            low: row.get(20),
            log: row.get(21),
            false_positive: row.get(22),
        },
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

fn normalize_protection_requirement(value: &str) -> String {
    match value {
        "normal" | "Normal" => "Normal".to_string(),
        "high" | "High" => "High".to_string(),
        "very_high" | "very high" | "Very High" => "Very High".to_string(),
        _ => value.to_string(),
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
        source_host_count: row.get("source_host_count"),
        source_port_count: row.get("source_port_count"),
        source_count,
        in_use: source_count > 0,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
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
        raw_evidence_href: format!("/report/{source_report_id}/result/{id}"),
        id,
        host: row.get("host"),
        host_asset_id: optional_row_string(row, "host_asset_id"),
        hostname: row.get("hostname"),
        port: row.get("port"),
        nvt_oid: row.get("nvt_oid"),
        name: row.get("name"),
        nvt_family: row.get("nvt_family"),
        description_excerpt: row.get("description_excerpt"),
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

fn normalize_authentication_state(state: &str) -> String {
    match state {
        "authenticated" | "Authenticated" => "Authenticated".to_string(),
        "authentication_failed" | "Authentication Failed" => "Authentication Failed".to_string(),
        "no_credential_path" | "No Credential Path" => "No Credential Path".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn unix_ts_to_rfc3339(value: i64) -> Option<String> {
    if value <= 0 {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(value)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collection_defaults_and_offset() {
        let query = normalize_collection_query(
            CollectionQuery {
                page: Some(3),
                page_size: Some(25),
                sort: None,
                filter: Some("router".to_string()),
            },
            "host",
        )
        .unwrap();
        assert_eq!(query.page, 3);
        assert_eq!(query.page_size, 25);
        assert_eq!(query.offset, 50);
        assert_eq!(query.sort, "host");
        assert_eq!(query.filter, "router");
    }

    #[test]
    fn normalize_collection_rejects_bad_page_size() {
        let err = normalize_collection_query(
            CollectionQuery {
                page: Some(1),
                page_size: Some(501),
                sort: None,
                filter: None,
            },
            "host",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn sort_clause_supports_descending_whitelist_only() {
        assert_eq!(
            sort_clause(
                "-result_count",
                &[("host", "host"), ("result_count", "result_count")]
            )
            .unwrap(),
            "result_count DESC"
        );
        assert!(sort_clause(";drop", &[("host", "host")]).is_err());
    }

    #[test]
    fn authentication_state_is_public_contract_shape() {
        assert_eq!(
            normalize_authentication_state("authenticated"),
            "Authenticated"
        );
        assert_eq!(
            normalize_authentication_state("authentication_failed"),
            "Authentication Failed"
        );
        assert_eq!(
            normalize_authentication_state("no_credential_path"),
            "No Credential Path"
        );
        assert_eq!(normalize_authentication_state("ambiguous"), "Unknown");
    }

    #[test]
    fn protection_requirement_is_public_contract_shape() {
        assert_eq!(normalize_protection_requirement("normal"), "Normal");
        assert_eq!(normalize_protection_requirement("high"), "High");
        assert_eq!(normalize_protection_requirement("very_high"), "Very High");
        assert_eq!(normalize_protection_requirement("Very High"), "Very High");
    }

    #[test]
    fn unix_timestamp_formats_as_rfc3339() {
        assert_eq!(unix_ts_to_rfc3339(0), None);
        assert_eq!(unix_ts_to_rfc3339(1).unwrap(), "1970-01-01T00:00:01Z");
    }
}
