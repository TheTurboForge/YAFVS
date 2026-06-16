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
struct CveItem {
    id: String,
    affected_system_count: i64,
    result_count: i64,
    max_severity: f64,
    source_report_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResultItem {
    id: String,
    host: String,
    port: String,
    nvt_oid: String,
    name: String,
    severity: f64,
    qod: i64,
    created_at: Option<String>,
    source_report_id: String,
    raw_evidence_href: String,
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
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/cves",
            get(scope_report_cves),
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
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
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
             SELECT id, host, port, nvt_oid, name, severity, qod, created_at_unix, source_report_id\n\
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

fn cve_from_row(row: &Row) -> CveItem {
    CveItem {
        id: row.get(1),
        affected_system_count: row.get(2),
        result_count: row.get(3),
        max_severity: row.get(4),
        source_report_ids: row.get(5),
    }
}

fn result_from_row(row: &Row) -> ResultItem {
    let id: String = row.get(1);
    let source_report_id: String = row.get(9);
    ResultItem {
        raw_evidence_href: format!("/report/{source_report_id}/result/{id}"),
        id,
        host: row.get(2),
        port: row.get(3),
        nvt_oid: row.get(4),
        name: row.get(5),
        severity: row.get(6),
        qod: row.get(7),
        created_at: unix_ts_to_rfc3339(row.get(8)),
        source_report_id,
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
