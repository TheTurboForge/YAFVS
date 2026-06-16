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
    max_severity: f64,
    latest_evidence_time: Option<String>,
    excluded_candidate_host_count: i64,
    creation_time: Option<String>,
    modification_time: Option<String>,
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
        .route(
            "/api/v1/scopes/:scope_id/reports/:scope_report_id/hosts",
            get(scope_report_hosts),
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
           SELECT sr.uuid, sr.scope_uuid, sr.scope_name, sr.protection_requirement,\n\
                  sr.source_report_count::bigint, sr.source_target_count::bigint,\n\
                  sr.member_host_count::bigint, sr.evidence_host_count::bigint,\n\
                  sr.missing_host_count::bigint, sr.result_count::bigint,\n\
                  sr.vulnerability_count::bigint, sr.max_severity::double precision,\n\
                  sr.latest_evidence_time::bigint, sr.excluded_candidate_host_count::bigint,\n\
                  sr.creation_time::bigint, sr.modification_time::bigint\n\
             FROM scope_reports sr\n\
            WHERE ($1 = '' OR lower(sr.uuid) = lower($1)\n\
                   OR lower(sr.scope_uuid) = lower($1)\n\
                   OR lower(sr.scope_name) LIKE '%' || lower($1) || '%')\n\
         )\n\
         SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
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
