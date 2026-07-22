// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use pdf_writer::{Content, Finish, Name, Pdf, Rect, Ref, Str};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio_postgres::{IsolationLevel, Row, Transaction};
use uuid::Uuid;

use crate::{app_state::AppState, errors::ApiError, formatters::unix_ts_to_rfc3339};

pub(crate) const CANONICAL_PDF_REPORT_FORMAT_ID: &str = "c402cc3e-b531-11e1-9163-406186ea4fc5";
const MAX_PDF_RESULT_ROWS: i64 = 3_000;
const MAX_PDF_SOURCE_TEXT_BYTES: i64 = 8 * 1024 * 1024;
const MAX_PDF_RENDERED_LINES: usize = 24_000;
const MAX_PDF_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
static PDF_GENERATION_PERMITS: Semaphore = Semaphore::const_new(2);
const PAGE_WIDTH_POINTS: f32 = 595.0;
const PAGE_HEIGHT_POINTS: f32 = 842.0;
const PAGE_MARGIN_POINTS: f32 = 42.5;
const PAGE_TOP_POINTS: f32 = PAGE_HEIGHT_POINTS - PAGE_MARGIN_POINTS;
const PAGE_BOTTOM_POINTS: f32 = PAGE_MARGIN_POINTS;
const BODY_LINE_HEIGHT_POINTS: f32 = 14.2;
const BODY_FONT_SIZE: f32 = 8.5;
const HEADING_FONT_SIZE: f32 = 11.0;
const TITLE_FONT_SIZE: f32 = 17.0;
const TEXT_LINE_WIDTH: usize = 92;

const PDF_LIMIT_SQL: &str = r#"
    SELECT count(*)::bigint AS row_count,
           coalesce(sum(
               octet_length(coalesce(r.uuid, ''))
               + octet_length(coalesce(r.host, ''))
               + octet_length(coalesce(r.hostname, ''))
               + octet_length(coalesce(r.port, ''))
               + octet_length(coalesce(r.nvt, ''))
               + octet_length(coalesce(r.type, ''))
               + octet_length(coalesce(r.description, ''))
               + octet_length(coalesce(r.qod_type, ''))
               + octet_length(coalesce(r.nvt_version, ''))
               + octet_length(coalesce(n.name, ''))
               + octet_length(coalesce(n.family, ''))
               + octet_length(coalesce(n.summary, ''))
               + octet_length(coalesce(n.insight, ''))
               + octet_length(coalesce(n.affected, ''))
               + octet_length(coalesce(n.impact, ''))
               + octet_length(coalesce(n.detection, ''))
               + octet_length(coalesce(n.solution_type, ''))
               + octet_length(coalesce(n.solution, ''))
               + octet_length(coalesce(n.cve, ''))
           ), 0)::bigint AS source_text_bytes
      FROM reports report
      JOIN results r ON r.report = report.id
      LEFT JOIN nvts n ON n.oid = r.nvt
     WHERE lower(report.uuid) = lower($1);
"#;

const PDF_REPORT_SQL: &str = r#"
    WITH base AS (
        SELECT r.id AS report_pk,
               r.uuid AS report_id,
               coalesce(nullif(t.name, ''), r.uuid) AS report_name,
               coalesce(u.name, '') AS owner_name,
               t.uuid AS task_id,
               t.name AS task_name,
               target.uuid AS target_id,
               target.name AS target_name,
               run_status_name(r.scan_run_status) AS status,
               coalesce(r.creation_time, 0)::bigint AS creation_time,
               coalesce(r.start_time, 0)::bigint AS scan_start,
               coalesce(r.end_time, 0)::bigint AS scan_end,
               coalesce(r.modification_time, 0)::bigint AS modification_time
          FROM reports r
          LEFT JOIN tasks t ON t.id = r.task
          LEFT JOIN users u ON u.id = r.owner
          LEFT JOIN targets target ON target.id = t.target
         WHERE lower(r.uuid) = lower($1)
           AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
    ),
    result_agg AS (
        SELECT base.report_pk,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) != -3.0)::bigint AS result_count,
               count(DISTINCT nullif(r.nvt, '')) FILTER (WHERE coalesce(r.severity, 0) != -3.0)::bigint AS vulnerability_count,
               coalesce(max(coalesce(r.severity, 0)) FILTER (WHERE coalesce(r.severity, 0) > 0), 0)::double precision AS max_severity,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) >= 9.0)::bigint AS severity_critical,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) >= 7.0 AND coalesce(r.severity, 0) < 9.0)::bigint AS severity_high,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) >= 4.0 AND coalesce(r.severity, 0) < 7.0)::bigint AS severity_medium,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) > 0.0 AND coalesce(r.severity, 0) < 4.0)::bigint AS severity_low,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) = 0.0)::bigint AS severity_log,
               count(r.id) FILTER (WHERE coalesce(r.severity, 0) = -1.0)::bigint AS severity_false_positive
          FROM base
          LEFT JOIN results r ON r.report = base.report_pk
         GROUP BY base.report_pk
    ),
    host_agg AS (
        SELECT base.report_pk,
               count(DISTINCT lower(report_host.host)) FILTER (WHERE coalesce(report_host.host, '') <> '')::bigint AS host_count
          FROM base
          LEFT JOIN report_hosts report_host ON report_host.report = base.report_pk
         GROUP BY base.report_pk
    ),
    cve_agg AS (
        SELECT base.report_pk,
               count(DISTINCT lower(vt_ref.ref_id)) FILTER (WHERE coalesce(vt_ref.ref_id, '') <> '')::bigint AS cve_count
          FROM base
          LEFT JOIN results r ON r.report = base.report_pk AND coalesce(r.severity, 0) > 0
          LEFT JOIN vt_refs vt_ref ON vt_ref.vt_oid = r.nvt AND lower(vt_ref.type) = 'cve'
         GROUP BY base.report_pk
    )
    SELECT base.report_id,
           base.report_name,
           base.owner_name,
           base.task_id,
           base.task_name,
           base.target_id,
           base.target_name,
           base.status,
           base.creation_time,
           base.scan_start,
           base.scan_end,
           base.modification_time,
           coalesce(result_agg.result_count, 0)::bigint AS result_count,
           coalesce(result_agg.vulnerability_count, 0)::bigint AS vulnerability_count,
           coalesce(host_agg.host_count, 0)::bigint AS host_count,
           coalesce(cve_agg.cve_count, 0)::bigint AS cve_count,
           coalesce(result_agg.max_severity, 0)::double precision AS max_severity,
           coalesce(result_agg.severity_critical, 0)::bigint AS severity_critical,
           coalesce(result_agg.severity_high, 0)::bigint AS severity_high,
           coalesce(result_agg.severity_medium, 0)::bigint AS severity_medium,
           coalesce(result_agg.severity_low, 0)::bigint AS severity_low,
           coalesce(result_agg.severity_log, 0)::bigint AS severity_log,
           coalesce(result_agg.severity_false_positive, 0)::bigint AS severity_false_positive
      FROM base
      LEFT JOIN result_agg ON result_agg.report_pk = base.report_pk
      LEFT JOIN host_agg ON host_agg.report_pk = base.report_pk
      LEFT JOIN cve_agg ON cve_agg.report_pk = base.report_pk;
"#;

const PDF_EVIDENCE_SQL: &str = r#"
    SELECT r.uuid AS id,
           r.host,
           r.hostname,
           r.port,
           r.nvt AS nvt_oid,
           nullif(n.name, '') AS nvt_name,
           nullif(n.family, '') AS nvt_family,
           r.type AS result_type,
           r.description,
           nullif(n.summary, '') AS summary,
           nullif(n.insight, '') AS insight,
           nullif(n.affected, '') AS affected,
           nullif(n.impact, '') AS impact,
           nullif(n.detection, '') AS detection,
           nullif(n.solution_type, '') AS solution_type,
           nullif(n.solution, '') AS solution,
           nullif(n.cve, '') AS cves,
           r.severity::double precision AS severity,
           r.qod::bigint AS qod,
           r.qod_type,
           nullif(r.nvt_version, '') AS scan_nvt_version,
           r.date::bigint AS created_at_unix
      FROM reports report
      JOIN results r ON r.report = report.id
      LEFT JOIN nvts n ON n.oid = r.nvt
     WHERE lower(report.uuid) = lower($1)
     ORDER BY coalesce(r.date, 0)::bigint ASC, r.uuid ASC
     LIMIT $2;
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportPdfDownloadQuery {
    report_format_id: Option<String>,
}

#[derive(Debug)]
struct NativePdfReport {
    report_id: String,
    report_name: String,
    owner_name: String,
    task_id: Option<String>,
    task_name: Option<String>,
    target_id: Option<String>,
    target_name: Option<String>,
    status: String,
    creation_time: Option<String>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    modification_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    host_count: i64,
    cve_count: i64,
    max_severity: f64,
    severity: PdfSeverityCounts,
    evidence: Vec<PdfEvidence>,
}

#[derive(Debug)]
struct PdfSeverityCounts {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    log: i64,
    false_positive: i64,
}

#[derive(Debug)]
struct PdfEvidence {
    id: String,
    host: Option<String>,
    hostname: Option<String>,
    port: Option<String>,
    nvt_oid: Option<String>,
    nvt_name: Option<String>,
    nvt_family: Option<String>,
    result_type: Option<String>,
    description: Option<String>,
    summary: Option<String>,
    insight: Option<String>,
    affected: Option<String>,
    impact: Option<String>,
    detection: Option<String>,
    solution_type: Option<String>,
    solution: Option<String>,
    cves: Option<String>,
    severity: Option<f64>,
    qod: Option<i64>,
    qod_type: Option<String>,
    scan_nvt_version: Option<String>,
    created_at: Option<String>,
}

pub(crate) async fn report_pdf_download(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    query: Result<Query<ReportPdfDownloadQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let _generation_permit = PDF_GENERATION_PERMITS
        .acquire()
        .await
        .map_err(|_| ApiError::Config)?;
    let canonical_report_id = canonical_report_id(&report_id)?;
    let Query(query) = query.map_err(|_| {
        ApiError::BadRequest("report PDF download accepts only report_format_id".to_string())
    })?;
    validate_report_pdf_download_query(query)?;

    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "native PDF snapshot transaction failed");
            ApiError::Database
        })?;
    let report = load_native_pdf_report(&transaction, &canonical_report_id).await?;
    transaction.commit().await.map_err(|error| {
        tracing::warn!(%error, "native PDF snapshot commit failed");
        ApiError::Database
    })?;
    let pdf = tokio::task::spawn_blocking(move || render_native_pdf(&report))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "native PDF render task failed");
            ApiError::Database
        })??;
    let headers = report_pdf_headers(&canonical_report_id)?;
    Ok((headers, pdf).into_response())
}

fn canonical_report_id(report_id: &str) -> Result<String, ApiError> {
    Uuid::parse_str(report_id)
        .map(|report_id| report_id.to_string())
        .map_err(|_| ApiError::BadRequest("path id must be a UUID".to_string()))
}

fn validate_report_pdf_download_query(query: ReportPdfDownloadQuery) -> Result<(), ApiError> {
    match query.report_format_id.as_deref() {
        None | Some(CANONICAL_PDF_REPORT_FORMAT_ID) => Ok(()),
        Some(_) => Err(ApiError::BadRequest(format!(
            "only the canonical PDF report_format_id {CANONICAL_PDF_REPORT_FORMAT_ID} is supported"
        ))),
    }
}

fn report_pdf_headers(report_id: &str) -> Result<HeaderMap, ApiError> {
    let filename = format!("yafvs-report-{report_id}.pdf");
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| ApiError::Config)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(headers)
}

async fn load_native_pdf_report(
    client: &Transaction<'_>,
    report_id: &str,
) -> Result<NativePdfReport, ApiError> {
    enforce_pdf_evidence_limits(client, report_id).await?;
    let row = client
        .query_opt(PDF_REPORT_SQL, &[&report_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "native PDF report metadata query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let result_limit = MAX_PDF_RESULT_ROWS + 1;
    let evidence_rows = client
        .query(PDF_EVIDENCE_SQL, &[&report_id, &result_limit])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "native PDF report evidence query failed");
            ApiError::Database
        })?;
    if evidence_rows.len() as i64 > MAX_PDF_RESULT_ROWS {
        return Err(ApiError::ReportPdfTooLarge);
    }
    let mut report = native_pdf_report_from_row(&row);
    report.evidence = evidence_rows.iter().map(pdf_evidence_from_row).collect();
    Ok(report)
}

async fn enforce_pdf_evidence_limits(
    client: &Transaction<'_>,
    report_id: &str,
) -> Result<(), ApiError> {
    let row = client
        .query_one(PDF_LIMIT_SQL, &[&report_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "native PDF report evidence limit query failed");
            ApiError::Database
        })?;
    let row_count: i64 = row.get("row_count");
    let source_text_bytes: i64 = row.get("source_text_bytes");
    if !pdf_evidence_is_within_limits(row_count, source_text_bytes) {
        return Err(ApiError::ReportPdfTooLarge);
    }
    Ok(())
}

fn pdf_evidence_is_within_limits(row_count: i64, source_text_bytes: i64) -> bool {
    row_count <= MAX_PDF_RESULT_ROWS && source_text_bytes <= MAX_PDF_SOURCE_TEXT_BYTES
}

fn native_pdf_report_from_row(row: &Row) -> NativePdfReport {
    NativePdfReport {
        report_id: row.get("report_id"),
        report_name: row.get("report_name"),
        owner_name: row.get("owner_name"),
        task_id: row.get("task_id"),
        task_name: row.get("task_name"),
        target_id: row.get("target_id"),
        target_name: row.get("target_name"),
        status: row.get("status"),
        creation_time: unix_ts_to_rfc3339(row.get("creation_time")),
        scan_start: unix_ts_to_rfc3339(row.get("scan_start")),
        scan_end: unix_ts_to_rfc3339(row.get("scan_end")),
        modification_time: unix_ts_to_rfc3339(row.get("modification_time")),
        result_count: row.get("result_count"),
        vulnerability_count: row.get("vulnerability_count"),
        host_count: row.get("host_count"),
        cve_count: row.get("cve_count"),
        max_severity: row.get("max_severity"),
        severity: PdfSeverityCounts {
            critical: row.get("severity_critical"),
            high: row.get("severity_high"),
            medium: row.get("severity_medium"),
            low: row.get("severity_low"),
            log: row.get("severity_log"),
            false_positive: row.get("severity_false_positive"),
        },
        evidence: Vec::new(),
    }
}

fn pdf_evidence_from_row(row: &Row) -> PdfEvidence {
    PdfEvidence {
        id: row.get("id"),
        host: row.get("host"),
        hostname: row.get("hostname"),
        port: row.get("port"),
        nvt_oid: row.get("nvt_oid"),
        nvt_name: row.get("nvt_name"),
        nvt_family: row.get("nvt_family"),
        result_type: row.get("result_type"),
        description: row.get("description"),
        summary: row.get("summary"),
        insight: row.get("insight"),
        affected: row.get("affected"),
        impact: row.get("impact"),
        detection: row.get("detection"),
        solution_type: row.get("solution_type"),
        solution: row.get("solution"),
        cves: row.get("cves"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        qod_type: row.get("qod_type"),
        scan_nvt_version: row.get("scan_nvt_version"),
        created_at: row
            .get::<_, Option<i64>>("created_at_unix")
            .and_then(unix_ts_to_rfc3339),
    }
}

fn render_native_pdf(report: &NativePdfReport) -> Result<Vec<u8>, ApiError> {
    let mut layout = PdfLayout::new(format!("YAFVS report {}", report.report_id));
    layout.add_title("YAFVS Native Report")?;
    layout.add_text("Typed PostgreSQL report metadata and raw scanner evidence")?;
    layout.add_blank_line()?;
    layout.add_section("Report Identity And Provenance")?;
    layout.add_field("Report ID", &report.report_id)?;
    layout.add_field("Report Name", &report.report_name)?;
    layout.add_field("Owner", &report.owner_name)?;
    layout.add_optional_field("Task ID", report.task_id.as_deref())?;
    layout.add_optional_field("Task Name", report.task_name.as_deref())?;
    layout.add_optional_field("Target ID", report.target_id.as_deref())?;
    layout.add_optional_field("Target Name", report.target_name.as_deref())?;
    layout.add_field("Status", &report.status)?;
    layout.add_optional_field("Created", report.creation_time.as_deref())?;
    layout.add_optional_field("Scan Start", report.scan_start.as_deref())?;
    layout.add_optional_field("Scan End", report.scan_end.as_deref())?;
    layout.add_optional_field("Last Modified", report.modification_time.as_deref())?;

    layout.add_blank_line()?;
    layout.add_section("Summary Counts")?;
    layout.add_text(&format!(
        "Results: {}  Vulnerabilities: {}  Hosts: {}  CVEs: {}",
        report.result_count, report.vulnerability_count, report.host_count, report.cve_count
    ))?;
    layout.add_text(&format!(
        "Severity: Critical {}  High {}  Medium {}  Low {}  Log {}  False Positive {}",
        report.severity.critical,
        report.severity.high,
        report.severity.medium,
        report.severity.low,
        report.severity.log,
        report.severity.false_positive
    ))?;
    layout.add_text(&format!("Maximum severity: {:.1}", report.max_severity))?;

    layout.add_blank_line()?;
    layout.add_section("Raw Evidence")?;
    if report.evidence.is_empty() {
        layout.add_text("No raw result rows were recorded for this report.")?;
    }
    for (index, evidence) in report.evidence.iter().enumerate() {
        render_evidence(&mut layout, index + 1, evidence)?;
    }

    let error_count = report
        .evidence
        .iter()
        .filter(|evidence| evidence.is_error())
        .count();
    layout.add_blank_line()?;
    layout.add_section("Scanner Error Messages")?;
    if error_count == 0 {
        layout.add_text("No scanner error rows were recorded for this report.")?;
    }
    for (index, evidence) in report
        .evidence
        .iter()
        .filter(|evidence| evidence.is_error())
        .enumerate()
    {
        render_scanner_error(&mut layout, index + 1, evidence)?;
    }

    let pdf = write_pdf_document(layout.finish());
    if pdf_output_is_within_limit(pdf.len()) {
        Ok(pdf)
    } else {
        Err(ApiError::ReportPdfTooLarge)
    }
}

fn pdf_output_is_within_limit(output_bytes: usize) -> bool {
    output_bytes <= MAX_PDF_OUTPUT_BYTES
}

fn render_evidence(
    layout: &mut PdfLayout,
    position: usize,
    evidence: &PdfEvidence,
) -> Result<(), ApiError> {
    layout.add_heading(&format!("Evidence {position}: {}", pdf_text(&evidence.id)))?;
    layout.add_field("Host", &host_label(evidence, false))?;
    layout.add_optional_field("Hostname", evidence.hostname.as_deref())?;
    layout.add_optional_field("Port", evidence.port.as_deref())?;
    layout.add_optional_field("NVT", evidence.nvt_oid.as_deref())?;
    layout.add_optional_field("NVT Name", evidence.nvt_name.as_deref())?;
    layout.add_optional_field("NVT Family", evidence.nvt_family.as_deref())?;
    layout.add_optional_field("CVEs", evidence.cves.as_deref())?;
    layout.add_optional_field("Type", evidence.result_type.as_deref())?;
    layout.add_field("Severity", &severity_label(evidence.severity))?;
    layout.add_field("QoD", &qod_label(evidence.qod))?;
    layout.add_optional_field("QoD Type", evidence.qod_type.as_deref())?;
    layout.add_optional_field("Scan NVT Version", evidence.scan_nvt_version.as_deref())?;
    layout.add_optional_field("Recorded", evidence.created_at.as_deref())?;
    layout.add_optional_field("Detection Result", evidence.description.as_deref())?;
    layout.add_optional_field("Summary", evidence.summary.as_deref())?;
    layout.add_optional_field("Insight", evidence.insight.as_deref())?;
    layout.add_optional_field("Affected", evidence.affected.as_deref())?;
    layout.add_optional_field("Impact", evidence.impact.as_deref())?;
    layout.add_optional_field("Detection Method", evidence.detection.as_deref())?;
    layout.add_optional_field("Solution Type", evidence.solution_type.as_deref())?;
    layout.add_optional_field("Solution", evidence.solution.as_deref())?;
    layout.add_blank_line()
}

fn render_scanner_error(
    layout: &mut PdfLayout,
    position: usize,
    evidence: &PdfEvidence,
) -> Result<(), ApiError> {
    layout.add_heading(&format!("Error {position}: {}", pdf_text(&evidence.id)))?;
    layout.add_field("Host", &host_label(evidence, true))?;
    layout.add_optional_field("Port", evidence.port.as_deref())?;
    layout.add_optional_field("NVT", evidence.nvt_oid.as_deref())?;
    layout.add_optional_field("Type", evidence.result_type.as_deref())?;
    layout.add_optional_field("Recorded", evidence.created_at.as_deref())?;
    layout.add_optional_field("Description", evidence.description.as_deref())?;
    layout.add_blank_line()
}

fn host_label(evidence: &PdfEvidence, error_row: bool) -> String {
    let host = evidence.host.as_deref().filter(|value| !value.is_empty());
    if let Some(host) = host {
        return pdf_text(host);
    }
    if error_row {
        "(hostless scanner error)".to_string()
    } else {
        "Not recorded".to_string()
    }
}

fn severity_label(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1}"))
        .unwrap_or_else(|| "Not recorded".to_string())
}

fn qod_label(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Not recorded".to_string())
}

impl PdfEvidence {
    fn is_error(&self) -> bool {
        self.result_type.as_deref() == Some("Error Message")
            || self.severity.is_some_and(|severity| severity == -3.0)
    }
}

// Core PDF fonts are intentionally limited to ASCII. Preserve every non-ASCII
// scalar as a visible escaped code point instead of dropping it or relying on a font fallback.
fn pdf_text(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            ' '..='~' => rendered.push(character),
            '\n' | '\r' | '\t' => rendered.push(' '),
            _ => rendered.push_str(&format!("\\u{{{:X}}}", character as u32)),
        }
    }
    rendered
}

fn wrap_pdf_text(value: &str, width: usize) -> Vec<String> {
    if value.is_empty() {
        return vec![String::new()];
    }
    let mut remaining = value.trim();
    let mut lines = Vec::new();
    while remaining.len() > width {
        let split_at = if remaining.as_bytes().get(width) == Some(&b' ') {
            width
        } else {
            remaining[..width]
                .rfind(' ')
                .filter(|position| *position > 0)
                .unwrap_or(width)
        };
        lines.push(remaining[..split_at].trim_end().to_string());
        remaining = remaining[split_at..].trim_start();
    }
    lines.push(remaining.to_string());
    lines
}

struct PdfLayout {
    page_header: String,
    pages: Vec<Vec<PdfLine>>,
    lines: Vec<PdfLine>,
    cursor_y: f32,
    rendered_lines: usize,
}

#[derive(Clone, Copy)]
enum PdfFont {
    Regular,
    Bold,
}

struct PdfLine {
    value: String,
    font: PdfFont,
    font_size: f32,
    x: f32,
    y: f32,
}

impl PdfLayout {
    fn new(page_header: String) -> Self {
        let mut layout = Self {
            page_header,
            pages: Vec::new(),
            lines: Vec::new(),
            cursor_y: PAGE_TOP_POINTS,
            rendered_lines: 0,
        };
        layout.start_page();
        layout
    }

    fn start_page(&mut self) {
        if !self.lines.is_empty() {
            self.pages.push(std::mem::take(&mut self.lines));
        }
        self.cursor_y = PAGE_TOP_POINTS;
        self.push_line(&self.page_header.clone(), PdfFont::Bold, 7.0);
        self.cursor_y -= 5.0;
    }

    fn add_title(&mut self, value: &str) -> Result<(), ApiError> {
        self.add_lines(&pdf_text(value), PdfFont::Bold, TITLE_FONT_SIZE)
    }

    fn add_section(&mut self, value: &str) -> Result<(), ApiError> {
        self.add_lines(&pdf_text(value), PdfFont::Bold, HEADING_FONT_SIZE)
    }

    fn add_heading(&mut self, value: &str) -> Result<(), ApiError> {
        self.add_lines(&pdf_text(value), PdfFont::Bold, BODY_FONT_SIZE)
    }

    fn add_text(&mut self, value: &str) -> Result<(), ApiError> {
        self.add_lines(&pdf_text(value), PdfFont::Regular, BODY_FONT_SIZE)
    }

    fn add_blank_line(&mut self) -> Result<(), ApiError> {
        self.add_lines("", PdfFont::Regular, BODY_FONT_SIZE)
    }

    fn add_field(&mut self, label: &str, value: &str) -> Result<(), ApiError> {
        let value = pdf_text(value);
        let mut lines = wrap_pdf_text(&value, TEXT_LINE_WIDTH.saturating_sub(label.len() + 2));
        let first = lines.remove(0);
        self.add_lines(
            &format!("{label}: {first}"),
            PdfFont::Regular,
            BODY_FONT_SIZE,
        )?;
        for line in lines {
            self.add_lines(&format!("  {line}"), PdfFont::Regular, BODY_FONT_SIZE)?;
        }
        Ok(())
    }

    fn add_optional_field(&mut self, label: &str, value: Option<&str>) -> Result<(), ApiError> {
        self.add_field(label, value.unwrap_or("Not recorded"))
    }

    fn add_lines(&mut self, value: &str, font: PdfFont, font_size: f32) -> Result<(), ApiError> {
        for line in wrap_pdf_text(value, TEXT_LINE_WIDTH) {
            if self.rendered_lines >= MAX_PDF_RENDERED_LINES {
                return Err(ApiError::ReportPdfTooLarge);
            }
            if self.cursor_y - BODY_LINE_HEIGHT_POINTS < PAGE_BOTTOM_POINTS {
                self.start_page();
            }
            self.push_line(&line, font, font_size);
            self.rendered_lines += 1;
        }
        Ok(())
    }

    fn push_line(&mut self, value: &str, font: PdfFont, font_size: f32) {
        self.lines.push(PdfLine {
            value: value.to_string(),
            font,
            font_size,
            x: PAGE_MARGIN_POINTS,
            y: self.cursor_y,
        });
        self.cursor_y -= BODY_LINE_HEIGHT_POINTS;
    }

    fn finish(mut self) -> Vec<Vec<PdfLine>> {
        if !self.lines.is_empty() {
            self.pages.push(self.lines);
        }
        self.pages
    }
}

fn write_pdf_document(pages: Vec<Vec<PdfLine>>) -> Vec<u8> {
    let catalog_id = Ref::new(1);
    let page_tree_id = Ref::new(2);
    let regular_font_id = Ref::new(3);
    let bold_font_id = Ref::new(4);
    let page_ids = (0..pages.len())
        .map(|index| Ref::new(5 + (index as i32 * 2)))
        .collect::<Vec<_>>();

    let mut pdf = Pdf::new();
    pdf.catalog(catalog_id).pages(page_tree_id);
    pdf.pages(page_tree_id)
        .kids(page_ids.iter().copied())
        .count(pages.len() as i32);
    pdf.type1_font(regular_font_id)
        .base_font(Name(b"Helvetica"));
    pdf.type1_font(bold_font_id)
        .base_font(Name(b"Helvetica-Bold"));

    for (index, lines) in pages.iter().enumerate() {
        let page_id = page_ids[index];
        let content_id = Ref::new(6 + (index as i32 * 2));
        let mut page = pdf.page(page_id);
        page.media_box(Rect::new(0.0, 0.0, PAGE_WIDTH_POINTS, PAGE_HEIGHT_POINTS));
        page.parent(page_tree_id);
        page.contents(content_id);
        {
            let mut resources = page.resources();
            let mut fonts = resources.fonts();
            fonts.pair(Name(b"F1"), regular_font_id);
            fonts.pair(Name(b"F2"), bold_font_id);
            fonts.finish();
            resources.finish();
        }
        page.finish();

        let mut content = Content::new();
        content.begin_text();
        for line in lines {
            let font_name = match line.font {
                PdfFont::Regular => Name(b"F1"),
                PdfFont::Bold => Name(b"F2"),
            };
            content.set_font(font_name, line.font_size);
            content.set_text_matrix([1.0, 0.0, 0.0, 1.0, line.x, line.y]);
            // Str writes PDF literal strings with the needed delimiter escaping.
            content.show(Str(line.value.as_bytes()));
        }
        content.end_text();
        pdf.stream(content_id, &content.finish());
    }

    pdf.finish()
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode, header};

    use super::*;
    use crate::direct_api_contract::{
        direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed,
    };

    const REPORT_ID: &str = "12345678-1234-1234-1234-123456789abc";
    const ROUTES: &str = include_str!("read_api_routes.rs");
    const STARTUP: &str = include_str!("startup.rs");
    const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
    const CARGO_MANIFEST: &str = include_str!("../Cargo.toml");

    fn sample_report() -> NativePdfReport {
        NativePdfReport {
            report_id: REPORT_ID.to_string(),
            report_name: "Example report".to_string(),
            owner_name: "admin".to_string(),
            task_id: Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string()),
            task_name: Some("Example task".to_string()),
            target_id: Some("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string()),
            target_name: Some("Example target".to_string()),
            status: "Done".to_string(),
            creation_time: Some("2026-01-01T00:00:00Z".to_string()),
            scan_start: Some("2026-01-01T00:01:00Z".to_string()),
            scan_end: Some("2026-01-01T00:02:00Z".to_string()),
            modification_time: Some("2026-01-01T00:03:00Z".to_string()),
            result_count: 1,
            vulnerability_count: 1,
            host_count: 1,
            cve_count: 0,
            max_severity: 9.8,
            severity: PdfSeverityCounts {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                log: 0,
                false_positive: 0,
            },
            evidence: vec![PdfEvidence {
                id: "cccccccc-cccc-cccc-cccc-cccccccccccc".to_string(),
                host: None,
                hostname: None,
                port: None,
                nvt_oid: Some("1.3.6.1.4.1.25623.1.0.1".to_string()),
                nvt_name: Some("Example NVT".to_string()),
                nvt_family: Some("General".to_string()),
                result_type: Some("Error Message".to_string()),
                description: Some(
                    "Scanner failed for caf\u{00e9} \u{1f680} (scanner)\\path".to_string(),
                ),
                summary: Some("Summary".to_string()),
                insight: Some("Insight".to_string()),
                affected: Some("Affected systems".to_string()),
                impact: Some("Impact".to_string()),
                detection: Some("Detection method".to_string()),
                solution_type: Some("VendorFix".to_string()),
                solution: Some("Upgrade".to_string()),
                cves: Some("CVE-2026-0001".to_string()),
                severity: Some(-3.0),
                qod: None,
                qod_type: None,
                scan_nvt_version: Some("2026-01-01T00:00:00Z".to_string()),
                created_at: Some("2026-01-01T00:01:30Z".to_string()),
            }],
        }
    }

    #[test]
    fn canonical_pdf_query_defaults_and_rejects_other_formats() {
        assert!(
            validate_report_pdf_download_query(ReportPdfDownloadQuery {
                report_format_id: None,
            })
            .is_ok()
        );
        assert!(
            validate_report_pdf_download_query(ReportPdfDownloadQuery {
                report_format_id: Some(CANONICAL_PDF_REPORT_FORMAT_ID.to_string()),
            })
            .is_ok()
        );
        let error = validate_report_pdf_download_query(ReportPdfDownloadQuery {
            report_format_id: Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string()),
        })
        .unwrap_err();
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
        assert!(
            error
                .public_message()
                .contains(CANONICAL_PDF_REPORT_FORMAT_ID)
        );
    }

    #[test]
    fn canonical_report_id_makes_the_download_filename_safe() {
        let canonical = canonical_report_id("12345678-1234-1234-1234-123456789ABC").unwrap();
        let headers = report_pdf_headers(&canonical).unwrap();
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/pdf"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(
            headers.get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"yafvs-report-12345678-1234-1234-1234-123456789abc.pdf\""
        );
        assert!(canonical_report_id("../not-a-report").is_err());
    }

    #[test]
    fn renderer_preserves_hostless_errors_and_escapes_unicode_without_panicking() {
        let report = sample_report();
        assert_eq!(
            host_label(&report.evidence[0], true),
            "(hostless scanner error)"
        );
        assert_eq!(
            pdf_text(report.evidence[0].description.as_deref().unwrap()),
            "Scanner failed for caf\\u{E9} \\u{1F680} (scanner)\\path"
        );
        let pdf = render_native_pdf(&report).unwrap();
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(pdf.windows(b"%%EOF".len()).any(|window| window == b"%%EOF"));
        let mut content = Content::new();
        content.show(Str(b"(unbalanced"));
        content.show(Str(b"\\path"));
        let content = content.finish();
        assert!(
            content
                .as_slice()
                .windows(b"\\(unbalanced".len())
                .any(|window| window == b"\\(unbalanced")
        );
        assert!(
            content
                .as_slice()
                .windows(b"\\\\path".len())
                .any(|window| window == b"\\\\path")
        );
    }

    #[test]
    fn renderer_wraps_deterministically_and_enforces_evidence_limits() {
        assert_eq!(
            wrap_pdf_text("one two three", 7),
            vec!["one two".to_string(), "three".to_string()]
        );
        assert!(pdf_evidence_is_within_limits(
            MAX_PDF_RESULT_ROWS,
            MAX_PDF_SOURCE_TEXT_BYTES
        ));
        assert!(!pdf_evidence_is_within_limits(MAX_PDF_RESULT_ROWS + 1, 0));
        assert!(!pdf_evidence_is_within_limits(
            0,
            MAX_PDF_SOURCE_TEXT_BYTES + 1
        ));
        assert!(pdf_output_is_within_limit(MAX_PDF_OUTPUT_BYTES));
        assert!(!pdf_output_is_within_limit(MAX_PDF_OUTPUT_BYTES + 1));
        let error = ApiError::ReportPdfTooLarge;
        assert_eq!(error.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.code(), "report_pdf_too_large");
    }

    #[test]
    fn native_pdf_route_is_registered_and_directly_allowlisted() {
        let path = format!("/api/v1/reports/{REPORT_ID}/download");
        assert!(ROUTES.contains("/api/v1/reports/:report_id/download"));
        assert!(direct_api_v1_path_is_allowed(&path));
        assert!(direct_api_v1_method_is_allowed(&Method::GET, &path, false));
        assert!(
            STARTUP.contains("direct_native_api_router(base_router, auth.write_control_enabled())")
        );
    }

    #[test]
    fn openapi_and_dependency_contract_are_explicitly_native_and_pdf_only() {
        let path = OPENAPI
            .split_once("  /reports/{report_id}/download:\n")
            .and_then(|(_, after)| after.split_once("  /reports/{report_id}/results:"))
            .map(|(path, _)| path)
            .expect("OpenAPI native PDF path must be present");
        assert!(path.contains("x-yafvs-direct: true"));
        assert!(path.contains("$ref: '#/components/parameters/CanonicalPdfReportFormatId'"));
        assert!(path.contains("application/pdf"));
        assert!(path.contains("RequestTooLarge"));
        assert!(path.contains("custom filters and scripts"));
        assert!(CARGO_MANIFEST.contains("pdf-writer = \"0.15.0\""));
    }
}
