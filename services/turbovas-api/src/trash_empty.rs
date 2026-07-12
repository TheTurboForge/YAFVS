// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Extension, Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    errors::ApiError,
    gvmd_control::{
        ControlSocketError, ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        request_gvmd_control_response_bytes,
    },
};

pub(crate) const MAX_TRASH_EMPTY_BODY_BYTES: usize = 1024;
const MAX_TRASH_EMPTY_TOTAL: u64 = i64::MAX as u64;
const TRASH_EMPTY_RESOURCE_FAMILY_COUNT: usize = 13;

#[derive(Debug, Serialize)]
pub(crate) struct TrashEmptyPreviewItem {
    resource_type: String,
    count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TrashEmptyPreview {
    scope: &'static str,
    items: Vec<TrashEmptyPreviewItem>,
    total: i64,
    snapshot_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrashEmptyRequest {
    acknowledge_permanent_deletion: bool,
    expected_total: u64,
    expected_snapshot_digest: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct TrashEmptyResult {
    scope: &'static str,
    deleted_total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrashEmptyControlOutcome {
    Emptied(u64),
    ExpectedSnapshotMismatch(u64),
}

pub(crate) async fn trash_empty_preview(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TrashEmptyPreview>, ApiError> {
    let operator = require_trash_empty_operator(operator)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(trash_empty_preview_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "trash empty preview query failed");
            ApiError::Database
        })?;
    if rows.is_empty() {
        tracing::warn!("trash empty preview operator does not resolve to a database user");
        return Err(ApiError::Forbidden);
    }
    let identity_rows = client
        .query(trash_empty_identity_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "trash empty identity preview query failed");
            ApiError::Database
        })?;
    trash_empty_preview_from_rows(&rows, &identity_rows).map(Json)
}

pub(crate) async fn empty_trashcan(
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<TrashEmptyRequest>, JsonRejection>,
) -> Result<Json<TrashEmptyResult>, ApiError> {
    let operator = require_trash_empty_operator(operator)?;
    let request = parse_trash_empty_payload(payload)?;
    validate_trash_empty_request(&request)?;
    let control_secret = gvmd_control_secret()?;
    let outcome = request_trash_empty(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        request.expected_total,
        &request.expected_snapshot_digest,
    )
    .await?;

    match outcome {
        TrashEmptyControlOutcome::Emptied(deleted_total) => Ok(Json(TrashEmptyResult {
            scope: "operator",
            deleted_total,
        })),
        TrashEmptyControlOutcome::ExpectedSnapshotMismatch(_actual_total) => Err(ApiError::Conflict(
            "Trashcan contents changed after preview; request a new empty preview before retrying."
                .to_string(),
        )),
    }
}

pub(crate) async fn browser_proxy_trash_empty_preview(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
) -> Result<Json<TrashEmptyPreview>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    trash_empty_preview(State(state), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_empty_trashcan(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<TrashEmptyRequest>, JsonRejection>,
) -> Result<Json<TrashEmptyResult>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    empty_trashcan(Some(Extension(operator)), payload).await
}

fn require_trash_empty_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("trash empty request missing operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

fn parse_trash_empty_payload(
    payload: Result<Json<TrashEmptyRequest>, JsonRejection>,
) -> Result<TrashEmptyRequest, ApiError> {
    payload.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::RequestTooLarge
        } else {
            ApiError::BadRequest(
                "request body must be application/json matching TrashEmptyRequest".to_string(),
            )
        }
    })
}

fn validate_trash_empty_request(request: &TrashEmptyRequest) -> Result<(), ApiError> {
    if !request.acknowledge_permanent_deletion {
        return Err(ApiError::BadRequest(
            "acknowledge_permanent_deletion must be true".to_string(),
        ));
    }
    if request.expected_total > MAX_TRASH_EMPTY_TOTAL {
        return Err(ApiError::BadRequest(
            "expected_total exceeds the supported maximum".to_string(),
        ));
    }
    if !is_snapshot_digest(&request.expected_snapshot_digest) {
        return Err(ApiError::BadRequest(
            "expected_snapshot_digest must be a lowercase SHA-256 hex digest".to_string(),
        ));
    }
    Ok(())
}

fn is_snapshot_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn trash_empty_preview_from_rows(
    rows: &[Row],
    identity_rows: &[Row],
) -> Result<TrashEmptyPreview, ApiError> {
    if rows.len() != TRASH_EMPTY_RESOURCE_FAMILY_COUNT {
        tracing::warn!(
            actual = rows.len(),
            expected = TRASH_EMPTY_RESOURCE_FAMILY_COUNT,
            "trash empty preview returned an incomplete resource-family set"
        );
        return Err(ApiError::Database);
    }
    let mut total = 0_i64;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let count: i64 = row.get("item_count");
        total = total.checked_add(count).ok_or_else(|| {
            tracing::warn!("trash empty preview total overflow");
            ApiError::Database
        })?;
        items.push(TrashEmptyPreviewItem {
            resource_type: row.get("resource_type"),
            count,
        });
    }
    Ok(TrashEmptyPreview {
        scope: "operator",
        items,
        total,
        snapshot_digest: trash_empty_snapshot_digest_from_rows(identity_rows),
    })
}

fn trash_empty_snapshot_digest_from_rows(rows: &[Row]) -> String {
    let identities = rows.iter().map(|row| {
        (
            row.get::<_, String>("resource_type"),
            row.get::<_, String>("item_uuid"),
        )
    });
    trash_empty_snapshot_digest(identities)
}

fn trash_empty_snapshot_digest<I>(identities: I) -> String
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut digest = Sha256::new();
    for (resource_type, item_uuid) in identities {
        digest.update(resource_type.as_bytes());
        digest.update([0]);
        digest.update(item_uuid.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

pub(crate) fn trash_empty_preview_sql() -> &'static str {
    r#"WITH operator_owner AS (
         SELECT id
           FROM users
          WHERE uuid = $1
       ), trash_counts AS (
         SELECT 1 AS sort_order, 'configs'::text AS resource_type, count(*)::bigint AS item_count
           FROM configs_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 2, 'alerts'::text, count(*)::bigint
           FROM alerts_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 3, 'credentials'::text, count(*)::bigint
           FROM credentials_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 4, 'filters'::text, count(*)::bigint
           FROM filters_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 5, 'overrides'::text, count(*)::bigint
           FROM overrides_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 6, 'port_lists'::text, count(*)::bigint
           FROM port_lists_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 7, 'report_configs'::text, count(*)::bigint
           FROM report_configs_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 8, 'scanners'::text, count(*)::bigint
           FROM scanners_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 9, 'schedules'::text, count(*)::bigint
           FROM schedules_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 10, 'tags'::text, count(*)::bigint
           FROM tags_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 11, 'targets'::text, count(*)::bigint
           FROM targets_trash WHERE owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 12, 'tasks'::text, count(*)::bigint
           FROM tasks
          WHERE hidden = 2
            AND owner = (SELECT id FROM operator_owner)
         UNION ALL
         SELECT 13, 'report_formats'::text, count(*)::bigint
           FROM report_formats_trash WHERE owner = (SELECT id FROM operator_owner)
       )
       SELECT resource_type, item_count
         FROM trash_counts
        WHERE EXISTS (SELECT 1 FROM operator_owner)
        ORDER BY sort_order ASC;"#
}

fn trash_empty_identity_sql() -> &'static str {
    r#"WITH operator_owner AS (
         SELECT id
           FROM users
          WHERE uuid = $1
       )
       SELECT resource_type, item_uuid
         FROM (
           SELECT 'alerts'::text AS resource_type, uuid::text AS item_uuid
             FROM alerts_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'configs'::text, uuid::text
             FROM configs_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'credentials'::text, uuid::text
             FROM credentials_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'filters'::text, uuid::text
             FROM filters_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'overrides'::text, uuid::text
             FROM overrides_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'port_lists'::text, uuid::text
             FROM port_lists_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'report_configs'::text, uuid::text
             FROM report_configs_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'report_formats'::text, uuid::text
             FROM report_formats_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'scanners'::text, uuid::text
             FROM scanners_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'schedules'::text, uuid::text
             FROM schedules_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'tags'::text, uuid::text
             FROM tags_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'targets'::text, uuid::text
             FROM targets_trash WHERE owner = (SELECT id FROM operator_owner)
           UNION ALL
           SELECT 'tasks'::text, uuid::text
             FROM tasks
            WHERE hidden = 2
              AND owner = (SELECT id FROM operator_owner)
         ) trash_items
        ORDER BY resource_type ASC, item_uuid ASC;"#
}

pub(crate) async fn request_trash_empty(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    expected_total: u64,
    expected_snapshot_digest: &str,
) -> Result<TrashEmptyControlOutcome, ApiError> {
    let command = trash_empty_command(
        control_secret,
        operator_uuid,
        expected_total,
        expected_snapshot_digest,
    );
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes())
            .await
            .map_err(map_trash_empty_transport_error)?;
    parse_trash_empty_response(&response)
}

pub(crate) fn trash_empty_command(
    control_secret: &str,
    operator_uuid: &str,
    expected_total: u64,
    expected_snapshot_digest: &str,
) -> ScrubbedControlFrame {
    ScrubbedControlFrame::new(
        format!(
            "trash-empty {control_secret} {operator_uuid} {expected_total} {expected_snapshot_digest}\n"
        )
        .into_bytes(),
    )
}

fn map_trash_empty_transport_error(error: ControlSocketError) -> ApiError {
    match error {
        ControlSocketError::Configuration => ApiError::Config,
        ControlSocketError::Forbidden => ApiError::Forbidden,
        ControlSocketError::NotFound => ApiError::Forbidden,
        ControlSocketError::Requested
        | ControlSocketError::ScannerUnverified
        | ControlSocketError::Unavailable
        | ControlSocketError::Failure
        | ControlSocketError::OutcomeIndeterminate => ApiError::MutationOutcomeIndeterminate,
    }
}

pub(crate) fn parse_trash_empty_response(
    response: &[u8],
) -> Result<TrashEmptyControlOutcome, ApiError> {
    if response == b"2 forbidden" || response == b"3 operator-not-found" {
        return Err(ApiError::Forbidden);
    }
    if response == b"-1 error" {
        return Err(ApiError::MutationOutcomeIndeterminate);
    }
    if let Some(count) = response
        .strip_prefix(b"0 emptied ")
        .and_then(parse_trash_empty_count)
    {
        return Ok(TrashEmptyControlOutcome::Emptied(count));
    }
    if let Some(count) = response
        .strip_prefix(b"1 expected-snapshot-mismatch ")
        .and_then(parse_trash_empty_count)
    {
        return Ok(TrashEmptyControlOutcome::ExpectedSnapshotMismatch(count));
    }

    Err(ApiError::MutationOutcomeIndeterminate)
}

fn parse_trash_empty_count(value: &[u8]) -> Option<u64> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return None;
    }
    let count = std::str::from_utf8(value).ok()?.parse::<u64>().ok()?;
    (count <= MAX_TRASH_EMPTY_TOTAL).then_some(count)
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    use super::*;
    use crate::direct_api_contract::direct_api_v1_method_is_allowed;

    const LEGACY_USERS_ROW_SHARE_LOCK: &str = "LOCK TABLE users IN ROW SHARE MODE;";

    // These are deliberately outside the active operator mutation inventory:
    // startup-only migration/repair, followed by bulk helpers with no in-tree
    // callers. None owns an active 13-family operator trash-count mutation.
    const LEGACY_TRASH_COUNT_WRITER_EXCLUSIONS: [&str; 7] = [
        "components/gvmd/src/manage_sql_report_formats.c:migrate_predefined_report_formats (startup-only owner migration)",
        "components/gvmd/src/manage_sql_report_formats.c:check_db_trash_report_formats (startup-only report-format repair)",
        "components/gvmd/src/manage_sql_report_formats.c:check_db_report_formats (startup-only report-format check entrypoint)",
        "components/gvmd/src/manage_sql_port_lists.c:delete_port_lists_user (bulk helper with no in-tree caller)",
        "components/gvmd/src/manage_sql_report_configs.c:delete_report_configs_user (bulk helper with no in-tree caller)",
        "components/gvmd/src/manage_sql_report_formats.c:delete_report_formats_user (bulk helper with no in-tree caller)",
        "components/gvmd/src/manage_sql_report_formats.c:delete_report_format_dirs_user (bulk helper with no in-tree caller)",
    ];

    struct LegacyTrashCountWriter {
        file: &'static str,
        source: &'static str,
        definition: &'static str,
        first_resource_access: &'static str,
    }

    enum CSourceState {
        Normal,
        LineComment,
        BlockComment,
        Quoted(u8),
    }

    fn c_function_block<'a>(source: &'a str, definition: &str) -> &'a str {
        assert_eq!(
            source.matches(definition).count(),
            1,
            "C definition must occur exactly once: {definition}"
        );
        let definition_start = source
            .find(definition)
            .unwrap_or_else(|| panic!("C definition must exist: {definition}"));
        let body_start = definition_start
            + source[definition_start..]
                .find('{')
                .unwrap_or_else(|| panic!("C definition must open a body: {definition}"));
        let bytes = source.as_bytes();
        let mut depth = 0usize;
        let mut index = body_start;
        let mut state = CSourceState::Normal;

        while index < bytes.len() {
            match state {
                CSourceState::Normal => match bytes[index] {
                    b'/' if bytes.get(index + 1) == Some(&b'/') => {
                        state = CSourceState::LineComment;
                        index += 2;
                    }
                    b'/' if bytes.get(index + 1) == Some(&b'*') => {
                        state = CSourceState::BlockComment;
                        index += 2;
                    }
                    b'\'' | b'"' => {
                        state = CSourceState::Quoted(bytes[index]);
                        index += 1;
                    }
                    b'{' => {
                        depth += 1;
                        index += 1;
                    }
                    b'}' => {
                        depth -= 1;
                        index += 1;
                        if depth == 0 {
                            return &source[definition_start..index];
                        }
                    }
                    _ => index += 1,
                },
                CSourceState::LineComment => {
                    if bytes[index] == b'\n' {
                        state = CSourceState::Normal;
                    }
                    index += 1;
                }
                CSourceState::BlockComment => {
                    if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        state = CSourceState::Normal;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                CSourceState::Quoted(quote) => {
                    if bytes[index] == b'\\' {
                        index += 2;
                    } else {
                        if bytes[index] == quote {
                            state = CSourceState::Normal;
                        }
                        index += 1;
                    }
                }
            }
        }

        panic!("C function body must terminate: {definition}");
    }

    fn c_marker_offset(block: &str, marker: &str, context: &str) -> usize {
        block
            .find(marker)
            .unwrap_or_else(|| panic!("{context} must contain {marker:?}"))
    }

    fn assert_legacy_trash_count_writer_has_users_gate(writer: &LegacyTrashCountWriter) {
        let block = c_function_block(writer.source, writer.definition);
        let transaction = c_marker_offset(block, "sql_begin_immediate ()", writer.definition);
        let users_gate = c_marker_offset(block, LEGACY_USERS_ROW_SHARE_LOCK, writer.definition);
        let resource_access =
            c_marker_offset(block, writer.first_resource_access, writer.definition);

        assert!(
            transaction < users_gate && users_gate < resource_access,
            "{}:{} must acquire users ROW SHARE after sql_begin_immediate and before {}",
            writer.file,
            writer.definition,
            writer.first_resource_access
        );
    }

    #[test]
    fn trash_empty_snapshot_digest_contract_matches_gvmd_locked_confirmation() {
        let rust_identity_sql = trash_empty_identity_sql();
        let c_source = include_str!("../../../components/gvmd/src/manage_sql.c");
        let c_digest = c_function_block(
            c_source,
            "trash_empty_identity_digest (long long int operator_id)",
        );
        let resource_types = [
            "alerts",
            "configs",
            "credentials",
            "filters",
            "overrides",
            "port_lists",
            "report_configs",
            "report_formats",
            "scanners",
            "schedules",
            "tags",
            "targets",
            "tasks",
        ];

        for source in [rust_identity_sql, c_digest] {
            let mut last = 0;
            for resource_type in resource_types {
                let marker = format!("'{resource_type}'::text");
                let offset = source
                    .find(&marker)
                    .unwrap_or_else(|| panic!("identity digest missing {resource_type}"));
                assert!(
                    offset >= last,
                    "identity digest resource types must be in lexical order"
                );
                last = offset;
            }
            assert_eq!(
                source.matches("uuid::text").count(),
                resource_types.len(),
                "identity digest must use the same UUID text representation for every family"
            );
        }
        assert!(rust_identity_sql.contains("ORDER BY resource_type ASC, item_uuid ASC"));
        assert!(c_digest.contains("ORDER BY resource_type ASC, item_uuid ASC"));
        assert_eq!(
            c_digest
                .matches(r#"g_checksum_update (checksum, (const guchar *) "\0", 1)"#)
                .count(),
            2,
            "gvmd must delimit each resource type and UUID with NUL bytes"
        );
        let rust_hasher = include_str!("trash_empty.rs")
            .split_once("fn trash_empty_snapshot_digest<I>")
            .expect("Rust digest helper must exist")
            .1
            .split_once("pub(crate) fn trash_empty_preview_sql")
            .expect("Rust digest helper must precede preview SQL")
            .0;
        assert_eq!(
            rust_hasher.matches("digest.update([0]);").count(),
            2,
            "Rust must delimit each resource type and UUID with NUL bytes"
        );
    }

    #[test]
    fn trash_empty_request_validation_is_explicit_and_bounded() {
        assert!(
            validate_trash_empty_request(&TrashEmptyRequest {
                acknowledge_permanent_deletion: true,
                expected_total: 0,
                expected_snapshot_digest: "0".repeat(64),
            })
            .is_ok()
        );
        assert!(
            validate_trash_empty_request(&TrashEmptyRequest {
                acknowledge_permanent_deletion: true,
                expected_total: MAX_TRASH_EMPTY_TOTAL,
                expected_snapshot_digest: "0".repeat(64),
            })
            .is_ok()
        );
        for request in [
            TrashEmptyRequest {
                acknowledge_permanent_deletion: false,
                expected_total: 0,
                expected_snapshot_digest: "0".repeat(64),
            },
            TrashEmptyRequest {
                acknowledge_permanent_deletion: true,
                expected_total: MAX_TRASH_EMPTY_TOTAL + 1,
                expected_snapshot_digest: "0".repeat(64),
            },
        ] {
            assert!(matches!(
                validate_trash_empty_request(&request),
                Err(ApiError::BadRequest(_))
            ));
        }
        let source = include_str!("trash_empty.rs");
        assert!(source.contains("#[serde(deny_unknown_fields)]"));
        assert!(source.contains("rejection.status() == StatusCode::PAYLOAD_TOO_LARGE"));
        assert!(source.contains("ApiError::RequestTooLarge"));
        assert!(
            serde_json::from_str::<TrashEmptyRequest>(
                r#"{"acknowledge_permanent_deletion":true,"expected_total":0,"expected_snapshot_digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#
            )
            .is_ok()
        );
        for payload in [
            r#"{"acknowledge_permanent_deletion":true,"expected_total":0,"expected_snapshot_digest":"0000000000000000000000000000000000000000000000000000000000000000","extra":1}"#,
            r#"{"acknowledge_permanent_deletion":true,"expected_total":-1}"#,
            r#"{"acknowledge_permanent_deletion":true}"#,
            r#"{"expected_total":0}"#,
        ] {
            assert!(
                serde_json::from_str::<TrashEmptyRequest>(payload).is_err(),
                "payload must be rejected: {payload}"
            );
        }
        assert!(matches!(
            validate_trash_empty_request(&TrashEmptyRequest {
                acknowledge_permanent_deletion: true,
                expected_total: 0,
                expected_snapshot_digest: "not-a-digest".to_string(),
            }),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn trash_empty_snapshot_digest_binds_ordered_resource_identities() {
        assert_eq!(
            trash_empty_snapshot_digest([(
                "alerts".to_string(),
                "11111111-1111-1111-1111-111111111111".to_string(),
            )]),
            "cbca8704e677d8e0ced4add536b24dc832e0ffdaaef34eb26aaab91406867a21"
        );
        assert_ne!(
            trash_empty_snapshot_digest([
                ("alerts".to_string(), "a".to_string()),
                ("targets".to_string(), "b".to_string()),
            ]),
            trash_empty_snapshot_digest([
                ("alerts".to_string(), "b".to_string()),
                ("targets".to_string(), "a".to_string()),
            ])
        );
    }

    #[test]
    fn trash_empty_preview_sql_is_exactly_owner_scoped() {
        let sql = trash_empty_preview_sql();
        assert!(sql.contains("FROM users"));
        assert!(sql.contains("WHERE uuid = $1"));
        assert!(sql.contains("WHERE EXISTS (SELECT 1 FROM operator_owner)"));
        for (resource_type, table) in [
            ("configs", "configs_trash"),
            ("alerts", "alerts_trash"),
            ("credentials", "credentials_trash"),
            ("filters", "filters_trash"),
            ("overrides", "overrides_trash"),
            ("port_lists", "port_lists_trash"),
            ("report_configs", "report_configs_trash"),
            ("scanners", "scanners_trash"),
            ("schedules", "schedules_trash"),
            ("tags", "tags_trash"),
            ("targets", "targets_trash"),
            ("report_formats", "report_formats_trash"),
        ] {
            assert!(
                sql.contains(&format!("'{resource_type}'::text")),
                "missing resource type {resource_type}"
            );
            assert!(
                sql.contains(&format!(
                    "FROM {table} WHERE owner = (SELECT id FROM operator_owner)"
                )),
                "{table} must be owner scoped"
            );
        }
        assert!(sql.contains("FROM tasks"));
        assert!(sql.contains("WHERE hidden = 2"));
        assert!(sql.contains("AND owner = (SELECT id FROM operator_owner)"));
        assert_eq!(
            sql.matches("AS resource_type").count(),
            1,
            "only the first UNION branch needs the resource_type alias"
        );
        assert_eq!(sql.matches("UNION ALL").count() + 1, 13);
    }

    #[test]
    fn legacy_trash_count_writers_take_the_users_gate_before_resource_access() {
        let manage_sql = include_str!("../../../components/gvmd/src/manage_sql.c");
        let alerts = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
        let configs = include_str!("../../../components/gvmd/src/manage_sql_configs.c");
        let filters = include_str!("../../../components/gvmd/src/manage_sql_filters.c");
        let overrides = include_str!("../../../components/gvmd/src/manage_sql_overrides.c");
        let port_lists = include_str!("../../../components/gvmd/src/manage_sql_port_lists.c");
        let report_configs =
            include_str!("../../../components/gvmd/src/manage_sql_report_configs.c");
        let schedules = include_str!("../../../components/gvmd/src/manage_sql_schedules.c");
        let tags = include_str!("../../../components/gvmd/src/manage_sql_tags.c");
        let targets = include_str!("../../../components/gvmd/src/manage_sql_targets.c");
        let users = include_str!("../../../components/gvmd/src/manage_sql_users.c");

        let writers = [
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql.c",
                source: manage_sql,
                definition: "delete_task_lock (task_t task, int ultimate)",
                first_resource_access: "SELECT hidden FROM tasks",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql.c",
                source: manage_sql,
                definition: "request_delete_task_uuid (const char *task_id, int ultimate)",
                first_resource_access: "find_task_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql.c",
                source: manage_sql,
                definition: "delete_credential (const char *credential_id, int ultimate)",
                first_resource_access: "find_credential_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql.c",
                source: manage_sql,
                definition: "delete_scanner (const char *scanner_id, int ultimate)",
                first_resource_access: "find_scanner_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_users.c",
                source: users,
                definition: "delete_user (const char *user_id_arg, const char *name_arg,",
                first_resource_access: "acl_user_may",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql.c",
                source: manage_sql,
                definition: "manage_restore (const char *id)",
                first_resource_access: "restore_port_list",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_alerts.c",
                source: alerts,
                definition: "delete_alert (const char *alert_id, int ultimate)",
                first_resource_access: "find_alert_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_configs.c",
                source: configs,
                definition: "delete_config (const char *config_id, int ultimate)",
                first_resource_access: "find_config_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_filters.c",
                source: filters,
                definition: "delete_filter (const char *filter_id, int ultimate)",
                first_resource_access: "find_filter_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_overrides.c",
                source: overrides,
                definition: "delete_override (const char *override_id, int ultimate)",
                first_resource_access: "find_override_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_port_lists.c",
                source: port_lists,
                definition: "delete_port_list (const char *port_list_id, int ultimate)",
                first_resource_access: "find_port_list_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_report_configs.c",
                source: report_configs,
                definition: "delete_report_config (const char *report_config_id, int ultimate)",
                first_resource_access: "find_report_config_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_schedules.c",
                source: schedules,
                definition: "delete_schedule (const char *schedule_id, int ultimate)",
                first_resource_access: "find_schedule_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_tags.c",
                source: tags,
                definition: "delete_tag (const char *tag_id, int ultimate)",
                first_resource_access: "find_tag_with_permission",
            },
            LegacyTrashCountWriter {
                file: "components/gvmd/src/manage_sql_targets.c",
                source: targets,
                definition: "delete_target (const char *target_id, int ultimate)",
                first_resource_access: "find_target_with_permission",
            },
        ];

        assert_eq!(
            writers.len(),
            15,
            "the remaining legacy trash writer inventory is explicit"
        );
        assert_eq!(
            LEGACY_TRASH_COUNT_WRITER_EXCLUSIONS.len(),
            7,
            "startup-only repair and no-caller bulk helpers stay outside the active inventory"
        );
        for writer in &writers {
            assert_legacy_trash_count_writer_has_users_gate(writer);
        }

        let scanner_delete = c_function_block(
            manage_sql,
            "delete_scanner (const char *scanner_id, int ultimate)",
        );
        let predefined_check = c_marker_offset(
            scanner_delete,
            "strcmp (scanner_id, SCANNER_UUID_CVE)",
            "delete_scanner predefined guard",
        );
        let predefined_return = c_marker_offset(
            scanner_delete,
            "return 3;",
            "delete_scanner predefined guard",
        );
        assert!(
            scanner_delete[predefined_check..predefined_return].contains("sql_rollback ()"),
            "predefined scanner rejection must close the transaction and release the users gate"
        );
    }

    #[test]
    fn native_empty_holds_only_the_users_exclusive_gate_before_counting() {
        let source = include_str!("../../../components/gvmd/src/manage_sql.c");
        let block = c_function_block(
            source,
            "manage_empty_trashcan_confirmed (long long int expected_total,",
        );
        let transaction = c_marker_offset(block, "sql_begin_immediate ()", "native empty");
        let users_gate =
            c_marker_offset(block, "LOCK TABLE users IN EXCLUSIVE MODE;", "native empty");
        let operator_for_update = c_marker_offset(
            block,
            "SELECT id FROM users WHERE uuid = '%s' FOR UPDATE;",
            "native empty",
        );
        let aggregate_count = c_marker_offset(
            block,
            "SELECT ((SELECT count(*) FROM configs_trash",
            "native empty",
        );

        assert!(
            transaction < users_gate
                && users_gate < operator_for_update
                && operator_for_update < aggregate_count,
            "native empty must take users EXCLUSIVE before operator FOR UPDATE and the aggregate count"
        );
        assert_eq!(
            block.matches("LOCK TABLE ").count(),
            1,
            "native empty must not add a per-family aggregate table lock"
        );
        for table in [
            "configs_trash",
            "alerts_trash",
            "credentials_trash",
            "filters_trash",
            "overrides_trash",
            "port_lists_trash",
            "report_configs_trash",
            "scanners_trash",
            "schedules_trash",
            "tags_trash",
            "targets_trash",
            "tasks",
            "report_formats_trash",
        ] {
            assert!(
                !block.contains(&format!("LOCK TABLE {table}")),
                "native empty must not aggregate-lock {table}"
            );
        }
    }

    #[test]
    fn trash_empty_control_command_is_exact_and_scrubbed() {
        let command = trash_empty_command(
            "0123456789abcdef0123456789abcdef",
            "11111111-1111-1111-1111-111111111111",
            42,
            "cbca8704e677d8e0ced4add536b24dc832e0ffdaaef34eb26aaab91406867a21",
        );
        assert_eq!(
            command.as_bytes(),
            b"trash-empty 0123456789abcdef0123456789abcdef 11111111-1111-1111-1111-111111111111 42 cbca8704e677d8e0ced4add536b24dc832e0ffdaaef34eb26aaab91406867a21\n"
        );
    }

    #[test]
    fn trash_empty_response_parser_maps_authoritative_outcomes() {
        assert_eq!(
            parse_trash_empty_response(b"0 emptied 0").unwrap(),
            TrashEmptyControlOutcome::Emptied(0)
        );
        assert_eq!(
            parse_trash_empty_response(b"0 emptied 42").unwrap(),
            TrashEmptyControlOutcome::Emptied(42)
        );
        assert_eq!(
            parse_trash_empty_response(b"1 expected-snapshot-mismatch 7").unwrap(),
            TrashEmptyControlOutcome::ExpectedSnapshotMismatch(7)
        );
        for response in [
            b"2 forbidden".as_slice(),
            b"3 operator-not-found".as_slice(),
        ] {
            assert_eq!(
                parse_trash_empty_response(response)
                    .unwrap_err()
                    .status_code(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            parse_trash_empty_response(b"-1 error").unwrap_err().code(),
            "mutation_outcome_indeterminate"
        );
    }

    #[test]
    fn trash_empty_response_parser_treats_ambiguous_data_as_indeterminate() {
        for response in [
            b"".as_slice(),
            b"0 emptied".as_slice(),
            b"0 emptied 01".as_slice(),
            b"0 emptied -1".as_slice(),
            b"0 emptied 1 extra".as_slice(),
            b"1 expected-total-mismatch".as_slice(),
            b"1 expected-total-mismatch unknown".as_slice(),
            b"2 forbidden extra".as_slice(),
            b"-1 internal".as_slice(),
            b"unknown".as_slice(),
        ] {
            assert_eq!(
                parse_trash_empty_response(response).unwrap_err().code(),
                "mutation_outcome_indeterminate",
                "response {response:?} must not be treated as safely retryable"
            );
        }
    }

    #[test]
    fn trash_empty_transport_errors_are_conservative_after_dispatch() {
        assert_eq!(
            map_trash_empty_transport_error(ControlSocketError::Configuration).code(),
            "configuration_error"
        );
        for error in [
            ControlSocketError::Requested,
            ControlSocketError::ScannerUnverified,
            ControlSocketError::Unavailable,
            ControlSocketError::Failure,
            ControlSocketError::OutcomeIndeterminate,
        ] {
            assert_eq!(
                map_trash_empty_transport_error(error).code(),
                "mutation_outcome_indeterminate"
            );
        }
    }

    #[test]
    fn trash_empty_routes_require_write_control_and_operator_proxy_auth() {
        for path in ["/api/v1/trashcan/empty-preview", "/api/v1/trashcan/empty"] {
            assert!(!direct_api_v1_method_is_allowed(
                if path.ends_with("empty-preview") {
                    &Method::GET
                } else {
                    &Method::POST
                },
                path,
                false
            ));
        }
        assert!(direct_api_v1_method_is_allowed(
            &Method::GET,
            "/api/v1/trashcan/empty-preview",
            true
        ));
        assert!(direct_api_v1_method_is_allowed(
            &Method::POST,
            "/api/v1/trashcan/empty",
            true
        ));

        let direct_routes = include_str!("direct_api_routes.rs");
        let browser_routes = include_str!("browser_proxy_routes.rs");
        for required in [
            "trash_empty_preview",
            "empty_trashcan",
            "MAX_TRASH_EMPTY_BODY_BYTES",
        ] {
            assert!(direct_routes.contains(required));
        }
        for required in [
            "browser_proxy_trash_empty_preview",
            "browser_proxy_empty_trashcan",
            "MAX_TRASH_EMPTY_BODY_BYTES",
        ] {
            assert!(browser_routes.contains(required));
        }
        assert!(browser_routes.contains("Extension(auth)"));
    }

    #[test]
    fn openapi_documents_trash_empty_safety_contract() {
        let openapi = include_str!("../../../api/openapi/turbovas-v1.yaml");
        for required in [
            "/trashcan/empty-preview:",
            "operationId: getTrashcanEmptyPreview",
            "/trashcan/empty:",
            "operationId: postTrashcanEmpty",
            "acknowledge_permanent_deletion",
            "expected_total",
            "expected_snapshot_digest",
            "additionalProperties: false",
            "mutation_outcome_indeterminate",
            "TrashEmptyPreview",
            "TrashEmptyResult",
        ] {
            assert!(openapi.contains(required), "OpenAPI missing {required}");
        }
    }
}
