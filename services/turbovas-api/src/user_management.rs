// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    browser_proxy_api::{BrowserProxyAuth, browser_proxy_operator_from_headers},
    collections::{USER_ACCOUNT_DEFAULT_SORT, USER_ACCOUNT_SORT_FIELDS},
    credential_write_validation::SensitiveBytes,
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    gvmd_control::{
        ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response_bytes,
    },
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe_params,
        normalize_collection_query, sort_clause,
    },
};

pub(crate) const MAX_USER_MANAGEMENT_BODY_BYTES: usize = 32 * 1024;
const MAX_USER_NAME_BYTES: usize = 256;
const MAX_USER_COMMENT_BYTES: usize = 4096;
const MAX_USER_PASSWORD_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UserAuthMethod {
    Password,
    Ldap,
    Radius,
}

impl UserAuthMethod {
    fn control_name(self) -> &'static str {
        match self {
            Self::Password => "file",
            Self::Ldap => "ldap_connect",
            Self::Radius => "radius_connect",
        }
    }

    fn from_database(value: &str) -> Result<Self, ApiError> {
        match value {
            "file" => Ok(Self::Password),
            "ldap_connect" => Ok(Self::Ldap),
            "radius_connect" => Ok(Self::Radius),
            _ => Err(ApiError::Conflict(
                "The user has an unsupported authentication method.".to_string(),
            )),
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct UserManagementItem {
    id: String,
    name: String,
    comment: String,
    auth_method: UserAuthMethod,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UserManagementCollectionQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    sort: Option<String>,
    filter: Option<String>,
    filter_type: Option<String>,
    active: Option<String>,
    predefined: Option<String>,
    resource_type: Option<String>,
    text: Option<String>,
    task_name: Option<String>,
    value: Option<String>,
}

impl UserManagementCollectionQuery {
    fn collection_query(&self) -> CollectionQuery {
        CollectionQuery {
            page: self.page,
            page_size: self.page_size,
            sort: self.sort.clone(),
            filter: self.filter.clone(),
            filter_type: self.filter_type.clone(),
            active: self.active.clone(),
            predefined: self.predefined.clone(),
            resource_type: self.resource_type.clone(),
            schedules_only: None,
            scope_id: None,
            text: self.text.clone(),
            task_name: self.task_name.clone(),
            value: self.value.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserCreateRequest {
    name: String,
    #[serde(default)]
    comment: String,
    auth_method: UserAuthMethod,
    password: Option<SensitiveBytes>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserModifyRequest {
    name: String,
    #[serde(default)]
    comment: String,
    auth_method: UserAuthMethod,
    password: Option<SensitiveBytes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserDeleteQuery {
    inheritor_id: Option<String>,
}

struct ValidatedUserMutation {
    name: String,
    comment: String,
    auth_method: UserAuthMethod,
    password: Option<SensitiveBytes>,
}

const USER_MANAGEMENT_LIST_SQL: &str = r#"
WITH operator AS (
  SELECT id FROM users WHERE uuid = $1
),
user_rows AS (
  SELECT u.uuid AS id,
         coalesce(u.name, '') AS name,
         coalesce(u.comment, '') AS comment,
         coalesce(u.method, '') AS auth_method,
         coalesce(u.creation_time, 0)::bigint AS created_at_unix,
         coalesce(u.modification_time, 0)::bigint AS modified_at_unix
  FROM users u CROSS JOIN operator
),
filtered AS (
  SELECT * FROM user_rows
  WHERE ($2 = ''
         OR lower(id) LIKE '%' || lower($2) || '%'
         OR lower(name) LIKE '%' || lower($2) || '%'
         OR lower(comment) LIKE '%' || lower($2) || '%')
)
SELECT count(*) OVER()::bigint AS total, * FROM filtered
ORDER BY {sort_sql}, name ASC, id ASC LIMIT $3 OFFSET $4
"#;

const USER_MANAGEMENT_DETAIL_SQL: &str = r#"
WITH operator AS (
  SELECT id FROM users WHERE uuid = $1
)
SELECT u.uuid AS id,
       coalesce(u.name, '') AS name,
       coalesce(u.comment, '') AS comment,
       coalesce(u.method, '') AS auth_method,
       coalesce(u.creation_time, 0)::bigint AS created_at_unix,
       coalesce(u.modification_time, 0)::bigint AS modified_at_unix
FROM users u CROSS JOIN operator
WHERE u.uuid = $2
LIMIT 1
"#;

fn user_management_from_row(row: &Row) -> Result<UserManagementItem, ApiError> {
    let auth_method = row.get::<_, String>("auth_method");
    Ok(UserManagementItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        auth_method: UserAuthMethod::from_database(&auth_method)?,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    })
}

fn require_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    operator
        .map(|Extension(operator)| operator)
        .ok_or(ApiError::Forbidden)
}

async fn load_user_management_item(
    state: &AppState,
    operator: &DirectApiOperator,
    user_id: &str,
) -> Result<UserManagementItem, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            USER_MANAGEMENT_DETAIL_SQL,
            &[&operator.user_uuid(), &user_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "user management detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    user_management_from_row(&row)
}

pub(crate) async fn user_management_users(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    ApiQuery(query): ApiQuery<UserManagementCollectionQuery>,
) -> Result<Json<Collection<UserManagementItem>>, ApiError> {
    let operator = require_operator(operator)?;
    let params = normalize_collection_query(query.collection_query(), USER_ACCOUNT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, USER_ACCOUNT_SORT_FIELDS)?;
    let sql = USER_MANAGEMENT_LIST_SQL.replace("{sort_sql}", &sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &operator.user_uuid(),
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "user management list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe_params(
        &client,
        &rows,
        &sql,
        &params,
        &[&operator.user_uuid(), &params.filter, &1_i64, &0_i64],
        "user management list",
    )
    .await?;
    let items = rows
        .iter()
        .map(user_management_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn user_management_detail(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<UserManagementItem>, ApiError> {
    let operator = require_operator(operator)?;
    let user_id = parse_uuid(&user_id)?.to_string();
    Ok(Json(
        load_user_management_item(&state, &operator, &user_id).await?,
    ))
}

pub(crate) async fn create_user(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<UserCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<UserManagementItem>), ApiError> {
    let operator = require_operator(operator)?;
    let request = validate_user_create(parse_json_payload(payload)?)?;
    let user_id = request_user_create(&operator, &request).await?;
    let item = load_user_management_item(&state, &operator, &user_id)
        .await
        .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
    Ok((StatusCode::CREATED, Json(item)))
}

pub(crate) async fn modify_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    payload: Result<Json<UserModifyRequest>, JsonRejection>,
) -> Result<Json<UserManagementItem>, ApiError> {
    let operator = require_operator(operator)?;
    let user_id = parse_uuid(&user_id)?.to_string();
    let request = validate_user_modify(parse_json_payload(payload)?)?;
    request_user_modify(&operator, &user_id, &request).await?;
    Ok(Json(
        load_user_management_item(&state, &operator, &user_id)
            .await
            .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?,
    ))
}

pub(crate) async fn delete_user(
    State(_state): State<AppState>,
    Path(user_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    ApiQuery(query): ApiQuery<UserDeleteQuery>,
) -> Result<StatusCode, ApiError> {
    let operator = require_operator(operator)?;
    let user_id = parse_uuid(&user_id)?.to_string();
    if user_id == operator.user_uuid() {
        return Err(ApiError::Conflict(
            "The authenticated operator account cannot delete itself.".to_string(),
        ));
    }
    let inheritor_id = query
        .inheritor_id
        .as_deref()
        .map(parse_uuid)
        .transpose()?
        .map(|value| value.to_string());
    request_user_delete(&operator, &user_id, inheritor_id.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn browser_proxy_user_management_users(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    query: ApiQuery<UserManagementCollectionQuery>,
) -> Result<Json<Collection<UserManagementItem>>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    user_management_users(State(state), Some(Extension(operator)), query).await
}

pub(crate) async fn browser_proxy_user_management_detail(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<UserManagementItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    user_management_detail(State(state), Path(user_id), Some(Extension(operator))).await
}

pub(crate) async fn browser_proxy_create_user(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    headers: HeaderMap,
    payload: Result<Json<UserCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<UserManagementItem>), ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    create_user(State(state), Some(Extension(operator)), payload).await
}

pub(crate) async fn browser_proxy_modify_user(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UserModifyRequest>, JsonRejection>,
) -> Result<Json<UserManagementItem>, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    modify_user(
        State(state),
        Path(user_id),
        Some(Extension(operator)),
        payload,
    )
    .await
}

pub(crate) async fn browser_proxy_delete_user(
    State(state): State<AppState>,
    Extension(auth): Extension<BrowserProxyAuth>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    query: ApiQuery<UserDeleteQuery>,
) -> Result<StatusCode, ApiError> {
    let operator = browser_proxy_operator_from_headers(&state, &auth, &headers).await?;
    delete_user(
        State(state),
        Path(user_id),
        Some(Extension(operator)),
        query,
    )
    .await
}

fn parse_json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload.map(|Json(request)| request).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::RequestTooLarge
        } else {
            ApiError::BadRequest("request body must match the user management schema".to_string())
        }
    })
}

fn validate_text(value: &str, field: &str, max_bytes: usize, empty: bool) -> Result<(), ApiError> {
    if (!empty && value.is_empty())
        || value.len() > max_bytes
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must {}be at most {max_bytes} UTF-8 bytes without control characters",
            if empty { "" } else { "be non-empty and " }
        )));
    }
    Ok(())
}

fn validate_password(password: &SensitiveBytes) -> Result<(), ApiError> {
    let text = std::str::from_utf8(password.as_bytes()).map_err(|_| {
        ApiError::BadRequest(
            "password must be non-empty text without control characters".to_string(),
        )
    })?;
    if password.as_bytes().is_empty()
        || password.as_bytes().len() > MAX_USER_PASSWORD_BYTES
        || password.as_bytes().contains(&0)
        || text.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "password must be non-empty text up to {MAX_USER_PASSWORD_BYTES} bytes without control characters"
        )));
    }
    Ok(())
}

fn validate_user_create(request: UserCreateRequest) -> Result<ValidatedUserMutation, ApiError> {
    validate_user_mutation(
        request.name,
        request.comment,
        request.auth_method,
        request.password,
        true,
    )
}

fn validate_user_modify(request: UserModifyRequest) -> Result<ValidatedUserMutation, ApiError> {
    validate_user_mutation(
        request.name,
        request.comment,
        request.auth_method,
        request.password,
        false,
    )
}

fn validate_user_mutation(
    name: String,
    comment: String,
    auth_method: UserAuthMethod,
    password: Option<SensitiveBytes>,
    creating: bool,
) -> Result<ValidatedUserMutation, ApiError> {
    validate_text(&name, "name", MAX_USER_NAME_BYTES, false)?;
    validate_text(&comment, "comment", MAX_USER_COMMENT_BYTES, true)?;
    if let Some(password) = password.as_ref() {
        validate_password(password)?;
    }
    match auth_method {
        UserAuthMethod::Password if creating && password.is_none() => {
            return Err(ApiError::BadRequest(
                "password is required when creating a password-authenticated user".to_string(),
            ));
        }
        UserAuthMethod::Ldap | UserAuthMethod::Radius if password.is_some() => {
            return Err(ApiError::BadRequest(
                "password must be omitted for LDAP or RADIUS users".to_string(),
            ));
        }
        _ => {}
    }
    Ok(ValidatedUserMutation {
        name,
        comment,
        auth_method,
        password,
    })
}

async fn request_user_create(
    operator: &DirectApiOperator,
    request: &ValidatedUserMutation,
) -> Result<String, ApiError> {
    let secret = gvmd_control_secret()?;
    let frame = user_mutation_command("user-create", &secret, operator, None, request);
    let response =
        request_gvmd_control_response_bytes(&gvmd_control_socket_path(), &secret, frame.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_user_create_response(&response)
}

async fn request_user_modify(
    operator: &DirectApiOperator,
    user_id: &str,
    request: &ValidatedUserMutation,
) -> Result<(), ApiError> {
    let secret = gvmd_control_secret()?;
    let frame = user_mutation_command("user-modify", &secret, operator, Some(user_id), request);
    let response =
        request_gvmd_control_response_bytes(&gvmd_control_socket_path(), &secret, frame.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_user_modify_response(&response)
}

async fn request_user_delete(
    operator: &DirectApiOperator,
    user_id: &str,
    inheritor_id: Option<&str>,
) -> Result<(), ApiError> {
    let secret = gvmd_control_secret()?;
    let frame = ScrubbedControlFrame::new(
        format!(
            "user-delete {secret} {} {user_id} {}\n",
            operator.user_uuid(),
            inheritor_id.unwrap_or("-")
        )
        .into_bytes(),
    );
    let response =
        request_gvmd_control_response_bytes(&gvmd_control_socket_path(), &secret, frame.as_bytes())
            .await
            .map_err(map_control_socket_error)?;
    parse_user_delete_response(&response)
}

fn user_mutation_command(
    command_name: &str,
    control_secret: &str,
    operator: &DirectApiOperator,
    user_id: Option<&str>,
    request: &ValidatedUserMutation,
) -> ScrubbedControlFrame {
    let mut frame = Vec::with_capacity(256 + request.name.len() + request.comment.len());
    frame.extend_from_slice(command_name.as_bytes());
    frame.push(b' ');
    frame.extend_from_slice(control_secret.as_bytes());
    frame.push(b' ');
    frame.extend_from_slice(operator.user_uuid().as_bytes());
    if let Some(user_id) = user_id {
        frame.push(b' ');
        frame.extend_from_slice(user_id.as_bytes());
    }
    frame.push(b' ');
    frame.extend_from_slice(request.auth_method.control_name().as_bytes());
    frame.push(b' ');
    append_base64(&mut frame, request.name.as_bytes());
    frame.push(b' ');
    append_base64(&mut frame, request.comment.as_bytes());
    frame.push(b' ');
    match request.password.as_ref() {
        Some(password) => append_base64(&mut frame, password.as_bytes()),
        None => frame.push(b'-'),
    }
    frame.push(b'\n');
    ScrubbedControlFrame::new(frame)
}

fn append_base64(frame: &mut Vec<u8>, value: &[u8]) {
    if value.is_empty() {
        frame.push(b'-');
    } else {
        let start = frame.len();
        let encoded_capacity = value.len().div_ceil(3) * 4;
        frame.resize(start + encoded_capacity, 0);
        let written = STANDARD
            .encode_slice(value, &mut frame[start..])
            .expect("preallocated base64 output must be sufficient");
        frame.truncate(start + written);
    }
}

fn parse_user_create_response(response: &[u8]) -> Result<String, ApiError> {
    if let Some(value) = response.strip_prefix(b"0 created ") {
        let user_id = std::str::from_utf8(value)
            .map_err(|_| ApiError::MutationCommittedResponseUnavailable)?;
        return parse_uuid(user_id)
            .map(|value| value.to_string())
            .map_err(|_| ApiError::MutationCommittedResponseUnavailable);
    }
    match response {
        b"1 exists" => Err(ApiError::Conflict(
            "A user with this name already exists.".to_string(),
        )),
        b"2 invalid_name" => Err(ApiError::BadRequest(
            "The user name is invalid.".to_string(),
        )),
        b"3 password_rejected" => Err(ApiError::NewPasswordRejected),
        b"4 invalid_method" => Err(ApiError::BadRequest(
            "The authentication method is invalid.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-3 committed_indeterminate" => Err(ApiError::MutationCommittedResponseUnavailable),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The user control request was rejected.".to_string(),
        )),
        _ => Err(ApiError::ControlFailure),
    }
}

fn parse_user_modify_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 modified" => Ok(()),
        b"1 not_found" => Err(ApiError::NotFound),
        b"2 invalid_name" => Err(ApiError::BadRequest(
            "The user name is invalid.".to_string(),
        )),
        b"3 exists" => Err(ApiError::Conflict(
            "A user with this name already exists.".to_string(),
        )),
        b"4 password_rejected" => Err(ApiError::NewPasswordRejected),
        b"5 password_required" => Err(ApiError::BadRequest(
            "A new password is required when changing to password authentication.".to_string(),
        )),
        b"6 self_mutation" => Err(ApiError::Conflict(
            "The authenticated operator account cannot rename itself.".to_string(),
        )),
        b"7 invalid_method" => Err(ApiError::BadRequest(
            "The authentication method is invalid.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-3 committed_indeterminate" => Err(ApiError::MutationCommittedResponseUnavailable),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The user control request was rejected.".to_string(),
        )),
        _ => Err(ApiError::ControlFailure),
    }
}

fn parse_user_delete_response(response: &[u8]) -> Result<(), ApiError> {
    match response {
        b"0 deleted" => Ok(()),
        b"1 not_found" => Err(ApiError::NotFound),
        b"2 current_user" => Err(ApiError::Conflict(
            "The authenticated operator account cannot delete itself.".to_string(),
        )),
        b"3 inheritor_not_found" => Err(ApiError::BadRequest(
            "The inheriting user was not found.".to_string(),
        )),
        b"4 same_inheritor" => Err(ApiError::BadRequest(
            "The deleted user cannot inherit its own resources.".to_string(),
        )),
        b"5 last_user" => Err(ApiError::Conflict(
            "The last remaining user cannot be deleted.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The user control request was rejected.".to_string(),
        )),
        _ => Err(ApiError::ControlFailure),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const OPERATOR: &str = "123e4567-e89b-12d3-a456-426614174000";
    const USER: &str = "123e4567-e89b-12d3-a456-426614174001";

    fn operator() -> DirectApiOperator {
        DirectApiOperator::new(OPERATOR, Some("operator".to_string())).unwrap()
    }

    #[test]
    fn user_payloads_are_strict_and_secret_safe() {
        let create: UserCreateRequest = serde_json::from_value(json!({
            "name": "alice",
            "comment": "operator",
            "auth_method": "password",
            "password": "private value"
        }))
        .unwrap();
        assert!(validate_user_create(create).is_ok());
        for value in [
            json!({"name":"alice","auth_method":"password"}),
            json!({"name":"alice","auth_method":"ldap","password":"secret"}),
            json!({"name":"","auth_method":"ldap"}),
            json!({"name":"alice\nroot","auth_method":"ldap"}),
        ] {
            let request: UserCreateRequest = serde_json::from_value(value).unwrap();
            assert!(validate_user_create(request).is_err());
        }
        assert!(
            serde_json::from_value::<UserCreateRequest>(json!({
                "name":"alice","auth_method":"ldap","unexpected":true
            }))
            .is_err()
        );
    }

    #[test]
    fn user_control_frames_are_exact_and_scrubbable() {
        let request = validate_user_modify(
            serde_json::from_value(json!({
                "name":"alice","comment":"ops","auth_method":"password","password":"new pass"
            }))
            .unwrap(),
        )
        .unwrap();
        let mut frame =
            user_mutation_command("user-modify", SECRET, &operator(), Some(USER), &request);
        assert_eq!(
            frame.as_bytes(),
            format!("user-modify {SECRET} {OPERATOR} {USER} file YWxpY2U= b3Bz bmV3IHBhc3M=\n")
                .as_bytes()
        );
        frame.scrub();
        assert!(frame.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn user_control_responses_map_stably() {
        assert_eq!(
            parse_user_create_response(format!("0 created {USER}").as_bytes()).unwrap(),
            USER
        );
        assert!(matches!(
            parse_user_create_response(b"1 exists"),
            Err(ApiError::Conflict(_))
        ));
        assert!(matches!(
            parse_user_modify_response(b"1 not_found"),
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            parse_user_modify_response(b"5 password_required"),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            parse_user_create_response(b"0 created invalid"),
            Err(ApiError::MutationCommittedResponseUnavailable)
        ));
        assert!(matches!(
            parse_user_modify_response(b"-3 committed_indeterminate"),
            Err(ApiError::MutationCommittedResponseUnavailable)
        ));
        assert!(matches!(
            parse_user_delete_response(b"5 last_user"),
            Err(ApiError::Conflict(_))
        ));
        assert!(matches!(
            parse_user_delete_response(b"99 forbidden"),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            parse_user_delete_response(b"anything else"),
            Err(ApiError::ControlFailure)
        ));
    }

    #[test]
    fn management_queries_require_operator_and_expose_only_safe_method_metadata() {
        let list = USER_MANAGEMENT_LIST_SQL.to_ascii_lowercase();
        let detail = USER_MANAGEMENT_DETAIL_SQL.to_ascii_lowercase();
        for sql in [&list, &detail] {
            assert!(sql.contains("operator"));
            assert!(sql.contains("auth_method"));
            for forbidden in ["password", "auth_cache", "token", "session", "timezone"] {
                assert!(
                    !sql.contains(forbidden),
                    "unsafe column in management read: {forbidden}"
                );
            }
        }
    }
}
