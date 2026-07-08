// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
};
use deadpool_postgres::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio_postgres::{Row, types::ToSql};

use crate::{
    collections::{
        DEFAULT_COLLECTION_PAGE_SIZE, MAX_COLLECTION_FILTER_LENGTH, MAX_COLLECTION_PAGE_SIZE,
    },
    errors::ApiError,
};

#[derive(Debug, Deserialize)]
pub(crate) struct CollectionQuery {
    pub(crate) page: Option<i64>,
    pub(crate) page_size: Option<i64>,
    pub(crate) sort: Option<String>,
    pub(crate) filter: Option<String>,
    pub(crate) filter_type: Option<String>,
    pub(crate) active: Option<String>,
    pub(crate) predefined: Option<String>,
    pub(crate) resource_type: Option<String>,
    pub(crate) schedules_only: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) task_name: Option<String>,
    pub(crate) value: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ApiQuery<T>(pub(crate) T);

#[axum::async_trait]
impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(query)| Self(query))
            .map_err(|_| ApiError::BadRequest("invalid query parameter".to_string()))
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct PageInfo {
    page: i64,
    page_size: i64,
    total: i64,
    sort: String,
    filter: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct Collection<T> {
    pub(crate) page: PageInfo,
    pub(crate) items: Vec<T>,
}

#[derive(Debug)]
pub(crate) struct NormalizedQuery {
    pub(crate) page: i64,
    pub(crate) page_size: i64,
    pub(crate) offset: i64,
    pub(crate) sort: String,
    pub(crate) filter: String,
}

impl NormalizedQuery {
    pub(crate) fn page_info(&self, total: i64) -> PageInfo {
        PageInfo {
            page: self.page,
            page_size: self.page_size,
            total,
            sort: self.sort.clone(),
            filter: self.filter.clone(),
        }
    }
}

pub(crate) fn needs_first_page_total_probe(row_count: usize, offset: i64) -> bool {
    row_count == 0 && offset > 0
}

pub(crate) async fn collection_total_with_empty_page_probe(
    client: &Client,
    rows: &[Row],
    sql: &str,
    params: &NormalizedQuery,
    log_context: &'static str,
) -> Result<i64, ApiError> {
    let probe_page_size = 1_i64;
    let probe_offset = 0_i64;
    collection_total_with_empty_page_probe_params(
        client,
        rows,
        sql,
        params,
        &[&params.filter, &probe_page_size, &probe_offset],
        log_context,
    )
    .await
}

pub(crate) async fn collection_total_with_empty_page_probe_params(
    client: &Client,
    rows: &[Row],
    sql: &str,
    params: &NormalizedQuery,
    probe_params: &[&(dyn ToSql + Sync)],
    log_context: &'static str,
) -> Result<i64, ApiError> {
    if let Some(row) = rows.first() {
        return Ok(row.get::<_, i64>("total"));
    }
    if !needs_first_page_total_probe(rows.len(), params.offset) {
        return Ok(0);
    }

    let probe_rows = client.query(sql, probe_params).await.map_err(|error| {
        tracing::warn!(%error, %log_context, "collection first-page total probe failed");
        ApiError::Database
    })?;
    Ok(probe_rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0))
}

pub(crate) fn normalize_collection_query(
    query: CollectionQuery,
    default_sort: &str,
) -> Result<NormalizedQuery, ApiError> {
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(DEFAULT_COLLECTION_PAGE_SIZE);
    if page < 1 {
        return Err(ApiError::BadRequest(
            "page must be greater than or equal to 1".to_string(),
        ));
    }
    if !(1..=MAX_COLLECTION_PAGE_SIZE).contains(&page_size) {
        return Err(ApiError::BadRequest(format!(
            "page_size must be between 1 and {MAX_COLLECTION_PAGE_SIZE}"
        )));
    }
    let sort = query
        .sort
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_sort.to_string());
    let filter = query.filter.unwrap_or_default();
    if filter.len() > MAX_COLLECTION_FILTER_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "filter must be at most {MAX_COLLECTION_FILTER_LENGTH} bytes"
        )));
    }
    let offset = (page - 1)
        .checked_mul(page_size)
        .ok_or_else(|| ApiError::BadRequest("page offset is too large".to_string()))?;

    Ok(NormalizedQuery {
        page,
        page_size,
        offset,
        sort,
        filter,
    })
}

pub(crate) fn sort_clause(sort: &str, allowed: &[(&str, &str)]) -> Result<String, ApiError> {
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
                filter_type: None,
                active: None,
                predefined: None,
                resource_type: None,
                schedules_only: None,
                text: None,
                task_name: None,
                value: None,
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
    fn normalize_collection_rejects_bad_page() {
        let err = normalize_collection_query(
            CollectionQuery {
                page: Some(0),
                page_size: Some(25),
                sort: None,
                filter: None,
                filter_type: None,
                active: None,
                predefined: None,
                resource_type: None,
                schedules_only: None,
                text: None,
                task_name: None,
                value: None,
            },
            "host",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn api_query_maps_malformed_values_to_bad_request() {
        let request = axum::http::Request::builder()
            .uri("/api/v1/scope-reports?page=abc&page_size=1")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();

        let err = ApiQuery::<CollectionQuery>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::BadRequest(_)));
        assert_eq!(err.code(), "bad_request");
        assert_eq!(err.public_message(), "invalid query parameter");
    }

    #[test]
    fn normalize_collection_rejects_bad_page_size() {
        let err = normalize_collection_query(
            CollectionQuery {
                page: Some(1),
                page_size: Some(501),
                sort: None,
                filter: None,
                filter_type: None,
                active: None,
                predefined: None,
                resource_type: None,
                schedules_only: None,
                text: None,
                task_name: None,
                value: None,
            },
            "host",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn normalize_collection_rejects_overflowing_offset() {
        let err = normalize_collection_query(
            CollectionQuery {
                page: Some(i64::MAX),
                page_size: Some(MAX_COLLECTION_PAGE_SIZE),
                sort: None,
                filter: None,
                filter_type: None,
                active: None,
                predefined: None,
                resource_type: None,
                schedules_only: None,
                text: None,
                task_name: None,
                value: None,
            },
            "host",
        )
        .unwrap_err();
        assert!(
            matches!(err, ApiError::BadRequest(message) if message == "page offset is too large")
        );
    }

    #[test]
    fn normalize_collection_rejects_oversized_filter() {
        let err = normalize_collection_query(
            CollectionQuery {
                page: Some(1),
                page_size: Some(25),
                sort: None,
                filter: Some("x".repeat(MAX_COLLECTION_FILTER_LENGTH + 1)),
                filter_type: None,
                active: None,
                predefined: None,
                resource_type: None,
                schedules_only: None,
                text: None,
                task_name: None,
                value: None,
            },
            "host",
        )
        .unwrap_err();
        assert!(
            matches!(err, ApiError::BadRequest(message) if message.contains("filter must be at most"))
        );
    }

    #[test]
    fn empty_page_total_probe_only_runs_for_out_of_range_pages() {
        assert!(!needs_first_page_total_probe(1, 50));
        assert!(!needs_first_page_total_probe(0, 0));
        assert!(needs_first_page_total_probe(0, 50));
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
}
