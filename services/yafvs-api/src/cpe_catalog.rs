// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
};
use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};
use tokio_postgres::Client;

use crate::{
    app_state::AppState,
    collections::{CPE_CATALOG_DEFAULT_SORT, CPE_CATALOG_SORT_FIELDS},
    cpe_catalog_payloads::{
        CatalogCpeDetail, CatalogCpeItem, CatalogCpeReference, catalog_cpe_cve_from_row,
        catalog_cpe_from_row,
    },
    errors::ApiError,
    path_ids::validate_cpe_id,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    user_tags::catalog_user_tags_for_aliases_and_row_id,
};

const MAX_CPE_REFERENCE_COUNT: usize = 128;

pub(crate) async fn cpe_catalog(
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
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "CPE catalog list")
            .await?;
    let items = rows
        .iter()
        .map(|row| catalog_cpe_from_row(row, Vec::new(), None))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn cpe_catalog_detail(
    State(state): State<AppState>,
    Path(cpe_id): Path<String>,
) -> Result<Json<CatalogCpeDetail>, ApiError> {
    let cpe_id = cpe_id.strip_prefix('/').unwrap_or(&cpe_id).to_string();
    validate_cpe_id(&cpe_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.uuid AS id,
                      c.id AS internal_id,
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
    let cpe_internal_id: i32 = row.get("internal_id");
    let cpe_uuid: String = row.get("id");
    let cpe_name: String = row.get("name");
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
            &[&cpe_name],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog deprecated-by query failed");
            ApiError::Database
        })?
        .map(|row| row.get("deprecated_by"));
    let references = cpe_references(&client, &cpe_name).await?;

    let cpe_tag_ids = vec![cpe_uuid, cpe_name.clone()];
    let user_tags = catalog_user_tags_for_aliases_and_row_id(
        &client,
        "cpe",
        &cpe_tag_ids,
        Some(cpe_internal_id),
    )
    .await?;
    Ok(Json(CatalogCpeDetail {
        item: catalog_cpe_from_row(&row, cves, deprecated_by),
        references,
        user_tags,
    }))
}

async fn cpe_references(
    client: &Client,
    cpe_name: &str,
) -> Result<Vec<CatalogCpeReference>, ApiError> {
    let details_xml = client
        .query_opt(
            r#"SELECT coalesce(details_xml, '') AS details_xml
                 FROM scap.cpe_details
                WHERE cpe_id = $1
                LIMIT 1;"#,
            &[&cpe_name],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "CPE catalog reference query failed");
            ApiError::Database
        })?
        .map(|row| row.get::<_, String>("details_xml"))
        .unwrap_or_default();

    Ok(cpe_references_from_details_xml(&details_xml))
}

fn cpe_references_from_details_xml(details_xml: &str) -> Vec<CatalogCpeReference> {
    let mut reader = Reader::from_str(details_xml);
    reader.config_mut().trim_text(true);
    let mut references = Vec::new();
    let mut seen = HashSet::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event))
                if xml_local_name(event.name().as_ref()) == b"reference" =>
            {
                push_cpe_reference_href(&event, &reader, &mut references, &mut seen);
                if references.len() >= MAX_CPE_REFERENCE_COUNT {
                    break;
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                tracing::warn!(%error, "CPE details XML parse failed");
                break;
            }
            _ => {}
        }
    }

    references
}

fn push_cpe_reference_href(
    event: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    references: &mut Vec<CatalogCpeReference>,
    seen: &mut HashSet<String>,
) {
    for attribute in event.attributes().flatten() {
        if xml_local_name(attribute.key.as_ref()) != b"href" {
            continue;
        }
        let Ok(value) =
            attribute.decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
        else {
            continue;
        };
        let url = value.trim().to_string();
        if !url.is_empty() && seen.insert(url.clone()) {
            references.push(CatalogCpeReference { url });
        }
        break;
    }
}

fn xml_local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpe_reference_hrefs_from_details_xml() {
        let references = cpe_references_from_details_xml(
            r#"<cpe-item>
                 <references>
                   <reference href="https://example.test/one">one</reference>
                   <ns:reference ns:href="https://example.test/two" />
                   <reference href="https://example.test/one">duplicate</reference>
                   <reference href="   " />
                 </references>
               </cpe-item>"#,
        );

        assert_eq!(
            references,
            vec![
                CatalogCpeReference {
                    url: "https://example.test/one".to_string()
                },
                CatalogCpeReference {
                    url: "https://example.test/two".to_string()
                },
            ]
        );
    }

    #[test]
    fn caps_cpe_reference_hrefs_from_details_xml() {
        let mut xml = String::from("<cpe-item><references>");
        for index in 0..(MAX_CPE_REFERENCE_COUNT + 4) {
            xml.push_str(&format!(
                r#"<reference href="https://example.test/{index}" />"#
            ));
        }
        xml.push_str("</references></cpe-item>");

        let references = cpe_references_from_details_xml(&xml);

        assert_eq!(references.len(), MAX_CPE_REFERENCE_COUNT);
        assert_eq!(references[0].url, "https://example.test/0");
        assert_eq!(
            references[MAX_CPE_REFERENCE_COUNT - 1].url,
            format!("https://example.test/{}", MAX_CPE_REFERENCE_COUNT - 1)
        );
    }

    #[test]
    fn returns_partial_cpe_references_for_malformed_details_xml() {
        let references = cpe_references_from_details_xml(
            r#"<cpe-item><references><reference href="https://example.test/one"><broken"#,
        );

        assert_eq!(
            references,
            vec![CatalogCpeReference {
                url: "https://example.test/one".to_string()
            }]
        );
    }
}
