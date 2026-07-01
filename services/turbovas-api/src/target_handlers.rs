// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{TARGET_DEFAULT_SORT, TARGET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    task_target_payloads::{TargetItem, target_from_row},
};

pub(crate) async fn targets(
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

pub(crate) async fn target_detail(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> Result<Json<TargetItem>, ApiError> {
    parse_uuid(&target_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(load_target_detail(&client, &target_id).await?))
}

pub(crate) async fn load_target_detail(
    client: &tokio_postgres::Client,
    target_id: &str,
) -> Result<TargetItem, ApiError> {
    parse_uuid(target_id)?;
    let sql = target_sql("lower(uuid) = lower($1)", "name ASC", "");
    let row = client
        .query_opt(&sql, &[&target_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(target_from_row(&row))
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
