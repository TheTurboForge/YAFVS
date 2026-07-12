// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::errors::ApiError;

pub(crate) fn normalize_tag_resource_type(value: String) -> String {
    value.trim().to_ascii_lowercase()
}

fn strip_wrapping_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        trimmed[1..trimmed.len() - 1].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn tag_resource_name_filter(filter: &str) -> (String, bool) {
    let trimmed = filter.trim();
    let lower = trimmed.to_ascii_lowercase();
    for prefix in ["uuid=", "id="] {
        if lower.starts_with(prefix) {
            return (strip_wrapping_quotes(&trimmed[prefix.len()..]), true);
        }
    }
    (trimmed.to_string(), false)
}

#[derive(Debug)]
struct TagResourceSqlSpec {
    table: &'static str,
    join_on: &'static str,
    id_expr: &'static str,
    name_expr: &'static str,
    extra_where: &'static str,
}

fn tag_resource_sql_spec(resource_type: &str) -> Result<TagResourceSqlSpec, ApiError> {
    match resource_type {
        "alert" => Ok(TagResourceSqlSpec {
            table: "alerts",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "credential" => Ok(TagResourceSqlSpec {
            table: "credentials",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "filter" => Ok(TagResourceSqlSpec {
            table: "filters",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "target" => Ok(TagResourceSqlSpec {
            table: "targets",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "task" => Ok(TagResourceSqlSpec {
            table: "tasks",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "coalesce(r.usage_type, 'scan') = 'scan' AND coalesce(r.hidden, 0) = 0",
        }),
        "host" => Ok(TagResourceSqlSpec {
            table: "hosts",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "os" => Ok(TagResourceSqlSpec {
            table: "oss",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "tls_certificate" => Ok(TagResourceSqlSpec {
            table: "tls_certificates",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), nullif(r.subject_dn, ''), r.uuid)",
            extra_where: "",
        }),
        "port_list" => Ok(TagResourceSqlSpec {
            table: "port_lists",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "config" => Ok(TagResourceSqlSpec {
            table: "configs",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "coalesce(r.usage_type, 'scan') = 'scan'",
        }),
        "report_config" => Ok(TagResourceSqlSpec {
            table: "report_configs",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "report_format" => Ok(TagResourceSqlSpec {
            table: "report_formats",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "report" => Ok(TagResourceSqlSpec {
            table: "reports",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "r.uuid",
            extra_where: "",
        }),
        "result" => Ok(TagResourceSqlSpec {
            table: "results",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.hostname, ''), nullif(r.host, ''), nullif(r.port, ''), r.uuid)",
            extra_where: "",
        }),
        "override" => Ok(TagResourceSqlSpec {
            table: "overrides",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.text, ''), nullif(r.nvt, ''), r.uuid)",
            extra_where: "",
        }),
        "scanner" => Ok(TagResourceSqlSpec {
            table: "scanners",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "schedule" => Ok(TagResourceSqlSpec {
            table: "schedules",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "user" => Ok(TagResourceSqlSpec {
            table: "users",
            join_on: "r.id = tr.resource",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "nvt" => Ok(TagResourceSqlSpec {
            table: "nvts",
            join_on: "r.id = tr.resource OR r.oid = tr.resource_uuid OR r.uuid = tr.resource_uuid",
            id_expr: "r.oid",
            name_expr: "coalesce(nullif(r.name, ''), r.oid)",
            extra_where: "",
        }),
        "cve" => Ok(TagResourceSqlSpec {
            table: "scap.cves",
            join_on: "r.id = tr.resource OR r.uuid = tr.resource_uuid OR lower(r.name) = lower(tr.resource_uuid)",
            id_expr: "r.name",
            name_expr: "r.name",
            extra_where: "",
        }),
        "cpe" => Ok(TagResourceSqlSpec {
            table: "scap.cpes",
            join_on: "r.id = tr.resource OR r.uuid = tr.resource_uuid OR r.name = tr.resource_uuid",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.title, ''), nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "cert_bund_adv" => Ok(TagResourceSqlSpec {
            table: "cert.cert_bund_advs",
            join_on: "r.id = tr.resource OR r.uuid = tr.resource_uuid OR r.name = tr.resource_uuid",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.title, ''), nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        "dfn_cert_adv" => Ok(TagResourceSqlSpec {
            table: "cert.dfn_cert_advs",
            join_on: "r.id = tr.resource OR r.uuid = tr.resource_uuid OR r.name = tr.resource_uuid",
            id_expr: "r.uuid",
            name_expr: "coalesce(nullif(r.title, ''), nullif(r.name, ''), r.uuid)",
            extra_where: "",
        }),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported tag resource type: {resource_type}"
        ))),
    }
}

pub(crate) fn tag_resource_type_is_supported(resource_type: &str) -> bool {
    tag_resource_sql_spec(resource_type).is_ok()
}

pub(crate) fn tag_resource_direct_write_type_is_supported(resource_type: &str) -> bool {
    matches!(
        resource_type,
        "alert"
            | "credential"
            | "filter"
            | "config"
            | "cert_bund_adv"
            | "cpe"
            | "cve"
            | "dfn_cert_adv"
            | "host"
            | "nvt"
            | "os"
            | "override"
            | "port_list"
            | "report"
            | "report_config"
            | "report_format"
            | "result"
            | "scanner"
            | "schedule"
            | "target"
            | "task"
            | "tls_certificate"
            | "user"
    )
}

pub(crate) fn tag_resource_direct_write_id_must_be_uuid(resource_type: &str) -> bool {
    !matches!(
        resource_type,
        "cert_bund_adv" | "cpe" | "cve" | "dfn_cert_adv" | "nvt"
    )
}

pub(crate) fn tag_resource_direct_write_requires_owner_match(resource_type: &str) -> bool {
    matches!(
        resource_type,
        "alert"
            | "credential"
            | "config"
            | "filter"
            | "host"
            | "os"
            | "override"
            | "port_list"
            | "report"
            | "report_config"
            | "report_format"
            | "result"
            | "scanner"
            | "schedule"
            | "target"
            | "task"
            | "tls_certificate"
    )
}

pub(crate) fn tag_resource_active_lookup_sql(resource_type: &str) -> Result<String, ApiError> {
    if !tag_resource_direct_write_type_is_supported(resource_type) {
        return Err(ApiError::BadRequest(format!(
            "unsupported direct tag resource write type: {resource_type}"
        )));
    }
    let spec = tag_resource_sql_spec(resource_type)?;
    let extra_where = if spec.extra_where.is_empty() {
        String::new()
    } else {
        format!("\n        AND {}", spec.extra_where)
    };

    Ok(format!(
        r#"SELECT r.id::integer,
                  ({id_expr})::text,
                  {owner_expr} AS owner_id
             FROM {table} r
            WHERE lower(({id_expr})::text) = lower($1){extra_where}
            LIMIT 1;"#,
        table = spec.table,
        id_expr = spec.id_expr,
        owner_expr = if tag_resource_direct_write_requires_owner_match(resource_type) {
            "r.owner::integer"
        } else {
            "NULL::integer"
        },
    ))
}

pub(crate) fn tag_resource_collection_sql(
    resource_type: &str,
    sort_sql: &str,
) -> Result<String, ApiError> {
    let spec = tag_resource_sql_spec(resource_type)?;
    let extra_where = if spec.extra_where.is_empty() {
        String::new()
    } else {
        format!("\n                AND {}", spec.extra_where)
    };

    Ok(format!(
        r#"WITH resource_rows AS (
             SELECT ({id_expr})::text AS id,
                    '{resource_type}'::text AS resource_type,
                    ({name_expr})::text AS name
               FROM tag_resources tr
               JOIN {table} r ON {join_on}
              WHERE tr.tag = $1
                AND tr.resource_type = '{resource_type}'
                AND tr.resource_location = 0{extra_where}
         ),
         filtered AS (
             SELECT * FROM resource_rows
              WHERE ($2 = ''
                     OR lower(id) LIKE '%' || lower($2) || '%'
                     OR lower(name) LIKE '%' || lower($2) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, id, resource_type, name
           FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC
          LIMIT $3 OFFSET $4;"#,
        table = spec.table,
        join_on = spec.join_on,
        id_expr = spec.id_expr,
        name_expr = spec.name_expr,
    ))
}

pub(crate) fn tag_resource_name_collection_sql(
    resource_type: &str,
    sort_sql: &str,
) -> Result<String, ApiError> {
    let spec = tag_resource_sql_spec(resource_type)?;
    let extra_where = if spec.extra_where.is_empty() {
        String::new()
    } else {
        format!("\n              WHERE {}", spec.extra_where)
    };

    Ok(format!(
        r#"WITH resource_rows AS (
             SELECT DISTINCT ({id_expr})::text AS id,
                    '{resource_type}'::text AS resource_type,
                    ({name_expr})::text AS name
               FROM {table} r{extra_where}
         ),
         filtered AS (
             SELECT * FROM resource_rows
              WHERE (($2 AND lower(id) = lower($1))
                     OR (NOT $2
                         AND ($1 = ''
                              OR lower(id) LIKE '%' || lower($1) || '%'
                              OR lower(name) LIKE '%' || lower($1) || '%')))
         )
         SELECT count(*) OVER()::bigint AS total, id, resource_type, name
           FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC
          LIMIT $3 OFFSET $4;"#,
        table = spec.table,
        id_expr = spec.id_expr,
        name_expr = spec.name_expr,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{
        collections::{TAG_RESOURCE_DEFAULT_SORT, TAG_RESOURCE_SORT_FIELDS},
        query::sort_clause,
    };

    use super::*;

    #[test]
    fn tag_resource_name_filter_supports_exact_id_syntax() {
        assert_eq!(
            tag_resource_name_filter("uuid=12345678-1234-1234-1234-123456789abc"),
            ("12345678-1234-1234-1234-123456789abc".to_string(), true)
        );
        assert_eq!(
            tag_resource_name_filter("id='CVE-2026-0001'"),
            ("CVE-2026-0001".to_string(), true)
        );
        assert_eq!(
            tag_resource_name_filter("nightly"),
            ("nightly".to_string(), false)
        );
    }

    #[test]
    fn tag_resource_sql_is_strictly_whitelisted() {
        let sort_sql = sort_clause(TAG_RESOURCE_DEFAULT_SORT, TAG_RESOURCE_SORT_FIELDS).unwrap();
        let sql = tag_resource_collection_sql("target", &sort_sql).unwrap();
        assert!(sql.contains("FROM tag_resources tr"));
        assert!(sql.contains("JOIN targets r ON r.id = tr.resource"));
        assert!(sql.contains("AND tr.resource_type = 'target'"));
        assert!(sql.contains("AND tr.resource_location = 0"));
        let alert_sql = tag_resource_collection_sql("alert", &sort_sql).unwrap();
        assert!(alert_sql.contains("JOIN alerts r ON r.id = tr.resource"));
        assert!(!alert_sql.contains("alert_method_data"));
        assert!(!alert_sql.contains("alert_event_data"));
        assert!(!alert_sql.contains("alert_condition_data"));
        let credential_sql = tag_resource_collection_sql("credential", &sort_sql).unwrap();
        assert!(credential_sql.contains("JOIN credentials r ON r.id = tr.resource"));
        let scanner_sql = tag_resource_collection_sql("scanner", &sort_sql).unwrap();
        assert!(scanner_sql.contains("JOIN scanners r ON r.id = tr.resource"));
        let schedule_sql = tag_resource_collection_sql("schedule", &sort_sql).unwrap();
        assert!(schedule_sql.contains("JOIN schedules r ON r.id = tr.resource"));
        let report_sql = tag_resource_collection_sql("report", &sort_sql).unwrap();
        assert!(report_sql.contains("JOIN reports r ON r.id = tr.resource"));
        let result_sql = tag_resource_collection_sql("result", &sort_sql).unwrap();
        assert!(result_sql.contains("JOIN results r ON r.id = tr.resource"));
    }

    #[test]
    fn tag_resource_direct_write_lookup_uses_whitelisted_public_ids() {
        let target_sql = tag_resource_active_lookup_sql("target").unwrap();
        assert!(target_sql.contains("FROM targets r"));
        assert!(target_sql.contains("lower((r.uuid)::text) = lower($1)"));
        assert!(target_sql.contains("r.owner::integer AS owner_id"));

        let task_sql = tag_resource_active_lookup_sql("task").unwrap();
        assert!(task_sql.contains("coalesce(r.usage_type, 'scan') = 'scan'"));
        assert!(task_sql.contains("coalesce(r.hidden, 0) = 0"));
        assert!(tag_resource_direct_write_requires_owner_match("task"));

        let cpe_sql = tag_resource_active_lookup_sql("cpe").unwrap();
        assert!(cpe_sql.contains("FROM scap.cpes r"));
        assert!(cpe_sql.contains("lower((r.uuid)::text) = lower($1)"));
        assert!(cpe_sql.contains("NULL::integer AS owner_id"));
        assert!(!tag_resource_direct_write_id_must_be_uuid("cpe"));
        assert!(!tag_resource_direct_write_requires_owner_match("cpe"));

        let cve_sql = tag_resource_active_lookup_sql("cve").unwrap();
        assert!(cve_sql.contains("FROM scap.cves r"));
        assert!(cve_sql.contains("lower((r.name)::text) = lower($1)"));
        assert!(!tag_resource_direct_write_id_must_be_uuid("cve"));

        let cert_sql = tag_resource_active_lookup_sql("cert_bund_adv").unwrap();
        assert!(cert_sql.contains("FROM cert.cert_bund_advs r"));
        assert!(!tag_resource_direct_write_id_must_be_uuid("cert_bund_adv"));

        let dfn_sql = tag_resource_active_lookup_sql("dfn_cert_adv").unwrap();
        assert!(dfn_sql.contains("FROM cert.dfn_cert_advs r"));
        assert!(!tag_resource_direct_write_id_must_be_uuid("dfn_cert_adv"));

        let nvt_sql = tag_resource_active_lookup_sql("nvt").unwrap();
        assert!(nvt_sql.contains("FROM nvts r"));
        assert!(nvt_sql.contains("lower((r.oid)::text) = lower($1)"));
        assert!(!tag_resource_direct_write_id_must_be_uuid("nvt"));

        assert!(tag_resource_direct_write_id_must_be_uuid("target"));
        assert!(tag_resource_direct_write_id_must_be_uuid("task"));

        let alert_sql = tag_resource_active_lookup_sql("alert").unwrap();
        assert!(alert_sql.contains("FROM alerts r"));
        assert!(alert_sql.contains("lower((r.uuid)::text) = lower($1)"));
        assert!(alert_sql.contains("r.owner::integer AS owner_id"));
        assert!(tag_resource_direct_write_id_must_be_uuid("alert"));
        assert!(!alert_sql.contains("alert_method_data"));
        assert!(!alert_sql.contains("alert_event_data"));
        assert!(!alert_sql.contains("alert_condition_data"));
        let credential_sql = tag_resource_active_lookup_sql("credential").unwrap();
        assert!(credential_sql.contains("FROM credentials r"));
        assert!(credential_sql.contains("lower((r.uuid)::text) = lower($1)"));
        assert!(credential_sql.contains("r.owner::integer AS owner_id"));
        assert!(tag_resource_direct_write_requires_owner_match("credential"));

        let report_sql = tag_resource_active_lookup_sql("report").unwrap();
        assert!(report_sql.contains("FROM reports r"));
        assert!(report_sql.contains("lower((r.uuid)::text) = lower($1)"));
        assert!(report_sql.contains("r.owner::integer AS owner_id"));
        assert!(tag_resource_direct_write_id_must_be_uuid("report"));
        assert!(tag_resource_direct_write_requires_owner_match("report"));

        let result_sql = tag_resource_active_lookup_sql("result").unwrap();
        assert!(result_sql.contains("FROM results r"));
        assert!(result_sql.contains("lower((r.uuid)::text) = lower($1)"));
        assert!(result_sql.contains("r.owner::integer AS owner_id"));
        assert!(tag_resource_direct_write_id_must_be_uuid("result"));
        assert!(tag_resource_direct_write_requires_owner_match("result"));
    }

    #[test]
    fn tag_resource_name_sql_is_strictly_whitelisted() {
        let sort_sql = sort_clause(TAG_RESOURCE_DEFAULT_SORT, TAG_RESOURCE_SORT_FIELDS).unwrap();
        let sql = tag_resource_name_collection_sql("task", &sort_sql).unwrap();
        assert!(sql.contains("FROM tasks r"));
        assert!(sql.contains("coalesce(r.usage_type, 'scan') = 'scan'"));
        assert!(sql.contains("coalesce(r.hidden, 0) = 0"));
        let alert_sql = tag_resource_name_collection_sql("alert", &sort_sql).unwrap();
        assert!(alert_sql.contains("FROM alerts r"));
        assert!(!alert_sql.contains("alert_method_data"));
        assert!(!alert_sql.contains("alert_event_data"));
        assert!(!alert_sql.contains("alert_condition_data"));
        let credential_sql = tag_resource_name_collection_sql("credential", &sort_sql).unwrap();
        assert!(credential_sql.contains("FROM credentials r"));
        let scanner_sql = tag_resource_name_collection_sql("scanner", &sort_sql).unwrap();
        assert!(scanner_sql.contains("FROM scanners r"));
        let schedule_sql = tag_resource_name_collection_sql("schedule", &sort_sql).unwrap();
        assert!(schedule_sql.contains("FROM schedules r"));
        let report_sql = tag_resource_name_collection_sql("report", &sort_sql).unwrap();
        assert!(report_sql.contains("FROM reports r"));
        let result_sql = tag_resource_name_collection_sql("result", &sort_sql).unwrap();
        assert!(result_sql.contains("FROM results r"));
        let user_sql = tag_resource_name_collection_sql("user", &sort_sql).unwrap();
        assert!(user_sql.contains("FROM users r"));
        let filter_sql = tag_resource_name_collection_sql("filter", &sort_sql).unwrap();
        assert!(filter_sql.contains("FROM filters r"));
        let override_sql = tag_resource_name_collection_sql("override", &sort_sql).unwrap();
        assert!(override_sql.contains("FROM overrides r"));
    }

    #[test]
    fn tag_resource_name_sql_supports_info_catalogs_by_reference() {
        let sort_sql = sort_clause("id", TAG_RESOURCE_SORT_FIELDS).unwrap();
        let cve_sql = tag_resource_name_collection_sql("cve", &sort_sql).unwrap();
        assert!(cve_sql.contains("FROM scap.cves r"));
        assert!(cve_sql.contains("r.name"));
        let nvt_sql = tag_resource_name_collection_sql("nvt", &sort_sql).unwrap();
        assert!(nvt_sql.contains("FROM nvts r"));
        assert!(nvt_sql.contains("r.oid"));
        let cert_sql = tag_resource_name_collection_sql("cert_bund_adv", &sort_sql).unwrap();
        assert!(cert_sql.contains("FROM cert.cert_bund_advs r"));
    }

    #[test]
    fn tag_resource_sql_supports_info_catalogs_by_reference() {
        let sort_sql = sort_clause("id", TAG_RESOURCE_SORT_FIELDS).unwrap();
        let cve_sql = tag_resource_collection_sql("cve", &sort_sql).unwrap();
        assert!(cve_sql.contains("JOIN scap.cves r ON"));
        assert!(cve_sql.contains("lower(r.name) = lower(tr.resource_uuid)"));
        let nvt_sql = tag_resource_collection_sql("nvt", &sort_sql).unwrap();
        assert!(nvt_sql.contains("JOIN nvts r ON"));
        assert!(nvt_sql.contains("r.oid = tr.resource_uuid"));
        let cert_sql = tag_resource_collection_sql("cert_bund_adv", &sort_sql).unwrap();
        assert!(cert_sql.contains("JOIN cert.cert_bund_advs r ON"));
    }
}
