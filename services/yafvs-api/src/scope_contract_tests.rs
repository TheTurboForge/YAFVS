// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::scope_payloads::{scope_candidate_hosts_sql, scope_sql};

#[test]
fn scope_candidate_hosts_sql_keeps_candidates_out_of_membership() {
    let sql = scope_candidate_hosts_sql();
    assert!(sql.contains("SELECT DISTINCT ON (t.id)"));
    assert!(sql.contains("run_status_name(r.scan_run_status) = 'Done'"));
    assert!(sql.contains("ORDER BY t.id, coalesce(r.end_time, r.creation_time) DESC, r.id DESC"));
    assert!(sql.contains("JOIN scope_targets st ON st.target = t.id"));
    assert!(sql.contains("JOIN report_hosts rh ON rh.report = nr.report"));
    assert!(sql.contains("AND NOT EXISTS"));
    assert!(sql.contains("FROM scope_hosts sh"));
    assert!(sql.contains("WHERE sh.scope = $1 AND lower(h.name) = lower(rh.host)"));
    assert!(!sql.contains("INSERT"));
    assert!(!sql.contains("UPDATE"));
    assert!(!sql.contains("DELETE"));
}

#[test]
fn scope_detail_loads_membership_candidates_and_reports() {
    let source = include_str!("scope_payloads.rs");
    let body = source
        .split_once("async fn scope_detail(")
        .expect("scope detail handler must exist")
        .1
        .split_once("fn scope_sql")
        .expect("scope detail handler must precede scope_sql")
        .0;

    for expected in [
        "let targets = scope_targets(&client, scope_pk, global).await?;",
        "let hosts = scope_hosts(&client, scope_pk, global).await?;",
        "let candidate_hosts = scope_candidate_hosts(&client, scope_pk, global).await?;",
        "let scope_reports = scope_report_references(&client, scope_pk).await?;",
    ] {
        assert!(
            body.contains(expected),
            "missing scope detail load: {expected}"
        );
    }

    assert!(body.contains("scope_from_row("));
    assert!(body.contains("targets,"));
    assert!(body.contains("hosts,"));
    assert!(body.contains("candidate_hosts,"));
    assert!(body.contains("scope_reports,"));
}

#[test]
fn global_scope_membership_queries_include_targets_and_hosts() {
    let sql = scope_sql("true", "name ASC", "");
    assert!(sql.contains("THEN (SELECT count(*) FROM targets)::bigint"));
    assert!(
        sql.contains("ELSE (SELECT count(*) FROM scope_targets st WHERE st.scope = s.id)::bigint")
    );
    assert!(sql.contains("THEN (SELECT count(*) FROM hosts)::bigint"));
    assert!(
        sql.contains("ELSE (SELECT count(*) FROM scope_hosts sh WHERE sh.scope = s.id)::bigint")
    );

    let source = include_str!("scope_payloads.rs");
    let targets_body = source
        .split_once("async fn scope_targets(")
        .expect("scope target helper must exist")
        .1
        .split_once("async fn scope_hosts(")
        .expect("scope target helper must precede scope host helper")
        .0;
    assert!(
        targets_body
            .contains("SELECT uuid, coalesce(name, uuid) FROM targets ORDER BY name, uuid;")
    );
    assert!(targets_body.contains("SELECT target_uuid, coalesce(target_name, target_uuid) FROM scope_targets WHERE scope = $1 ORDER BY target_name, target_uuid;"));

    let hosts_body = source
        .split_once("async fn scope_hosts(")
        .expect("scope host helper must exist")
        .1
        .split_once("fn scope_candidate_hosts_sql")
        .expect("scope host helper must precede candidate host SQL")
        .0;
    assert!(
        hosts_body.contains("SELECT uuid, coalesce(name, uuid) FROM hosts ORDER BY name, uuid;")
    );
    assert!(hosts_body.contains("SELECT host_uuid, coalesce(host_name, host_uuid) FROM scope_hosts WHERE scope = $1 ORDER BY host_name, host_uuid;"));
}

#[test]
fn native_write_owner_resolvers_lock_operator_rows_for_key_share() {
    let resolvers = [
        (
            "alert_write_db.rs",
            include_str!("alert_write_db.rs"),
            "resolve_alert_write_operator_owner",
        ),
        (
            "credential_write_db.rs",
            include_str!("credential_write_db.rs"),
            "resolve_credential_write_operator_owner",
        ),
        (
            "filter_write_db.rs",
            include_str!("filter_write_db.rs"),
            "resolve_filter_write_operator_owner",
        ),
        (
            "host_write_db.rs",
            include_str!("host_write_db.rs"),
            "resolve_host_write_operator_owner",
        ),
        (
            "override_write_db.rs",
            include_str!("override_write_db.rs"),
            "resolve_override_write_operator_owner",
        ),
        (
            "port_list_write_db.rs",
            include_str!("port_list_write_db.rs"),
            "resolve_port_list_write_operator_owner",
        ),
        (
            "scan_config_write_db.rs",
            include_str!("scan_config_write_db.rs"),
            "resolve_scan_config_write_operator_owner",
        ),
        (
            "scanner_write_db.rs",
            include_str!("scanner_write_db.rs"),
            "resolve_scanner_write_operator_owner",
        ),
        (
            "schedule_write_db.rs",
            include_str!("schedule_write_db.rs"),
            "resolve_schedule_write_operator_owner",
        ),
        (
            "scope_write_db.rs",
            include_str!("scope_write_db.rs"),
            "resolve_scope_write_operator_owner",
        ),
        (
            "tag_write_db.rs",
            include_str!("tag_write_db.rs"),
            "resolve_tag_write_operator_owner",
        ),
        (
            "target_write_db.rs",
            include_str!("target_write_db.rs"),
            "resolve_target_write_operator_owner",
        ),
        (
            "task_write_db.rs",
            include_str!("task_write_db.rs"),
            "resolve_task_write_operator_owner",
        ),
        (
            "tls_certificate_write_db.rs",
            include_str!("tls_certificate_write_db.rs"),
            "resolve_tls_certificate_write_operator_owner",
        ),
    ];

    assert_eq!(resolvers.len(), 14);
    for (file, source, resolver) in resolvers {
        let marker = format!("pub(crate) async fn {resolver}");
        let resolver_tail = source
            .split_once(&marker)
            .unwrap_or_else(|| panic!("{file} must define {resolver}"))
            .1;
        let body = resolver_tail
            .split_once("\npub(crate)")
            .map_or(resolver_tail, |(body, _)| body);

        assert!(
            body.contains("FOR KEY SHARE"),
            "{resolver} in {file} must lock the operator user row FOR KEY SHARE"
        );
        assert!(
            body.contains("trim_end_matches(';')"),
            "{resolver} in {file} must append the lock clause to its owner query"
        );
    }
}
