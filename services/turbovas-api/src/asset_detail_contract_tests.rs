// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    alert_query_sql::{alert_asset_detail_sql, alert_asset_tasks_sql, alert_assets_sql},
    asset_user_tag_query_sql::{
        host_user_tags_sql, operating_system_user_tags_sql, port_list_user_tags_sql,
        scan_config_user_tags_sql, scanner_user_tags_sql, schedule_user_tags_sql,
        tls_certificate_user_tags_sql,
    },
    collections::{ALERT_DEFAULT_SORT, ALERT_SORT_FIELDS},
    port_list_query_sql::{
        port_list_asset_detail_sql, port_list_assets_sql, port_list_ranges_sql,
        port_list_targets_sql,
    },
    query::sort_clause,
    scan_config_query_sql::{scan_config_asset_detail_sql, scan_config_task_references_sql},
    scanner_assets::scanner_task_references_sql,
    user_tags::catalog_user_tags_sql,
};

#[test]
fn cve_catalog_detail_reads_reference_context_without_mutation_workflows() {
    let source = include_str!("cve_catalog.rs");
    let cve_payload_source = include_str!("cve_catalog_payloads.rs");
    let detail_source = source
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog detail handler must exist")
        .1;
    let list_source = source
        .split_once("async fn cve_catalog(")
        .expect("CVE catalog list handler must exist")
        .1
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog list handler must precede detail handler")
        .0;
    let payload_source = cve_payload_source
        .split_once("struct CatalogCveItem {")
        .expect("CVE catalog payload must exist")
        .1
        .split_once("struct CatalogCveDetail")
        .expect("CVE catalog item payload must precede detail payload")
        .0;

    assert!(payload_source.contains("cert_refs: Vec<CatalogCveCertReference>"));
    assert!(payload_source.contains("nvt_refs: Vec<CatalogCveNvtReference>"));
    assert!(payload_source.contains("references: Vec<CatalogCveReference>"));
    assert!(payload_source.contains("configuration_nodes: Option<CatalogCveConfigurationNodes>"));
    assert!(payload_source.contains("epss: Option<CatalogEpssItem>"));
    assert!(detail_source.contains("LEFT JOIN scap.epss_scores e ON e.cve = c.name"));
    assert!(detail_source.contains("item.cert_refs = cve_cert_refs(&client, &cve_id).await?"));
    assert!(detail_source.contains("item.nvt_refs = cve_nvt_refs(&client, &cve_id).await?"));
    assert!(
        detail_source.contains("item.references = cve_references(&client, cve_internal_id).await?")
    );
    assert!(detail_source.contains(
        "item.configuration_nodes = cve_configuration_nodes(&client, cve_internal_id).await?"
    ));
    assert!(detail_source.contains("FROM scap.cve_references"));
    assert!(detail_source.contains("FROM scap.cpe_match_nodes"));
    assert!(detail_source.contains("FROM scap.cpe_match_strings"));
    assert!(detail_source.contains("FROM scap.cpe_matches"));
    assert!(detail_source.contains("FROM cert.cert_bund_cves dc"));
    assert!(detail_source.contains("FROM cert.dfn_cert_cves dc"));
    assert!(detail_source.contains("FROM vt_refs vr"));
    assert!(!list_source.contains("cve_configuration_nodes"));
    assert!(!list_source.contains("cve_references"));
    assert!(!list_source.contains("cve_cert_refs"));
    assert!(!list_source.contains("cve_nvt_refs"));
    let detail_source_without_native_metadata_export =
        detail_source.replace("cve_catalog_export", "cve_catalog_metadata_read");
    for inherited_workflow in ["export", "delete", "modify", "create"] {
        assert!(!detail_source_without_native_metadata_export.contains(inherited_workflow));
    }
}

#[test]
fn port_list_read_sql_is_metadata_ranges_and_target_backlinks_only() {
    let list_sql = port_list_assets_sql("name ASC");
    let detail_sql = port_list_asset_detail_sql();
    for sql in [&list_sql, detail_sql] {
        assert!(sql.contains("FROM port_lists pl"));
        assert!(sql.contains("FROM port_ranges pr"));
        assert!(sql.contains("port_count_all"));
        assert!(sql.contains("port_count_tcp"));
        assert!(sql.contains("port_count_udp"));
        assert!(!sql.contains("credential"));
        assert!(!sql.contains("reports"));
        assert!(!sql.contains("results"));
        assert!(!sql.contains("xml"));
        assert!(!sql.contains("export"));
    }
    assert!(list_sql.contains("count(*) OVER()::bigint AS total"));
    assert!(list_sql.contains("ORDER BY name ASC, name ASC, id ASC LIMIT $2 OFFSET $3"));

    let ranges_sql = port_list_ranges_sql();
    assert!(ranges_sql.contains("FROM port_ranges pr"));
    assert!(ranges_sql.contains("WHERE pr.port_list = $1"));
    assert!(ranges_sql.contains("CASE WHEN pr.type = 1 THEN 'udp' ELSE 'tcp' END"));

    let targets_sql = port_list_targets_sql();
    assert!(targets_sql.contains("FROM targets t"));
    assert!(targets_sql.contains("WHERE t.port_list = $1"));
    assert!(!targets_sql.contains("credentials"));
}

#[test]
fn task_detail_contract_includes_db_owned_schedule_lifecycle_metadata() {
    let task_source = include_str!("task_query_sql.rs");
    let payload_source = include_str!("task_target_payloads.rs");

    for column in [
        "coalesce(task.start_time, 0)::bigint AS start_time",
        "coalesce(task.end_time, 0)::bigint AS end_time",
        "coalesce(task.schedule_next_time, 0)::bigint AS schedule_next_time",
        "task.schedule_periods::bigint AS schedule_periods",
        "ELSE coalesce(task.alterable, 0) <> 0 END AS alterable",
    ] {
        assert!(
            task_source.contains(column),
            "task SQL must expose {column}"
        );
    }

    for field in [
        "start_time: Option<String>",
        "end_time: Option<String>",
        "schedule_next_time: Option<String>",
        "schedule_periods: Option<i64>",
        "alterable: Option<bool>",
    ] {
        assert!(
            payload_source.contains(field),
            "task payload must keep {field}"
        );
    }
}

#[test]
fn catalog_detail_user_tags_are_detail_only_active_info_tags() {
    let cve_source = include_str!("cve_catalog.rs");
    let cve_payload_source = include_str!("cve_catalog_payloads.rs");
    let cpe_source = include_str!("cpe_catalog.rs");
    let cpe_payload_source = include_str!("cpe_catalog_payloads.rs");
    let cve_item_payload = cve_payload_source
        .split_once("struct CatalogCveItem {")
        .expect("CVE catalog payload must exist")
        .1
        .split_once("struct CatalogCveDetail")
        .expect("CVE catalog payload must precede detail payload")
        .0;
    let cpe_item_payload = cpe_payload_source
        .split_once("struct CatalogCpeItem {")
        .expect("CPE catalog payload must exist")
        .1
        .split_once("struct CatalogCpeDetail")
        .expect("CPE catalog payload must precede detail payload")
        .0;
    let cve_detail_source = cve_source
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog detail handler must exist")
        .1
        .split_once("async fn cve_cert_refs")
        .expect("CVE catalog detail handler must precede reference helpers")
        .0;
    let cpe_detail_source = cpe_source
        .split_once("async fn cpe_catalog_detail")
        .expect("CPE catalog detail handler must exist")
        .1
        .split_once("async fn cpe_references")
        .expect("CPE catalog detail handler must precede reference helper")
        .0;
    let cve_list_source = cve_source
        .split_once("async fn cve_catalog(")
        .expect("CVE catalog list handler must exist")
        .1
        .split_once("async fn cve_catalog_detail")
        .expect("CVE catalog list handler must precede detail handler")
        .0;
    let cpe_list_source = cpe_source
        .split_once("async fn cpe_catalog(")
        .expect("CPE catalog list handler must exist")
        .1
        .split_once("async fn cpe_catalog_detail")
        .expect("CPE catalog list handler must precede detail handler")
        .0;

    assert!(!cve_item_payload.contains("user_tags"));
    assert!(!cpe_item_payload.contains("user_tags"));
    assert!(cve_payload_source.contains("struct CatalogCveDetail"));
    assert!(cpe_payload_source.contains("struct CatalogCpeDetail"));
    assert!(cve_detail_source.contains("catalog_user_tags(&client, \"cve\", &cve_id).await?"));
    assert!(cpe_detail_source.contains("catalog_user_tags_for_aliases_and_row_id("));
    assert!(cpe_detail_source.contains("Some(cpe_internal_id)"));
    assert!(!cve_list_source.contains("catalog_user_tags"));
    assert!(!cpe_list_source.contains("catalog_user_tags"));

    let sql = catalog_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("lower(tr.resource_uuid) = ANY($1::text[])"));
    assert!(sql.contains("tr.resource = $3"));
    assert!(sql.contains("tr.resource_type = $2"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn cpe_catalog_detail_resolves_deprecated_by_by_cpe_name() {
    let source = include_str!("cpe_catalog.rs");
    let cpe_detail_source = source
        .split_once("async fn cpe_catalog_detail")
        .expect("CPE catalog detail handler must exist")
        .1
        .split_once("async fn cpe_references")
        .expect("CPE catalog detail handler must precede reference helper")
        .0;

    assert!(cpe_detail_source.contains("let cpe_name: String = row.get(\"name\");"));
    assert!(cpe_detail_source.contains("let cpe_internal_id: i32 = row.get(\"internal_id\");"));
    assert!(cpe_detail_source.contains("let cpe_uuid: String = row.get(\"id\");"));
    assert!(cpe_detail_source.contains("let cpe_tag_ids = vec![cpe_uuid, cpe_name.clone()];"));
    assert!(cpe_detail_source.contains("FROM scap.cpes_deprecated_by"));
    assert!(cpe_detail_source.contains("WHERE cpe = $1"));
    assert!(cpe_detail_source.contains("&[&cpe_name]"));
    assert!(cpe_detail_source.contains("cpe_references(&client, &cpe_name).await?"));
    assert!(source.contains("FROM scap.cpe_details"));
    assert!(source.contains("WHERE cpe_id = $1"));
    assert!(source.contains("cpe_references_from_details_xml"));
}

#[test]
fn nvt_detail_user_tags_are_detail_only_active_info_tags() {
    let source = include_str!("nvt_catalog.rs");
    let catalog_payload_source = include_str!("nvt_catalog_payloads.rs");
    let nvt_item_payload = catalog_payload_source
        .split_once("struct NvtCatalogItem {")
        .expect("NVT catalog item payload must exist")
        .1
        .split_once("struct NvtCatalogDetail")
        .expect("NVT catalog item payload must precede detail payload")
        .0;
    let nvt_detail_source = source
        .split_once("pub(crate) async fn nvt_catalog_detail")
        .expect("NVT catalog detail handler must exist")
        .1;
    let nvt_list_source = source
        .split_once("pub(crate) async fn nvt_catalog(")
        .expect("NVT catalog list handler must exist")
        .1
        .split_once("fn nvt_filter_parts")
        .expect("NVT catalog list handler must precede filter helper")
        .0;

    assert!(!nvt_item_payload.contains("user_tags"));
    assert!(catalog_payload_source.contains("struct NvtCatalogDetail"));
    assert!(nvt_detail_source.contains("catalog_user_tags(&client, \"nvt\", &nvt_id).await?"));
    assert!(!nvt_list_source.contains("catalog_user_tags"));

    let sql = catalog_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("lower(tr.resource_uuid) = ANY($1::text[])"));
    assert!(sql.contains("tr.resource_type = $2"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn cert_advisory_detail_user_tags_use_resolved_uuid_only() {
    let source = include_str!("cert_advisories.rs");
    let payload_source = include_str!("cert_advisory_payloads.rs");
    let cert_bund_item_payload = payload_source
        .split_once("struct CertBundAdvisoryItem {")
        .expect("CERT-Bund advisory payload must exist")
        .1
        .split_once("struct CertBundAdvisoryDetail")
        .expect("CERT-Bund advisory payload must precede detail payload")
        .0;
    let dfn_cert_item_payload = payload_source
        .split_once("struct DfnCertAdvisoryItem {")
        .expect("DFN-CERT advisory payload must exist")
        .1
        .split_once("struct DfnCertAdvisoryDetail")
        .expect("DFN-CERT advisory payload must precede detail payload")
        .0;
    let cert_bund_detail_source = source
        .split_once("pub(crate) async fn cert_bund_advisory_detail")
        .expect("CERT-Bund detail handler must exist")
        .1;
    let dfn_cert_detail_source = source
        .split_once("pub(crate) async fn dfn_cert_advisory_detail")
        .expect("DFN-CERT detail handler must exist")
        .1
        .split_once("pub(crate) async fn cert_bund_advisories")
        .expect("DFN-CERT detail handler must precede CERT-Bund list")
        .0;
    let cert_bund_list_source = source
        .split_once("pub(crate) async fn cert_bund_advisories(")
        .expect("CERT-Bund list handler must exist")
        .1
        .split_once("pub(crate) async fn cert_bund_advisory_detail")
        .expect("CERT-Bund list handler must precede detail handler")
        .0;
    let dfn_cert_list_source = source
        .split_once("pub(crate) async fn dfn_cert_advisories(")
        .expect("DFN-CERT list handler must exist")
        .1
        .split_once("pub(crate) async fn dfn_cert_advisory_detail")
        .expect("DFN-CERT list handler must precede detail handler")
        .0;

    assert!(!cert_bund_item_payload.contains("user_tags"));
    assert!(!dfn_cert_item_payload.contains("user_tags"));
    assert!(payload_source.contains("struct CertBundAdvisoryDetail"));
    assert!(payload_source.contains("struct DfnCertAdvisoryDetail"));
    assert!(cert_bund_detail_source.contains("let id: String = row.get(\"id\");"));
    assert!(dfn_cert_detail_source.contains("let id: String = row.get(\"id\");"));
    assert!(
        cert_bund_detail_source
            .contains("catalog_user_tags(&client, \"cert_bund_adv\", &id).await?")
    );
    assert!(
        dfn_cert_detail_source.contains("catalog_user_tags(&client, \"dfn_cert_adv\", &id).await?")
    );
    assert!(!cert_bund_list_source.contains("catalog_user_tags"));
    assert!(!dfn_cert_list_source.contains("catalog_user_tags"));
}

#[test]
fn alert_assets_sql_redacts_payload_tables() {
    let sort_sql = sort_clause(ALERT_DEFAULT_SORT, ALERT_SORT_FIELDS).unwrap();
    let sql = alert_assets_sql(&sort_sql);
    assert!(sql.contains("FROM alerts a"));
    assert!(sql.contains("LEFT JOIN users u ON u.id = a.owner"));
    assert!(sql.contains("LEFT JOIN filters f ON f.id = a.filter"));
    assert!(sql.contains("FROM task_alerts ta"));
    assert!(!sql.contains("alert_method_data"));
    assert!(!sql.contains("alert_event_data"));
    assert!(!sql.contains("alert_condition_data"));
    let detail_sql = alert_asset_detail_sql();
    assert!(detail_sql.contains("FROM alerts a"));
    assert!(detail_sql.contains("LEFT JOIN users u ON u.id = a.owner"));
    assert!(detail_sql.contains("LEFT JOIN filters f ON f.id = a.filter"));
    assert!(detail_sql.contains("FROM task_alerts ta"));
    assert!(!detail_sql.contains("alert_method_data"));
    assert!(!detail_sql.contains("alert_event_data"));
    assert!(!detail_sql.contains("alert_condition_data"));
    let tasks_sql = alert_asset_tasks_sql();
    assert!(tasks_sql.contains("FROM alerts a"));
    assert!(tasks_sql.contains("JOIN task_alerts ta ON ta.alert = a.id"));
    assert!(tasks_sql.contains("JOIN tasks t ON t.id = ta.task"));
    assert!(!tasks_sql.contains("alert_method_data"));
    assert!(!tasks_sql.contains("alert_event_data"));
    assert!(!tasks_sql.contains("alert_condition_data"));
}

#[test]
fn operating_system_user_tags_are_active_os_tags_only() {
    let sql = operating_system_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN oss ON oss.id = tr.resource"));
    assert!(sql.contains("tr.resource_type = 'os'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn host_user_tags_are_detail_only_active_host_tags() {
    let payload_source = include_str!("host_asset_payloads.rs");
    let host_list_payload = payload_source
        .split_once("pub(crate) struct HostAssetItem {")
        .expect("host list payload struct must exist")
        .1
        .split_once("pub(crate) struct HostAssetDetailIdentifier")
        .expect("host list payload struct must precede detail identifiers")
        .0;
    let host_detail_payload = payload_source
        .split_once("pub(crate) struct HostAssetDetail {")
        .expect("host detail payload struct must exist")
        .1
        .split_once("fn host_identifier_from_row")
        .expect("host detail payload struct must precede row mapping helpers")
        .0;

    assert!(!host_list_payload.contains("user_tags"));
    assert!(host_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = host_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN hosts ON hosts.id = tr.resource"));
    assert!(sql.contains("lower(hosts.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'host'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn tls_certificate_user_tags_are_active_tls_certificate_tags_only() {
    let sql = tls_certificate_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN tls_certificates ON tls_certificates.id = tr.resource"));
    assert!(sql.contains("lower(tls_certificates.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'tls_certificate'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn tls_certificate_detail_contract_excludes_certificate_bytes() {
    let source = include_str!("tls_certificates.rs");
    let detail_source = source
        .split_once("pub(crate) async fn tls_certificate_asset_detail")
        .expect("TLS certificate detail handler must exist")
        .1
        .split_once("pub(crate) async fn tls_certificate_asset_export")
        .expect("TLS certificate detail handler must precede export handler")
        .0;

    assert!(detail_source.contains("valid_int"));
    assert!(detail_source.contains("trust_int"));
    assert!(detail_source.contains("time_status"));
    assert!(detail_source.contains("host_asset_id"));
    assert!(detail_source.contains("tls_certificate_user_tags"));
    assert!(!detail_source.contains("c.certificate"));
    assert!(!detail_source.contains("certificate_format"));
}

#[test]
fn scanner_user_tags_are_detail_only_active_scanner_tags() {
    let source = include_str!("scanner_asset_payloads.rs");
    let scanner_list_payload = source
        .split_once("pub(crate) struct ScannerAssetItem {")
        .expect("scanner list payload struct must exist")
        .1
        .split_once("pub(crate) struct ScannerTaskReference")
        .expect("scanner list payload struct must precede detail references")
        .0;
    let scanner_detail_payload = source
        .split_once("pub(crate) struct ScannerAssetDetail {")
        .expect("scanner detail payload struct must exist")
        .1
        .split_once("pub(crate) fn scanner_asset_from_row")
        .expect("scanner detail payload struct must precede row mapper")
        .0;

    assert!(!scanner_list_payload.contains("user_tags"));
    assert!(scanner_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = scanner_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN scanners ON scanners.id = tr.resource"));
    assert!(sql.contains("lower(scanners.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'scanner'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn scanner_task_references_are_non_hidden_backlinks_only() {
    let sql = scanner_task_references_sql();
    assert!(sql.contains("FROM scanners s"));
    assert!(sql.contains("JOIN tasks t ON t.scanner = s.id"));
    assert!(sql.contains("lower(s.uuid) = lower($1)"));
    assert!(sql.contains("coalesce(t.hidden, 0) = 0"));
    assert!(sql.contains("coalesce(t.usage_type, 'scan') AS usage_type"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("results"));
}

#[test]
fn scanner_detail_contract_excludes_certificate_and_secret_material() {
    let source = include_str!("scanner_assets.rs");
    let detail_source = source
        .split_once("pub(crate) async fn scanner_asset_detail")
        .expect("scanner detail handler must exist")
        .1
        .split_once("pub(crate) fn scanner_task_references_sql")
        .expect("scanner detail handler must precede task-reference helper")
        .0;

    assert!(detail_source.contains("scanner_task_references"));
    assert!(detail_source.contains("scanner_user_tags"));
    assert!(!detail_source.contains("ca_pub"));
    assert!(!detail_source.contains("credential_value"));
    assert!(!detail_source.contains("private_key"));
    assert!(!detail_source.contains("password"));
    assert!(!detail_source.contains("secret"));
    assert!(!detail_source.contains("certificate_info"));
    assert!(!detail_source.contains("send_scanner_info"));
}

#[test]
fn scan_config_user_tags_are_detail_only_active_config_tags() {
    let payload_source = include_str!("scan_config_payloads.rs");
    let scan_config_list_payload = payload_source
        .split_once("pub(crate) struct ScanConfigAssetItem {")
        .expect("scan config list payload struct must exist")
        .1
        .split_once("pub(crate) struct ScanConfigAssetDetail")
        .expect("scan config list payload struct must precede detail payload")
        .0;
    let scan_config_detail_payload = payload_source
        .split_once("pub(crate) struct ScanConfigAssetDetail {")
        .expect("scan config detail payload struct must exist")
        .1
        .split_once("pub(crate) fn scan_config_asset_from_row")
        .expect("scan config detail payload must precede row mapper")
        .0;

    assert!(!scan_config_list_payload.contains("user_tags"));
    assert!(scan_config_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = scan_config_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN configs c ON c.id = tr.resource"));
    assert!(sql.contains("lower(c.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'config'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn scan_config_task_references_are_non_hidden_config_backlinks_only() {
    let sql = scan_config_task_references_sql();
    assert!(sql.contains("FROM configs c"));
    assert!(sql.contains("JOIN tasks t ON t.config = c.id"));
    assert!(sql.contains("lower(c.uuid) = lower($1)"));
    assert!(sql.contains("t.config_location = 0"));
    assert!(sql.contains("coalesce(t.hidden, 0) = 0"));
    assert!(sql.contains("coalesce(t.usage_type, 'scan') AS usage_type"));
    assert!(!sql.contains("credentials"));
    assert!(!sql.contains("results"));
}

#[test]
fn schedule_user_tags_are_detail_only_active_schedule_tags() {
    let source = include_str!("schedule_payloads.rs");
    let schedule_list_payload = source
        .split_once("struct ScheduleAssetItem {")
        .expect("schedule list payload struct must exist")
        .1
        .split_once("struct ScheduleAssetDetail")
        .expect("schedule list payload struct must precede detail payload")
        .0;
    let schedule_detail_payload = source
        .split_once("struct ScheduleAssetDetail {")
        .expect("schedule detail payload struct must exist")
        .1
        .split_once("pub(crate) fn schedule_task_from_row")
        .expect("schedule detail payload must precede row mappers")
        .0;

    assert!(!schedule_list_payload.contains("user_tags"));
    assert!(schedule_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = schedule_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN schedules s ON s.id = tr.resource"));
    assert!(sql.contains("lower(s.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'schedule'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn port_list_user_tags_are_detail_only_active_port_list_tags() {
    let payloads = include_str!("port_list_payloads.rs");
    let port_list_payload = payloads
        .split_once("struct PortListAssetItem {")
        .expect("port list payload struct must exist")
        .1
        .split_once("struct PortListAssetDetail")
        .expect("port list payload struct must precede detail payload")
        .0;
    let port_list_detail_payload = payloads
        .split_once("struct PortListAssetDetail {")
        .expect("port list detail payload struct must exist")
        .1
        .split_once("pub(crate) fn port_range_from_row")
        .expect("port list detail payload must precede row mappers")
        .0;

    assert!(!port_list_payload.contains("user_tags"));
    assert!(port_list_detail_payload.contains("user_tags: Vec<ReportUserTag>"));

    let sql = port_list_user_tags_sql();
    assert!(sql.contains("FROM tags t"));
    assert!(sql.contains("JOIN tag_resources tr ON tr.tag = t.id"));
    assert!(sql.contains("JOIN port_lists pl ON pl.id = tr.resource"));
    assert!(sql.contains("lower(pl.uuid) = lower($1)"));
    assert!(sql.contains("tr.resource_type = 'port_list'"));
    assert!(sql.contains("tr.resource_location = 0"));
    assert!(sql.contains("coalesce(t.active, 0) = 1"));
    assert!(!sql.contains("credential"));
    assert!(!sql.contains("reports"));
    assert!(!sql.contains("results"));
}

#[test]
fn scan_config_detail_contract_excludes_preferences_and_secret_material() {
    let source = include_str!("scan_configs.rs");
    let detail_sql = scan_config_asset_detail_sql();
    let detail_source = source
        .split_once("pub(crate) async fn load_scan_config_asset_detail")
        .expect("scan config detail loader must exist")
        .1
        .split_once("async fn scan_config_task_references")
        .expect("scan config task-reference loader must follow detail loader")
        .0;
    let routes = include_str!("routes.rs");
    let detail_route = routes
        .find("get(scan_config_asset_detail)")
        .expect("scan config detail route must exist");
    let export_route = routes
        .find("get(export_scan_config_metadata)")
        .expect("scan config metadata export route must exist");
    let family_route = routes
        .find("get(scan_config_asset_families)")
        .expect("scan config family route must exist");

    assert!(detail_source.contains("scan_config_task_references"));
    assert!(detail_source.contains("scan_config_user_tags"));
    assert!(detail_sql.contains("FROM configs c"));
    assert!(detail_sql.contains("coalesce(c.usage_type, 'scan') = 'scan'"));
    assert!(detail_route < family_route);
    assert!(detail_route < export_route);
    for sql_or_loader in [detail_source, detail_sql] {
        assert!(!sql_or_loader.contains("preferences"));
        assert!(!sql_or_loader.contains("nvt_selector"));
        assert!(!sql_or_loader.contains("credential"));
        assert!(!sql_or_loader.contains("password"));
        assert!(!sql_or_loader.contains("secret"));
        assert!(!sql_or_loader.contains("private_key"));
        assert!(!sql_or_loader.contains("export"));
        assert!(!sql_or_loader.contains("xml"));
    }
}
