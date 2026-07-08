// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

fn collection_handler_sources() -> Vec<(&'static str, &'static str)> {
    vec![
        ("main.rs", include_str!("main.rs")),
        ("alerts.rs", include_str!("alerts.rs")),
        ("nvt_catalog.rs", include_str!("nvt_catalog.rs")),
        ("cpe_catalog.rs", include_str!("cpe_catalog.rs")),
        ("cve_catalog.rs", include_str!("cve_catalog.rs")),
        ("cert_advisories.rs", include_str!("cert_advisories.rs")),
        ("filters.rs", include_str!("filters.rs")),
        (
            "host_asset_payloads.rs",
            include_str!("host_asset_payloads.rs"),
        ),
        ("host_assets.rs", include_str!("host_assets.rs")),
        ("operating_systems.rs", include_str!("operating_systems.rs")),
        ("overrides.rs", include_str!("overrides.rs")),
        ("port_lists.rs", include_str!("port_lists.rs")),
        (
            "report_applications.rs",
            include_str!("report_applications.rs"),
        ),
        ("report_configs.rs", include_str!("report_configs.rs")),
        ("report_cves.rs", include_str!("report_cves.rs")),
        ("report_errors.rs", include_str!("report_errors.rs")),
        (
            "report_format_payloads.rs",
            include_str!("report_format_payloads.rs"),
        ),
        ("report_formats.rs", include_str!("report_formats.rs")),
        ("report_hosts.rs", include_str!("report_hosts.rs")),
        (
            "report_operating_systems.rs",
            include_str!("report_operating_systems.rs"),
        ),
        ("report_payloads.rs", include_str!("report_payloads.rs")),
        ("report_ports.rs", include_str!("report_ports.rs")),
        (
            "report_tls_certificates.rs",
            include_str!("report_tls_certificates.rs"),
        ),
        ("result_payloads.rs", include_str!("result_payloads.rs")),
        (
            "scan_config_payloads.rs",
            include_str!("scan_config_payloads.rs"),
        ),
        ("scan_configs.rs", include_str!("scan_configs.rs")),
        ("scope_payloads.rs", include_str!("scope_payloads.rs")),
        (
            "scope_report_applications.rs",
            include_str!("scope_report_applications.rs"),
        ),
        ("scope_report_cves.rs", include_str!("scope_report_cves.rs")),
        (
            "scope_report_errors.rs",
            include_str!("scope_report_errors.rs"),
        ),
        ("scope_reports.rs", include_str!("scope_reports.rs")),
        (
            "scope_report_hosts.rs",
            include_str!("scope_report_hosts.rs"),
        ),
        (
            "scope_report_operating_systems.rs",
            include_str!("scope_report_operating_systems.rs"),
        ),
        (
            "scope_report_ports.rs",
            include_str!("scope_report_ports.rs"),
        ),
        (
            "scope_report_retention.rs",
            include_str!("scope_report_retention.rs"),
        ),
        (
            "scope_report_results.rs",
            include_str!("scope_report_results.rs"),
        ),
        (
            "scope_report_tls_certificates.rs",
            include_str!("scope_report_tls_certificates.rs"),
        ),
        ("scanner_assets.rs", include_str!("scanner_assets.rs")),
        ("schedules.rs", include_str!("schedules.rs")),
        ("tags.rs", include_str!("tags.rs")),
        ("target_handlers.rs", include_str!("target_handlers.rs")),
        ("task_handlers.rs", include_str!("task_handlers.rs")),
        (
            "task_target_payloads.rs",
            include_str!("task_target_payloads.rs"),
        ),
        ("tls_certificates.rs", include_str!("tls_certificates.rs")),
        (
            "vulnerability_payloads.rs",
            include_str!("vulnerability_payloads.rs"),
        ),
    ]
}

#[test]
fn collection_handlers_use_api_query_contract_extractor() {
    let source = collection_handler_sources()
        .iter()
        .map(|(_, source)| *source)
        .collect::<Vec<_>>()
        .join("\n");
    let raw_axum_query = concat!("Query", "(query): Query", "<CollectionQuery>");
    let api_query = concat!("ApiQuery", "(query): ApiQuery", "<CollectionQuery>");

    assert_eq!(
        source.matches(raw_axum_query).count(),
        0,
        "collection handlers must not use Axum Query directly"
    );
    assert_eq!(
        source.matches(api_query).count(),
        44,
        "every checked collection contract should use ApiQuery"
    );
}

#[test]
fn collection_handlers_use_empty_page_total_probe_helpers() {
    for (path, source) in collection_handler_sources() {
        for forbidden in [
            "row.get::<_, i64>(\"total\")",
            ".map(|row| row.get::<_, i64>(\"total\"))",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must use collection_total_with_empty_page_probe helpers instead of direct total extraction"
            );
        }
    }
}
