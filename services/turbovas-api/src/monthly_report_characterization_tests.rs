// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const ROUTES_RS: &str = include_str!("read_api_routes.rs");
const MONTHLY_GOS3: &str =
    include_str!("../../../components/gvm-tools/scripts/monthly-report-gos3.gmp.py");
const MONTHLY_GOS4: &str =
    include_str!("../../../components/gvm-tools/scripts/monthly-report-gos4.gmp.py");
const MONTHLY_GOS2410: &str =
    include_str!("../../../components/gvm-tools/scripts/monthly-report-gos24.10.gmp.py");

#[test]
fn inherited_monthly_reports_share_first_day_exclusive_upper_month_window() {
    for (source, label) in [
        (MONTHLY_GOS3, "gos3"),
        (MONTHLY_GOS4, "gos4"),
        (MONTHLY_GOS2410, "gos24.10"),
    ] {
        assert!(
            source.contains("from_date = date(")
                || source.contains("from_date = date(script_args.year, script_args.month, 1)"),
            "{label} must construct the first day of the requested month"
        );
        assert!(
            source.contains("to_date = from_date + timedelta(days=31)"),
            "{label} must derive the next-month boundary by advancing from the first day"
        );
        assert!(
            source.contains("to_date = to_date.replace(day=1)"),
            "{label} must normalize the upper bound to the first day of the next month"
        );
    }
}

#[test]
fn gos3_monthly_report_is_report_created_summary_with_optional_host_tables() {
    for required in [
        "f\"rows=-1 created>{from_date.isoformat()} and created<{to_date.isoformat()}\"",
        "return gmp.get_reports(filter_string=report_filter)",
        "sum(report/report/result_count/hole/full/text())",
        "sum(report/report/result_count/warning/full/text())",
        "sum(report/report/result_count/info/full/text())",
        "if \"with-tables\" in args.script:",
        "gmp.get_report(report_id)",
        "host.xpath(\"result_count/hole/page/text()\")[0]",
        "host.xpath(\"result_count/warning/page/text()\")[0]",
        "host.xpath(\"result_count/info/page/text()\")[0]",
    ] {
        assert!(MONTHLY_GOS3.contains(required), "gos3 missing {required}");
    }
    for forbidden in ["Critical", "get_hosts", "get_results("] {
        assert!(
            !MONTHLY_GOS3.contains(forbidden),
            "gos3 monthly semantics must stay report-summary based, not host/result based: {forbidden}"
        );
    }
}

#[test]
fn gos4_monthly_report_is_host_modified_and_counts_all_positive_results_per_host() {
    for required in [
        r#"f"rows=-1 and modified>{from_date.isoformat()} "#,
        r#"f"and modified<{to_date.isoformat()}""#,
        "hosts_xml = gmp.get_hosts(filter_string=host_filter)",
        "if len(hostnames) == 0:",
        "continue",
        "gmp.get_results(details=False, filter=f\"host={ip} and severity>0.0\")",
        "count(//result/threat[text()=\"Low\"])",
        "count(//result/threat[text()=\"Medium\"])",
        "count(//result/threat[text()=\"High\"])",
        "host/detail/name[text()=\"best_os_cpe\"]/../source/@id",
    ] {
        assert!(MONTHLY_GOS4.contains(required), "gos4 missing {required}");
    }
    assert!(
        !MONTHLY_GOS4.contains("Critical"),
        "gos4 monthly semantics must not grow a critical bucket without an explicit replacement decision"
    );
    assert_eq!(
        MONTHLY_GOS4
            .matches("modified<{to_date.isoformat()}")
            .count(),
        1,
        "gos4 must only bound the host query by month; gos24.10 adds the result-month upper bound"
    );
}

#[test]
fn gos2410_monthly_report_deduplicates_vts_within_month_and_controls_report_column() {
    for required in [
        r#"f"rows=-1 and modified>{from_date.isoformat()} "#,
        r#"f"and created<{to_date.isoformat()}""#,
        "hosts_xml = gmp.get_hosts(filter_string=host_filter)",
        "f\"rows=-1 host={ip} and severity>0.0\"",
        "f\" and modified>{from_date.isoformat()}\"",
        "f\" and modified<{to_date.isoformat()}\"",
        "result[  not (./nvt/@oid = preceding-sibling::result/nvt/@oid)]",
        "if threat == \"Critical\":",
        "elif threat == \"High\":",
        "elif threat == \"Medium\":",
        "elif threat == \"Low\":",
        "choices=[\"none\", \"last\", \"list\"]",
        "source/deleted = 0",
        "source/type = \"Report Host\"",
        "source/type = \"Report Host Detail\"",
        "if reports_choice == \"last\":\n                    break",
    ] {
        assert!(
            MONTHLY_GOS2410.contains(required),
            "gos24.10 missing {required}"
        );
    }
}

#[test]
fn native_api_has_no_explicit_monthly_report_replacement_route_yet() {
    for path in [
        "/api/v1/monthly-reports",
        "/api/v1/monthly-reports/2026/06",
        "/api/v1/reports/monthly/2026/06",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "monthly report replacement path must stay closed until semantics are explicit: {path}"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "monthly report replacement GET must stay closed until a native contract lands: {path}"
        );
    }
    for forbidden in [
        "monthly-reports",
        "/reports/monthly",
        "monthly-report-gos3",
        "monthly-report-gos4",
        "monthly-report-gos24.10",
    ] {
        assert!(
            !OPENAPI.contains(forbidden),
            "OpenAPI must not document a monthly report replacement until semantics are explicit: {forbidden}"
        );
        assert!(
            !ROUTES_RS.contains(forbidden),
            "Rust routes must not expose a monthly report replacement until semantics are explicit: {forbidden}"
        );
    }
}
