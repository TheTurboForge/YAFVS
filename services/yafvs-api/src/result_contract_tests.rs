// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");

fn openapi_path_block(path: &str) -> String {
    let marker = format!("  {path}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{path} path block must exist"));
    let tail = &OPENAPI[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("  /") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn result_routes_are_direct_get_only_until_action_contracts_exist() {
    for path in [
        "/api/v1/results",
        "/api/v1/results/12345678-1234-1234-1234-123456789abc",
        "/api/v1/results/12345678-1234-1234-1234-123456789abc/export",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "GET {path} must be direct-read allowlisted"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "GET {path} must be allowed without direct write-control"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, true),
            "GET {path} must remain allowed when write-control is enabled"
        );
        for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "{method} {path} must stay closed until result actions/export/tag/override contracts exist"
            );
        }
    }
}

#[test]
fn result_openapi_documents_read_only_boundary() {
    for (path, replaces, inherited) in [
        ("/results", "result-list-and-effective-overrides-read", ""),
        (
            "/results/{result_id}",
            "result-detail-metadata-tags-and-overrides-read",
            "",
        ),
        (
            "/results/{result_id}/export",
            "result-metadata-export-read",
            "",
        ),
    ] {
        let block = openapi_path_block(path);
        for required in [
            "get:",
            "x-yafvs-direct: true",
            "x-yafvs-exposure: direct-read",
            "x-yafvs-maturity: live-read",
            replaces,
        ] {
            assert!(block.contains(required), "{path} block missing {required}");
        }
        if inherited.is_empty() {
            assert!(!block.contains("x-yafvs-inherited-still-owns:"));
        } else {
            assert!(
                block.contains(inherited),
                "{path} block missing {inherited}"
            );
        }
        for forbidden in [
            "x-yafvs-exposure: direct-write",
            "x-yafvs-safety-contract: write-control-v1",
            "\n    post:",
            "\n    patch:",
            "\n    delete:",
        ] {
            assert!(
                !block.contains(forbidden),
                "{path} must not advertise result action/export/tag/override workflows: {forbidden}"
            );
        }
    }
}

#[test]
fn result_rows_expose_nvt_epss_context_without_mutation_workflows() {
    let source = include_str!("result_payloads.rs");
    let result_query_sql_source = include_str!("result_query_sql.rs");
    let result_row_source = include_str!("result_payload_rows.rs");
    let scope_report_results_source = include_str!("scope_report_results.rs");
    let result_payload = result_row_source
        .split_once("pub(crate) struct ResultItem {")
        .expect("result payload struct must exist")
        .1
        .split_once("pub(crate) fn result_from_row")
        .expect("result payload must precede row mapper")
        .0;
    let result_list_sql_source = source
        .split_once("async fn results")
        .expect("result list handler must exist")
        .1
        .split_once("async fn result_detail")
        .expect("result list handler must precede result detail")
        .0;
    let result_detail_handler_source = source
        .split_once("async fn result_detail")
        .expect("result detail handler must exist")
        .1
        .split_once("async fn result_export")
        .expect("result detail handler must precede result export wrapper")
        .0;
    let result_detail_sql_source = result_query_sql_source
        .split_once("pub(crate) fn result_detail_sql")
        .expect("result detail SQL helper must exist")
        .1
        .split_once("pub(crate) fn result_user_tags_sql")
        .expect("result detail SQL helper must precede user-tag SQL helper")
        .0;
    let report_result_sql_source = source
        .split_once("async fn report_results")
        .expect("report result list handler must exist")
        .1;
    let scope_report_result_sql_source = scope_report_results_source
        .split_once("fn scope_report_results_sql")
        .expect("scope report result SQL helper must exist")
        .1;
    let result_sql_sources = [
        result_list_sql_source,
        result_detail_sql_source,
        report_result_sql_source,
        scope_report_result_sql_source,
    ];
    let row_mapper = result_row_source
        .split_once("pub(crate) fn result_from_row")
        .expect("result row mapper must exist")
        .1
        .split_once("pub(crate) fn result_override_from_row")
        .expect("result row mapper must precede override row mapper")
        .0;
    let result_user_tag_source = result_query_sql_source
        .split_once("pub(crate) fn result_user_tags_sql")
        .expect("result user-tag SQL helper must exist")
        .1
        .split_once("pub(crate) fn result_effective_overrides_sql")
        .expect("result user-tag SQL helper must precede override SQL helper")
        .0;
    let result_override_source = result_query_sql_source
        .split_once("pub(crate) fn result_effective_overrides_sql")
        .expect("result override SQL helper must exist")
        .1;

    for expected in [
        "max_epss: Option<NvtEpssItem>",
        "max_severity: Option<NvtEpssItem>",
        "user_tags: Vec<ReportUserTag>",
        "overrides: Vec<ResultOverrideItem>",
    ] {
        assert!(result_payload.contains(expected));
    }
    for sql_source in result_sql_sources {
        for expected in [
            "n.epss_score",
            "n.epss_percentile",
            "n.epss_cve",
            "n.epss_severity",
            "n.max_epss_score",
            "n.max_epss_percentile",
            "n.max_epss_cve",
            "n.max_epss_severity",
        ] {
            assert!(sql_source.contains(expected));
        }
    }
    assert!(row_mapper.contains("max_epss: nvt_epss_from_row(row)"));
    assert!(row_mapper.contains("max_severity: nvt_max_severity_from_row(row)"));
    assert!(row_mapper.contains("overrides: result_overrides_from_row(row)"));
    assert!(result_sql_sources[0].contains("r.id AS result_internal_id"));
    assert!(result_sql_sources[0].contains("ro.result = p.result_internal_id"));
    assert!(result_sql_sources[0].contains("array_agg(m.id ORDER BY"));
    assert!(result_sql_sources[0].contains("override_active_ints"));
    assert!(result_detail_handler_source.contains("result_detail_sql()"));
    assert!(result_detail_handler_source.contains("result_user_tags(&client, &result_id)"));
    assert!(
        result_detail_handler_source.contains("result_effective_overrides(&client, &result_id)")
    );
    assert!(result_user_tag_source.contains("tr.resource_type = 'result'"));
    assert!(result_user_tag_source.contains("coalesce(t.active, 0) = 1"));
    assert!(result_override_source.contains("FROM result_overrides ro"));
    assert!(result_override_source.contains("JOIN overrides o ON o.id = ro.override"));
    for list_source in [
        result_sql_sources[0],
        result_sql_sources[2],
        result_sql_sources[3],
    ] {
        assert!(!list_source.contains("result_user_tags"));
        assert!(!list_source.contains("result_effective_overrides"));
    }
    for inherited_workflow in [
        "export",
        "create_override",
        "modify_override",
        "delete_override",
    ] {
        assert!(!result_detail_handler_source.contains(inherited_workflow));
    }
}

#[test]
fn result_export_reuses_native_detail_without_inherited_actions() {
    let source = include_str!("result_payloads.rs");
    let export_source = source
        .split_once("async fn result_export")
        .expect("result export wrapper must exist")
        .1
        .split_once("async fn result_user_tags")
        .expect("result export wrapper must precede user-tag loader")
        .0;

    assert!(export_source.contains("result_detail(state, path).await"));
    for inherited_workflow in [
        "export_result_gmp",
        "export_results_gmp",
        "create_override",
        "modify_override",
        "delete_override",
        "delete_result",
    ] {
        assert!(!export_source.contains(inherited_workflow));
    }
}
