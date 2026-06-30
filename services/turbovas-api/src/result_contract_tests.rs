// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[test]
fn result_rows_expose_nvt_epss_context_without_mutation_workflows() {
    let source = include_str!("result_payloads.rs");
    let result_row_source = include_str!("result_payload_rows.rs");
    let scope_report_results_source = include_str!("scope_report_results.rs");
    let result_payload = result_row_source
        .split_once("pub(crate) struct ResultItem {")
        .expect("result payload struct must exist")
        .1
        .split_once("pub(crate) fn result_from_row")
        .expect("result payload must precede row mapper")
        .0;
    let result_sql_sources = [
        source
            .split_once("async fn results")
            .expect("result list handler must exist")
            .1
            .split_once("async fn result_detail")
            .expect("result list handler must precede result detail")
            .0,
        source
            .split_once("async fn result_detail")
            .expect("result detail handler must exist")
            .1
            .split_once("async fn report_results")
            .expect("result detail handler must precede report result list")
            .0,
        source
            .split_once("async fn report_results")
            .expect("report result list handler must exist")
            .1,
        scope_report_results_source
            .split_once("fn scope_report_results_sql")
            .expect("scope report result SQL helper must exist")
            .1,
    ];
    let row_mapper = result_row_source
        .split_once("pub(crate) fn result_from_row")
        .expect("result row mapper must exist")
        .1
        .split_once("pub(crate) fn result_override_from_row")
        .expect("result row mapper must precede override row mapper")
        .0;

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
    assert!(result_sql_sources[1].contains("result_user_tags(&client, &result_id)"));
    assert!(result_sql_sources[1].contains("result_effective_overrides(&client, &result_id)"));
    assert!(result_sql_sources[1].contains("tr.resource_type = 'result'"));
    assert!(result_sql_sources[1].contains("coalesce(t.active, 0) = 1"));
    assert!(result_sql_sources[1].contains("FROM result_overrides ro"));
    assert!(result_sql_sources[1].contains("JOIN overrides o ON o.id = ro.override"));
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
        assert!(!result_sql_sources[1].contains(inherited_workflow));
    }
}
