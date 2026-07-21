// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::runtime_performance_snapshot::{psql, psql_value, service_running};
use crate::process::{CommandRunner, ProcessOutput};
use std::path::Path;

const FULL_TEST_TASK_PREFIX: &str = "YAFVS full test scan ";

pub(crate) fn latest_completed_full_test_report_id(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> Result<String, (String, Option<ProcessOutput>)> {
    if !service_running(repo_root, "postgres", runner) {
        return Err((
            "Postgres is not running; start the app profile before selecting the latest full-test report.".into(),
            None,
        ));
    }
    let query = format!(
        "SELECT r.uuid FROM reports r JOIN tasks t ON t.id = r.task WHERE t.name LIKE '{}%' AND run_status_name(r.scan_run_status) = 'Done' AND coalesce(r.start_time, 0) > 0 ORDER BY coalesce(r.end_time, 0) DESC, coalesce(r.start_time, 0) DESC, r.id DESC LIMIT 1;",
        FULL_TEST_TASK_PREFIX.replace('\'', "''")
    );
    let output = psql(repo_root, &query, runner);
    if !output.success {
        return Err((
            "Latest full-test report selection query failed.".into(),
            Some(output),
        ));
    }
    let report_id = psql_value(&output.stdout).trim();
    if report_id.is_empty() {
        return Err((
            "No completed full-test raw report exists; pass --report-id to inspect a specific report.".into(),
            Some(output),
        ));
    }
    Ok(report_id.to_string())
}
