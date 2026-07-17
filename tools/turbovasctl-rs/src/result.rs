// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use serde_json::Value;

const STATUSES: [&str; 3] = ["pass", "warn", "fail"];

#[derive(Debug, Serialize, PartialEq)]
pub struct ResultEnvelope {
    pub(crate) status: String,
    pub(crate) summary: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) artifacts: Vec<String>,
    pub(crate) metadata: Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) details: Option<Value>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Finding {
    pub(crate) status: String,
    pub(crate) check: String,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) details: Option<Value>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Metadata {
    pub(crate) command: String,
    pub(crate) generated_at: String,
    pub(crate) repo_root: String,
    pub(crate) head: Option<String>,
}

impl Finding {
    pub(crate) fn new(status: &str, check: &str, message: String) -> Self {
        Self {
            status: status.to_string(),
            check: check.to_string(),
            message,
            path: None,
            details: None,
        }
    }

    pub(crate) fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    pub(crate) fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

pub(crate) fn make_result(
    metadata: Metadata,
    summary: String,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    ResultEnvelope {
        status: aggregate_status(&findings),
        summary,
        findings,
        artifacts: Vec::new(),
        metadata,
        details: None,
    }
}

impl ResultEnvelope {
    pub(crate) fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

fn aggregate_status(findings: &[Finding]) -> String {
    findings
        .iter()
        .max_by_key(|finding| status_rank(&finding.status))
        .map(|finding| finding.status.clone())
        .unwrap_or_else(|| "pass".to_string())
}

fn status_rank(status: &str) -> usize {
    STATUSES
        .iter()
        .position(|candidate| *candidate == status)
        .unwrap_or(2)
}

pub fn exit_code(result: &ResultEnvelope) -> i32 {
    i32::from(result.status == "fail")
}
