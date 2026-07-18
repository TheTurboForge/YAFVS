// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::result::ResultEnvelope;

pub fn render_human(result: &ResultEnvelope) -> String {
    let mut lines = vec![format!(
        "{}: {}",
        result.status.to_uppercase(),
        result.summary
    )];
    for finding in &result.findings {
        let mut line = format!(
            "[{}] {}: {}",
            finding.status, finding.check, finding.message
        );
        if let Some(path) = &finding.path {
            line.push_str(&format!(" ({path})"));
        }
        lines.push(line);
    }
    format!("{}\n", lines.join("\n"))
}

pub fn render_json(result: &ResultEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(result).map(|text| format!("{text}\n"))
}
