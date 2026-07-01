// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;
use uuid::Uuid;

pub(crate) fn direct_api_v1_path_is_allowed(path: &str) -> bool {
    if direct_api_wildcard_detail_path_is_allowed(path) {
        return true;
    }
    let parts = path.split('/').collect::<Vec<_>>();
    matches!(
        parts.as_slice(),
        ["", "api", "v1", "results"]
            | ["", "api", "v1", "vulnerabilities"]
            | ["", "api", "v1", "cpes"]
            | ["", "api", "v1", "cves"]
            | ["", "api", "v1", "cert-bund-advisories"]
            | ["", "api", "v1", "dfn-cert-advisories"]
            | ["", "api", "v1", "nvts"]
            | ["", "api", "v1", "operating-systems"]
            | ["", "api", "v1", "hosts"]
            | ["", "api", "v1", "tls-certificates"]
            | ["", "api", "v1", "scanners"]
            | ["", "api", "v1", "credentials"]
            | ["", "api", "v1", "scan-configs"]
            | ["", "api", "v1", "filters"]
            | ["", "api", "v1", "feeds"]
            | ["", "api", "v1", "alerts"]
            | ["", "api", "v1", "tags"]
            | ["", "api", "v1", "overrides"]
            | ["", "api", "v1", "port-lists"]
            | ["", "api", "v1", "schedules"]
            | ["", "api", "v1", "timezones"]
            | ["", "api", "v1", "report-configs"]
            | ["", "api", "v1", "report-formats"]
            | ["", "api", "v1", "trashcan", "summary"]
            | ["", "api", "v1", "reports"]
            | ["", "api", "v1", "scopes"]
            | ["", "api", "v1", "targets"]
            | ["", "api", "v1", "tasks"]
            | ["", "api", "v1", "scope-reports"]
            | ["", "api", "v1", "results", _]
            | ["", "api", "v1", "cves", _]
            | ["", "api", "v1", "cves", _, "export"]
            | ["", "api", "v1", "nvts", _]
            | ["", "api", "v1", "nvts", _, "export"]
            | ["", "api", "v1", "operating-systems", _]
            | ["", "api", "v1", "operating-systems", _, "export"]
            | ["", "api", "v1", "hosts", _]
            | ["", "api", "v1", "hosts", _, "export"]
            | ["", "api", "v1", "tls-certificates", _]
            | ["", "api", "v1", "tls-certificates", _, "export"]
            | ["", "api", "v1", "scanners", _]
            | ["", "api", "v1", "scanners", _, "export"]
            | ["", "api", "v1", "credentials", _]
            | ["", "api", "v1", "scan-configs", _]
            | ["", "api", "v1", "filters", _]
            | ["", "api", "v1", "filters", _, "export"]
            | ["", "api", "v1", "alerts", _]
            | ["", "api", "v1", "alerts", _, "export"]
            | ["", "api", "v1", "tags", _]
            | ["", "api", "v1", "overrides", _]
            | ["", "api", "v1", "overrides", _, "export"]
            | ["", "api", "v1", "port-lists", _]
            | ["", "api", "v1", "port-lists", _, "export"]
            | ["", "api", "v1", "schedules", _]
            | ["", "api", "v1", "schedules", _, "export"]
            | ["", "api", "v1", "report-configs", _]
            | ["", "api", "v1", "report-configs", _, "export"]
            | ["", "api", "v1", "report-formats", _]
            | ["", "api", "v1", "report-formats", _, "export"]
            | ["", "api", "v1", "reports", _]
            | ["", "api", "v1", "reports", _, "results"]
            | ["", "api", "v1", "reports", _, "hosts"]
            | ["", "api", "v1", "reports", _, "ports"]
            | ["", "api", "v1", "reports", _, "applications"]
            | ["", "api", "v1", "reports", _, "operating-systems"]
            | ["", "api", "v1", "reports", _, "cves"]
            | ["", "api", "v1", "reports", _, "tls-certificates"]
            | ["", "api", "v1", "reports", _, "errors"]
            | ["", "api", "v1", "reports", _, "metrics"]
            | ["", "api", "v1", "scopes", _]
            | ["", "api", "v1", "targets", _]
            | ["", "api", "v1", "targets", _, "export"]
            | ["", "api", "v1", "tasks", _]
            | ["", "api", "v1", "tasks", _, "export"]
            | ["", "api", "v1", "scope-reports", _]
            | ["", "api", "v1", "tags", _, "resources"]
            | ["", "api", "v1", "tags", _, "export"]
            | ["", "api", "v1", "tags", _, "clone"]
            | ["", "api", "v1", "tags", _, "restore"]
            | ["", "api", "v1", "tags", _, "trash"]
            | ["", "api", "v1", "tags", "resource-names", _]
            | ["", "api", "v1", "scan-configs", _, "families"]
            | ["", "api", "v1", "scan-configs", _, "export"]
            if direct_api_segments_are_nonempty(&parts)
    ) || matches!(
        parts.as_slice(),
        ["", "api", "v1", "scopes", scope_id, "reports", scope_report_id, section]
            if direct_api_segments_are_nonempty(&parts)
                && matches!(
                    *section,
                    "results"
                        | "hosts"
                        | "ports"
                        | "applications"
                        | "operating-systems"
                        | "cves"
                        | "tls-certificates"
                        | "errors"
                        | "metrics"
                        | "retention-plan"
                )
                && !scope_id.is_empty()
                && !scope_report_id.is_empty()
    )
}

pub(crate) fn direct_api_v1_method_is_allowed(
    method: &Method,
    path: &str,
    write_control_enabled: bool,
) -> bool {
    if write_control_enabled && direct_api_v1_write_method_path_is_allowed(method, path) {
        return true;
    }
    method == Method::GET && direct_api_v1_path_is_allowed(path)
}

fn direct_api_v1_write_method_path_is_allowed(method: &Method, path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    match (method, parts.as_slice()) {
        (&Method::POST, ["", "api", "v1", "scopes"]) => true,
        (&Method::PATCH | &Method::DELETE, ["", "api", "v1", "scopes", scope_id]) => {
            direct_api_write_id_segment_is_allowed(scope_id)
        }
        (&Method::POST, ["", "api", "v1", "tags"]) => true,
        (&Method::PATCH | &Method::DELETE, ["", "api", "v1", "tags", tag_id]) => {
            direct_api_write_id_segment_is_allowed(tag_id)
        }
        (&Method::POST, ["", "api", "v1", "tags", tag_id, "resources"]) => {
            direct_api_write_id_segment_is_allowed(tag_id)
        }
        (&Method::POST, ["", "api", "v1", "tags", tag_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(tag_id)
        }
        (&Method::POST, ["", "api", "v1", "tags", tag_id, "restore"]) => {
            direct_api_write_id_segment_is_allowed(tag_id)
        }
        (&Method::DELETE, ["", "api", "v1", "tags", tag_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(tag_id)
        }
        (&Method::POST, ["", "api", "v1", "report-configs"]) => true,
        (
            &Method::PATCH | &Method::DELETE,
            ["", "api", "v1", "report-configs", report_config_id],
        ) => direct_api_write_id_segment_is_allowed(report_config_id),
        (&Method::POST, ["", "api", "v1", "report-configs", report_config_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(report_config_id)
        }
        (
            &Method::POST,
            [
                "",
                "api",
                "v1",
                "report-configs",
                report_config_id,
                "restore",
            ],
        ) => direct_api_write_id_segment_is_allowed(report_config_id),
        (&Method::DELETE, ["", "api", "v1", "report-configs", report_config_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(report_config_id)
        }
        (&Method::PATCH | &Method::DELETE, ["", "api", "v1", "scan-configs", scan_config_id]) => {
            direct_api_write_id_segment_is_allowed(scan_config_id)
        }
        (&Method::POST, ["", "api", "v1", "scan-configs", scan_config_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(scan_config_id)
        }
        (&Method::POST, ["", "api", "v1", "scan-configs", scan_config_id, "restore"]) => {
            direct_api_write_id_segment_is_allowed(scan_config_id)
        }
        (&Method::DELETE, ["", "api", "v1", "scan-configs", scan_config_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(scan_config_id)
        }
        (&Method::PATCH, ["", "api", "v1", "alerts", alert_id]) => {
            direct_api_write_id_segment_is_allowed(alert_id)
        }
        (&Method::PATCH, ["", "api", "v1", "credentials", credential_id]) => {
            direct_api_write_id_segment_is_allowed(credential_id)
        }
        (&Method::PATCH, ["", "api", "v1", "targets", target_id]) => {
            direct_api_write_id_segment_is_allowed(target_id)
        }
        (&Method::POST, ["", "api", "v1", "targets"]) => true,
        (&Method::DELETE, ["", "api", "v1", "targets", target_id]) => {
            direct_api_write_id_segment_is_allowed(target_id)
        }
        (&Method::POST, ["", "api", "v1", "targets", target_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(target_id)
        }
        (&Method::POST, ["", "api", "v1", "targets", target_id, "restore"]) => {
            direct_api_write_id_segment_is_allowed(target_id)
        }
        (&Method::DELETE, ["", "api", "v1", "targets", target_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(target_id)
        }
        (&Method::PATCH, ["", "api", "v1", "tasks", task_id]) => {
            direct_api_write_id_segment_is_allowed(task_id)
        }
        (&Method::POST, ["", "api", "v1", "filters"]) => true,
        (&Method::PATCH | &Method::DELETE, ["", "api", "v1", "filters", filter_id]) => {
            direct_api_write_id_segment_is_allowed(filter_id)
        }
        (&Method::POST, ["", "api", "v1", "filters", filter_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(filter_id)
        }
        (&Method::POST, ["", "api", "v1", "filters", filter_id, "restore"]) => {
            direct_api_write_id_segment_is_allowed(filter_id)
        }
        (&Method::DELETE, ["", "api", "v1", "filters", filter_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(filter_id)
        }
        (&Method::POST, ["", "api", "v1", "port-lists"]) => true,
        (&Method::PATCH | &Method::DELETE, ["", "api", "v1", "port-lists", port_list_id]) => {
            direct_api_write_id_segment_is_allowed(port_list_id)
        }
        (&Method::POST, ["", "api", "v1", "port-lists", port_list_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(port_list_id)
        }
        (&Method::DELETE, ["", "api", "v1", "port-lists", port_list_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(port_list_id)
        }
        (&Method::POST, ["", "api", "v1", "port-lists", port_list_id, "restore"]) => {
            direct_api_write_id_segment_is_allowed(port_list_id)
        }
        (&Method::PATCH | &Method::DELETE, ["", "api", "v1", "schedules", schedule_id]) => {
            direct_api_write_id_segment_is_allowed(schedule_id)
        }
        (&Method::POST, ["", "api", "v1", "schedules", schedule_id, "clone"]) => {
            direct_api_write_id_segment_is_allowed(schedule_id)
        }
        (&Method::POST, ["", "api", "v1", "schedules", schedule_id, "restore"]) => {
            direct_api_write_id_segment_is_allowed(schedule_id)
        }
        (&Method::DELETE, ["", "api", "v1", "schedules", schedule_id, "trash"]) => {
            direct_api_write_id_segment_is_allowed(schedule_id)
        }
        _ => false,
    }
}

fn direct_api_write_id_segment_is_allowed(segment: &str) -> bool {
    Uuid::parse_str(segment).is_ok()
}

fn direct_api_segments_are_nonempty(parts: &[&str]) -> bool {
    parts
        .iter()
        .skip(4)
        .all(|part| !part.is_empty() && *part != "." && *part != "..")
}

fn direct_api_wildcard_detail_path_is_allowed(path: &str) -> bool {
    [
        "/api/v1/cpes/",
        "/api/v1/cert-bund-advisories/",
        "/api/v1/dfn-cert-advisories/",
    ]
    .iter()
    .any(|prefix| {
        path.strip_prefix(prefix)
            .is_some_and(direct_api_wildcard_tail_is_allowed)
    })
}

fn direct_api_wildcard_tail_is_allowed(tail: &str) -> bool {
    !tail.is_empty()
        && tail
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
