# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read TurboVAS raw-report and scope-report metrics over GMP."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import runtime_full_test_scan
import runtime_report
import runtime_scope


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


def response_root(response: Any) -> Any | None:
    if isinstance(response, bytes):
        response = response.decode("utf-8", errors="replace")
    if isinstance(response, str):
        try:
            return ET.fromstring(response)
        except ET.ParseError:
            return None
    return response


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def child_element(element: Any, child_name: str) -> Any | None:
    for child in list(element):
        if local_name(str(child.tag)) == child_name:
            return child
    return None


def child_text(element: Any, child_name: str) -> str | None:
    child = child_element(element, child_name)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def text_int(value: str | None) -> int:
    if value in (None, ""):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def text_float(value: str | None) -> float:
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0


def first_element(response: Any, element_name: str) -> Any | None:
    root = response_root(response)
    if root is None or not hasattr(root, "iter"):
        return None
    for element in root.iter():
        if local_name(str(element.tag)) == element_name:
            return element
    return None


def metric_summary(element: Any) -> dict[str, Any]:
    summary = child_element(element, "summary")
    if summary is None:
        return {}
    return {
        "alive_system_count": text_int(child_text(summary, "alive_system_count")),
        "total_system_cvss_load": text_float(child_text(summary, "total_system_cvss_load")),
        "average_system_cvss_load": text_float(child_text(summary, "average_system_cvss_load")),
        "vulnerability_count": text_int(child_text(summary, "vulnerability_count")),
        "authenticated_system_count": text_int(child_text(summary, "authenticated_system_count")),
        "authentication_failed_system_count": text_int(child_text(summary, "authentication_failed_system_count")),
        "no_credential_path_system_count": text_int(child_text(summary, "no_credential_path_system_count")),
        "unknown_authentication_system_count": text_int(child_text(summary, "unknown_authentication_system_count")),
        "authenticated_scan_coverage_percent": text_float(child_text(summary, "authenticated_scan_coverage_percent")),
    }


def metric_systems(element: Any) -> list[dict[str, Any]]:
    systems = child_element(element, "systems")
    if systems is None:
        return []
    rows: list[dict[str, Any]] = []
    for system in list(systems):
        if local_name(str(system.tag)) != "system":
            continue
        rows.append(
            {
                "host": child_text(system, "host"),
                "cvss_load": text_float(child_text(system, "cvss_load")),
                "max_cvss": text_float(child_text(system, "max_cvss")),
                "vulnerability_count": text_int(child_text(system, "vulnerability_count")),
                "authentication_state": child_text(system, "authentication_state") or "unknown",
                "source_report_count": text_int(child_text(system, "source_report_count")),
            }
        )
    return rows


def metric_vulnerabilities(element: Any) -> list[dict[str, Any]]:
    vulnerabilities = child_element(element, "vulnerabilities")
    if vulnerabilities is None:
        return []
    rows: list[dict[str, Any]] = []
    for vulnerability in list(vulnerabilities):
        if local_name(str(vulnerability.tag)) != "vulnerability":
            continue
        rows.append(
            {
                "nvt_oid": child_text(vulnerability, "nvt_oid"),
                "name": child_text(vulnerability, "name"),
                "cvss_score": text_float(child_text(vulnerability, "cvss_score")),
                "affected_system_count": text_int(child_text(vulnerability, "affected_system_count")),
                "cvss_load": text_float(child_text(vulnerability, "cvss_load")),
                "average_contribution": text_float(child_text(vulnerability, "average_contribution")),
                "source_report_count": text_int(child_text(vulnerability, "source_report_count")),
            }
        )
    return rows


def parse_metrics(response: Any, element_name: str) -> dict[str, Any] | None:
    element = first_element(response, element_name)
    if element is None:
        return None
    return {
        "id": element.get("id"),
        "summary": metric_summary(element),
        "systems": metric_systems(element),
        "vulnerabilities": metric_vulnerabilities(element),
    }


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def command_report_metrics(gmp: Any, artifact_dir: Path, report_id: str | None) -> dict[str, Any]:
    listing, select_error = runtime_report.select_report(gmp, report_id)
    if select_error or not listing or not listing.get("id"):
        payload = result("fail", "Runtime report metrics failed because no report could be selected.", error=select_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "report-metrics-failed.json", payload)]
        return payload
    selected_report_id = listing["id"]
    response = gmp.get_report_metrics(selected_report_id)
    metrics = parse_metrics(response, "report_metrics")
    if metrics is None:
        payload = result("fail", "Runtime report metrics response did not include report metrics.", report_id=selected_report_id)
        payload["artifacts"] = [write_artifact(artifact_dir, "report-metrics-failed.json", payload)]
        return payload
    payload = result("pass", "Runtime report metrics read.", report_id=selected_report_id, metrics=metrics)
    payload["artifacts"] = [write_artifact(artifact_dir, "report-metrics.json", payload)]
    return payload


def command_scope_report_metrics(gmp: Any, artifact_dir: Path, scope_report_id: str | None) -> dict[str, Any]:
    scope: dict[str, Any] | None = None
    selected_scope_report_id = scope_report_id
    if selected_scope_report_id is None:
        scope = runtime_scope.organization_scope(gmp)
        if not scope or not scope.get("id"):
            payload = result("fail", "Runtime scope report metrics failed because the Organization scope is missing.")
            payload["artifacts"] = [write_artifact(artifact_dir, "scope-report-metrics-failed.json", payload)]
            return payload
        reports = runtime_scope.scope_reports(gmp, scope["id"])
        if not reports or not reports[0].get("id"):
            payload = result("fail", "Runtime scope report metrics failed because no Organization scope report exists.", scope=scope)
            payload["artifacts"] = [write_artifact(artifact_dir, "scope-report-metrics-failed.json", payload)]
            return payload
        selected_scope_report_id = reports[0]["id"]
    response = gmp.get_scope_report_metrics(selected_scope_report_id)
    metrics = parse_metrics(response, "scope_report_metrics")
    if metrics is None:
        payload = result("fail", "Runtime scope report metrics response did not include scope report metrics.", scope_report_id=selected_scope_report_id)
        payload["artifacts"] = [write_artifact(artifact_dir, "scope-report-metrics-failed.json", payload)]
        return payload
    payload = result("pass", "Runtime scope report metrics read.", scope=scope, scope_report_id=selected_scope_report_id, metrics=metrics)
    payload["artifacts"] = [write_artifact(artifact_dir, "scope-report-metrics.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read TurboVAS report metrics over GMP")
    parser.add_argument("command", choices=("report", "scope-report"))
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for metric artifacts")
    parser.add_argument("--report-id", help="optional raw report id; defaults to the latest completed full-test scan report")
    parser.add_argument("--scope-report-id", help="optional scope report id; defaults to the latest Organization scope report")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    gmp = None
    try:
        gmp, password = runtime_full_test_scan.connect_gmp(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        if args.command == "report":
            payload = command_report_metrics(gmp, Path(args.artifact_dir), args.report_id)
        else:
            payload = command_scope_report_metrics(gmp, Path(args.artifact_dir), args.scope_report_id)
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Runtime metrics helper failed.", error_type=type(error).__name__, error=str(error).replace(password, "[redacted]"))
    finally:
        if gmp is not None:
            try:
                gmp.disconnect()
            except Exception:
                pass
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
