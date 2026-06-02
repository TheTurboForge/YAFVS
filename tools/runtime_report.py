#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read the current TurboVAS full-test report and write JSON artifacts."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import runtime_full_test_scan


DEFAULT_MAX_RESULTS = 1000
DEFAULT_TOP_RESULTS = 10
REPORT_FILTER_TEMPLATE = "apply_overrides=0 min_qod=0 first=1 rows={max_results} sort-reverse=severity"
SEVERITY_BUCKETS = ("Critical", "High", "Medium", "Low", "Log", "False Positive", "Unknown")


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


def child_id(element: Any, child_name: str) -> str | None:
    child = child_element(element, child_name)
    return child.get("id") if child is not None else None


def child_path_text(element: Any, child_names: tuple[str, ...]) -> str | None:
    current = element
    for child_name in child_names:
        current = child_element(current, child_name)
        if current is None:
            return None
    return current.text.strip() if current.text else None


def text_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def text_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def normalize_text(value: str | None, limit: int | None = None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"\s+", " ", value).strip()
    if limit is not None and len(normalized) > limit:
        return normalized[: limit - 1].rstrip() + "..."
    return normalized


def first_report_element(response: Any, report_id: str | None = None) -> Any | None:
    root = response_root(response)
    if root is None or not hasattr(root, "iter"):
        return None
    for element in list(root):
        if local_name(str(element.tag)) != "report":
            continue
        if report_id is None or element.get("id") == report_id:
            return element
    return None


def report_detail_element(report: Any) -> Any:
    detail = child_element(report, "report")
    return detail if detail is not None else report


def report_task(report: Any, detail: Any) -> dict[str, str | None]:
    task = child_element(report, "task")
    if task is None:
        task = child_element(detail, "task")
    if task is None:
        return {"id": None, "name": None}
    return {"id": task.get("id"), "name": child_text(task, "name")}


def report_count(listing_row: dict[str, str | None] | None, listing_key: str, detail: Any, path: tuple[str, ...]) -> int | None:
    if listing_row and listing_row.get(listing_key) is not None:
        return text_int(listing_row.get(listing_key))
    return text_int(child_path_text(detail, path))


def result_row(element: Any) -> dict[str, Any]:
    host = child_element(element, "host")
    nvt = child_element(element, "nvt")
    qod = child_element(element, "qod")
    severity = child_text(element, "severity")
    return {
        "id": element.get("id"),
        "name": child_text(element, "name"),
        "host": host.text.strip() if host is not None and host.text else None,
        "hostname": child_text(host, "hostname") if host is not None else None,
        "port": child_text(element, "port"),
        "severity": severity,
        "severity_score": text_float(severity),
        "threat": child_text(element, "threat"),
        "qod": text_int(child_text(qod, "value")) if qod is not None else None,
        "nvt_oid": nvt.get("oid") if nvt is not None else None,
        "nvt_name": child_text(nvt, "name") if nvt is not None else None,
        "nvt_family": child_text(nvt, "family") if nvt is not None else None,
        "description_excerpt": normalize_text(child_text(element, "description"), limit=240),
    }


def report_results(detail: Any) -> list[dict[str, Any]]:
    results = child_element(detail, "results")
    if results is None:
        return []
    return [result_row(element) for element in list(results) if local_name(str(element.tag)) == "result"]


def severity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {bucket: 0 for bucket in SEVERITY_BUCKETS}
    for row in rows:
        threat = row.get("threat") or "Unknown"
        bucket = threat if threat in counts else "Unknown"
        counts[bucket] += 1
    return counts


def affected_hosts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    for row in rows:
        host = row.get("host") or "unknown"
        current = hosts.setdefault(
            host,
            {
                "host": host,
                "hostnames": set(),
                "result_count": 0,
                "vulnerability_count": 0,
                "max_severity": 0.0,
                "threats": set(),
            },
        )
        current["result_count"] += 1
        if row.get("hostname"):
            current["hostnames"].add(row["hostname"])
        severity = row.get("severity_score") or 0.0
        current["max_severity"] = max(current["max_severity"], severity)
        if severity > 0:
            current["vulnerability_count"] += 1
        if row.get("threat"):
            current["threats"].add(row["threat"])

    normalized = []
    for host in hosts.values():
        normalized.append(
            {
                "host": host["host"],
                "hostnames": sorted(host["hostnames"]),
                "result_count": host["result_count"],
                "vulnerability_count": host["vulnerability_count"],
                "max_severity": host["max_severity"],
                "threats": sorted(host["threats"]),
            }
        )
    return sorted(normalized, key=lambda item: (-item["max_severity"], item["host"]))


def top_results(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    ordered = sorted(
        rows,
        key=lambda row: (
            -(row.get("severity_score") or 0.0),
            row.get("host") or "",
            row.get("port") or "",
            row.get("name") or "",
            row.get("id") or "",
        ),
    )
    return ordered[:limit]


def parse_report_payload(
    response: Any,
    listing_row: dict[str, str | None] | None = None,
    top_limit: int = DEFAULT_TOP_RESULTS,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> tuple[dict[str, Any] | None, str | None]:
    report = first_report_element(response, listing_row.get("id") if listing_row else None)
    if report is None:
        return None, "Could not find a report element in the GMP response."
    detail = report_detail_element(report)
    task = report_task(report, detail)
    rows = report_results(detail)
    result_count = report_count(listing_row, "result_count", detail, ("result_count", "full"))
    export_complete = result_count is None or len(rows) >= result_count
    payload = {
        "report": {
            "id": report.get("id") or (listing_row.get("id") if listing_row else None),
            "name": child_text(report, "name") or (listing_row.get("name") if listing_row else None),
            "task_id": task["id"] or (listing_row.get("task_id") if listing_row else None),
            "task_name": task["name"],
            "scan_run_status": child_text(detail, "scan_run_status") or (listing_row.get("scan_run_status") if listing_row else None),
            "scan_start": child_text(detail, "scan_start") or (listing_row.get("scan_start") if listing_row else None),
            "scan_end": child_text(detail, "scan_end") or (listing_row.get("scan_end") if listing_row else None),
            "counts": {
                "hosts": report_count(listing_row, "hosts_count", detail, ("hosts", "count")),
                "results": result_count,
                "vulnerabilities": report_count(listing_row, "vulns_count", detail, ("vulns", "count")),
                "cves": report_count(listing_row, "cves_count", detail, ("cves", "count")),
                "operating_systems": report_count(listing_row, "os_count", detail, ("os", "count")),
            },
        },
        "result_filter": REPORT_FILTER_TEMPLATE.format(max_results=max_results),
        "parsed_result_count": len(rows),
        "export_complete": export_complete,
        "severity_counts": severity_counts(rows),
        "affected_hosts": affected_hosts(rows),
        "top_results": top_results(rows, top_limit),
    }
    return payload, None


def select_report(gmp: Any, report_id: str | None) -> tuple[dict[str, str | None] | None, str | None]:
    if report_id:
        return {"id": report_id}, None
    state = runtime_full_test_scan.load_state(gmp)
    task, task_error = runtime_full_test_scan.single_named(state["tasks"], runtime_full_test_scan.FULL_TEST_TASK_NAME)
    if task_error:
        return None, task_error
    if not task or not task.get("id"):
        return None, "Full-test task does not exist yet."
    latest, report_error = runtime_full_test_scan.latest_report_for_task(gmp, task["id"])
    if report_error:
        return None, report_error
    if not latest or not latest.get("id"):
        return None, "No report found for the full-test task."
    return latest, None


def fetch_report(gmp: Any, report_id: str, max_results: int) -> Any:
    return gmp.get_report(
        report_id=report_id,
        filter_string=REPORT_FILTER_TEMPLATE.format(max_results=max_results),
        details=True,
        ignore_pagination=False,
    )


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def command_summary(gmp: Any, artifact_dir: Path, report_id: str | None, max_results: int, top_results_limit: int) -> dict[str, Any]:
    listing, select_error = select_report(gmp, report_id)
    if select_error or not listing or not listing.get("id"):
        payload = result("fail", "Runtime report summary failed because no report could be selected.", error=select_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "summary-failed.json", payload)]
        return payload
    response = fetch_report(gmp, listing["id"], max_results)
    parsed, parse_error = parse_report_payload(response, listing, top_results_limit, max_results)
    if parse_error or parsed is None:
        payload = result("fail", "Runtime report summary failed while parsing the report.", report_id=listing["id"], error=parse_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "summary-failed.json", payload)]
        return payload
    payload = result("pass" if parsed["export_complete"] else "warn", "Runtime report summary read.", **parsed)
    payload["artifacts"] = [write_artifact(artifact_dir, "summary.json", payload)]
    return payload


def command_export(gmp: Any, artifact_dir: Path, report_id: str | None, max_results: int, top_results_limit: int) -> dict[str, Any]:
    listing, select_error = select_report(gmp, report_id)
    if select_error or not listing or not listing.get("id"):
        payload = result("fail", "Runtime report export failed because no report could be selected.", error=select_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "export-failed.json", payload)]
        return payload
    response = fetch_report(gmp, listing["id"], max_results)
    parsed, parse_error = parse_report_payload(response, listing, top_results_limit, max_results)
    if parse_error or parsed is None:
        payload = result("fail", "Runtime report export failed while parsing the report.", report_id=listing["id"], error=parse_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "export-failed.json", payload)]
        return payload
    report = first_report_element(response, listing["id"])
    rows = report_results(report_detail_element(report)) if report is not None else []
    payload = result("pass" if parsed["export_complete"] else "warn", "Runtime report export read.", **parsed, results=rows)
    payload["artifacts"] = [write_artifact(artifact_dir, "export.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read TurboVAS runtime report data over GMP")
    parser.add_argument("command", choices=("summary", "export"))
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for report artifacts")
    parser.add_argument("--report-id", help="optional report id; defaults to the latest full-test scan report")
    parser.add_argument("--max-results", type=int, default=DEFAULT_MAX_RESULTS, help="maximum results to fetch from the selected report")
    parser.add_argument("--top-results", type=int, default=DEFAULT_TOP_RESULTS, help="number of top results to include in the summary")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    gmp = None
    try:
        gmp, password = runtime_full_test_scan.connect_gmp(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        if args.command == "summary":
            payload = command_summary(gmp, Path(args.artifact_dir), args.report_id, args.max_results, args.top_results)
        else:
            payload = command_export(gmp, Path(args.artifact_dir), args.report_id, args.max_results, args.top_results)
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Runtime report helper failed.", error_type=type(error).__name__, error=str(error).replace(password, "[redacted]"))
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
