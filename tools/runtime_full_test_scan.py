#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guarded GMP command surface for the authorized YAFVS full test scan."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import quoteattr

from runtime_gmp_smoke import gmp_authenticate_xml, send_gmp_xml_command


FULL_AND_FAST_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
IANA_TCP_UDP_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
OPENVAS_SCANNER_NAME = "OpenVAS Default"
MAX_FULL_TEST_TARGET_ADDRESSES = 256
ACTIVE_TASK_STATUSES = {
    "Requested",
    "Queued",
    "Running",
    "Stop Requested",
    "Resume Requested",
}
HANDOFF_TASK_STATUSES = {"Queued", "Running", "Done"}
COMPLETED_REPORT_STATUS = "Done"
INTERRUPTED_REPORT_STATUS = "Interrupted"
ZERO_PROGRESS_COUNTS = ("result_count", "hosts_count", "vulns_count", "cves_count", "os_count")


@dataclass(frozen=True)
class FullTestTarget:
    cidr: str
    target_name: str
    task_name: str


def parse_full_test_target(value: str) -> FullTestTarget:
    candidate = value.strip()
    if not candidate:
        raise ValueError("Full-test target CIDR must not be empty.")
    try:
        network = ipaddress.ip_network(candidate, strict=True)
    except ValueError as error:
        raise ValueError(f"Full-test target must be a canonical CIDR: {error}") from error
    if network.is_unspecified or network.is_multicast:
        raise ValueError("Full-test target must not be an unspecified or multicast network.")
    if network.num_addresses > MAX_FULL_TEST_TARGET_ADDRESSES:
        raise ValueError(
            f"Full-test target may contain at most {MAX_FULL_TEST_TARGET_ADDRESSES} addresses; got {network.num_addresses}."
        )
    canonical = str(network)
    return FullTestTarget(
        cidr=canonical,
        target_name=f"YAFVS full test target {canonical}",
        task_name=f"YAFVS full test scan {canonical}",
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def response_root(response: Any) -> Any | None:
    if isinstance(response, bytes):
        response = response.decode("utf-8", errors="replace")
    if isinstance(response, str):
        try:
            return ET.fromstring(response)
        except ET.ParseError:
            return None
    return response


def child_text(element: Any, child_name: str) -> str | None:
    for child in list(element):
        if local_name(str(child.tag)) == child_name:
            return child.text
    return None


def child_id(element: Any, child_name: str) -> str | None:
    for child in list(element):
        if local_name(str(child.tag)) == child_name:
            return child.get("id")
    return None


def child_element(element: Any, child_name: str) -> Any | None:
    for child in list(element):
        if local_name(str(child.tag)) == child_name:
            return child
    return None


def descendant_text(element: Any, child_name: str) -> str | None:
    for child in element.iter():
        if local_name(str(child.tag)) == child_name and child.text:
            return child.text
    return None


def child_path_text(element: Any, child_names: tuple[str, ...]) -> str | None:
    current = element
    for child_name in child_names:
        current = child_element(current, child_name)
        if current is None:
            return None
    return current.text


def object_rows(response: Any, object_tag: str) -> list[dict[str, str | None]]:
    root = response_root(response)
    if root is None or not hasattr(root, "iter"):
        return []
    rows: list[dict[str, str | None]] = []
    for element in root.iter():
        if local_name(str(element.tag)) != object_tag:
            continue
        rows.append(
            {
                "id": element.get("id"),
                "name": child_text(element, "name"),
                "status": child_text(element, "status"),
                "progress": child_text(element, "progress"),
                "target_id": child_id(element, "target"),
                "scanner_id": child_id(element, "scanner"),
                "config_id": child_id(element, "config"),
                "report_id": child_id(element, "report"),
            }
        )
    return rows


def native_report_rows(repo_root: Path, *, page_size: int = 100) -> list[dict[str, str | None]]:
    payload = native_api_json(repo_root, f"/api/v1/reports?page_size={page_size}&sort=-creation_time")
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    rows: list[dict[str, str | None]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        rows.append(
            {
                "id": item.get("id") if isinstance(item.get("id"), str) else None,
                "task_id": task.get("id") if isinstance(task.get("id"), str) else None,
                "name": item.get("name") if isinstance(item.get("name"), str) else None,
                "scan_run_status": item.get("status") if isinstance(item.get("status"), str) else None,
                "scan_start": item.get("scan_start") if isinstance(item.get("scan_start"), str) else None,
                "scan_end": item.get("scan_end") if isinstance(item.get("scan_end"), str) else None,
                "result_count": str(item.get("result_count")) if item.get("result_count") is not None else None,
                "hosts_count": str(item.get("host_count")) if item.get("host_count") is not None else None,
                "vulns_count": str(item.get("vulnerability_count")) if item.get("vulnerability_count") is not None else None,
                "cves_count": str(item.get("cve_count")) if item.get("cve_count") is not None else None,
                "os_count": None,
            }
        )
    return rows


def native_api_json(repo_root: Path, path: str) -> dict[str, Any]:
    command = [
        "docker",
        "compose",
        "-f",
        str(repo_root / "compose" / "dev.yaml"),
        "exec",
        "-T",
        "yafvs-api",
        "curl",
        "-fsS",
        "--max-time",
        "10",
        f"http://127.0.0.1:9080{path}",
    ]
    completed = subprocess.run(
        command,
        cwd=repo_root,
        env=os.environ.copy(),
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"native API request failed: {completed.stderr.strip() or completed.stdout.strip()}")
    parsed = json.loads(completed.stdout)
    if not isinstance(parsed, dict):
        raise RuntimeError("native API returned a non-object payload")
    return parsed


def native_api_browser_proxy_json(
    repo_root: Path,
    path: str,
    *,
    method: str,
    payload: dict[str, Any] | None,
    operator_name: str,
    expected_statuses: set[str],
) -> dict[str, Any]:
    if method != "POST":
        raise ValueError(f"unsupported native browser-proxy JSON method: {method}")
    if not path.startswith("/api/v1/"):
        raise ValueError(f"unsupported native browser-proxy JSON path: {path}")
    command = [
        "docker",
        "compose",
        "-f",
        str(repo_root / "compose" / "dev.yaml"),
        "exec",
        "-T",
        "-e",
        "YAFVS_FULL_TEST_OPERATOR_NAME",
        "-e",
        "YAFVS_FULL_TEST_METHOD",
        "-e",
        "YAFVS_FULL_TEST_PATH",
        "-e",
        "YAFVS_FULL_TEST_JSON",
        "-e",
        "YAFVS_FULL_TEST_HAS_JSON",
        "yafvs-api",
        "sh",
        "-ceu",
        (
            "test -n \"${YAFVS_API_BROWSER_PROXY_SECRET:-}\"; "
            "if [ \"${YAFVS_FULL_TEST_HAS_JSON}\" = 1 ]; then "
            "set -- -H \"content-type: application/json\" --data \"${YAFVS_FULL_TEST_JSON}\"; "
            "else set --; fi; "
            "curl -sS --max-time 10 -X \"${YAFVS_FULL_TEST_METHOD}\" -w '\\n%{http_code}' "
            "-H \"x-yafvs-browser-proxy-secret: ${YAFVS_API_BROWSER_PROXY_SECRET}\" "
            "-H \"x-yafvs-operator-name: ${YAFVS_FULL_TEST_OPERATOR_NAME}\" "
            "\"$@\" "
            "\"http://127.0.0.1:9080${YAFVS_FULL_TEST_PATH}\""
        ),
    ]
    env = os.environ.copy()
    env["YAFVS_FULL_TEST_OPERATOR_NAME"] = operator_name
    env["YAFVS_FULL_TEST_METHOD"] = method
    env["YAFVS_FULL_TEST_PATH"] = path
    env["YAFVS_FULL_TEST_JSON"] = json.dumps(payload) if payload is not None else ""
    env["YAFVS_FULL_TEST_HAS_JSON"] = "1" if payload is not None else "0"
    completed = subprocess.run(
        command,
        cwd=repo_root,
        env=env,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    lines = completed.stdout.splitlines()
    status = lines[-1].strip() if lines else ""
    body = "\n".join(lines[:-1]).strip()
    if completed.returncode != 0 or status not in expected_statuses:
        reason = (
            completed.stderr.strip()
            or body
            or completed.stdout.strip()
            or f"container command exited {completed.returncode} without output"
        )
        raise RuntimeError(f"native API {method} failed with HTTP {status or 'unknown'}: {reason}")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"native API {method} returned a non-object payload")
    return parsed


def native_items(repo_root: Path, resource: str, *, page_size: int = 500) -> list[dict[str, Any]]:
    payload = native_api_json(repo_root, f"/api/v1/{resource}?page_size={page_size}")
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def native_object_rows(repo_root: Path, resource: str) -> list[dict[str, str | None]]:
    rows: list[dict[str, str | None]] = []
    for item in native_items(repo_root, resource):
        target = item.get("target") if isinstance(item.get("target"), dict) else {}
        scanner = item.get("scanner") if isinstance(item.get("scanner"), dict) else {}
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        report = item.get("current_report") or item.get("last_report")
        if not isinstance(report, dict):
            report = {}
        rows.append(
            {
                "id": item.get("id") if isinstance(item.get("id"), str) else None,
                "name": item.get("name") if isinstance(item.get("name"), str) else None,
                "status": item.get("status") if isinstance(item.get("status"), str) else None,
                "progress": str(item.get("progress")) if item.get("progress") is not None else None,
                "target_id": target.get("id") if isinstance(target.get("id"), str) else None,
                "scanner_id": scanner.get("id") if isinstance(scanner.get("id"), str) else None,
                "config_id": config.get("id") if isinstance(config.get("id"), str) else None,
                "report_id": report.get("id") if isinstance(report.get("id"), str) else None,
            }
        )
    return rows


def report_rows(response: Any) -> list[dict[str, str | None]]:
    root = response_root(response)
    if root is None or not hasattr(root, "iter"):
        return []
    rows: list[dict[str, str | None]] = []
    for element in list(root):
        if local_name(str(element.tag)) != "report":
            continue
        detail = child_element(element, "report")
        if detail is None:
            detail = element
        rows.append(
            {
                "id": element.get("id"),
                "task_id": child_id(element, "task") or child_id(detail, "task"),
                "name": child_text(element, "name"),
                "scan_run_status": descendant_text(detail, "scan_run_status"),
                "scan_start": descendant_text(detail, "scan_start"),
                "scan_end": descendant_text(detail, "scan_end"),
                "result_count": child_path_text(detail, ("result_count", "full")),
                "hosts_count": child_path_text(detail, ("hosts", "count")),
                "vulns_count": child_path_text(detail, ("vulns", "count")),
                "cves_count": child_path_text(detail, ("cves", "count")),
                "os_count": child_path_text(detail, ("os", "count")),
            }
        )
    return rows


def reports_for_task(
    client: Any,
    task_id: str,
    rows: int = 10,
    repo_root: Path | None = None,
) -> tuple[list[dict[str, str | None]], str | None]:
    if repo_root is not None:
        try:
            native_rows = native_report_rows(repo_root, page_size=max(rows, 100))
        except Exception as error:  # pylint: disable=broad-except
            return [], f"native report lookup failed: {type(error).__name__}: {error}"
        return [row for row in native_rows if row.get("task_id") == task_id][:rows], None
    try:
        response = getattr(client, "get_reports")(
            filter_string=f"task_id={task_id} rows={rows} sort-reverse=date",
            details=True,
            ignore_pagination=True,
        )
    except Exception as error:  # pylint: disable=broad-except
        return [], f"{type(error).__name__}: {error}"
    return [row for row in report_rows(response) if row.get("task_id") == task_id], None


def latest_report_for_task(client: Any, task_id: str, repo_root: Path | None = None) -> tuple[dict[str, str | None] | None, str | None]:
    reports, error = reports_for_task(client, task_id, rows=10, repo_root=repo_root)
    return (reports[0] if reports else None), error


def first_report_with_status(reports: list[dict[str, str | None]], status: str) -> dict[str, str | None] | None:
    for report in reports:
        if report.get("scan_run_status") == status:
            return report
    return None


def first_completed_report_with_start(reports: list[dict[str, str | None]]) -> dict[str, str | None] | None:
    for report in reports:
        if report.get("scan_run_status") == COMPLETED_REPORT_STATUS and report.get("scan_start"):
            return report
    return None


def first_no_start_completed_report(reports: list[dict[str, str | None]]) -> dict[str, str | None] | None:
    for report in reports:
        if report.get("scan_run_status") == COMPLETED_REPORT_STATUS and not report.get("scan_start"):
            return report
    return None


def parse_count(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def interrupted_before_scanner_handoff(report: dict[str, str | None] | None) -> bool:
    if not report or report.get("scan_run_status") != INTERRUPTED_REPORT_STATUS:
        return False
    if report.get("scan_start") or report.get("scan_end"):
        return False
    return all(parse_count(report.get(key)) in (None, 0) for key in ZERO_PROGRESS_COUNTS)


def report_handoff_observed(report: dict[str, str | None] | None) -> bool:
    if not report:
        return False
    if report.get("scan_run_status") == COMPLETED_REPORT_STATUS and report.get("scan_start"):
        return True
    if report.get("scan_start"):
        return True
    return report.get("scan_run_status") in {"Queued", "Running"}


def ospd_handoff_evidence(log_file: Path | None, report_id: str | None, task_id: str | None) -> dict[str, Any]:
    if log_file is None:
        return {"checked": False, "reason": "no OSPD log file was supplied"}
    if not log_file.is_file():
        return {"checked": True, "log_file": str(log_file), "matched": False, "reason": "log file is missing"}
    needles = [value for value in (report_id, task_id) if value]
    try:
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-1000:]
    except OSError as error:
        return {"checked": True, "log_file": str(log_file), "matched": False, "reason": str(error)}
    matches = [line for line in lines if any(needle in line for needle in needles)] if needles else []
    return {
        "checked": True,
        "log_file": str(log_file),
        "matched": bool(matches),
        "needles": needles,
        "matched_lines": matches[-20:],
        "checked_tail_lines": len(lines),
    }


def task_status_snapshot(
    client: Any,
    task: dict[str, str | None],
    ospd_log_file: Path | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    reports, report_error = reports_for_task(client, task["id"] or "", repo_root=repo_root) if task.get("id") else ([], None)
    latest_report = reports[0] if reports else None
    latest_completed_report = first_completed_report_with_start(reports)
    latest_no_start_completed_report = first_no_start_completed_report(reports)
    latest_interrupted_report = first_report_with_status(reports, INTERRUPTED_REPORT_STATUS)
    return {
        "task": task,
        "latest_report": latest_report,
        "latest_completed_report": latest_completed_report,
        "latest_no_start_completed_report": latest_no_start_completed_report,
        "latest_interrupted_report": latest_interrupted_report,
        "reports_checked": len(reports),
        "report_lookup_error": report_error,
        "latest_report_no_start": bool(latest_report and not latest_report.get("scan_start")),
        "latest_report_zero_progress": all(parse_count(latest_report.get(key)) in (None, 0) for key in ZERO_PROGRESS_COUNTS) if latest_report else None,
        "latest_report_interrupted_before_scanner_handoff": interrupted_before_scanner_handoff(latest_report),
        "latest_interrupted_before_scanner_handoff": interrupted_before_scanner_handoff(latest_interrupted_report),
        "ospd_handoff_evidence": ospd_handoff_evidence(ospd_log_file, latest_report.get("id") if latest_report else None, task.get("id")),
    }


def current_full_test_task(client: Any, target: FullTestTarget, repo_root: Path | None = None) -> tuple[dict[str, str | None] | None, str | None]:
    state = load_state(client, repo_root)
    return single_named(state["tasks"], target.task_name)


def response_id(response: Any) -> str | None:
    root = response_root(response)
    if root is None:
        return None
    if root.get("id"):
        return root.get("id")
    report_id = child_text(root, "report_id")
    if report_id:
        return report_id
    for child in root.iter():
        if child.get("id"):
            return child.get("id")
    return None


def named(rows: list[dict[str, str | None]], name: str) -> list[dict[str, str | None]]:
    return [row for row in rows if row.get("name") == name]


def id_present(rows: list[dict[str, str | None]], expected_id: str) -> bool:
    return any(row.get("id") == expected_id for row in rows)


def active_full_test_tasks(task_rows: list[dict[str, str | None]], target: FullTestTarget) -> list[dict[str, str | None]]:
    return [row for row in named(task_rows, target.task_name) if row.get("status") in ACTIVE_TASK_STATUSES]


def single_named(rows: list[dict[str, str | None]], name: str) -> tuple[dict[str, str | None] | None, str | None]:
    matches = named(rows, name)
    if len(matches) > 1:
        return None, f"Multiple objects named {name!r} exist."
    return (matches[0], None) if matches else (None, None)


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


class RawGmpClient:
    """Minimal raw GMP bridge for retained helper side effects."""

    def __init__(self, socket_path: Path, username: str, password: str, timeout: int) -> None:
        self.socket_path = socket_path
        self.username = username
        self.password = password
        self.timeout = timeout
        self.connection: socket.socket | None = None

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect(str(self.socket_path))
            send_gmp_xml_command(connection, gmp_authenticate_xml(self.username, self.password))
        except Exception:
            connection.close()
            raise
        self.connection = connection

    def send_xml(self, command: str) -> bytes:
        if self.connection is None:
            raise RuntimeError("GMP socket is not connected")
        return send_gmp_xml_command(self.connection, command)

    def start_task(self, task_id: str) -> bytes:
        return self.send_xml(f"<start_task task_id={quoteattr(task_id)}/>")

    def disconnect(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def connect_raw_gmp_client(socket_path: Path, username: str, password_file: Path, timeout: int):
    if not socket_path.is_socket():
        raise RuntimeError(f"gvmd socket is not ready: {socket_path}")
    if not password_file.is_file():
        raise RuntimeError(f"password file is missing: {password_file}")
    password = password_file.read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError(f"password file is empty: {password_file}")

    client = RawGmpClient(socket_path, username, password, timeout)
    client.connect()
    return client, password


def load_state(client: Any, repo_root: Path | None = None) -> dict[str, Any]:
    if repo_root is not None:
        return {
            "scan_configs": native_object_rows(repo_root, "scan-configs"),
            "port_lists": native_object_rows(repo_root, "port-lists"),
            "scanners": native_object_rows(repo_root, "scanners"),
            "targets": native_object_rows(repo_root, "targets"),
            "tasks": native_object_rows(repo_root, "tasks"),
        }
    return {
        "scan_configs": object_rows(getattr(client, "get_scan_configs")(), "config"),
        "port_lists": object_rows(getattr(client, "get_port_lists")(), "port_list"),
        "scanners": object_rows(getattr(client, "get_scanners")(details=True), "scanner"),
        "targets": object_rows(getattr(client, "get_targets")(tasks=True), "target"),
        "tasks": object_rows(getattr(client, "get_tasks")(details=True, ignore_pagination=True), "task"),
    }


def preflight_state(state: dict[str, Any], target_config: FullTestTarget) -> dict[str, Any]:
    scan_config_ok = id_present(state["scan_configs"], FULL_AND_FAST_SCAN_CONFIG_ID)
    port_list_ok = id_present(state["port_lists"], IANA_TCP_UDP_PORT_LIST_ID)
    scanner, scanner_error = single_named(state["scanners"], OPENVAS_SCANNER_NAME)
    target, target_error = single_named(state["targets"], target_config.target_name)
    task, task_error = single_named(state["tasks"], target_config.task_name)
    active = active_full_test_tasks(state["tasks"], target_config)
    status = "pass" if scan_config_ok and port_list_ok and scanner and not scanner_error and not target_error and not task_error and not active else "fail"
    return result(
        status,
        "Full test scan preflight passed." if status == "pass" else "Full test scan preflight failed.",
        target_cidr=target_config.cidr,
        scan_config={"id": FULL_AND_FAST_SCAN_CONFIG_ID, "present": scan_config_ok},
        port_list={"id": IANA_TCP_UDP_PORT_LIST_ID, "present": port_list_ok},
        scanner={"name": OPENVAS_SCANNER_NAME, "id": scanner.get("id") if scanner else None, "error": scanner_error},
        target={"name": target_config.target_name, "id": target.get("id") if target else None, "error": target_error},
        task={"name": target_config.task_name, "id": task.get("id") if task else None, "status": task.get("status") if task else None, "error": task_error},
        active_duplicate_tasks=active,
    )


def ensure_target(
    client: Any,
    state: dict[str, Any],
    target_config: FullTestTarget,
    *,
    repo_root: Path | None = None,
    operator_name: str = "admin",
) -> tuple[str | None, str | None]:
    target, error = single_named(state["targets"], target_config.target_name)
    if error:
        return None, error
    if target and target.get("id"):
        return target["id"], None
    if repo_root is not None:
        try:
            created = native_api_browser_proxy_json(
                repo_root,
                "/api/v1/targets",
                method="POST",
                payload={
                    "name": target_config.target_name,
                    "comment": "Explicitly authorized YAFVS full test target.",
                    "alive_tests": ["Scan Config Default"],
                    "allow_simultaneous_ips": True,
                    "reverse_lookup_only": False,
                    "reverse_lookup_unify": False,
                    "port_list_id": IANA_TCP_UDP_PORT_LIST_ID,
                    "hosts": [target_config.cidr],
                    "exclude_hosts": [],
                },
                operator_name=operator_name,
                expected_statuses={"201"},
            )
        except Exception as error:  # pylint: disable=broad-except
            return None, f"native target create failed: {type(error).__name__}: {error}"
        target_id = created.get("id")
        return (target_id, None) if isinstance(target_id, str) and target_id else (None, "Native target creation response did not include an id.")
    response = getattr(client, "create_target")(
        target_config.target_name,
        hosts=[target_config.cidr],
        port_list_id=IANA_TCP_UDP_PORT_LIST_ID,
        comment="Explicitly authorized YAFVS full test target.",
    )
    target_id = response_id(response)
    if not target_id:
        return None, "Could not parse created target id."
    return target_id, None


def ensure_task(
    client: Any,
    state: dict[str, Any],
    target_config: FullTestTarget,
    target_id: str,
    scanner_id: str,
    *,
    repo_root: Path | None = None,
    operator_name: str = "admin",
) -> tuple[str | None, str | None]:
    task, error = single_named(state["tasks"], target_config.task_name)
    if error:
        return None, error
    if task and task.get("id"):
        return task["id"], None
    if repo_root is not None:
        try:
            created = native_api_browser_proxy_json(
                repo_root,
                "/api/v1/tasks",
                method="POST",
                payload={
                    "name": target_config.task_name,
                    "comment": "Explicitly authorized YAFVS full test scan.",
                    "target_id": target_id,
                    "config_id": FULL_AND_FAST_SCAN_CONFIG_ID,
                    "scanner_id": scanner_id,
                },
                operator_name=operator_name,
                expected_statuses={"201"},
            )
        except Exception as error:  # pylint: disable=broad-except
            return None, f"native task create failed: {type(error).__name__}: {error}"
        task_id = created.get("id")
        return (task_id, None) if isinstance(task_id, str) and task_id else (None, "Native task creation response did not include an id.")
    response = getattr(client, "create_task")(
        target_config.task_name,
        FULL_AND_FAST_SCAN_CONFIG_ID,
        target_id,
        scanner_id,
        comment="Explicitly authorized YAFVS full test scan.",
    )
    task_id = response_id(response)
    if not task_id:
        return None, "Could not parse created task id."
    return task_id, None


def command_preflight(client: Any, artifact_dir: Path, target_config: FullTestTarget, repo_root: Path | None = None) -> dict[str, Any]:
    state = load_state(client, repo_root)
    payload = preflight_state(state, target_config)
    payload["artifacts"] = [write_artifact(artifact_dir, "preflight.json", payload)]
    return payload


def command_start(
    client: Any,
    artifact_dir: Path,
    target_config: FullTestTarget,
    confirm_authorized_target: str | None,
    repo_root: Path | None = None,
    operator_name: str = "admin",
    poll_seconds: int = 90,
    poll_interval: int = 5,
    ospd_log_file: Path | None = None,
    reconnect_client: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    if not confirm_authorized_target:
        payload = result("fail", "Full test scan start refused without --confirm-authorized-target.", target_cidr=target_config.cidr)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload
    try:
        confirmed_target = parse_full_test_target(confirm_authorized_target)
    except ValueError as error:
        payload = result("fail", "Full test scan start refused because the confirmed target is invalid.", target_cidr=target_config.cidr, error=str(error))
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload
    if confirmed_target.cidr != target_config.cidr:
        payload = result(
            "fail",
            "Full test scan start refused because the confirmed target does not match --target-cidr.",
            target_cidr=target_config.cidr,
            confirmed_target_cidr=confirmed_target.cidr,
        )
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    state = load_state(client, repo_root)
    preflight = preflight_state(state, target_config)
    if preflight["status"] == "fail" and preflight["details"]["active_duplicate_tasks"]:
        preflight["summary"] = "Full test scan start refused because a matching task is already active."
        preflight["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", preflight)]
        return preflight
    if preflight["status"] == "fail" and (
        not preflight["details"]["scan_config"]["present"]
        or not preflight["details"]["port_list"]["present"]
        or not preflight["details"]["scanner"]["id"]
    ):
        preflight["summary"] = "Full test scan start refused because required feed/scanner objects are missing."
        preflight["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", preflight)]
        return preflight

    scanner_id = preflight["details"]["scanner"]["id"]
    target_id, target_error = ensure_target(client, state, target_config, repo_root=repo_root, operator_name=operator_name)
    if target_error or not target_id:
        payload = result("fail", "Full test scan start refused because the target could not be prepared.", error=target_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    state = load_state(client, repo_root)
    task_id, task_error = ensure_task(client, state, target_config, target_id, scanner_id, repo_root=repo_root, operator_name=operator_name)
    if task_error or not task_id:
        payload = result("fail", "Full test scan start refused because the task could not be prepared.", error=task_error, target_id=target_id)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    refreshed = load_state(client, repo_root)
    active = active_full_test_tasks(refreshed["tasks"], target_config)
    if active:
        payload = result("fail", "Full test scan start refused because a matching task is already active.", active_duplicate_tasks=active)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    pre_start_reports, _ = reports_for_task(client, task_id, rows=20, repo_root=repo_root)
    pre_start_report_ids = {report["id"] for report in pre_start_reports if report.get("id")}
    start_error: str | None = None
    report_id: str | None = None
    try:
        if repo_root is not None:
            start_response = native_api_browser_proxy_json(
                repo_root,
                f"/api/v1/tasks/{task_id}/start",
                method="POST",
                payload=None,
                operator_name=operator_name,
                expected_statuses={"202"},
            )
            report_id_value = start_response.get("report_id")
            report_id = report_id_value if isinstance(report_id_value, str) else None
        else:
            start_response = getattr(client, "start_task")(task_id)
            report_id = response_id(start_response)
    except Exception as error:  # pylint: disable=broad-except
        start_error = f"{type(error).__name__}: {error}"
        if reconnect_client is not None:
            try:
                client = reconnect_client()
            except Exception as reconnect_error:  # pylint: disable=broad-except
                start_error = f"{start_error}; reconnect failed: {type(reconnect_error).__name__}: {reconnect_error}"

    deadline = time.monotonic() + poll_seconds
    observed: dict[str, Any] | None = None
    observed_report: dict[str, str | None] | None = None
    observed_new_report = False
    poll_errors: list[str] = []
    while time.monotonic() <= deadline:
        try:
            task, task_error = current_full_test_task(client, target_config, repo_root)
            if task_error:
                observed = {"task_lookup_error": task_error}
                break
            if not task:
                observed = {"task_lookup_error": "full test task disappeared after start request"}
                break
            observed = task_status_snapshot(client, task, ospd_log_file=ospd_log_file, repo_root=repo_root)
            reports, _ = reports_for_task(client, task_id, rows=10, repo_root=repo_root)
        except Exception as error:  # pylint: disable=broad-except
            poll_errors.append(f"{type(error).__name__}: {error}")
            if reconnect_client is not None:
                try:
                    client = reconnect_client()
                    continue
                except Exception as reconnect_error:  # pylint: disable=broad-except
                    poll_errors.append(f"reconnect failed: {type(reconnect_error).__name__}: {reconnect_error}")
            observed = {"poll_error": poll_errors[-1], "poll_errors": poll_errors}
            break
        new_reports = [report for report in reports if report.get("id") and report["id"] not in pre_start_report_ids]
        if report_id:
            observed_report = next((report for report in reports if report.get("id") == report_id), None)
        else:
            observed_report = new_reports[0] if new_reports else None
        observed_new_report = bool(
            observed_report
            and observed_report.get("id")
            and observed_report["id"] not in pre_start_report_ids
        )
        evidence = ospd_handoff_evidence(
            ospd_log_file,
            observed_report.get("id") if observed_report else report_id,
            None,
        )
        observed["start_ospd_handoff_evidence"] = evidence
        start_evidence = bool(report_id or observed_new_report)
        if interrupted_before_scanner_handoff(observed_report):
            break
        if start_error and not start_evidence:
            break
        if start_evidence and (
            task.get("status") in HANDOFF_TASK_STATUSES
            or report_handoff_observed(observed_report)
            or evidence.get("matched")
        ):
            break
        if task.get("status") in HANDOFF_TASK_STATUSES and report_id and observed_report and observed_report.get("scan_run_status") != INTERRUPTED_REPORT_STATUS:
            break
        time.sleep(poll_interval)

    interrupted_before_handoff = interrupted_before_scanner_handoff(observed_report)
    handoff_evidence = observed.get("start_ospd_handoff_evidence", {}) if observed else {}
    start_evidence = bool(report_id or observed_new_report)
    handoff_observed = bool(
        observed
        and start_evidence
        and (
            observed.get("task", {}).get("status") in HANDOFF_TASK_STATUSES
            or report_handoff_observed(observed_report)
            or handoff_evidence.get("matched")
        )
    )
    if interrupted_before_handoff:
        status = "fail"
        summary = "Full test scan start failed: the new report interrupted before scanner handoff."
        artifact_name = "start-failed.json"
    elif not start_evidence:
        status = "fail"
        summary = "Full test scan start failed because no accepted start or new report could be verified."
        artifact_name = "start-failed.json"
    elif handoff_observed:
        status = "pass"
        summary = "Full test scan start was accepted and scanner handoff/progress was observed."
        artifact_name = "start.json"
    else:
        status = "warn"
        summary = "Full test scan start was submitted, but scanner handoff was not observed before the polling timeout."
        artifact_name = "start.json"

    payload = result(
        status,
        summary,
        target_cidr=target_config.cidr,
        target_id=target_id,
        task_id=task_id,
        report_id=report_id,
        observed_report=observed_report,
        observed_state=observed,
        poll_errors=poll_errors,
        pre_start_report_ids=sorted(pre_start_report_ids),
        start_evidence=start_evidence,
        observed_new_report=observed_new_report,
        start_error=start_error,
        poll_seconds=poll_seconds,
        poll_interval=poll_interval,
        scan_config_id=FULL_AND_FAST_SCAN_CONFIG_ID,
        port_list_id=IANA_TCP_UDP_PORT_LIST_ID,
        scanner_id=scanner_id,
    )
    payload["artifacts"] = [write_artifact(artifact_dir, artifact_name, payload)]
    return payload


def command_status(client: Any, artifact_dir: Path, target_config: FullTestTarget, ospd_log_file: Path | None = None, repo_root: Path | None = None) -> dict[str, Any]:
    state = load_state(client, repo_root)
    task, task_error = single_named(state["tasks"], target_config.task_name)
    if task_error:
        payload = result("fail", "Full test scan status failed because multiple matching tasks exist.", error=task_error)
    elif not task:
        payload = result("warn", "Full test scan task does not exist yet.", target_cidr=target_config.cidr)
    else:
        payload = result("pass", "Full test scan status read.", target_cidr=target_config.cidr, **task_status_snapshot(client, task, ospd_log_file=ospd_log_file, repo_root=repo_root))
    payload["artifacts"] = [write_artifact(artifact_dir, "status.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guarded YAFVS full test scan helper")
    parser.add_argument("command", choices=("preflight", "start", "status"))
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for scan artifacts")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    parser.add_argument("--poll-seconds", type=int, default=90, help="seconds to poll after start_task before accepting start state")
    parser.add_argument("--poll-interval", type=int, default=5, help="seconds between post-start status polls")
    parser.add_argument("--ospd-log-file", help="optional OSPD log file used to find scanner handoff evidence")
    parser.add_argument("--repo-root", help="repository root for native API container reads")
    parser.add_argument("--target-cidr", required=True, help="explicit canonical authorized target CIDR; at most 256 addresses")
    parser.add_argument("--confirm-authorized-target", help="required for start; must exactly match --target-cidr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    connections = []

    def open_connection():
        nonlocal password
        connection, password = connect_raw_gmp_client(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        connections.append(connection)
        return connection

    try:
        target_config = parse_full_test_target(args.target_cidr)
        repo_root = Path(args.repo_root) if args.repo_root else None
        if args.command == "preflight":
            payload = command_preflight(None, Path(args.artifact_dir), target_config, repo_root=repo_root)
        elif args.command == "start":
            client = None if repo_root is not None else open_connection()
            payload = command_start(
                client,
                Path(args.artifact_dir),
                target_config,
                args.confirm_authorized_target,
                repo_root=repo_root,
                operator_name=args.username,
                poll_seconds=args.poll_seconds,
                poll_interval=args.poll_interval,
                ospd_log_file=Path(args.ospd_log_file) if args.ospd_log_file else None,
                reconnect_client=None if repo_root is not None else open_connection,
            )
        else:
            payload = command_status(None, Path(args.artifact_dir), target_config, ospd_log_file=Path(args.ospd_log_file) if args.ospd_log_file else None, repo_root=repo_root)
    except Exception as error:  # pylint: disable=broad-except
        error_text = str(error)
        if password:
            error_text = error_text.replace(password, "[redacted]")
        payload = result("fail", "Full test scan helper failed.", error_type=type(error).__name__, error=error_text)
    finally:
        for connection in reversed(connections):
            try:
                connection.disconnect()
            except Exception:
                pass
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
