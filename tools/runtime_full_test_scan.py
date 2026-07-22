#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guarded native API command surface for the authorized YAFVS full test scan."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
MAX_CONSECUTIVE_POLL_ERRORS = 3


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
    operator_uuid = native_operator_uuid(repo_root, operator_name)
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
        "YAFVS_FULL_TEST_OPERATOR_UUID",
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
            "-H \"x-yafvs-operator-uuid: ${YAFVS_FULL_TEST_OPERATOR_UUID}\" "
            "\"$@\" "
            "\"http://127.0.0.1:9080${YAFVS_FULL_TEST_PATH}\""
        ),
    ]
    env = os.environ.copy()
    env["YAFVS_FULL_TEST_OPERATOR_NAME"] = operator_name
    env["YAFVS_FULL_TEST_OPERATOR_UUID"] = operator_uuid
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


def native_operator_uuid(repo_root: Path, operator_name: str) -> str:
    matches = [
        item
        for item in native_items(repo_root, "users")
        if item.get("name") == operator_name
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one native API user named {operator_name!r}; "
            f"found {len(matches)}"
        )
    candidate = matches[0].get("id")
    try:
        return str(uuid.UUID(candidate))
    except (AttributeError, TypeError, ValueError) as error:
        raise RuntimeError(
            f"native API user {operator_name!r} has an invalid UUID"
        ) from error


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


def reports_for_task(
    repo_root: Path,
    task_id: str,
    rows: int = 10,
) -> tuple[list[dict[str, str | None]], str | None]:
    try:
        native_rows = native_report_rows(repo_root, page_size=max(rows, 100))
    except Exception as error:  # pylint: disable=broad-except
        return [], f"native report lookup failed: {type(error).__name__}: {error}"
    return [row for row in native_rows if row.get("task_id") == task_id][:rows], None


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
    repo_root: Path,
    task: dict[str, str | None],
    ospd_log_file: Path | None = None,
) -> dict[str, Any]:
    reports, report_error = reports_for_task(repo_root, task["id"] or "") if task.get("id") else ([], None)
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


def current_full_test_task(repo_root: Path, target: FullTestTarget) -> tuple[dict[str, str | None] | None, str | None]:
    state = load_state(repo_root)
    return single_named(state["tasks"], target.task_name)


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


def load_state(repo_root: Path) -> dict[str, Any]:
    return {
        "scan_configs": native_object_rows(repo_root, "scan-configs"),
        "port_lists": native_object_rows(repo_root, "port-lists"),
        "scanners": native_object_rows(repo_root, "scanners"),
        "targets": native_object_rows(repo_root, "targets"),
        "tasks": native_object_rows(repo_root, "tasks"),
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
    repo_root: Path,
    state: dict[str, Any],
    target_config: FullTestTarget,
    *,
    operator_name: str = "admin",
) -> tuple[str | None, str | None]:
    target, error = single_named(state["targets"], target_config.target_name)
    if error:
        return None, error
    if target and target.get("id"):
        return target["id"], None
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


def ensure_task(
    repo_root: Path,
    state: dict[str, Any],
    target_config: FullTestTarget,
    target_id: str,
    scanner_id: str,
    *,
    operator_name: str = "admin",
) -> tuple[str | None, str | None]:
    task, error = single_named(state["tasks"], target_config.task_name)
    if error:
        return None, error
    if task and task.get("id"):
        return task["id"], None
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


def command_preflight(artifact_dir: Path, target_config: FullTestTarget, repo_root: Path) -> dict[str, Any]:
    state = load_state(repo_root)
    payload = preflight_state(state, target_config)
    payload["artifacts"] = [write_artifact(artifact_dir, "preflight.json", payload)]
    return payload


def command_start(
    artifact_dir: Path,
    target_config: FullTestTarget,
    confirm_authorized_target: str | None,
    repo_root: Path,
    operator_name: str = "admin",
    poll_seconds: int = 90,
    poll_interval: int = 5,
    ospd_log_file: Path | None = None,
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

    state = load_state(repo_root)
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
    target_id, target_error = ensure_target(repo_root, state, target_config, operator_name=operator_name)
    if target_error or not target_id:
        payload = result("fail", "Full test scan start refused because the target could not be prepared.", error=target_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    state = load_state(repo_root)
    task_id, task_error = ensure_task(repo_root, state, target_config, target_id, scanner_id, operator_name=operator_name)
    if task_error or not task_id:
        payload = result("fail", "Full test scan start refused because the task could not be prepared.", error=task_error, target_id=target_id)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    refreshed = load_state(repo_root)
    active = active_full_test_tasks(refreshed["tasks"], target_config)
    if active:
        payload = result("fail", "Full test scan start refused because a matching task is already active.", active_duplicate_tasks=active)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    pre_start_reports, _ = reports_for_task(repo_root, task_id, rows=20)
    pre_start_report_ids = {report["id"] for report in pre_start_reports if report.get("id")}
    start_error: str | None = None
    report_id: str | None = None
    try:
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
    except Exception as error:  # pylint: disable=broad-except
        start_error = f"{type(error).__name__}: {error}"

    deadline = time.monotonic() + poll_seconds
    observed: dict[str, Any] | None = None
    observed_report: dict[str, str | None] | None = None
    observed_new_report = False
    poll_errors: list[str] = []
    consecutive_poll_errors = 0
    while time.monotonic() <= deadline:
        try:
            task, task_error = current_full_test_task(repo_root, target_config)
            if task_error:
                observed = {"task_lookup_error": task_error}
                break
            if not task:
                observed = {"task_lookup_error": "full test task disappeared after start request"}
                break
            observed = task_status_snapshot(repo_root, task, ospd_log_file=ospd_log_file)
            reports, report_error = reports_for_task(repo_root, task_id, rows=10)
            if report_error:
                raise RuntimeError(report_error)
        except Exception as error:  # pylint: disable=broad-except
            poll_errors.append(f"{type(error).__name__}: {error}")
            observed = {"poll_error": poll_errors[-1], "poll_errors": poll_errors}
            consecutive_poll_errors += 1
            if consecutive_poll_errors >= MAX_CONSECUTIVE_POLL_ERRORS:
                break
            time.sleep(poll_interval)
            continue
        consecutive_poll_errors = 0
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


def command_status(repo_root: Path, artifact_dir: Path, target_config: FullTestTarget, ospd_log_file: Path | None = None) -> dict[str, Any]:
    state = load_state(repo_root)
    task, task_error = single_named(state["tasks"], target_config.task_name)
    if task_error:
        payload = result("fail", "Full test scan status failed because multiple matching tasks exist.", error=task_error)
    elif not task:
        payload = result("warn", "Full test scan task does not exist yet.", target_cidr=target_config.cidr)
    else:
        payload = result("pass", "Full test scan status read.", target_cidr=target_config.cidr, **task_status_snapshot(repo_root, task, ospd_log_file=ospd_log_file))
    payload["artifacts"] = [write_artifact(artifact_dir, "status.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guarded YAFVS full test scan helper")
    parser.add_argument("command", choices=("preflight", "start", "status"))
    parser.add_argument("--operator-name", required=True, help="native API operator name")
    parser.add_argument("--artifact-dir", required=True, help="directory for scan artifacts")
    parser.add_argument("--poll-seconds", type=int, default=90, help="seconds to poll after task start before accepting start state")
    parser.add_argument("--poll-interval", type=int, default=5, help="seconds between post-start status polls")
    parser.add_argument("--ospd-log-file", help="optional OSPD log file used to find scanner handoff evidence")
    parser.add_argument("--repo-root", required=True, help="repository root for native API container access")
    parser.add_argument("--target-cidr", required=True, help="explicit canonical authorized target CIDR; at most 256 addresses")
    parser.add_argument("--confirm-authorized-target", help="required for start; must exactly match --target-cidr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        target_config = parse_full_test_target(args.target_cidr)
        repo_root = Path(args.repo_root)
        if args.command == "preflight":
            payload = command_preflight(Path(args.artifact_dir), target_config, repo_root)
        elif args.command == "start":
            payload = command_start(
                Path(args.artifact_dir),
                target_config,
                args.confirm_authorized_target,
                repo_root,
                operator_name=args.operator_name,
                poll_seconds=args.poll_seconds,
                poll_interval=args.poll_interval,
                ospd_log_file=Path(args.ospd_log_file) if args.ospd_log_file else None,
            )
        else:
            payload = command_status(
                repo_root,
                Path(args.artifact_dir),
                target_config,
                ospd_log_file=Path(args.ospd_log_file) if args.ospd_log_file else None,
            )
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Full test scan helper failed.", error_type=type(error).__name__, error=str(error))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
