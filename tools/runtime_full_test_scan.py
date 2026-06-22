#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guarded GMP command surface for the authorized TurboVAS full test scan."""

from __future__ import annotations

import argparse
import json
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUTHORIZED_TARGET_CIDR = "192.168.178.0/24"
FULL_AND_FAST_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
IANA_TCP_UDP_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
OPENVAS_SCANNER_NAME = "OpenVAS Default"
FULL_TEST_TARGET_NAME = f"TurboVAS full test target {AUTHORIZED_TARGET_CIDR}"
FULL_TEST_TASK_NAME = f"TurboVAS full test scan {AUTHORIZED_TARGET_CIDR}"
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


def reports_for_task(gmp: Any, task_id: str, rows: int = 10) -> tuple[list[dict[str, str | None]], str | None]:
    try:
        response = gmp.get_reports(
            filter_string=f"task_id={task_id} rows={rows} sort-reverse=date",
            details=True,
            ignore_pagination=True,
        )
    except Exception as error:  # pylint: disable=broad-except
        return [], f"{type(error).__name__}: {error}"
    return [row for row in report_rows(response) if row.get("task_id") == task_id], None


def latest_report_for_task(gmp: Any, task_id: str) -> tuple[dict[str, str | None] | None, str | None]:
    reports, error = reports_for_task(gmp, task_id, rows=10)
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


def task_status_snapshot(gmp: Any, task: dict[str, str | None], ospd_log_file: Path | None = None) -> dict[str, Any]:
    reports, report_error = reports_for_task(gmp, task["id"] or "") if task.get("id") else ([], None)
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


def current_full_test_task(gmp: Any) -> tuple[dict[str, str | None] | None, str | None]:
    state = load_state(gmp)
    return single_named(state["tasks"], FULL_TEST_TASK_NAME)


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


def active_full_test_tasks(task_rows: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
    return [row for row in named(task_rows, FULL_TEST_TASK_NAME) if row.get("status") in ACTIVE_TASK_STATUSES]


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


def connect_gmp(socket_path: Path, username: str, password_file: Path, timeout: int):
    if not socket_path.is_socket():
        raise RuntimeError(f"gvmd socket is not ready: {socket_path}")
    if not password_file.is_file():
        raise RuntimeError(f"password file is missing: {password_file}")
    password = password_file.read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError(f"password file is empty: {password_file}")

    from gvm.connections import UnixSocketConnection
    from gvm.protocols.latest import GMP

    connection = UnixSocketConnection(path=socket_path, timeout=timeout)
    gmp = GMP(connection=connection)
    gmp.connect()
    gmp.authenticate(username, password)
    return gmp, password


def load_state(gmp: Any) -> dict[str, Any]:
    return {
        "scan_configs": object_rows(gmp.get_scan_configs(), "config"),
        "port_lists": object_rows(gmp.get_port_lists(), "port_list"),
        "scanners": object_rows(gmp.get_scanners(details=True), "scanner"),
        "targets": object_rows(gmp.get_targets(tasks=True), "target"),
        "tasks": object_rows(gmp.get_tasks(details=True, ignore_pagination=True), "task"),
    }


def preflight_state(state: dict[str, Any]) -> dict[str, Any]:
    scan_config_ok = id_present(state["scan_configs"], FULL_AND_FAST_SCAN_CONFIG_ID)
    port_list_ok = id_present(state["port_lists"], IANA_TCP_UDP_PORT_LIST_ID)
    scanner, scanner_error = single_named(state["scanners"], OPENVAS_SCANNER_NAME)
    target, target_error = single_named(state["targets"], FULL_TEST_TARGET_NAME)
    task, task_error = single_named(state["tasks"], FULL_TEST_TASK_NAME)
    active = active_full_test_tasks(state["tasks"])
    status = "pass" if scan_config_ok and port_list_ok and scanner and not scanner_error and not target_error and not task_error and not active else "fail"
    return result(
        status,
        "Full test scan preflight passed." if status == "pass" else "Full test scan preflight failed.",
        target_cidr=AUTHORIZED_TARGET_CIDR,
        scan_config={"id": FULL_AND_FAST_SCAN_CONFIG_ID, "present": scan_config_ok},
        port_list={"id": IANA_TCP_UDP_PORT_LIST_ID, "present": port_list_ok},
        scanner={"name": OPENVAS_SCANNER_NAME, "id": scanner.get("id") if scanner else None, "error": scanner_error},
        target={"name": FULL_TEST_TARGET_NAME, "id": target.get("id") if target else None, "error": target_error},
        task={"name": FULL_TEST_TASK_NAME, "id": task.get("id") if task else None, "status": task.get("status") if task else None, "error": task_error},
        active_duplicate_tasks=active,
    )


def ensure_target(gmp: Any, state: dict[str, Any]) -> tuple[str | None, str | None]:
    target, error = single_named(state["targets"], FULL_TEST_TARGET_NAME)
    if error:
        return None, error
    if target and target.get("id"):
        return target["id"], None
    response = gmp.create_target(
        FULL_TEST_TARGET_NAME,
        hosts=[AUTHORIZED_TARGET_CIDR],
        port_list_id=IANA_TCP_UDP_PORT_LIST_ID,
        comment="Authorized TurboVAS full test LAN target.",
    )
    target_id = response_id(response)
    if not target_id:
        return None, "Could not parse created target id."
    return target_id, None


def ensure_task(gmp: Any, state: dict[str, Any], target_id: str, scanner_id: str) -> tuple[str | None, str | None]:
    task, error = single_named(state["tasks"], FULL_TEST_TASK_NAME)
    if error:
        return None, error
    if task and task.get("id"):
        return task["id"], None
    response = gmp.create_task(
        FULL_TEST_TASK_NAME,
        FULL_AND_FAST_SCAN_CONFIG_ID,
        target_id,
        scanner_id,
        comment="Authorized TurboVAS full test LAN scan.",
    )
    task_id = response_id(response)
    if not task_id:
        return None, "Could not parse created task id."
    return task_id, None


def command_preflight(gmp: Any, artifact_dir: Path) -> dict[str, Any]:
    state = load_state(gmp)
    payload = preflight_state(state)
    payload["artifacts"] = [write_artifact(artifact_dir, "preflight.json", payload)]
    return payload


def command_start(
    gmp: Any,
    artifact_dir: Path,
    confirm_authorized_lan: bool,
    poll_seconds: int = 90,
    poll_interval: int = 5,
    ospd_log_file: Path | None = None,
    reconnect_gmp: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    if not confirm_authorized_lan:
        payload = result("fail", "Full test scan start refused without --confirm-authorized-lan.", target_cidr=AUTHORIZED_TARGET_CIDR)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    state = load_state(gmp)
    preflight = preflight_state(state)
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
    target_id, target_error = ensure_target(gmp, state)
    if target_error or not target_id:
        payload = result("fail", "Full test scan start refused because the target could not be prepared.", error=target_error)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    state = load_state(gmp)
    task_id, task_error = ensure_task(gmp, state, target_id, scanner_id)
    if task_error or not task_id:
        payload = result("fail", "Full test scan start refused because the task could not be prepared.", error=task_error, target_id=target_id)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    refreshed = load_state(gmp)
    active = active_full_test_tasks(refreshed["tasks"])
    if active:
        payload = result("fail", "Full test scan start refused because a matching task is already active.", active_duplicate_tasks=active)
        payload["artifacts"] = [write_artifact(artifact_dir, "start-refused.json", payload)]
        return payload

    pre_start_reports, _ = reports_for_task(gmp, task_id, rows=20)
    pre_start_report_ids = {report["id"] for report in pre_start_reports if report.get("id")}
    start_error: str | None = None
    report_id: str | None = None
    try:
        start_response = gmp.start_task(task_id)
        report_id = response_id(start_response)
    except Exception as error:  # pylint: disable=broad-except
        start_error = f"{type(error).__name__}: {error}"
        if reconnect_gmp is not None:
            try:
                gmp = reconnect_gmp()
            except Exception as reconnect_error:  # pylint: disable=broad-except
                start_error = f"{start_error}; reconnect failed: {type(reconnect_error).__name__}: {reconnect_error}"

    deadline = time.monotonic() + poll_seconds
    observed: dict[str, Any] | None = None
    observed_report: dict[str, str | None] | None = None
    poll_errors: list[str] = []
    while time.monotonic() <= deadline:
        try:
            task, task_error = current_full_test_task(gmp)
            if task_error:
                observed = {"task_lookup_error": task_error}
                break
            if not task:
                observed = {"task_lookup_error": "full test task disappeared after start request"}
                break
            observed = task_status_snapshot(gmp, task, ospd_log_file=ospd_log_file)
            reports, _ = reports_for_task(gmp, task_id, rows=10)
        except Exception as error:  # pylint: disable=broad-except
            poll_errors.append(f"{type(error).__name__}: {error}")
            if reconnect_gmp is not None:
                try:
                    gmp = reconnect_gmp()
                    continue
                except Exception as reconnect_error:  # pylint: disable=broad-except
                    poll_errors.append(f"reconnect failed: {type(reconnect_error).__name__}: {reconnect_error}")
            observed = {"poll_error": poll_errors[-1], "poll_errors": poll_errors}
            break
        new_reports = [report for report in reports if report.get("id") and report["id"] not in pre_start_report_ids]
        if report_id:
            observed_report = next((report for report in reports if report.get("id") == report_id), None)
        else:
            observed_report = new_reports[0] if new_reports else (reports[0] if start_error is None and reports else None)
        evidence = observed.get("ospd_handoff_evidence", {})
        if interrupted_before_scanner_handoff(observed_report):
            break
        if task.get("status") in HANDOFF_TASK_STATUSES or report_handoff_observed(observed_report) or evidence.get("matched"):
            break
        if task.get("status") in HANDOFF_TASK_STATUSES and report_id and observed_report and observed_report.get("scan_run_status") != INTERRUPTED_REPORT_STATUS:
            break
        time.sleep(poll_interval)

    interrupted_before_handoff = interrupted_before_scanner_handoff(observed_report)
    handoff_evidence = observed.get("ospd_handoff_evidence", {}) if observed else {}
    handoff_observed = bool(
        observed
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
    elif start_error and not handoff_observed:
        status = "fail"
        summary = "Full test scan start failed before scanner handoff could be verified."
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
        target_cidr=AUTHORIZED_TARGET_CIDR,
        target_id=target_id,
        task_id=task_id,
        report_id=report_id,
        observed_report=observed_report,
        observed_state=observed,
        poll_errors=poll_errors,
        pre_start_report_ids=sorted(pre_start_report_ids),
        start_error=start_error,
        poll_seconds=poll_seconds,
        poll_interval=poll_interval,
        scan_config_id=FULL_AND_FAST_SCAN_CONFIG_ID,
        port_list_id=IANA_TCP_UDP_PORT_LIST_ID,
        scanner_id=scanner_id,
    )
    payload["artifacts"] = [write_artifact(artifact_dir, artifact_name, payload)]
    return payload


def command_status(gmp: Any, artifact_dir: Path, ospd_log_file: Path | None = None) -> dict[str, Any]:
    state = load_state(gmp)
    task, task_error = single_named(state["tasks"], FULL_TEST_TASK_NAME)
    if task_error:
        payload = result("fail", "Full test scan status failed because multiple matching tasks exist.", error=task_error)
    elif not task:
        payload = result("warn", "Full test scan task does not exist yet.", target_cidr=AUTHORIZED_TARGET_CIDR)
    else:
        payload = result("pass", "Full test scan status read.", target_cidr=AUTHORIZED_TARGET_CIDR, **task_status_snapshot(gmp, task, ospd_log_file=ospd_log_file))
    payload["artifacts"] = [write_artifact(artifact_dir, "status.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guarded TurboVAS full test scan helper")
    parser.add_argument("command", choices=("preflight", "start", "status"))
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for scan artifacts")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    parser.add_argument("--poll-seconds", type=int, default=90, help="seconds to poll after start_task before accepting start state")
    parser.add_argument("--poll-interval", type=int, default=5, help="seconds between post-start status polls")
    parser.add_argument("--ospd-log-file", help="optional OSPD log file used to find scanner handoff evidence")
    parser.add_argument("--confirm-authorized-lan", action="store_true", help="required for start; confirms authorization for 192.168.178.0/24")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    gmp_connections = []

    def open_gmp_connection():
        nonlocal password
        gmp_connection, password = connect_gmp(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        gmp_connections.append(gmp_connection)
        return gmp_connection

    try:
        gmp = open_gmp_connection()
        if args.command == "preflight":
            payload = command_preflight(gmp, Path(args.artifact_dir))
        elif args.command == "start":
            payload = command_start(
                gmp,
                Path(args.artifact_dir),
                args.confirm_authorized_lan,
                poll_seconds=args.poll_seconds,
                poll_interval=args.poll_interval,
                ospd_log_file=Path(args.ospd_log_file) if args.ospd_log_file else None,
                reconnect_gmp=open_gmp_connection,
            )
        else:
            payload = command_status(gmp, Path(args.artifact_dir), ospd_log_file=Path(args.ospd_log_file) if args.ospd_log_file else None)
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Full test scan helper failed.", error_type=type(error).__name__, error=str(error).replace(password, "[redacted]"))
    finally:
        for gmp in reversed(gmp_connections):
            try:
                gmp.disconnect()
            except Exception:
                pass
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
