#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guarded GMP command surface for the authorized TurboVAS full test scan."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
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


def response_id(response: Any) -> str | None:
    root = response_root(response)
    if root is None:
        return None
    if root.get("id"):
        return root.get("id")
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


def command_start(gmp: Any, artifact_dir: Path, confirm_authorized_lan: bool) -> dict[str, Any]:
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

    start_response = gmp.start_task(task_id)
    report_id = response_id(start_response)
    payload = result(
        "pass",
        "Full test scan started.",
        target_cidr=AUTHORIZED_TARGET_CIDR,
        target_id=target_id,
        task_id=task_id,
        report_id=report_id,
        scan_config_id=FULL_AND_FAST_SCAN_CONFIG_ID,
        port_list_id=IANA_TCP_UDP_PORT_LIST_ID,
        scanner_id=scanner_id,
    )
    payload["artifacts"] = [write_artifact(artifact_dir, "start.json", payload)]
    return payload


def command_status(gmp: Any, artifact_dir: Path) -> dict[str, Any]:
    state = load_state(gmp)
    task, task_error = single_named(state["tasks"], FULL_TEST_TASK_NAME)
    if task_error:
        payload = result("fail", "Full test scan status failed because multiple matching tasks exist.", error=task_error)
    elif not task:
        payload = result("warn", "Full test scan task does not exist yet.", target_cidr=AUTHORIZED_TARGET_CIDR)
    else:
        payload = result("pass", "Full test scan status read.", target_cidr=AUTHORIZED_TARGET_CIDR, task=task)
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
    parser.add_argument("--confirm-authorized-lan", action="store_true", help="required for start; confirms authorization for 192.168.178.0/24")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    gmp = None
    try:
        gmp, password = connect_gmp(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        if args.command == "preflight":
            payload = command_preflight(gmp, Path(args.artifact_dir))
        elif args.command == "start":
            payload = command_start(gmp, Path(args.artifact_dir), args.confirm_authorized_lan)
        else:
            payload = command_status(gmp, Path(args.artifact_dir))
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Full test scan helper failed.", error_type=type(error).__name__, error=str(error).replace(password, "[redacted]"))
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
