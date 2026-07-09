#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify TurboVAS operator-account semantics over GMP without starting scans."""

from __future__ import annotations

import argparse
import json
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import runtime_full_test_scan

SECONDARY_USER = "turbovas-rbac-smoke"
TEMP_FILTER_PREFIX = "TurboVAS RBAC smoke filter"


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


def object_rows(response: Any, object_tag: str) -> list[dict[str, str | None]]:
    root_node = response_root(response)
    if root_node is None or not hasattr(root_node, "iter"):
        return []
    rows: list[dict[str, str | None]] = []
    for element in root_node.iter():
        if local_name(str(element.tag)) != object_tag:
            continue
        rows.append(
            {
                "id": element.get("id"),
                "name": runtime_full_test_scan.child_text(element, "name"),
                "status": runtime_full_test_scan.child_text(element, "status"),
                "owner": runtime_full_test_scan.child_path_text(element, ("owner", "name")),
            }
        )
    return rows


def named_row(gmp: Any, object_tag: str, getter_name: str, name: str) -> dict[str, str | None] | None:
    getter = getattr(gmp, getter_name)
    try:
        response = getter(filter_string=f"name={name}")
    except TypeError:
        response = getter()
    for row in object_rows(response, object_tag):
        if row.get("name") == name:
            return row
    return None


def connect_with_password(socket_path: Path, username: str, password: str, timeout: int):
    if not socket_path.is_socket():
        raise RuntimeError(f"gvmd socket is not ready: {socket_path}")

    from gvm.connections import UnixSocketConnection
    from gvm.protocols.latest import GMP

    connection = UnixSocketConnection(path=socket_path, timeout=timeout)
    gmp = GMP(connection=connection)
    gmp.connect()
    gmp.authenticate(username, password)
    return gmp


def ensure_secondary_user(admin_gmp: Any, password: str) -> dict[str, Any]:
    existing = named_row(admin_gmp, "user", "get_users", SECONDARY_USER)
    action = "reused"
    if existing is None:
        response = admin_gmp.create_user(SECONDARY_USER, password=password)
        user_id = runtime_full_test_scan.response_id(response)
        action = "created"
    else:
        user_id = existing.get("id")
        admin_gmp.modify_user(user_id, name=SECONDARY_USER, password=password, comment="TurboVAS RBAC smoke secondary operator")
    if not user_id:
        refreshed = named_row(admin_gmp, "user", "get_users", SECONDARY_USER)
        user_id = refreshed.get("id") if refreshed else None
    if not user_id:
        raise RuntimeError("Could not determine secondary smoke user id")
    return {"id": user_id, "name": SECONDARY_USER, "action": action}


def verify_full_test_visibility(gmp: Any) -> dict[str, Any]:
    state = runtime_full_test_scan.load_state(gmp)
    task, task_error = runtime_full_test_scan.single_named(
        state["tasks"], runtime_full_test_scan.FULL_TEST_TASK_NAME
    )
    if task_error:
        return {"status": "fail", "task_error": task_error, "task": None, "latest_report": None}
    if not task or not task.get("id"):
        return {"status": "fail", "task_error": "Full-test task is not visible.", "task": task, "latest_report": None}
    latest_report, report_error = runtime_full_test_scan.latest_report_for_task(gmp, task["id"])
    if report_error or latest_report is None:
        return {"status": "fail", "task_error": None, "task": task, "latest_report": latest_report, "report_error": report_error or "Latest full-test report is not visible."}
    return {"status": "pass", "task_error": None, "task": task, "latest_report": latest_report, "report_error": None}


def verify_cross_user_filter_admin(admin_gmp: Any, secondary_gmp: Any) -> dict[str, Any]:
    filter_name = f"{TEMP_FILTER_PREFIX} {secrets.token_hex(4)}"
    modified_name = filter_name + " modified"
    filter_id: str | None = None
    deleted_by_secondary = False
    admin_cleanup = None
    try:
        response = admin_gmp.create_filter(
            filter_name,
            filter_type="task",
            term="rows=1",
            comment="Temporary filter created by runtime-rbac-smoke.",
        )
        filter_id = runtime_full_test_scan.response_id(response)
        if not filter_id:
            raise RuntimeError("Could not parse created filter id")
        secondary_gmp.modify_filter(
            filter_id,
            name=modified_name,
            term="rows=2",
            filter_type="task",
            comment="Modified by the secondary runtime-rbac-smoke account.",
        )
        secondary_gmp.delete_filter(filter_id, ultimate=True)
        deleted_by_secondary = True
        return {
            "status": "pass",
            "filter_id": filter_id,
            "created_by": "admin",
            "modified_by": SECONDARY_USER,
            "deleted_by_secondary": deleted_by_secondary,
            "admin_cleanup": admin_cleanup,
        }
    except Exception as error:  # pylint: disable=broad-except
        if filter_id and not deleted_by_secondary:
            try:
                admin_gmp.delete_filter(filter_id, ultimate=True)
                admin_cleanup = "deleted"
            except Exception as cleanup_error:  # pylint: disable=broad-except
                admin_cleanup = f"failed: {type(cleanup_error).__name__}: {cleanup_error}"
        return {
            "status": "fail",
            "filter_id": filter_id,
            "created_by": "admin" if filter_id else None,
            "modified_by": SECONDARY_USER if filter_id else None,
            "deleted_by_secondary": deleted_by_secondary,
            "admin_cleanup": admin_cleanup,
            "error_type": type(error).__name__,
            "error": str(error),
        }


def write_artifact(artifact_dir: Path, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / "rbac-smoke.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify TurboVAS operator-account semantics over GMP")
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="admin GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the admin GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for smoke artifacts")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    socket_path = Path(args.socket)
    password_path = Path(args.password_file)
    artifact_dir = Path(args.artifact_dir)
    admin_password = ""
    secondary_password = secrets.token_urlsafe(24)
    admin_gmp = None
    secondary_gmp = None
    try:
        if not password_path.is_file():
            raise RuntimeError(f"admin password file is missing: {password_path}")
        admin_password = password_path.read_text(encoding="utf-8").strip()
        if not admin_password:
            raise RuntimeError(f"admin password file is empty: {password_path}")
        admin_gmp = connect_with_password(socket_path, args.username, admin_password, args.timeout)
        secondary_user = ensure_secondary_user(admin_gmp, secondary_password)
        secondary_gmp = connect_with_password(socket_path, SECONDARY_USER, secondary_password, args.timeout)
        visibility = verify_full_test_visibility(secondary_gmp)
        filter_admin = verify_cross_user_filter_admin(admin_gmp, secondary_gmp)
        status = "pass" if visibility["status"] == "pass" and filter_admin["status"] == "pass" else "fail"
        payload = result(
            status,
            "Runtime RBAC smoke passed for the operator-account model." if status == "pass" else "Runtime RBAC smoke failed for the operator-account model.",
            secondary_user=secondary_user,
            full_test_visibility=visibility,
            cross_user_filter_admin=filter_admin,
            scans_started=0,
        )
    except Exception as error:  # pylint: disable=broad-except
        error_text = str(error)
        for secret in (admin_password, secondary_password):
            if secret:
                error_text = error_text.replace(secret, "[redacted]")
        payload = result(
            "fail",
            "Runtime RBAC smoke helper failed.",
            error_type=type(error).__name__,
            error=error_text,
            scans_started=0,
        )
    finally:
        for gmp in (secondary_gmp, admin_gmp):
            if gmp is not None:
                try:
                    gmp.disconnect()
                except Exception:
                    pass
    payload["artifacts"] = [write_artifact(artifact_dir, payload)]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
