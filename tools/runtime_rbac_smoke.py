#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify YAFVS operator-account semantics over GMP without starting scans."""

from __future__ import annotations

import argparse
import json
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr

import runtime_full_test_scan

SECONDARY_USER = "yafvs-rbac-smoke"
TEMP_FILTER_PREFIX = "YAFVS RBAC smoke filter"


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


def xml_text_element(name: str, value: str) -> str:
    return f"<{name}>{escape(value)}</{name}>"


def xml_bool(value: bool | None) -> str:
    return "1" if value else "0"


def require_ok_response(response: Any, action: str) -> Any:
    root_node = response_root(response)
    if root_node is None:
        raise RuntimeError(f"{action} returned an unparsable GMP response")
    status = root_node.get("status")
    if status and not status.startswith("2"):
        status_text = root_node.get("status_text") or ""
        raise RuntimeError(f"{action} failed with GMP status {status}: {status_text}")
    return response


class RbacGmpClient(runtime_full_test_scan.RawGmpClient):
    """Tiny raw GMP subset for the operator-account runtime smoke."""

    def get_users(self, *, filter_string: str | None = None) -> bytes:
        attributes = f" filter={quoteattr(filter_string)}" if filter_string else ""
        return self.send_xml(f"<get_users{attributes}/>")

    def create_user(self, name: str, *, password: str | None = None) -> bytes:
        body = xml_text_element("name", name)
        if password:
            body += xml_text_element("password", password)
        return self.send_xml(f"<create_user>{body}</create_user>")

    def modify_user(
        self,
        user_id: str,
        *,
        name: str | None = None,
        password: str | None = None,
        comment: str | None = None,
    ) -> bytes:
        body = ""
        if name:
            body += xml_text_element("new_name", name)
        if comment:
            body += xml_text_element("comment", comment)
        if password:
            body += xml_text_element("password", password)
        return self.send_xml(f"<modify_user user_id={quoteattr(user_id)}>{body}</modify_user>")

    def get_tasks(
        self,
        *,
        details: bool | None = None,
        ignore_pagination: bool | None = None,
    ) -> bytes:
        attributes = " usage_type=\"scan\""
        if details is not None:
            attributes += f" details={quoteattr(xml_bool(details))}"
        if ignore_pagination is not None:
            attributes += f" ignore_pagination={quoteattr(xml_bool(ignore_pagination))}"
        return self.send_xml(f"<get_tasks{attributes}/>")

    def get_reports(
        self,
        *,
        filter_string: str | None = None,
        details: bool | None = None,
        ignore_pagination: bool | None = None,
    ) -> bytes:
        attributes = " usage_type=\"scan\""
        if filter_string:
            attributes += f" report_filter={quoteattr(filter_string)}"
        if details is not None:
            attributes += f" details={quoteattr(xml_bool(details))}"
        if ignore_pagination is not None:
            attributes += f" ignore_pagination={quoteattr(xml_bool(ignore_pagination))}"
        return self.send_xml(f"<get_reports{attributes}/>")

    def create_filter(
        self,
        name: str,
        *,
        filter_type: str | None = None,
        term: str | None = None,
        comment: str | None = None,
    ) -> bytes:
        body = xml_text_element("name", name)
        if comment:
            body += xml_text_element("comment", comment)
        if term:
            body += xml_text_element("term", term)
        if filter_type:
            body += xml_text_element("type", filter_type)
        return self.send_xml(f"<create_filter>{body}</create_filter>")

    def modify_filter(
        self,
        filter_id: str,
        *,
        name: str | None = None,
        term: str | None = None,
        filter_type: str | None = None,
        comment: str | None = None,
    ) -> bytes:
        body = ""
        if comment:
            body += xml_text_element("comment", comment)
        if name:
            body += xml_text_element("name", name)
        if term:
            body += xml_text_element("term", term)
        if filter_type:
            body += xml_text_element("type", filter_type)
        return self.send_xml(f"<modify_filter filter_id={quoteattr(filter_id)}>{body}</modify_filter>")

    def delete_filter(self, filter_id: str, *, ultimate: bool | None = False) -> bytes:
        return self.send_xml(
            f"<delete_filter filter_id={quoteattr(filter_id)} ultimate={quoteattr(xml_bool(ultimate))}/>"
        )


def named_row(client: Any, object_tag: str, getter_name: str, name: str) -> dict[str, str | None] | None:
    getter = getattr(client, getter_name)
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
    client = RbacGmpClient(socket_path, username, password, timeout)
    client.connect()
    return client


def ensure_secondary_user(admin_client: Any, password: str) -> dict[str, Any]:
    existing = named_row(admin_client, "user", "get_users", SECONDARY_USER)
    action = "reused"
    if existing is None:
        response = require_ok_response(admin_client.create_user(SECONDARY_USER, password=password), "create secondary user")
        user_id = runtime_full_test_scan.response_id(response)
        action = "created"
    else:
        user_id = existing.get("id")
        require_ok_response(
            admin_client.modify_user(
                user_id,
                name=SECONDARY_USER,
                password=password,
                comment="YAFVS RBAC smoke secondary operator",
            ),
            "modify secondary user",
        )
    if not user_id:
        refreshed = named_row(admin_client, "user", "get_users", SECONDARY_USER)
        user_id = refreshed.get("id") if refreshed else None
    if not user_id:
        raise RuntimeError("Could not determine secondary smoke user id")
    return {"id": user_id, "name": SECONDARY_USER, "action": action}


def verify_full_test_visibility(client: Any) -> dict[str, Any]:
    task_rows = runtime_full_test_scan.object_rows(client.get_tasks(details=True, ignore_pagination=True), "task")
    task, task_error = runtime_full_test_scan.single_named(
        task_rows, runtime_full_test_scan.FULL_TEST_TASK_NAME
    )
    if task_error:
        return {"status": "fail", "task_error": task_error, "task": None, "latest_report": None}
    if not task or not task.get("id"):
        return {"status": "fail", "task_error": "Full-test task is not visible.", "task": task, "latest_report": None}
    latest_report, report_error = runtime_full_test_scan.latest_report_for_task(client, task["id"])
    if report_error or latest_report is None:
        return {"status": "fail", "task_error": None, "task": task, "latest_report": latest_report, "report_error": report_error or "Latest full-test report is not visible."}
    return {"status": "pass", "task_error": None, "task": task, "latest_report": latest_report, "report_error": None}


def verify_cross_user_filter_admin(admin_client: Any, secondary_client: Any) -> dict[str, Any]:
    filter_name = f"{TEMP_FILTER_PREFIX} {secrets.token_hex(4)}"
    modified_name = filter_name + " modified"
    filter_id: str | None = None
    deleted_by_secondary = False
    admin_cleanup = None
    try:
        response = require_ok_response(
            admin_client.create_filter(
                filter_name,
                filter_type="task",
                term="rows=1",
                comment="Temporary filter created by runtime-rbac-smoke.",
            ),
            "create temporary filter",
        )
        filter_id = runtime_full_test_scan.response_id(response)
        if not filter_id:
            raise RuntimeError("Could not parse created filter id")
        require_ok_response(
            secondary_client.modify_filter(
                filter_id,
                name=modified_name,
                term="rows=2",
                filter_type="task",
                comment="Modified by the secondary runtime-rbac-smoke account.",
            ),
            "modify temporary filter as secondary user",
        )
        require_ok_response(secondary_client.delete_filter(filter_id, ultimate=True), "delete temporary filter as secondary user")
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
                require_ok_response(admin_client.delete_filter(filter_id, ultimate=True), "admin cleanup temporary filter")
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
    parser = argparse.ArgumentParser(description="Verify YAFVS operator-account semantics over GMP")
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
    admin_client = None
    secondary_client = None
    try:
        if not password_path.is_file():
            raise RuntimeError(f"admin password file is missing: {password_path}")
        admin_password = password_path.read_text(encoding="utf-8").strip()
        if not admin_password:
            raise RuntimeError(f"admin password file is empty: {password_path}")
        admin_client = connect_with_password(socket_path, args.username, admin_password, args.timeout)
        secondary_user = ensure_secondary_user(admin_client, secondary_password)
        secondary_client = connect_with_password(socket_path, SECONDARY_USER, secondary_password, args.timeout)
        visibility = verify_full_test_visibility(secondary_client)
        filter_admin = verify_cross_user_filter_admin(admin_client, secondary_client)
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
        for client in (secondary_client, admin_client):
            if client is not None:
                try:
                    client.disconnect()
                except Exception:
                    pass
    payload["artifacts"] = [write_artifact(artifact_dir, payload)]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
