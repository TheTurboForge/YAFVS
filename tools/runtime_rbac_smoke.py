#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify YAFVS operator-account semantics over GMP without starting scans."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from xml.sax.saxutils import escape, quoteattr

from runtime_gmp_smoke import gmp_authenticate_xml, send_gmp_xml_command

SECONDARY_USER = "yafvs-rbac-smoke"
TEMP_FILTER_PREFIX = "YAFVS RBAC smoke filter"
TEMP_TARGET_PREFIX = "YAFVS RBAC smoke target"
TEMP_TASK_PREFIX = "YAFVS RBAC smoke task"
FULL_TEST_TASK_PREFIXES = ("YAFVS full test scan ", "TurboVAS full test scan ")


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


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


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


def latest_report_for_task(
    client: Any, task_id: str
) -> tuple[dict[str, str | None] | None, str | None]:
    try:
        response = client.get_reports(
            filter_string=f"task_id={task_id} rows=10 sort-reverse=date",
            details=True,
            ignore_pagination=True,
        )
    except Exception as error:  # pylint: disable=broad-except
        return None, f"{type(error).__name__}: {error}"
    reports = [row for row in report_rows(response) if row.get("task_id") == task_id]
    return (reports[0] if reports else None), None


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


class RawGmpClient:
    """Minimal raw GMP connection retained only for RBAC characterization."""

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

    def disconnect(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None


class RbacGmpClient(RawGmpClient):
    """Tiny raw GMP subset for the operator-account runtime smoke."""

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

    def delete_task(self, task_id: str, *, ultimate: bool | None = False) -> bytes:
        return self.send_xml(
            f"<delete_task task_id={quoteattr(task_id)} ultimate={quoteattr(xml_bool(ultimate))}/>"
        )


class NativeBrowserClient:
    """Small same-origin native API client for operator-model checks."""

    def __init__(self, base_url: str, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = ""
        cookie_jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar),
            urllib.request.HTTPSHandler(context=context),
        )

    def login(self, username: str, password: str) -> None:
        boundary = f"YAFVS-{secrets.token_hex(16)}"
        parts = []
        for name, value in (("login", username), ("password", password)):
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                f"\r\n\r\n{value}\r\n".encode()
            )
        parts.append(f"--{boundary}--\r\n".encode())
        request = urllib.request.Request(
            f"{self.base_url}/login",
            data=b"".join(parts),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                root = ET.fromstring(response.read())
        except (OSError, ET.ParseError, urllib.error.URLError) as error:
            raise RuntimeError("Native API login failed") from error
        token = root.findtext("token") or ""
        if not token:
            raise RuntimeError("Native API login returned no session token")
        self.token = token

    def request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        query: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if not self.token:
            raise RuntimeError("Native API request requires an authenticated session")
        parameters = dict(query or {})
        parameters["token"] = self.token
        url = f"{self.base_url}/api/v1/{path.lstrip('/')}?{urllib.parse.urlencode(parameters)}"
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Accept": "application/json", "X-YAFVS-Token": self.token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                response_body = response.read()
        except urllib.error.HTTPError as error:
            response_body = error.read()
            detail = ""
            try:
                problem = json.loads(response_body)
                if isinstance(problem, dict):
                    code = problem.get("error")
                    message = problem.get("message")
                    if isinstance(code, str) and isinstance(message, str):
                        detail = f": {code}: {message}"
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            raise RuntimeError(
                f"Native API request failed with status {error.code}{detail}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError("Native API request failed") from error
        if not response_body:
            return {}
        try:
            decoded = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Native API returned invalid JSON") from error
        if not isinstance(decoded, dict):
            raise RuntimeError("Native API returned an invalid response shape")
        return decoded


def connect_with_password(socket_path: Path, username: str, password: str, timeout: int):
    if not socket_path.is_socket():
        raise RuntimeError(f"gvmd socket is not ready: {socket_path}")
    client = RbacGmpClient(socket_path, username, password, timeout)
    client.connect()
    return client


def ensure_secondary_user(admin_client: NativeBrowserClient, password: str) -> dict[str, Any]:
    collection = admin_client.request_json(
        "GET",
        "user-management/users",
        query={"page": "1", "page_size": "500", "sort": "name", "filter": ""},
    )
    existing = next(
        (
            item
            for item in collection.get("items", [])
            if isinstance(item, dict) and item.get("name") == SECONDARY_USER
        ),
        None,
    )
    payload = {
        "name": SECONDARY_USER,
        "comment": "YAFVS RBAC smoke secondary operator",
        "auth_method": "password",
        "password": password,
    }
    action = "reused"
    if existing is None:
        response = admin_client.request_json(
            "POST", "user-management/users", payload=payload
        )
        user_id = response.get("id")
        action = "created"
    else:
        user_id = existing.get("id")
        if not isinstance(user_id, str) or not user_id:
            raise RuntimeError("Existing secondary smoke user has no id")
        response = admin_client.request_json(
            "PATCH", f"user-management/users/{user_id}", payload=payload
        )
        user_id = response.get("id", user_id)
    if not user_id:
        raise RuntimeError("Could not determine secondary smoke user id")
    return {"id": user_id, "name": SECONDARY_USER, "action": action}


def verify_full_test_visibility(client: Any) -> dict[str, Any]:
    task_rows = object_rows(client.get_tasks(details=True, ignore_pagination=True), "task")
    candidates = sorted(
        (
            task
            for task in task_rows
            if (task.get("name") or "").startswith(FULL_TEST_TASK_PREFIXES)
            and task.get("id")
        ),
        key=lambda task: task.get("name") or "",
    )
    if not candidates:
        return {
            "status": "fail",
            "task_error": "No authorized full-test task is visible.",
            "task": None,
            "latest_report": None,
        }
    report_errors = []
    for task in candidates:
        latest_report, report_error = latest_report_for_task(client, task["id"])
        if latest_report is not None and report_error is None:
            return {
                "status": "pass",
                "task_error": None,
                "task": task,
                "latest_report": latest_report,
                "report_error": None,
            }
        report_errors.append(report_error or "Latest full-test report is not visible.")
    return {
        "status": "fail",
        "task_error": None,
        "task": candidates[0],
        "latest_report": None,
        "report_error": "; ".join(report_errors),
    }


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
        filter_id = response_id(response)
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


def verify_native_cross_user_filter_admin(
    admin_client: NativeBrowserClient,
    secondary_client: NativeBrowserClient,
) -> dict[str, Any]:
    """Prove that native filter ownership is attribution, not team isolation."""
    filter_name = f"{TEMP_FILTER_PREFIX} native {secrets.token_hex(4)}"
    modified_name = filter_name + " modified"
    filter_id: str | None = None
    lifecycle_state = "not-created"
    admin_cleanup = None
    try:
        created = admin_client.request_json(
            "POST",
            "filters",
            payload={
                "name": filter_name,
                "filter_type": "task",
                "term": "rows=1",
                "comment": "Temporary native filter created by runtime-rbac-smoke.",
            },
        )
        filter_id = created.get("id")
        if not isinstance(filter_id, str) or not filter_id:
            raise RuntimeError("Native filter create returned no id")
        lifecycle_state = "live"
        secondary_client.request_json(
            "PATCH",
            f"filters/{filter_id}",
            payload={
                "name": modified_name,
                "term": "rows=2",
                "comment": "Modified by the secondary runtime-rbac-smoke account.",
            },
        )
        secondary_client.request_json("DELETE", f"filters/{filter_id}")
        lifecycle_state = "trash"
        secondary_client.request_json("DELETE", f"filters/{filter_id}/trash")
        lifecycle_state = "deleted"
        return {
            "status": "pass",
            "filter_id": filter_id,
            "created_by": "admin",
            "modified_by": SECONDARY_USER,
            "deleted_by_secondary": True,
            "admin_cleanup": admin_cleanup,
        }
    except Exception as error:  # pylint: disable=broad-except
        if filter_id and lifecycle_state != "deleted":
            try:
                if lifecycle_state == "live":
                    admin_client.request_json("DELETE", f"filters/{filter_id}")
                admin_client.request_json("DELETE", f"filters/{filter_id}/trash")
                admin_cleanup = "deleted"
            except Exception as cleanup_error:  # pylint: disable=broad-except
                admin_cleanup = (
                    f"failed: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        return {
            "status": "fail",
            "filter_id": filter_id,
            "created_by": "admin" if filter_id else None,
            "modified_by": SECONDARY_USER if filter_id else None,
            "deleted_by_secondary": False,
            "admin_cleanup": admin_cleanup,
            "error_type": type(error).__name__,
            "error": str(error),
        }


def first_native_resource_id(
    client: NativeBrowserClient,
    path: str,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
) -> str:
    collection = client.request_json(
        "GET",
        path,
        query={"page": "1", "page_size": "500", "sort": "name", "filter": ""},
    )
    for item in collection.get("items", []):
        if (
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and item["id"]
            and (predicate is None or predicate(item))
        ):
            return item["id"]
    raise RuntimeError(f"Native {path} collection contains no assignable resource")


def verify_native_cross_user_target_task_admin(
    admin_client: NativeBrowserClient,
    secondary_client: NativeBrowserClient,
    secondary_gmp_client: RbacGmpClient,
) -> dict[str, Any]:
    """Prove target/task team authority without starting a scan."""
    suffix = secrets.token_hex(4)
    target_id: str | None = None
    task_id: str | None = None
    target_state = "absent"
    task_state = "absent"
    try:
        port_list_id = first_native_resource_id(admin_client, "port-lists")
        config_id = first_native_resource_id(admin_client, "scan-configs")
        scanner_id = first_native_resource_id(
            admin_client,
            "scanners",
            lambda item: item.get("scanner_type") in (2, 5, 6, 8),
        )
        target = admin_client.request_json(
            "POST",
            "targets",
            payload={
                "name": f"{TEMP_TARGET_PREFIX} {suffix}",
                "comment": "Temporary target created by runtime-rbac-smoke.",
                "alive_tests": ["Consider Alive"],
                "allow_simultaneous_ips": False,
                "reverse_lookup_only": False,
                "reverse_lookup_unify": False,
                "port_list_id": port_list_id,
                "hosts": ["127.0.0.1"],
                "exclude_hosts": [],
            },
        )
        target_id = target.get("id")
        if not isinstance(target_id, str) or not target_id:
            raise RuntimeError("Native target create returned no id")
        target_state = "live"

        task = secondary_client.request_json(
            "POST",
            "tasks",
            payload={
                "name": f"{TEMP_TASK_PREFIX} {suffix}",
                "comment": "Temporary task created by runtime-rbac-smoke.",
                "target_id": target_id,
                "config_id": config_id,
                "scanner_id": scanner_id,
            },
        )
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise RuntimeError("Native task create returned no id")
        task_state = "live"

        admin_client.request_json(
            "PATCH",
            f"tasks/{task_id}",
            payload={"comment": "Modified by the admin runtime-rbac-smoke account."},
        )
        admin_client.request_json("DELETE", f"tasks/{task_id}")
        task_state = "trash"
        require_ok_response(
            secondary_gmp_client.delete_task(task_id, ultimate=True),
            "hard-delete temporary task as secondary user",
        )
        task_state = "deleted"

        secondary_client.request_json(
            "PATCH",
            f"targets/{target_id}",
            payload={"comment": "Modified by the secondary runtime-rbac-smoke account."},
        )
        secondary_client.request_json("DELETE", f"targets/{target_id}")
        target_state = "trash"
        secondary_client.request_json("POST", f"targets/{target_id}/restore")
        target_state = "live"
        secondary_client.request_json("DELETE", f"targets/{target_id}")
        target_state = "trash"
        secondary_client.request_json("DELETE", f"targets/{target_id}/trash")
        target_state = "deleted"

        return {
            "status": "pass",
            "target_id": target_id,
            "task_id": task_id,
            "target_created_by": "admin",
            "task_created_by": SECONDARY_USER,
            "task_modified_and_deleted_by": "admin",
            "target_modified_and_deleted_by": SECONDARY_USER,
            "scans_started": 0,
        }
    except Exception as error:  # pylint: disable=broad-except
        if task_id and task_state != "deleted":
            try:
                require_ok_response(
                    secondary_gmp_client.delete_task(task_id, ultimate=True),
                    "cleanup temporary task",
                )
            except Exception:
                pass
        if target_id and target_state != "deleted":
            try:
                if target_state == "live":
                    admin_client.request_json("DELETE", f"targets/{target_id}")
                admin_client.request_json("DELETE", f"targets/{target_id}/trash")
            except Exception:
                pass
        return {
            "status": "fail",
            "target_id": target_id,
            "target_state": target_state,
            "task_id": task_id,
            "task_state": task_state,
            "error_type": type(error).__name__,
            "error": str(error),
            "scans_started": 0,
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
    parser.add_argument("--base-url", required=True, help="development GSA base URL")
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
        native_admin = NativeBrowserClient(args.base_url, args.timeout)
        native_admin.login(args.username, admin_password)
        secondary_user = ensure_secondary_user(native_admin, secondary_password)
        native_secondary = NativeBrowserClient(args.base_url, args.timeout)
        native_secondary.login(SECONDARY_USER, secondary_password)
        admin_client = connect_with_password(socket_path, args.username, admin_password, args.timeout)
        secondary_client = connect_with_password(socket_path, SECONDARY_USER, secondary_password, args.timeout)
        visibility = verify_full_test_visibility(secondary_client)
        filter_admin = verify_cross_user_filter_admin(admin_client, secondary_client)
        native_filter_admin = verify_native_cross_user_filter_admin(
            native_admin, native_secondary
        )
        native_target_task_admin = verify_native_cross_user_target_task_admin(
            native_admin, native_secondary, secondary_client
        )
        checks = (
            visibility,
            filter_admin,
            native_filter_admin,
            native_target_task_admin,
        )
        status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
        payload = result(
            status,
            "Runtime RBAC smoke passed for the operator-account model." if status == "pass" else "Runtime RBAC smoke failed for the operator-account model.",
            secondary_user=secondary_user,
            full_test_visibility=visibility,
            cross_user_filter_admin=filter_admin,
            native_cross_user_filter_admin=native_filter_admin,
            native_cross_user_target_task_admin=native_target_task_admin,
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
