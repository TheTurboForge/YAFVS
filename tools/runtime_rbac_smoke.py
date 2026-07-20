#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify YAFVS operator-account semantics over GMP without starting scans."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr

import runtime_full_test_scan

SECONDARY_USER = "yafvs-rbac-smoke"
TEMP_FILTER_PREFIX = "YAFVS RBAC smoke filter"
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


class RbacGmpClient(runtime_full_test_scan.RawGmpClient):
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
            raise RuntimeError(
                f"Native API request failed with status {error.code}"
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
    task_rows = runtime_full_test_scan.object_rows(client.get_tasks(details=True, ignore_pagination=True), "task")
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
        latest_report, report_error = runtime_full_test_scan.latest_report_for_task(
            client, task["id"]
        )
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
        checks = (visibility, filter_admin, native_filter_admin)
        status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
        payload = result(
            status,
            "Runtime RBAC smoke passed for the operator-account model." if status == "pass" else "Runtime RBAC smoke failed for the operator-account model.",
            secondary_user=secondary_user,
            full_test_visibility=visibility,
            cross_user_filter_admin=filter_admin,
            native_cross_user_filter_admin=native_filter_admin,
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
