#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify YAFVS trusted operator-team semantics without starting scans."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SECONDARY_USER = "yafvs-rbac-smoke"
TEMP_FILTER_PREFIX = "YAFVS RBAC smoke filter"
TEMP_TARGET_PREFIX = "YAFVS RBAC smoke target"
TEMP_TASK_PREFIX = "YAFVS RBAC smoke task"
FULL_TEST_TASK_PREFIXES = ("YAFVS full test scan ", "TurboVAS full test scan ")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


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


def verify_full_test_visibility(client: NativeBrowserClient) -> dict[str, Any]:
    try:
        tasks_response = client.request_json(
            "GET",
            "tasks",
            query={"page": "1", "page_size": "500", "sort": "name"},
        )
    except Exception as error:  # pylint: disable=broad-except
        return {
            "status": "fail",
            "task_error": f"{type(error).__name__}: {error}",
            "task": None,
            "latest_report": None,
        }
    candidates = sorted(
        (
            item
            for item in tasks_response.get("items", [])
            if isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and (item.get("name") or "").startswith(FULL_TEST_TASK_PREFIXES)
        ),
        key=lambda item: item.get("name") or "",
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
        task_id = task["id"]
        try:
            reports_response = client.request_json(
                "GET",
                "reports",
                query={
                    "task_id": task_id,
                    "page": "1",
                    "page_size": "10",
                    "sort": "-creation_time",
                },
            )
        except Exception as error:  # pylint: disable=broad-except
            report_errors.append(f"{type(error).__name__}: {error}")
            continue
        latest_report = next(
            (
                report
                for report in reports_response.get("items", [])
                if isinstance(report, dict)
                and isinstance(report.get("task"), dict)
                and report["task"].get("id") == task_id
            ),
            None,
        )
        if latest_report is not None:
            return {
                "status": "pass",
                "task_error": None,
                "task": task,
                "latest_report": latest_report,
                "report_error": None,
            }
        report_errors.append(f"No report returned for task {task_id}.")
    return {
        "status": "fail",
        "task_error": None,
        "task": candidates[0],
        "latest_report": None,
        "report_error": "; ".join(report_errors),
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
        secondary_client.request_json("DELETE", f"tasks/{task_id}/trash")
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
            "task_modified_and_trashed_by": "admin",
            "task_hard_deleted_by": SECONDARY_USER,
            "target_modified_and_deleted_by": SECONDARY_USER,
            "scans_started": 0,
        }
    except Exception as error:  # pylint: disable=broad-except
        if task_id and task_state != "deleted":
            try:
                if task_state == "live":
                    secondary_client.request_json("DELETE", f"tasks/{task_id}")
                secondary_client.request_json("DELETE", f"tasks/{task_id}/trash")
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
    parser = argparse.ArgumentParser(description="Verify YAFVS trusted operator-team semantics")
    parser.add_argument("--username", required=True, help="admin native API username")
    parser.add_argument("--password-file", required=True, help="file containing the admin native API password")
    parser.add_argument("--base-url", required=True, help="development GSA base URL")
    parser.add_argument("--artifact-dir", required=True, help="directory for smoke artifacts")
    parser.add_argument("--timeout", type=int, default=60, help="native API timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password_path = Path(args.password_file)
    artifact_dir = Path(args.artifact_dir)
    admin_password = ""
    secondary_password = secrets.token_urlsafe(24)
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
        visibility = verify_full_test_visibility(native_secondary)
        native_filter_admin = verify_native_cross_user_filter_admin(
            native_admin, native_secondary
        )
        native_target_task_admin = verify_native_cross_user_target_task_admin(
            native_admin, native_secondary
        )
        checks = (
            visibility,
            native_filter_admin,
            native_target_task_admin,
        )
        status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
        payload = result(
            status,
            "Runtime RBAC smoke passed for the operator-account model." if status == "pass" else "Runtime RBAC smoke failed for the operator-account model.",
            secondary_user=secondary_user,
            full_test_visibility=visibility,
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
    payload["artifacts"] = [str(artifact_dir / "rbac-smoke.json")]
    write_artifact(artifact_dir, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
