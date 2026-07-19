#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise TurboVAS scope and scope-report writes over native JSON."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import urllib.parse

SMOKE_SCOPE_PREFIX = "TurboVAS scope smoke"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "generated_at": now_iso(), "details": details}


def text_int(value: str | None) -> int:
    if value in (None, ""):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def native_scope_row(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "global": item.get("global") is True,
        "protection_requirement": item.get("protection_requirement"),
        "target_count": text_int(str(item.get("target_count") or "0")),
        "host_count": text_int(str(item.get("host_count") or "0")),
        "scope_report_count": text_int(str(item.get("scope_report_count") or "0")),
    }


def native_scope_report_row(item: dict[str, Any]) -> dict[str, Any]:
    scope = item.get("scope") if isinstance(item.get("scope"), dict) else {}
    severity = item.get("severity") if isinstance(item.get("severity"), dict) else {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "scope_id": scope.get("id"),
        "scope_name": scope.get("name"),
        "created": item.get("creation_time"),
        "latest_evidence_time": item.get("latest_evidence_time"),
        "source_report_count": text_int(str(item.get("source_report_count") or "0")),
        "hosts_total": text_int(str(item.get("member_host_count") or "0")),
        "hosts_with_evidence": text_int(str(item.get("evidence_host_count") or "0")),
        "hosts_missing_evidence": text_int(str(item.get("missing_host_count") or "0")),
        "results_total": text_int(str(item.get("result_count") or "0")),
        "vulnerabilities_total": text_int(str(item.get("vulnerability_count") or "0")),
        "excluded_candidate_hosts": text_int(str(item.get("excluded_candidate_host_count") or "0")),
        "severity": {
            "high": text_int(str(severity.get("high") or "0")),
            "medium": text_int(str(severity.get("medium") or "0")),
            "low": text_int(str(severity.get("low") or "0")),
            "log": text_int(str(severity.get("log") or "0")),
            "false_positive": text_int(str(severity.get("false_positive") or "0")),
        },
    }


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


def native_api_browser_proxy_delete(repo_root: Path, path: str, *, operator_name: str) -> None:
    command = [
        "docker",
        "compose",
        "-f",
        str(repo_root / "compose" / "dev.yaml"),
        "exec",
        "-T",
        "-e",
        "YAFVS_SCOPE_OPERATOR_NAME",
        "-e",
        "YAFVS_SCOPE_DELETE_PATH",
        "yafvs-api",
        "sh",
        "-ceu",
        (
            "test -n \"${YAFVS_API_BROWSER_PROXY_SECRET:-}\"; "
            "curl -sS --max-time 10 -X DELETE -w '\\n%{http_code}' "
            "-H \"x-yafvs-browser-proxy-secret: ${YAFVS_API_BROWSER_PROXY_SECRET}\" "
            "-H \"x-yafvs-operator-name: ${YAFVS_SCOPE_OPERATOR_NAME}\" "
            "\"http://127.0.0.1:9080${YAFVS_SCOPE_DELETE_PATH}\""
        ),
    ]
    env = os.environ.copy()
    env["YAFVS_SCOPE_OPERATOR_NAME"] = operator_name
    env["YAFVS_SCOPE_DELETE_PATH"] = path
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
    if completed.returncode != 0 or status not in {"204", "404"}:
        reason = completed.stderr.strip() or body or completed.stdout.strip()
        raise RuntimeError(f"native API DELETE failed with HTTP {status or 'unknown'}: {reason}")


def native_api_browser_proxy_json(
    repo_root: Path,
    path: str,
    *,
    method: str,
    payload: dict[str, Any],
    operator_name: str,
    expected_statuses: set[str],
) -> dict[str, Any]:
    if method not in {"POST", "PATCH"}:
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
        "YAFVS_SCOPE_OPERATOR_NAME",
        "-e",
        "YAFVS_SCOPE_METHOD",
        "-e",
        "YAFVS_SCOPE_PATH",
        "-e",
        "YAFVS_SCOPE_JSON",
        "yafvs-api",
        "sh",
        "-ceu",
        (
            "test -n \"${YAFVS_API_BROWSER_PROXY_SECRET:-}\"; "
            "curl -sS --max-time 10 -X \"${YAFVS_SCOPE_METHOD}\" -w '\\n%{http_code}' "
            "-H \"content-type: application/json\" "
            "-H \"x-yafvs-browser-proxy-secret: ${YAFVS_API_BROWSER_PROXY_SECRET}\" "
            "-H \"x-yafvs-operator-name: ${YAFVS_SCOPE_OPERATOR_NAME}\" "
            "--data \"${YAFVS_SCOPE_JSON}\" "
            "\"http://127.0.0.1:9080${YAFVS_SCOPE_PATH}\""
        ),
    ]
    env = os.environ.copy()
    env["YAFVS_SCOPE_OPERATOR_NAME"] = operator_name
    env["YAFVS_SCOPE_METHOD"] = method
    env["YAFVS_SCOPE_PATH"] = path
    env["YAFVS_SCOPE_JSON"] = json.dumps(payload)
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
        reason = completed.stderr.strip() or body or completed.stdout.strip()
        raise RuntimeError(f"native API {method} failed with HTTP {status or 'unknown'}: {reason}")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"native API {method} returned a non-object payload")
    return parsed


def native_scope_report(repo_root: Path, scope_report_id: str) -> dict[str, Any]:
    path = f"/api/v1/scope-reports/{urllib.parse.quote(scope_report_id)}"
    return native_scope_report_row(native_api_json(repo_root, path))


def native_scope_details(repo_root: Path, scope_id: str) -> dict[str, Any]:
    path = f"/api/v1/scopes/{urllib.parse.quote(scope_id)}"
    return native_scope_row(native_api_json(repo_root, path))


def native_scopes(repo_root: Path, filter_value: str = "") -> list[dict[str, Any]]:
    path = "/api/v1/scopes?page_size=5"
    if filter_value:
        path = f"{path}&filter={urllib.parse.quote(filter_value)}"
    payload = native_api_json(repo_root, path)
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return [native_scope_row(item) for item in items if isinstance(item, dict)]


def native_named_rows(repo_root: Path, resource: str, page_size: int = 5) -> list[dict[str, Any]]:
    payload = native_api_json(repo_root, f"/api/v1/{resource}?page_size={page_size}")
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return [
        {"id": item.get("id"), "name": item.get("name")}
        for item in items
        if isinstance(item, dict) and item.get("id")
    ]


def native_scope_reports(repo_root: Path, scope_id: str | None = None) -> list[dict[str, Any]]:
    path = "/api/v1/scope-reports?page_size=1&sort=-creation_time"
    if scope_id:
        path = f"{path}&filter={urllib.parse.quote(scope_id)}"
    payload = native_api_json(repo_root, path)
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return [native_scope_report_row(item) for item in items if isinstance(item, dict)]


def native_generate_scope_report(repo_root: Path, scope_id: str, *, operator_name: str) -> dict[str, Any]:
    path = f"/api/v1/scopes/{urllib.parse.quote(scope_id)}/reports"
    return native_api_browser_proxy_json(
        repo_root,
        path,
        method="POST",
        payload={},
        operator_name=operator_name,
        expected_statuses={"201"},
    )


def organization_scope(repo_root: Path) -> dict[str, Any] | None:
    for scope in native_scopes(repo_root, "Organization"):
        if scope.get("global") or scope.get("name") == "Organization":
            return scope
    return None


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def command_smoke(artifact_dir: Path, repo_root: Path, username: str) -> dict[str, Any]:
    targets = native_named_rows(repo_root, "targets")
    hosts = native_named_rows(repo_root, "hosts")
    target = targets[0] if targets else None
    host = hosts[0] if hosts else None
    org = organization_scope(repo_root)
    if target is None or host is None or org is None:
        payload = result("fail", "Scope smoke prerequisites are missing.", target=target, host=host, organization_scope=org)
        payload["artifacts"] = [write_artifact(artifact_dir, "smoke-failed.json", payload)]
        return payload

    added_target = targets[1] if len(targets) > 1 else target
    added_host = hosts[1] if len(hosts) > 1 else host

    smoke_name = f"{SMOKE_SCOPE_PREFIX} {secrets.token_hex(4)}"
    created_scope_id = None
    created_report_id = None
    organization_report_id = None
    organization_report: dict[str, Any] | None = None
    cleanup: dict[str, Any] = {}
    try:
        organization_response = native_generate_scope_report(repo_root, org["id"], operator_name=username)
        organization_report_id = organization_response.get("id")
        if organization_report_id:
            organization_report = native_scope_report(repo_root, organization_report_id)
        created_scope = native_api_browser_proxy_json(
            repo_root,
            "/api/v1/scopes",
            method="POST",
            payload={
                "name": smoke_name,
                "protection_requirement": "high",
                "target_ids": [target["id"]],
                "host_ids": [host["id"]],
            },
            operator_name=username,
            expected_statuses={"201"},
        )
        created_scope_id = created_scope.get("id")
        if not created_scope_id:
            raise RuntimeError("Native scope creation response did not include an id")
        expanded_target_ids = list(dict.fromkeys([target["id"], added_target["id"]]))
        expanded_host_ids = list(dict.fromkeys([host["id"], added_host["id"]]))
        native_api_browser_proxy_json(
            repo_root,
            f"/api/v1/scopes/{urllib.parse.quote(created_scope_id)}",
            method="PATCH",
            payload={
                "name": smoke_name,
                "protection_requirement": "high",
                "target_ids": expanded_target_ids,
                "host_ids": expanded_host_ids,
            },
            operator_name=username,
            expected_statuses={"200"},
        )
        scope_after_add = native_scope_details(repo_root, created_scope_id)
        native_api_browser_proxy_json(
            repo_root,
            f"/api/v1/scopes/{urllib.parse.quote(created_scope_id)}",
            method="PATCH",
            payload={
                "name": smoke_name,
                "protection_requirement": "high",
                "target_ids": [target["id"]],
                "host_ids": [host["id"]],
            },
            operator_name=username,
            expected_statuses={"200"},
        )
        scope_after_remove = native_scope_details(repo_root, created_scope_id)
        report_response = native_generate_scope_report(repo_root, created_scope_id, operator_name=username)
        created_report_id = report_response.get("id")
        if not created_report_id:
            raise RuntimeError("Scope report generation response did not include an id")
        report = native_scope_reports(repo_root, created_scope_id)[0]
        membership_checked = bool(
            scope_after_add
            and scope_after_add.get("target_count", 0) >= len(expanded_target_ids)
            and scope_after_add.get("host_count", 0) >= len(expanded_host_ids)
            and scope_after_remove
            and scope_after_remove.get("target_count") == 1
            and scope_after_remove.get("host_count") == 1
        )
        status = "pass" if report.get("source_report_count", 0) > 0 and membership_checked else "warn"
        summary = "Scope smoke edited membership and generated a report without starting a scan."
        payload = result(
            status,
            summary,
            scope_id=created_scope_id,
            scope_after_add=scope_after_add,
            scope_after_remove=scope_after_remove,
            scope_report=report,
            target=target,
            added_target=added_target,
            host=host,
            added_host=added_host,
            organization_scope=org,
            organization_scope_report=organization_report,
        )
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Scope smoke failed.", error_type=type(error).__name__, error=str(error), scope_id=created_scope_id, report_id=created_report_id, target=target, host=host)
    finally:
        if organization_report_id:
            try:
                path = f"/api/v1/scope-reports/{urllib.parse.quote(organization_report_id)}"
                native_api_browser_proxy_delete(repo_root, path, operator_name=username)
                cleanup["organization_scope_report"] = "deleted"
            except Exception as error:  # pylint: disable=broad-except
                cleanup["organization_scope_report"] = f"delete failed: {error}"
        if created_report_id:
            try:
                path = f"/api/v1/scope-reports/{urllib.parse.quote(created_report_id)}"
                native_api_browser_proxy_delete(repo_root, path, operator_name=username)
                cleanup["scope_report"] = "deleted"
            except Exception as error:  # pylint: disable=broad-except
                cleanup["scope_report"] = f"delete failed: {error}"
        if created_scope_id:
            try:
                path = f"/api/v1/scopes/{urllib.parse.quote(created_scope_id)}"
                native_api_browser_proxy_delete(repo_root, path, operator_name=username)
                cleanup["scope"] = "deleted"
            except Exception as error:  # pylint: disable=broad-except
                cleanup["scope"] = f"delete failed: {error}"
    payload["details"]["cleanup"] = cleanup
    payload["artifacts"] = [write_artifact(artifact_dir, "smoke.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Exercise TurboVAS scope and scope-report writes over native JSON")
    parser.add_argument("command", choices=("smoke",))
    parser.add_argument("--username", required=True, help="native API operator name")
    parser.add_argument("--artifact-dir", required=True, help="directory for scope-report artifacts")
    parser.add_argument("--repo-root", required=True, help="repository root for native API container access")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = command_smoke(Path(args.artifact_dir), Path(args.repo_root), args.username)
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Runtime scope helper failed.", error_type=type(error).__name__, error=str(error))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
