#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise TurboVAS scope writes over GMP and scope-report reads over native JSON."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import urllib.parse

import runtime_full_test_scan

SMOKE_SCOPE_PREFIX = "TurboVAS scope smoke"


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


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def child_element(element: Any, child_name: str) -> Any | None:
    for child in list(element):
        if local_name(str(child.tag)) == child_name:
            return child
    return None


def child_text(element: Any, child_name: str) -> str | None:
    child = child_element(element, child_name)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def child_path_text(element: Any, child_names: tuple[str, ...]) -> str | None:
    current = element
    for child_name in child_names:
        current = child_element(current, child_name)
        if current is None:
            return None
    return current.text.strip() if current.text else None


def text_int(value: str | None) -> int:
    if value in (None, ""):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def iter_elements(response: Any, element_name: str) -> list[Any]:
    root = response_root(response)
    if root is None or not hasattr(root, "iter"):
        return []
    return [element for element in root.iter() if local_name(str(element.tag)) == element_name]


def response_id(response: Any) -> str | None:
    root = response_root(response)
    if root is None:
        return None
    return root.get("id")


def row(element: Any) -> dict[str, Any]:
    return {
        "id": element.get("id"),
        "name": child_text(element, "name"),
    }


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


def scope_report_row(element: Any) -> dict[str, Any]:
    counts = child_element(element, "counts")
    severity = child_element(element, "severity")
    return {
        "id": element.get("id"),
        "name": child_text(element, "name"),
        "scope_id": child_path_text(element, ("scope", "id")),
        "scope_name": child_path_text(element, ("scope", "name")),
        "created": child_text(element, "created") or child_text(element, "creation_time"),
        "latest_evidence_time": child_text(element, "latest_evidence_time"),
        "source_report_count": text_int(child_text(counts, "source_reports") if counts is not None else child_text(element, "source_report_count")),
        "hosts_total": text_int(child_text(counts, "hosts_total") if counts is not None else child_text(element, "member_host_count")),
        "hosts_with_evidence": text_int(child_text(counts, "hosts_with_evidence") if counts is not None else child_text(element, "evidence_host_count")),
        "hosts_missing_evidence": text_int(child_text(counts, "hosts_missing_evidence") if counts is not None else child_text(element, "missing_host_count")),
        "results_total": text_int(child_text(counts, "results_total") if counts is not None else child_text(element, "result_count")),
        "vulnerabilities_total": text_int(child_text(counts, "vulnerabilities_total") if counts is not None else child_text(element, "vulnerability_count")),
        "excluded_candidate_hosts": text_int(child_text(counts, "excluded_candidate_hosts") if counts is not None else child_text(element, "excluded_candidate_host_count")),
        "severity": {
            "high": text_int(child_text(severity, "high") if severity is not None else None),
            "medium": text_int(child_text(severity, "medium") if severity is not None else None),
            "low": text_int(child_text(severity, "low") if severity is not None else None),
            "log": text_int(child_text(severity, "log") if severity is not None else None),
            "false_positive": text_int(child_text(severity, "false_positive") if severity is not None else None),
        },
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
        "turbovas-api",
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


def native_scope_reports(repo_root: Path, scope_id: str | None = None) -> list[dict[str, Any]]:
    path = "/api/v1/scope-reports?page_size=1&sort=-creation_time"
    if scope_id:
        path = f"{path}&filter={urllib.parse.quote(scope_id)}"
    payload = native_api_json(repo_root, path)
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return [native_scope_report_row(item) for item in items if isinstance(item, dict)]


def organization_scope(repo_root: Path) -> dict[str, Any] | None:
    for scope in native_scopes(repo_root, "Organization"):
        if scope.get("global") or scope.get("name") == "Organization":
            return scope
    return None


def entity_rows(gmp: Any, getter_name: str, element_name: str) -> list[dict[str, Any]]:
    getter = getattr(gmp, getter_name)
    try:
        response = getter(filter_string="rows=-1", details=True)
    except TypeError:
        response = getter(filter_string="rows=-1")
    if element_name == "host":
        rows = [
            row(element)
            for element in iter_elements(response, "asset")
            if child_text(element, "type") == "host"
        ]
    else:
        rows = [row(element) for element in iter_elements(response, element_name)]
    return [entry for entry in rows if entry.get("id")]


def first_row(gmp: Any, getter_name: str, element_name: str) -> dict[str, Any] | None:
    rows = entity_rows(gmp, getter_name, element_name)
    return rows[0] if rows else None


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def command_smoke(gmp: Any, artifact_dir: Path, repo_root: Path) -> dict[str, Any]:
    targets = entity_rows(gmp, "get_targets", "target")
    hosts = entity_rows(gmp, "get_hosts", "host")
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
    organization_report: dict[str, Any] | None = None
    cleanup: dict[str, Any] = {}
    try:
        organization_response = gmp.generate_scope_report(org["id"])
        organization_report_id = response_id(organization_response)
        if organization_report_id:
            organization_report = native_scope_report(repo_root, organization_report_id)
        create_response = gmp.create_scope(
            smoke_name,
            protection_requirement="high",
            target_ids=[target["id"]],
            host_ids=[host["id"]],
        )
        created_scope_id = response_id(create_response)
        if not created_scope_id:
            raise RuntimeError("Scope creation response did not include an id")
        expanded_target_ids = list(dict.fromkeys([target["id"], added_target["id"]]))
        expanded_host_ids = list(dict.fromkeys([host["id"], added_host["id"]]))
        gmp.modify_scope(
            created_scope_id,
            name=smoke_name,
            protection_requirement="high",
            target_ids=expanded_target_ids,
            host_ids=expanded_host_ids,
        )
        scope_after_add = native_scope_details(repo_root, created_scope_id)
        gmp.modify_scope(
            created_scope_id,
            name=smoke_name,
            protection_requirement="high",
            target_ids=[target["id"]],
            host_ids=[host["id"]],
        )
        scope_after_remove = native_scope_details(repo_root, created_scope_id)
        report_response = gmp.generate_scope_report(created_scope_id)
        created_report_id = response_id(report_response)
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
        if created_report_id:
            try:
                gmp.delete_scope_report(created_report_id)
                cleanup["scope_report"] = "deleted"
            except Exception as error:  # pylint: disable=broad-except
                cleanup["scope_report"] = f"delete failed: {error}"
        if created_scope_id:
            try:
                gmp.delete_scope(created_scope_id)
                cleanup["scope"] = "deleted"
            except Exception as error:  # pylint: disable=broad-except
                cleanup["scope"] = f"delete failed: {error}"
    payload["details"]["cleanup"] = cleanup
    payload["artifacts"] = [write_artifact(artifact_dir, "smoke.json", payload)]
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Exercise TurboVAS scope writes over GMP and scope-report reads over native JSON")
    parser.add_argument("command", choices=("smoke",))
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for scope-report artifacts")
    parser.add_argument("--repo-root", required=True, help="repository root for native API container access")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    gmp = None
    try:
        gmp, password = runtime_full_test_scan.connect_gmp(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        payload = command_smoke(gmp, Path(args.artifact_dir), Path(args.repo_root))
    except Exception as error:  # pylint: disable=broad-except
        payload = result("fail", "Runtime scope helper failed.", error_type=type(error).__name__, error=str(error).replace(password, "[redacted]"))
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
