#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise TurboVAS scope reporting over GMP without starting scans."""

from __future__ import annotations

import argparse
import json
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def scope_row(element: Any) -> dict[str, Any]:
    counts = child_element(element, "counts")
    return {
        "id": element.get("id"),
        "name": child_text(element, "name"),
        "global": child_text(element, "global") == "1",
        "protection_requirement": child_text(element, "protection_requirement"),
        "target_count": text_int(child_text(counts, "targets") if counts is not None else child_text(element, "target_count")),
        "host_count": text_int(child_text(counts, "hosts") if counts is not None else child_text(element, "host_count")),
        "scope_report_count": text_int(child_text(counts, "scope_reports") if counts is not None else child_text(element, "scope_report_count")),
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


def scope_reports(gmp: Any, scope_id: str | None = None) -> list[dict[str, Any]]:
    if scope_id:
        response = gmp.get_scope_reports(scope_id=scope_id, details=True)
    else:
        response = gmp.get_scope_reports(details=True)
    return [scope_report_row(element) for element in iter_elements(response, "scope_report")]


def organization_scope(gmp: Any) -> dict[str, Any] | None:
    scopes = [scope_row(element) for element in iter_elements(gmp.get_scopes(details=True), "scope")]
    for scope in scopes:
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


def scope_details(gmp: Any, scope_id: str) -> dict[str, Any] | None:
    scopes = [scope_row(element) for element in iter_elements(gmp.get_scope(scope_id, details=True), "scope")]
    return scopes[0] if scopes else None


def write_artifact(artifact_dir: Path, name: str, payload: dict[str, Any]) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def command_smoke(gmp: Any, artifact_dir: Path) -> dict[str, Any]:
    targets = entity_rows(gmp, "get_targets", "target")
    hosts = entity_rows(gmp, "get_hosts", "host")
    target = targets[0] if targets else None
    host = hosts[0] if hosts else None
    org = organization_scope(gmp)
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
            organization_reports = [scope_report_row(element) for element in iter_elements(gmp.get_scope_report(organization_report_id, details=True), "scope_report")]
            organization_report = organization_reports[0] if organization_reports else {"id": organization_report_id}
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
        scope_after_add = scope_details(gmp, created_scope_id)
        gmp.modify_scope(
            created_scope_id,
            name=smoke_name,
            protection_requirement="high",
            target_ids=[target["id"]],
            host_ids=[host["id"]],
        )
        scope_after_remove = scope_details(gmp, created_scope_id)
        report_response = gmp.generate_scope_report(created_scope_id)
        created_report_id = response_id(report_response)
        if not created_report_id:
            raise RuntimeError("Scope report generation response did not include an id")
        report = scope_reports(gmp, created_scope_id)[0]
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
    parser = argparse.ArgumentParser(description="Exercise TurboVAS scope reporting over GMP")
    parser.add_argument("command", choices=("smoke",))
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--artifact-dir", required=True, help="directory for scope-report artifacts")
    parser.add_argument("--timeout", type=int, default=60, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = ""
    gmp = None
    try:
        gmp, password = runtime_full_test_scan.connect_gmp(Path(args.socket), args.username, Path(args.password_file), args.timeout)
        payload = command_smoke(gmp, Path(args.artifact_dir))
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
