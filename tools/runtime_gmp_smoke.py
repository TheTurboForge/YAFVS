#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Authenticate to gvmd over a Unix socket and emit a compact JSON smoke result."""

from __future__ import annotations

import argparse
import json
import socket
import xml.etree.ElementTree as ET
import uuid
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


READ_CHUNK_BYTES = 16 * 1024



def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "details": details}


def parse_version(response: Any) -> str | None:
    if isinstance(response, bytes):
        response = response.decode("utf-8", errors="replace")
    if isinstance(response, str):
        try:
            root = ET.fromstring(response)
        except ET.ParseError:
            return None
    else:
        root = response
    try:
        version = root.find("version")
    except AttributeError:
        return None
    if version is not None and getattr(version, "text", None):
        return version.text
    return None


def gmp_authenticate_xml(username: str, password: str) -> str:
    return (
        "<authenticate><credentials>"
        f"<username>{escape(username)}</username>"
        f"<password>{escape(password)}</password>"
        "</credentials></authenticate>"
    )


def read_gmp_xml_response(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = connection.recv(READ_CHUNK_BYTES)
        if not chunk:
            raise RuntimeError("gvmd closed the GMP socket before sending a complete response")
        chunks.append(chunk)
        payload = b"".join(chunks)
        try:
            ET.fromstring(payload)
            return payload
        except ET.ParseError:
            continue


def send_gmp_xml_command(connection: socket.socket, command: str) -> bytes:
    connection.sendall(command.encode("utf-8"))
    return read_gmp_xml_response(connection)


def parse_gmp_response(response: bytes) -> ET.Element:
    return ET.fromstring(response)


def raw_gmp_checks(
    socket_path: Path, username: str, password: str, timeout: int
) -> tuple[bytes, bytes, bytes, bytes, bytes, str]:
    probe_name = f"yafvs-retired-copy-probe-{uuid.uuid4()}"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(socket_path))
        send_gmp_xml_command(connection, gmp_authenticate_xml(username, password))
        version_response = send_gmp_xml_command(connection, "<get_version/>")
        copy_response = send_gmp_xml_command(
            connection,
            "<create_credential>"
            f"<name>{escape(probe_name)}</name>"
            "<copy>00000000-0000-0000-0000-000000000000</copy>"
            "</create_credential>",
        )
        copy_only_response = send_gmp_xml_command(
            connection,
            "<create_credential>"
            "<copy>00000000-0000-0000-0000-000000000000</copy>"
            "</create_credential>",
        )
        credentials_response = send_gmp_xml_command(
            connection, '<get_credentials filter="rows=-1"/>'
        )
        aggregate_response = send_gmp_xml_command(
            connection,
            '<get_aggregates type="vuln" group_column="severity" first_group="1" max_groups="1"/>',
        )
        return (
            version_response,
            copy_response,
            copy_only_response,
            credentials_response,
            aggregate_response,
            probe_name,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a YAFVS GMP runtime smoke check")
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--timeout", type=int, default=20, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    socket_path = Path(args.socket)
    password_path = Path(args.password_file)

    if not socket_path.is_socket():
        print(json.dumps(result("fail", "gvmd socket is not ready", socket=str(socket_path))))
        return 1
    if not password_path.is_file():
        print(json.dumps(result("fail", "password file is missing", password_file=str(password_path))))
        return 1

    password = password_path.read_text(encoding="utf-8").strip()
    if not password:
        print(json.dumps(result("fail", "password file is empty", password_file=str(password_path))))
        return 1

    try:
        (
            version_response,
            copy_response,
            copy_only_response,
            credentials_response,
            aggregate_response,
            probe_name,
        ) = raw_gmp_checks(socket_path, args.username, password, args.timeout)
    except Exception as error:  # pylint: disable=broad-except
        print(
            json.dumps(
                result(
                    "fail",
                    "GMP smoke failed",
                    error_type=type(error).__name__,
                    error=str(error).replace(password, "[redacted]"),
                )
            )
        )
        return 1

    version = parse_version(version_response)
    copy_root = parse_gmp_response(copy_response)
    copy_rejected = (
        copy_root.get("status") == "400"
        and copy_root.get("status_text") == "Credential copy is no longer supported"
    )
    copy_only_root = parse_gmp_response(copy_only_response)
    copy_only_rejected = (
        copy_only_root.get("status") == "400"
        and copy_only_root.get("status_text") == "Credential copy is no longer supported"
    )
    credential_names = {
        name.text
        for name in parse_gmp_response(credentials_response).findall("./credential/name")
        if name.text
    }
    no_credential_created = probe_name not in credential_names
    aggregate_root = parse_gmp_response(aggregate_response)
    vulnerability_aggregate_available = (
        aggregate_root.tag == "get_aggregates_response"
        and aggregate_root.get("status") == "200"
    )
    passed = (
        bool(version)
        and copy_rejected
        and copy_only_rejected
        and no_credential_created
        and vulnerability_aggregate_available
    )
    print(
        json.dumps(
            result(
                "pass" if passed else "fail",
                "GMP authentication, retained vulnerability aggregation, and retired credential-copy rejection completed",
                authenticated=True,
                version=version,
                credential_copy_rejected=copy_rejected,
                credential_copy_status=copy_root.get("status"),
                credential_copy_status_text=copy_root.get("status_text"),
                credential_copy_only_rejected=copy_only_rejected,
                credential_copy_only_status=copy_only_root.get("status"),
                credential_copy_only_status_text=copy_only_root.get("status_text"),
                credential_copy_residue_absent=no_credential_created,
                vulnerability_aggregate_available=vulnerability_aggregate_available,
                vulnerability_aggregate_status=aggregate_root.get("status"),
                vulnerability_aggregate_status_text=aggregate_root.get("status_text"),
            )
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
