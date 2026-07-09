#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Authenticate to gvmd over a Unix socket and emit a compact JSON smoke result."""

from __future__ import annotations

import argparse
import json
import socket
import xml.etree.ElementTree as ET
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


def raw_gmp_get_version(socket_path: Path, username: str, password: str, timeout: int) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(socket_path))
        send_gmp_xml_command(connection, gmp_authenticate_xml(username, password))
        return send_gmp_xml_command(connection, "<get_version/>")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a TurboVAS GMP runtime smoke check")
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
        version_response = raw_gmp_get_version(socket_path, args.username, password, args.timeout)
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
    print(
        json.dumps(
            result(
                "pass" if version else "warn",
                "GMP authentication and get_version completed",
                authenticated=True,
                version=version,
            )
        )
    )
    return 0 if version else 2


if __name__ == "__main__":
    raise SystemExit(main())
