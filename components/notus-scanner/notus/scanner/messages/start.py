# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from ..errors import MessageParsingError
from .message import Message, MessageType

MAX_PACKAGES = 10_000
MAX_PACKAGE_NAME_LENGTH = 4_096
MAX_PACKAGE_LIST_BYTES = 3 * 1024 * 1024
MAX_START_PAYLOAD_BYTES = (4 * 1024 * 1024) - 1024
MAX_START_FIELD_LENGTH = 255


def _validate_start_fields(
    scan_id: str,
    host_ip: str,
    host_name: str,
    os_release: str,
    package_list: List[str],
) -> Dict[str, Union[str, List[str]]]:
    fields = {}
    for name, value in (
        ("scan_id", scan_id),
        ("host_ip", host_ip),
        ("os_release", os_release),
    ):
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_START_FIELD_LENGTH
            or not value.isprintable()
        ):
            raise MessageParsingError(
                f"{name} must be a bounded printable string"
            )
        fields[name] = value
    if (
        not isinstance(host_name, str)
        or len(host_name) > MAX_START_FIELD_LENGTH
        or not (host_name.isprintable() or host_name == "")
    ):
        raise MessageParsingError(
            "host_name must be a bounded printable string"
        )
    if not isinstance(package_list, list) or len(package_list) > MAX_PACKAGES:
        raise MessageParsingError(
            "package_list must contain a list within limits"
        )
    package_bytes = 0
    for package in package_list:
        if (
            not isinstance(package, str)
            or not package
            or len(package) > MAX_PACKAGE_NAME_LENGTH
            or not package.isprintable()
        ):
            raise MessageParsingError(
                "package_list entries must be bounded printable strings"
            )
        package_bytes += len(package.encode("utf-8"))
        if package_bytes > MAX_PACKAGE_LIST_BYTES:
            raise MessageParsingError("package_list exceeds the byte limit")
    fields["host_name"] = host_name
    fields["package_list"] = list(package_list)
    return fields


class ScanStartMessage(Message):
    message_type: MessageType = MessageType.SCAN_START
    topic = "scanner/package/cmd/notus"
    max_payload_bytes = MAX_START_PAYLOAD_BYTES

    scan_id: str
    host_ip: str
    host_name: str
    os_release: str
    package_list: List[str]

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        host_name: str,
        os_release: str,
        package_list: List[str],
        message_id: Optional[UUID] = None,
        group_id: Optional[str] = None,
        created: Optional[datetime] = None,
    ):
        fields = _validate_start_fields(
            scan_id, host_ip, host_name, os_release, package_list
        )
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = fields["scan_id"]
        self.host_ip = fields["host_ip"]
        self.host_name = fields["host_name"]
        self.os_release = fields["os_release"]
        self.package_list = fields["package_list"]

    def serialize(self) -> Dict[str, Union[int, str, List[str]]]:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "host_name": self.host_name,
                "os_release": self.os_release,
                "package_list": self.package_list,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        kwargs.update(
            _validate_start_fields(
                data.get("scan_id"),
                data.get("host_ip"),
                data.get("host_name"),
                data.get("os_release"),
                data.get("package_list"),
            )
        )
        return kwargs
