# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from .message import Message, MessageType

MAX_PACKAGE_LIST_BYTES = 3 * 1024 * 1024
MAX_PACKAGES = 10_000
MAX_PACKAGE_BYTES = 4096
MAX_START_PAYLOAD_BYTES = (4 * 1024 * 1024) - 1024


class ScanStartMessage(Message):
    """The immutable run identity published before a Notus host scan."""

    message_type: MessageType = MessageType.SCAN_START
    topic = 'scanner/package/cmd/notus'
    max_payload_bytes = MAX_START_PAYLOAD_BYTES

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
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.host_name = host_name
        self.os_release = os_release
        self.package_list = package_list

    def serialize(self) -> Dict[str, Union[int, str, List[str]]]:
        message = super().serialize()
        message.update(
            {
                'scan_id': self.scan_id,
                'host_ip': self.host_ip,
                'host_name': self.host_name,
                'os_release': self.os_release,
                'package_list': self.package_list,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        for field in ('scan_id', 'host_ip', 'os_release'):
            value = data.get(field)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > (128 if field == 'scan_id' else 255)
                or not value.isprintable()
            ):
                raise ValueError(f'{field} must be a bounded printable string')
        host_name = data.get('host_name')
        if (
            not isinstance(host_name, str)
            or len(host_name) > 255
            or not (host_name.isprintable() or host_name == '')
        ):
            raise ValueError('host_name must be a bounded printable string')
        package_list = data.get('package_list')
        if (
            not isinstance(package_list, list)
            or len(package_list) > MAX_PACKAGES
        ):
            raise ValueError('package_list must contain a list')
        package_bytes = 0
        for package in package_list:
            if (
                not isinstance(package, str)
                or not package
                or len(package) > MAX_PACKAGE_BYTES
                or not package.isprintable()
            ):
                raise ValueError('package_list contains an invalid entry')
            package_bytes += len(package.encode('utf-8'))
            if package_bytes > MAX_PACKAGE_LIST_BYTES:
                raise ValueError('package_list exceeds the byte limit')
        kwargs.update(
            {
                'scan_id': data['scan_id'],
                'host_ip': data['host_ip'],
                'host_name': data['host_name'],
                'os_release': data['os_release'],
                'package_list': package_list,
            }
        )
        return kwargs
