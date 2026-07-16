# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from enum import Enum
from typing import Dict, Union, Any, Optional
from uuid import UUID

from .message import Message, MessageType

MAX_RESULT_FIELD_BYTES = 64 * 1024
MAX_RESULT_PAYLOAD_BYTES = 128 * 1024
MAX_RESULT_IDENTITY_LENGTH = 255
MAX_RESULT_URI_LENGTH = 4096


def _validate_result_text(
    name: str,
    value: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    allow_whitespace: bool = False,
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f'{name} must be a string')
    if len(value) > max_bytes or len(value.encode('utf-8')) > max_bytes:
        raise ValueError(f'{name} exceeds the byte limit')
    if any(
        not character.isprintable()
        and (not allow_whitespace or character not in '\r\n\t')
        for character in value
    ):
        raise ValueError(f'{name} contains unsupported characters')
    return value


class ResultType(Enum):
    ALARM = "ALARM"


class ResultMessage(Message):
    message_type: MessageType = MessageType.RESULT
    topic = "scanner/scan/info"
    max_payload_bytes = MAX_RESULT_PAYLOAD_BYTES

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        host_name: str,
        oid: str,
        value: str,
        port: str = "package",
        uri: str = None,
        result_type: ResultType = ResultType.ALARM,
        message_id: Optional[UUID] = None,
        group_id: Optional[UUID] = None,
        created: Optional[datetime] = None,
    ):
        scan_id = _validate_result_text(
            'scan_id', scan_id, max_bytes=128, allow_empty=False
        )
        host_ip = _validate_result_text(
            'host_ip',
            host_ip,
            max_bytes=MAX_RESULT_IDENTITY_LENGTH,
            allow_empty=False,
        )
        host_name = _validate_result_text(
            'host_name',
            host_name,
            max_bytes=MAX_RESULT_IDENTITY_LENGTH,
            allow_empty=True,
        )
        oid = _validate_result_text(
            'oid', oid, max_bytes=MAX_RESULT_IDENTITY_LENGTH, allow_empty=False
        )
        value = _validate_result_text(
            'value',
            value,
            max_bytes=MAX_RESULT_FIELD_BYTES,
            allow_empty=True,
            allow_whitespace=True,
        )
        port = _validate_result_text(
            'port', port, max_bytes=64, allow_empty=False
        )
        uri = _validate_result_text(
            'uri', uri, max_bytes=MAX_RESULT_URI_LENGTH, allow_empty=True
        )
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.host_name = host_name
        self.oid = oid
        self.value = value
        self.port = port
        self.uri = uri
        self.result_type = result_type

    def serialize(self) -> Dict[str, Union[int, str]]:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "host_name": self.host_name,
                "oid": self.oid,
                "value": self.value,
                "port": self.port,
                "uri": self.uri,
                "result_type": self.result_type.value,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        kwargs.update(
            {
                "scan_id": data.get("scan_id"),
                "host_ip": data.get("host_ip"),
                "host_name": data.get("host_name"),
                "oid": data.get("oid"),
                "value": data.get("value"),
                "port": data.get("port"),
                "uri": data.get("uri"),
                "result_type": ResultType(data.get("result_type")),
            }
        )
        return kwargs
