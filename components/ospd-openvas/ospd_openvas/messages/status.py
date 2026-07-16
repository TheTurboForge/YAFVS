# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union
from uuid import UUID

from .message import Message, MessageType

MAX_NOTUS_RESULT_COUNT = 10_000


class ScanStatus(Enum):
    FINISHED = 'finished'
    RUNNING = 'running'
    INTERRUPTED = 'interrupted'


class ScanStatusMessage(Message):
    """A Notus run state, including the exact terminal result count."""

    message_type = MessageType.SCAN_STATUS
    topic = 'scanner/status'
    max_payload_bytes = 16 * 1024

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        status: ScanStatus,
        result_count: Optional[int] = None,
        message_id: Optional[UUID] = None,
        group_id: Optional[str] = None,
        created: Optional[datetime] = None,
    ):
        if status == ScanStatus.FINISHED and result_count is None:
            raise ValueError('finished status requires result_count')
        if status != ScanStatus.FINISHED and result_count is not None:
            raise ValueError('result_count is only valid for finished status')
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.status = status
        self.result_count = result_count

    def serialize(self) -> Dict[str, Union[int, str]]:
        message = super().serialize()
        message.update(
            {
                'scan_id': self.scan_id,
                'host_ip': self.host_ip,
                'status': self.status.value,
            }
        )
        if self.result_count is not None:
            message['result_count'] = self.result_count
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        for field in ('scan_id', 'host_ip'):
            value = data.get(field)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 255
                or not value.isprintable()
            ):
                raise ValueError(f'{field} must be a bounded printable string')
        result_count = data.get('result_count')
        if result_count is not None and (
            not isinstance(result_count, int)
            or isinstance(result_count, bool)
            or result_count < 0
            or result_count > MAX_NOTUS_RESULT_COUNT
        ):
            raise ValueError('result_count exceeds the supported range')
        kwargs.update(
            {
                'scan_id': data['scan_id'],
                'host_ip': data['host_ip'],
                'status': ScanStatus(data.get('status')),
                'result_count': result_count,
            }
        )
        return kwargs
