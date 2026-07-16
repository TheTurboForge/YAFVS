# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Union, Optional
from uuid import UUID, uuid4

DEFAULT_MAX_MQTT_PAYLOAD_BYTES = 128 * 1024


class MessagePayloadTooLarge(ValueError):
    """Raised before JSON parsing when an MQTT payload exceeds its contract."""


class MessageType(Enum):
    RESULT = "result.scan"
    SCAN_STATUS = "scan.status"
    SCAN_START = "scan.start"


class Message:
    topic: str = None
    message_type: MessageType = None
    message_id: UUID = None
    group_id: str = None
    created: datetime = None
    max_payload_bytes = DEFAULT_MAX_MQTT_PAYLOAD_BYTES

    def __init__(
        self,
        *,
        message_id: Optional[UUID] = None,
        group_id: Optional[str] = None,
        created: Optional[datetime] = None,
    ):
        self.message_id = message_id if message_id else uuid4()
        self.group_id = group_id if group_id else str(uuid4())
        self.created = created if created else datetime.now(timezone.utc)

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        if not isinstance(data, dict):
            raise ValueError('message payload must be a JSON object')
        message_type = MessageType(data.get('message_type'))
        if message_type != cls.message_type:
            raise ValueError(
                f"Invalid message type {message_type} for {cls.__name__}. "
                f"Must be {cls.message_type}.",
            )
        group_id = data.get('group_id')
        if (
            not isinstance(group_id, str)
            or not group_id
            or len(group_id) > 128
            or not group_id.isprintable()
        ):
            raise ValueError('group_id must be a bounded printable string')
        try:
            message_id = UUID(data.get('message_id'))
            created = datetime.fromtimestamp(
                float(data.get('created')), timezone.utc
            )
        except (OSError, OverflowError, TypeError, ValueError) as error:
            raise ValueError(
                'message identity or timestamp is invalid'
            ) from error
        return {
            'message_id': message_id,
            'group_id': group_id,
            'created': created,
        }

    def serialize(self) -> Dict[str, Union[int, str]]:
        return {
            "message_id": str(self.message_id),
            "message_type": (
                self.message_type.value if self.message_type else None
            ),
            "group_id": str(self.group_id),
            "created": self.created.timestamp(),
        }

    @classmethod
    def deserialize(cls, data: Dict[str, Union[int, str]]) -> "Message":
        kwargs = cls._parse(data)
        return cls(**kwargs)

    @classmethod
    def load(cls, payload: Union[str, bytes]) -> "Message":
        if not isinstance(payload, (str, bytes)):
            raise ValueError('message payload must be text or bytes')
        if len(payload) > cls.max_payload_bytes:
            raise MessagePayloadTooLarge(
                'message payload exceeds the byte limit'
            )
        if (
            isinstance(payload, str)
            and len(payload.encode('utf-8')) > cls.max_payload_bytes
        ):
            raise MessagePayloadTooLarge(
                'message payload exceeds the byte limit'
            )
        data = json.loads(payload)
        return cls.deserialize(data)

    def dump(self) -> str:
        return json.dumps(self.serialize())

    def __str__(self) -> str:
        return self.dump()
