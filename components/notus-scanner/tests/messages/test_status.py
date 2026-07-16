# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime, timezone
from unittest import TestCase
from uuid import UUID

from notus.scanner.errors import MessageParsingError
from notus.scanner.messages.message import MessageType
from notus.scanner.messages.status import ScanStatus, ScanStatusMessage


class ScanStatusMessageTestCase(TestCase):
    def test_constructor(self):
        message = ScanStatusMessage(
            scan_id="scan_1",
            host_ip="1.1.1.1",
            status=ScanStatus.FINISHED,
            result_count=0,
        )

        self.assertIsInstance(message.message_id, UUID)
        self.assertIsInstance(message.group_id, str)
        self.assertIsInstance(message.created, datetime)

        self.assertEqual(message.message_type, MessageType.SCAN_STATUS)
        self.assertEqual(message.topic, "scanner/status")

        self.assertEqual(message.scan_id, "scan_1")
        self.assertEqual(message.host_ip, "1.1.1.1")
        self.assertEqual(message.status, ScanStatus.FINISHED)
        self.assertEqual(message.result_count, 0)

    def test_serialize(self):
        created = datetime.fromtimestamp(1628512774)
        message_id = UUID("63026767-029d-417e-9148-77f4da49f49a")
        group_id = UUID("866350e8-1492-497e-b12b-c079287d51dd")
        message = ScanStatusMessage(
            message_id=message_id,
            group_id=group_id,
            created=created,
            scan_id="scan_1",
            host_ip="1.1.1.1",
            status=ScanStatus.FINISHED,
            result_count=2,
        )

        serialized = message.serialize()
        self.assertEqual(serialized["created"], 1628512774.0)
        self.assertEqual(
            serialized["message_id"], "63026767-029d-417e-9148-77f4da49f49a"
        )
        self.assertEqual(
            serialized["group_id"], "866350e8-1492-497e-b12b-c079287d51dd"
        )
        self.assertEqual(serialized["message_type"], "scan.status")
        self.assertEqual(serialized["scan_id"], "scan_1")
        self.assertEqual(serialized["host_ip"], "1.1.1.1")
        self.assertEqual(serialized["status"], "finished")
        self.assertEqual(serialized["result_count"], 2)

    def test_deserialize(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.status",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "finished",
            "result_count": 2,
        }

        message = ScanStatusMessage.deserialize(data)
        self.assertEqual(
            message.message_id, UUID("63026767-029d-417e-9148-77f4da49f49a")
        )
        self.assertEqual(
            message.group_id, "866350e8-1492-497e-b12b-c079287d51dd"
        )
        self.assertEqual(
            message.created,
            datetime.fromtimestamp(1628512774.0, tz=timezone.utc),
        )
        self.assertEqual(message.message_type, MessageType.SCAN_STATUS)

        self.assertEqual(message.scan_id, "scan_1")
        self.assertEqual(message.host_ip, "1.1.1.1")
        self.assertEqual(message.status, ScanStatus.FINISHED)
        self.assertEqual(message.result_count, 2)
        self.assertEqual(message.topic, "scanner/status")

    def test_deserialize_invalid_status(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.status",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "foo",
        }

        with self.assertRaisesRegex(
            MessageParsingError, "status is unsupported"
        ):
            ScanStatusMessage.deserialize(data)

    def test_finished_requires_nonnegative_result_count(self):
        with self.assertRaisesRegex(ValueError, "requires result_count"):
            ScanStatusMessage(
                scan_id="scan_1",
                host_ip="1.1.1.1",
                status=ScanStatus.FINISHED,
            )

        with self.assertRaisesRegex(ValueError, "supported range"):
            ScanStatusMessage(
                scan_id="scan_1",
                host_ip="1.1.1.1",
                status=ScanStatus.FINISHED,
                result_count=-1,
            )

        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.status",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "finished",
            "result_count": -1,
        }
        with self.assertRaisesRegex(ValueError, "supported range"):
            ScanStatusMessage.deserialize(data)

        data["result_count"] = 10_001
        with self.assertRaisesRegex(ValueError, "supported range"):
            ScanStatusMessage.deserialize(data)

    def test_deserialize_invalid_message_type(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.start",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "foo",
        }

        with self.assertRaisesRegex(
            MessageParsingError,
            "Invalid message type MessageType.SCAN_START for ScanStatusMessage."
            " Must be MessageType.SCAN_STATUS.",
        ):
            ScanStatusMessage.deserialize(data)
