# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import TestCase

from ospd_openvas.messages.start import ScanStartMessage
from ospd_openvas.messages.status import ScanStatus, ScanStatusMessage

BASE = {
    'message_id': '63026767-029d-417e-9148-77f4da49f49a',
    'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
    'created': 1628512774.0,
    'scan_id': 'scan-1',
    'host_ip': '192.0.2.1',
}


class NotusFenceMessageTestCase(TestCase):
    def test_start_preserves_run_identity(self):
        message = ScanStartMessage.deserialize(
            {
                **BASE,
                'message_type': 'scan.start',
                'host_name': 'host',
                'os_release': 'debian_12',
                'package_list': ['example=1'],
            }
        )
        self.assertEqual(message.group_id, BASE['group_id'])
        self.assertEqual(message.serialize()['group_id'], BASE['group_id'])

    def test_finished_status_requires_and_preserves_exact_count(self):
        message = ScanStatusMessage.deserialize(
            {
                **BASE,
                'message_type': 'scan.status',
                'status': 'finished',
                'result_count': 0,
            }
        )
        self.assertEqual(message.status, ScanStatus.FINISHED)
        self.assertEqual(message.result_count, 0)
        self.assertEqual(message.serialize()['result_count'], 0)

    def test_missing_run_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'group_id'):
            ScanStatusMessage.deserialize(
                {
                    **BASE,
                    'group_id': None,
                    'message_type': 'scan.status',
                    'status': 'running',
                }
            )

    def test_finished_status_rejects_unbounded_count(self):
        with self.assertRaisesRegex(ValueError, 'supported range'):
            ScanStatusMessage.deserialize(
                {
                    **BASE,
                    'message_type': 'scan.status',
                    'status': 'finished',
                    'result_count': 10_001,
                }
            )

    def test_finished_status_without_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'result_count'):
            ScanStatusMessage.deserialize(
                {
                    **BASE,
                    'message_type': 'scan.status',
                    'status': 'finished',
                }
            )
