# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.protocols.gmp.requests.v224 import Schedules


class SchedulesTestUnit(unittest.TestCase):
    def test_get_schedules(self):
        request = Schedules.get_schedules()
        self.assertEqual(bytes(request), b"<get_schedules/>")

    def test_get_schedules_with_filter_string(self):
        request = Schedules.get_schedules(filter_string="filter_string")
        self.assertEqual(
            bytes(request),
            b'<get_schedules filter="filter_string"/>',
        )

    def test_get_schedules_with_filter_id(self):
        request = Schedules.get_schedules(filter_id="filter_id")
        self.assertEqual(
            bytes(request),
            b'<get_schedules filt_id="filter_id"/>',
        )

    def test_get_schedules_with_trash(self):
        request = Schedules.get_schedules(trash=True)
        self.assertEqual(
            bytes(request),
            b'<get_schedules trash="1"/>',
        )

        request = Schedules.get_schedules(trash=False)
        self.assertEqual(
            bytes(request),
            b'<get_schedules trash="0"/>',
        )

    def test_get_schedules_with_tasks(self):
        request = Schedules.get_schedules(tasks=True)
        self.assertEqual(
            bytes(request),
            b'<get_schedules tasks="1"/>',
        )

        request = Schedules.get_schedules(tasks=False)
        self.assertEqual(
            bytes(request),
            b'<get_schedules tasks="0"/>',
        )
