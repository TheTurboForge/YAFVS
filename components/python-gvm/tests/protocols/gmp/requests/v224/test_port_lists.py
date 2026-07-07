# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.errors import RequiredArgument
from gvm.protocols.gmp.requests.v224 import PortLists


class PortListsTestCase(unittest.TestCase):
    def test_get_port_lists(self):
        request = PortLists.get_port_lists()

        self.assertEqual(bytes(request), b"<get_port_lists/>")

    def test_get_port_lists_with_filter_string(self):
        request = PortLists.get_port_lists(filter_string="foo=bar")

        self.assertEqual(bytes(request), b'<get_port_lists filter="foo=bar"/>')

    def test_get_port_lists_with_filter_id(self):
        request = PortLists.get_port_lists(filter_id="f1")

        self.assertEqual(bytes(request), b'<get_port_lists filt_id="f1"/>')

    def test_get_port_lists_with_trash(self):
        request = PortLists.get_port_lists(trash=True)

        self.assertEqual(bytes(request), b'<get_port_lists trash="1"/>')

        request = PortLists.get_port_lists(trash=False)

        self.assertEqual(bytes(request), b'<get_port_lists trash="0"/>')

    def test_get_port_lists_with_details(self):
        request = PortLists.get_port_lists(details=True)

        self.assertEqual(bytes(request), b'<get_port_lists details="1"/>')

        request = PortLists.get_port_lists(details=False)

        self.assertEqual(bytes(request), b'<get_port_lists details="0"/>')

    def test_get_port_lists_with_targets(self):
        request = PortLists.get_port_lists(targets=True)

        self.assertEqual(bytes(request), b'<get_port_lists targets="1"/>')

        request = PortLists.get_port_lists(targets=False)

        self.assertEqual(bytes(request), b'<get_port_lists targets="0"/>')

    def test_get_port_list(self):
        request = PortLists.get_port_list(port_list_id="port_list_id")

        self.assertEqual(
            bytes(request),
            b'<get_port_lists port_list_id="port_list_id" details="1"/>',
        )

    def test_get_port_list_missing_port_list_id(self):
        with self.assertRaises(RequiredArgument):
            PortLists.get_port_list(port_list_id=None)

        with self.assertRaises(RequiredArgument):
            PortLists.get_port_list(port_list_id="")

        with self.assertRaises(RequiredArgument):
            PortLists.get_port_list("")
