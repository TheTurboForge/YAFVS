# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .port_lists import GmpGetPortListsTestMixin, GmpGetPortListTestMixin


class Gmpv224GetPortListTestCase(GmpGetPortListTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetPortListsTestCase(GmpGetPortListsTestMixin, Gmpv224TestCase):
    pass
