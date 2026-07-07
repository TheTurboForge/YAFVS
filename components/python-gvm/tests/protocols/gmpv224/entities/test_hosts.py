# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .hosts import (
    GmpCreateHostTestMixin,
    GmpDeleteHostTestMixin,
    GmpGetHostsTestMixin,
    GmpModifyHostTestMixin,
)


class Gmpv224CreateHostTestCase(GmpCreateHostTestMixin, Gmpv224TestCase):
    pass


class Gmpv224DeleteHostTestCase(GmpDeleteHostTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetHostsTestCase(GmpGetHostsTestMixin, Gmpv224TestCase):
    pass


class Gmpv224ModifyHostTestCase(GmpModifyHostTestMixin, Gmpv224TestCase):
    pass
