# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .alerts import (
    GmpCloneAlertTestMixin,
    GmpCreateAlertTestMixin,
    GmpDeleteAlertTestMixin,
    GmpGetAlertsTestMixin,
    GmpGetAlertTestMixin,
    GmpModifyAlertTestMixin,
    GmpTestAlertTestMixin,
)


class Gmpv224CloneAlertTestCase(GmpCloneAlertTestMixin, Gmpv224TestCase):
    pass


class Gmpv224CreateAlertTestCase(GmpCreateAlertTestMixin, Gmpv224TestCase):
    pass


class Gmpv224DeleteAlertTestCase(GmpDeleteAlertTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetAlertTestCase(GmpGetAlertTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetAlertsTestCase(GmpGetAlertsTestMixin, Gmpv224TestCase):
    pass


class Gmpv224ModifyAlertTestCase(GmpModifyAlertTestMixin, Gmpv224TestCase):
    pass


class Gmpv224TestAlertTestCase(GmpTestAlertTestMixin, Gmpv224TestCase):
    pass
