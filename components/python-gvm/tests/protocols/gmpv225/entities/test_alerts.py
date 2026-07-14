# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.alerts import (
    GmpCloneAlertTestMixin,
    GmpCreateAlertTestMixin,
    GmpDeleteAlertTestMixin,
    GmpGetAlertsTestMixin,
    GmpGetAlertTestMixin,
    GmpModifyAlertTestMixin,
    GmpTestAlertTestMixin,
)
from ...gmpv225 import GMPTestCase


class Gmpv225CloneAlertTestCase(GmpCloneAlertTestMixin, GMPTestCase):
    pass

class Gmpv225CreateAlertTestCase(GmpCreateAlertTestMixin, GMPTestCase):
    pass


class Gmpv225DeleteAlertTestCase(GmpDeleteAlertTestMixin, GMPTestCase):
    pass


class Gmpv225GetAlertTestCase(GmpGetAlertTestMixin, GMPTestCase):
    pass


class Gmpv225GetAlertsTestCase(GmpGetAlertsTestMixin, GMPTestCase):
    pass


class Gmpv225ModifyAlertTestCase(GmpModifyAlertTestMixin, GMPTestCase):
    pass


class Gmpv225TestAlertTestCase(GmpTestAlertTestMixin, GMPTestCase):
    pass
