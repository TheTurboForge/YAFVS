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
from ...gmpv226 import GMPTestCase


class GMPCloneAlertTestCase(GmpCloneAlertTestMixin, GMPTestCase):
    pass

class GMPCreateAlertTestCase(GmpCreateAlertTestMixin, GMPTestCase):
    pass


class GMPDeleteAlertTestCase(GmpDeleteAlertTestMixin, GMPTestCase):
    pass


class GMPGetAlertTestCase(GmpGetAlertTestMixin, GMPTestCase):
    pass


class GMPGetAlertsTestCase(GmpGetAlertsTestMixin, GMPTestCase):
    pass


class GMPModifyAlertTestCase(GmpModifyAlertTestMixin, GMPTestCase):
    pass


class GMPTestAlertTestCase(GmpTestAlertTestMixin, GMPTestCase):
    pass
