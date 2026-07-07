# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.hosts import (
    GmpCreateHostTestMixin,
    GmpDeleteHostTestMixin,
    GmpGetHostsTestMixin,
    GmpModifyHostTestMixin,
)
from ...gmpv227 import GMPTestCase


class GMPCreateHostTestCase(GmpCreateHostTestMixin, GMPTestCase):
    pass


class GMPDeleteHostTestCase(GmpDeleteHostTestMixin, GMPTestCase):
    pass


class GMPGetHostsTestCase(GmpGetHostsTestMixin, GMPTestCase):
    pass


class GMPModifyHostTestCase(GmpModifyHostTestMixin, GMPTestCase):
    pass
