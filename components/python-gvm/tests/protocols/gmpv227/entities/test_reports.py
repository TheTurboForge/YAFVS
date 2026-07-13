# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv226.entities.reports import (
    GmpDeleteReportTestMixin,
    GmpGetReportsTestMixin,
    GmpGetReportTestMixin,
)
from ...gmpv227 import GMPTestCase


class GMPDeleteReportTestCase(GmpDeleteReportTestMixin, GMPTestCase):
    pass


class GMPGetReportTestCase(GmpGetReportTestMixin, GMPTestCase):
    pass


class GMPGetReportsTestCase(GmpGetReportsTestMixin, GMPTestCase):
    pass
