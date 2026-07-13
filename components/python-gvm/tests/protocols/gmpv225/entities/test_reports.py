# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.reports import (
    GmpDeleteReportTestMixin,
    GmpGetReportsTestMixin,
    GmpGetReportTestMixin,
)
from ...gmpv225 import GMPTestCase


class Gmpv225DeleteReportTestCase(GmpDeleteReportTestMixin, GMPTestCase):
    pass


class Gmpv225GetReportTestCase(GmpGetReportTestMixin, GMPTestCase):
    pass


class Gmpv225GetReportsTestCase(GmpGetReportsTestMixin, GMPTestCase):
    pass
