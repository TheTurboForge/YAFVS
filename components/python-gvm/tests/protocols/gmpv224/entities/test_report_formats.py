# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .report_formats import (
    GmpGetReportFormatsTestMixin,
    GmpGetReportFormatTestMixin,
)


class Gmpv224GetReportFormatTestCase(
    GmpGetReportFormatTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetReportFormatsTestCase(
    GmpGetReportFormatsTestMixin, Gmpv224TestCase
):
    pass
