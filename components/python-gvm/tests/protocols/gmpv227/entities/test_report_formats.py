# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.report_formats import (
    GmpGetReportFormatsTestMixin,
    GmpGetReportFormatTestMixin,
)
from ...gmpv227 import GMPTestCase


class GMPGetReportFormatTestCase(GmpGetReportFormatTestMixin, GMPTestCase):
    pass


class GMPGetReportFormatsTestCase(GmpGetReportFormatsTestMixin, GMPTestCase):
    pass
