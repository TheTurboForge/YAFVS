# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv226 import GMPTestCase
from .report_configs import (
    GMPCloneReportConfigTestMixin,
    GMPCreateReportConfigTestMixin,
    GMPDeleteReportConfigTestMixin,
    GMPModifyReportConfigTestMixin,
)


class GMPCloneReportConfigTestCase(GMPCloneReportConfigTestMixin, GMPTestCase):
    pass


class GMPCreateReportConfigTestCase(
    GMPCreateReportConfigTestMixin, GMPTestCase
):
    pass


class GMPDeleteReportConfigTestCase(
    GMPDeleteReportConfigTestMixin, GMPTestCase
):
    pass


class GMPModifyReportConfigTestCase(
    GMPModifyReportConfigTestMixin, GMPTestCase
):
    pass
