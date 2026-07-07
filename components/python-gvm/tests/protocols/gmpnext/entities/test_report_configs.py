# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv226.entities.report_configs import (
    GMPCloneReportConfigTestMixin,
    GMPCreateReportConfigTestMixin,
    GMPDeleteReportConfigTestMixin,
    GMPModifyReportConfigTestMixin,
)
from ...gmpv227 import GMPTestCase


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
