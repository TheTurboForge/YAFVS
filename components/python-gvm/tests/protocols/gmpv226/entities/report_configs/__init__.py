# SPDX-FileCopyrightText: 2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from .test_clone_report_config import GMPCloneReportConfigTestMixin
from .test_create_report_config import GMPCreateReportConfigTestMixin
from .test_delete_report_config import GMPDeleteReportConfigTestMixin
from .test_modify_report_config import GMPModifyReportConfigTestMixin

__all__ = (
    "GMPCloneReportConfigTestMixin",
    "GMPCreateReportConfigTestMixin",
    "GMPDeleteReportConfigTestMixin",
    "GMPModifyReportConfigTestMixin",
)
