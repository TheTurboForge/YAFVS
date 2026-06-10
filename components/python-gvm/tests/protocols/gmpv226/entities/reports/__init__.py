# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from .test_delete_report import GmpDeleteReportTestMixin
from .test_get_report import GmpGetReportTestMixin
from .test_get_reports import GmpGetReportsTestMixin

__all__ = (
    "GmpDeleteReportTestMixin",
    "GmpGetReportTestMixin",
    "GmpGetReportsTestMixin",
)
