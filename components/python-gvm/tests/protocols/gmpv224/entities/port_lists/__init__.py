# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from .test_get_port_list import GmpGetPortListTestMixin
from .test_get_port_lists import GmpGetPortListsTestMixin

__all__ = (
    "GmpGetPortListTestMixin",
    "GmpGetPortListsTestMixin",
)
