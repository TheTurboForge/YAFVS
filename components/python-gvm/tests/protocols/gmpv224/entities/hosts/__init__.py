# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from .test_create_host import GmpCreateHostTestMixin
from .test_delete_host import GmpDeleteHostTestMixin
from .test_get_hosts import GmpGetHostsTestMixin
from .test_modify_host import GmpModifyHostTestMixin

__all__ = (
    "GmpCreateHostTestMixin",
    "GmpDeleteHostTestMixin",
    "GmpGetHostsTestMixin",
    "GmpModifyHostTestMixin",
)
