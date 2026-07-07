# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.port_lists import (
    GmpGetPortListsTestMixin,
    GmpGetPortListTestMixin,
)
from ...gmpv227 import GMPTestCase


class GMPGetPortListTestCase(GmpGetPortListTestMixin, GMPTestCase):
    pass


class GMPGetPortListsTestCase(GmpGetPortListsTestMixin, GMPTestCase):
    pass
