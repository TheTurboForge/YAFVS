# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.filters import (
    GmpCreateFilterTestMixin,
    GmpDeleteFilterTestMixin,
    GmpGetFiltersTestMixin,
    GmpGetFilterTestMixin,
    GmpModifyFilterTestMixin,
)
from ...gmpv227 import GMPTestCase


class GMPDeleteFilterTestCase(GmpDeleteFilterTestMixin, GMPTestCase):
    pass


class GMPGetFilterTestCase(GmpGetFilterTestMixin, GMPTestCase):
    pass


class GMPGetFiltersTestCase(GmpGetFiltersTestMixin, GMPTestCase):
    pass


class GMPCreateFilterTestCase(GmpCreateFilterTestMixin, GMPTestCase):
    pass


class GMPModifyFilterTestCase(GmpModifyFilterTestMixin, GMPTestCase):
    pass
