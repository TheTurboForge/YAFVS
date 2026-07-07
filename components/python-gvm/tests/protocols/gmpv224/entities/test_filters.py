# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .filters import (
    GmpCreateFilterTestMixin,
    GmpDeleteFilterTestMixin,
    GmpGetFiltersTestMixin,
    GmpModifyFilterTestMixin,
)


class Gmpv224DeleteFilterTestCase(GmpDeleteFilterTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetFiltersTestCase(GmpGetFiltersTestMixin, Gmpv224TestCase):
    pass


class Gmpv224CreateFilterTestCase(GmpCreateFilterTestMixin, Gmpv224TestCase):
    pass


class Gmpv224ModifyFilterTestCase(GmpModifyFilterTestMixin, Gmpv224TestCase):
    pass
