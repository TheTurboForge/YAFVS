# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .overrides import (
    GmpCloneOverrideTestMixin,
    GmpCreateOverrideTestMixin,
    GmpDeleteOverrideTestMixin,
    GmpGetOverridesTestMixin,
    GmpModifyOverrideTestMixin,
)


class Gmpv224CloneOverrideTestCase(GmpCloneOverrideTestMixin, Gmpv224TestCase):
    pass


class Gmpv224CreateOverrideTestCase(
    GmpCreateOverrideTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224DeleteOverrideTestCase(
    GmpDeleteOverrideTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetOverridesTestCase(GmpGetOverridesTestMixin, Gmpv224TestCase):
    pass


class Gmpv224ModifyOverrideTestCase(
    GmpModifyOverrideTestMixin, Gmpv224TestCase
):
    pass
