# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.overrides import (
    GmpCloneOverrideTestMixin,
    GmpCreateOverrideTestMixin,
    GmpDeleteOverrideTestMixin,
    GmpGetOverridesTestMixin,
    GmpModifyOverrideTestMixin,
)
from ...gmpv225 import GMPTestCase


class Gmpv225CloneOverrideTestCase(GmpCloneOverrideTestMixin, GMPTestCase):
    pass


class Gmpv225CreateOverrideTestCase(GmpCreateOverrideTestMixin, GMPTestCase):
    pass


class Gmpv225DeleteOverrideTestCase(GmpDeleteOverrideTestMixin, GMPTestCase):
    pass


class Gmpv225GetOverridesTestCase(GmpGetOverridesTestMixin, GMPTestCase):
    pass


class Gmpv225ModifyOverrideTestCase(GmpModifyOverrideTestMixin, GMPTestCase):
    pass
