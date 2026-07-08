# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.tags import (
    GmpCreateTagTestMixin,
    GmpGetTagsTestMixin,
    GmpModifyTagTestMixin,
)
from ...gmpv225 import GMPTestCase


class Gmpv225GetTagsTestCase(GmpGetTagsTestMixin, GMPTestCase):
    pass


class Gmpv225CreateTagTestCase(GmpCreateTagTestMixin, GMPTestCase):
    pass


class Gmpv225ModifyTagTestCase(GmpModifyTagTestMixin, GMPTestCase):
    pass
