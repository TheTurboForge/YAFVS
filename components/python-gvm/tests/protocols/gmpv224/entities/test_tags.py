# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .tags import (
    GmpCreateTagTestMixin,
    GmpDeleteTagTestMixin,
    GmpGetTagsTestMixin,
    GmpModifyTagTestMixin,
)


class Gmpv224DeleteTagTestCase(GmpDeleteTagTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetTagsTestCase(GmpGetTagsTestMixin, Gmpv224TestCase):
    pass


class Gmpv224CreateTagTestCase(GmpCreateTagTestMixin, Gmpv224TestCase):
    pass


class Gmpv224ModifyTagTestCase(GmpModifyTagTestMixin, Gmpv224TestCase):
    pass
