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
from ...gmpv227 import GMPTestCase


class GMPGetTagsTestCase(GmpGetTagsTestMixin, GMPTestCase):
    pass


class GMPCreateTagTestCase(GmpCreateTagTestMixin, GMPTestCase):
    pass


class GMPModifyTagTestCase(GmpModifyTagTestMixin, GMPTestCase):
    pass
