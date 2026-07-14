# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .authentication import GmpAuthenticateTestMixin


class Gmpv224AuthenticateTestCase(GmpAuthenticateTestMixin, Gmpv224TestCase):
    pass
