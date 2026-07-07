# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.schedules import (
    GmpCreateScheduleTestMixin,
    GmpGetSchedulesTestMixin,
)
from ...gmpv225 import GMPTestCase


class Gmpv225GetSchedulesTestCase(GmpGetSchedulesTestMixin, GMPTestCase):
    pass


class Gmpv225CreateScheduleTestCase(GmpCreateScheduleTestMixin, GMPTestCase):
    pass
