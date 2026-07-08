# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from .test_create_tag import GmpCreateTagTestMixin
from .test_get_tags import GmpGetTagsTestMixin
from .test_modify_tag import GmpModifyTagTestMixin

__all__ = (
    "GmpCreateTagTestMixin",
    "GmpGetTagsTestMixin",
    "GmpModifyTagTestMixin",
)
