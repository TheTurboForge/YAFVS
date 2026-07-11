# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from gvm.errors import RequiredArgument
from gvm.protocols.core import Request
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class TrashCan:
    @classmethod
    def restore_from_trashcan(cls, entity_id: EntityID) -> Request:
        """Restore an entity from the trashcan

        Args:
            entity_id: ID of the entity to be restored from the trashcan
        """

        if not entity_id:
            raise RequiredArgument(
                function=cls.restore_from_trashcan.__name__,
                argument="entity_id",
            )

        cmd = XmlCommand("restore")
        cmd.set_attribute("id", str(entity_id))

        return cmd
