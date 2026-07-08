# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import Sequence

from gvm.errors import RequiredArgument
from gvm.protocols.core import Request
from gvm.utils import to_bool
from gvm.xml import XmlCommand

from .._entity_id import EntityID


def _joined_ids(ids: Sequence[EntityID] | str | None) -> str | None:
    if ids is None:
        return None
    if isinstance(ids, str):
        return ids
    return " ".join(str(item) for item in ids)


class Scopes:
    @classmethod
    def create_scope(
        cls,
        name: str,
        *,
        comment: str | None = None,
        protection_requirement: str | None = None,
        target_ids: Sequence[EntityID] | str | None = None,
        host_ids: Sequence[EntityID] | str | None = None,
    ) -> Request:
        """Create a scope for operator-facing reporting.

        Args:
            name: Scope name.
            comment: Optional scope comment.
            protection_requirement: normal, high, or very_high.
            target_ids: Target UUIDs used as evidence sources.
            host_ids: Host asset UUIDs included in official scope membership.
        """
        if not name:
            raise RequiredArgument(
                function=cls.create_scope.__name__, argument="name"
            )

        cmd = XmlCommand("create_scope")
        cmd.set_attribute("name", name)
        if comment is not None:
            cmd.set_attribute("comment", comment)
        if protection_requirement is not None:
            cmd.set_attribute("protection_requirement", protection_requirement)
        if (joined := _joined_ids(target_ids)) is not None:
            cmd.set_attribute("target_ids", joined)
        if (joined := _joined_ids(host_ids)) is not None:
            cmd.set_attribute("host_ids", joined)
        return cmd

    @classmethod
    def modify_scope(
        cls,
        scope_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        protection_requirement: str | None = None,
        target_ids: Sequence[EntityID] | str | None = None,
        host_ids: Sequence[EntityID] | str | None = None,
    ) -> Request:
        """Modify an existing scope."""
        if not scope_id:
            raise RequiredArgument(
                function=cls.modify_scope.__name__, argument="scope_id"
            )

        cmd = XmlCommand("modify_scope")
        cmd.set_attribute("scope_id", str(scope_id))
        if name is not None:
            cmd.set_attribute("name", name)
        if comment is not None:
            cmd.set_attribute("comment", comment)
        if protection_requirement is not None:
            cmd.set_attribute("protection_requirement", protection_requirement)
        if (joined := _joined_ids(target_ids)) is not None:
            cmd.set_attribute("target_ids", joined)
        if (joined := _joined_ids(host_ids)) is not None:
            cmd.set_attribute("host_ids", joined)
        return cmd

    @classmethod
    def delete_scope(cls, scope_id: EntityID) -> Request:
        """Delete a scope."""
        if not scope_id:
            raise RequiredArgument(
                function=cls.delete_scope.__name__, argument="scope_id"
            )

        cmd = XmlCommand("delete_scope")
        cmd.set_attribute("scope_id", str(scope_id))
        return cmd

    @staticmethod
    def get_scopes(*, scope_id: EntityID | None = None, details: bool | None = None) -> Request:
        """Request scopes."""
        cmd = XmlCommand("get_scopes")
        if scope_id:
            cmd.set_attribute("scope_id", str(scope_id))
        if details is not None:
            cmd.set_attribute("details", to_bool(details))
        return cmd

    @classmethod
    def generate_scope_report(cls, scope_id: EntityID) -> Request:
        """Generate a persistent scope-report snapshot."""
        if not scope_id:
            raise RequiredArgument(
                function=cls.generate_scope_report.__name__, argument="scope_id"
            )

        cmd = XmlCommand("generate_scope_report")
        cmd.set_attribute("scope_id", str(scope_id))
        return cmd

    @classmethod
    def delete_scope_report(cls, scope_report_id: EntityID) -> Request:
        """Delete a scope report."""
        if not scope_report_id:
            raise RequiredArgument(
                function=cls.delete_scope_report.__name__,
                argument="scope_report_id",
            )

        cmd = XmlCommand("delete_scope_report")
        cmd.set_attribute("scope_report_id", str(scope_report_id))
        return cmd
