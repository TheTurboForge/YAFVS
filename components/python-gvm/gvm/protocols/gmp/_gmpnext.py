#  SPDX-FileCopyrightText: 2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
#  SPDX-License-Identifier: GPL-3.0-or-later

from collections.abc import Mapping, Sequence
from typing import Any

from gvm.protocols.gmp.requests import EntityID

from ...utils import SupportsStr
from .._protocol import T
from ._gmp227 import GMPv227
from .requests.next import (
    Credentials,
    IntegrationConfigs,
    Tasks,
)
from .requests.v224 import HostsOrdering


class GMPNext(GMPv227[T]):
    """
    A class implementing the "Next" version of Greenbone Management Protocol (GMP)
    containing features that are not part of the stable release yet.

    These features may change at any time and may not be available in all builds
    of the gvmd back-end.

    Example:

        .. code-block:: python

            from gvm.protocols.gmp.next import GMP

            with GMP(connection) as gmp:
                resp = gmp.get_tasks()
    """

    @staticmethod
    def get_protocol_version() -> tuple[int, int]:
        return (22, 8)

    def clone_task(self, task_id: EntityID) -> T:
        """Clone an existing task

        Args:
            task_id: UUID of existing task to clone from
        """
        return self._send_request_and_transform_response(
            Tasks.clone_task(task_id)
        )

    def create_task(
        self,
        name: str,
        config_id: EntityID,
        target_id: EntityID,
        scanner_id: EntityID,
        *,
        hosts_ordering: HostsOrdering | None = None,
        schedule_id: EntityID | None = None,
        alert_ids: Sequence[EntityID] | None = None,
        comment: str | None = None,
        schedule_periods: int | None = None,
        preferences: Mapping[str, SupportsStr] | None = None,
    ) -> T:
        """Create a new scan task

        Args:
            name: Name of the new task
            config_id: UUID of config to use by the task
            target_id: UUID of target to be scanned
            scanner_id: UUID of scanner to use for scanning the target
            comment: Comment for the task
            alert_ids: List of UUIDs for alerts to be applied to the task
            hosts_ordering: The order hosts are scanned in
            schedule_id: UUID of a schedule when the task should be run.
            schedule_periods: A limit to the number of times the task will be
                scheduled, or 0 for no limit
                observe this task
            preferences: Name/Value pairs of scanner preferences.
        """
        return self._send_request_and_transform_response(
            Tasks.create_task(
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
                hosts_ordering=hosts_ordering,
                schedule_id=schedule_id,
                alert_ids=alert_ids,
                comment=comment,
                schedule_periods=schedule_periods,
                preferences=preferences,
            )
        )

    def delete_task(
        self, task_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Deletes an existing task

        Args:
            task_id: UUID of the task to be deleted.
            ultimate: Whether to remove entirely, or to the trashcan.
        """
        return self._send_request_and_transform_response(
            Tasks.delete_task(task_id=task_id, ultimate=ultimate)
        )

    def get_tasks(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        details: bool | None = None,
        schedules_only: bool | None = None,
        ignore_pagination: bool | None = None,
    ) -> T:
        """Request a list of tasks

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan tasks instead
            details: Whether to include full task details
            schedules_only: Whether to only include id, name and schedule
                details
            ignore_pagination: Whether to ignore pagination settings (filter
                terms "first" and "rows"). Default is False.
        """
        return self._send_request_and_transform_response(
            Tasks.get_tasks(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                details=details,
                schedules_only=schedules_only,
                ignore_pagination=ignore_pagination,
            )
        )

    def get_task(self, task_id: EntityID) -> T:
        """Request a single task

        Args:
            task_id: UUID of an existing task
        """
        return self._send_request_and_transform_response(
            Tasks.get_task(task_id=task_id)
        )

    def modify_task(
        self,
        task_id: EntityID,
        *,
        name: str | None = None,
        config_id: EntityID | None = None,
        target_id: EntityID | None = None,
        scanner_id: EntityID | None = None,
        hosts_ordering: HostsOrdering | None = None,
        schedule_id: EntityID | None = None,
        schedule_periods: int | None = None,
        comment: str | None = None,
        alert_ids: Sequence[EntityID] | None = None,
        preferences: Mapping[str, SupportsStr] | None = None,
    ) -> T:
        """Modifies an existing task.

        Args:
            task_id: UUID of task to modify.
            name: The name of the task.
            config_id: UUID of scan config to use by the task
            target_id: UUID of target to be scanned
            scanner_id: UUID of scanner to use for scanning the target
            comment: The comment on the task.
            alert_ids: List of UUIDs for alerts to be applied to the task
            hosts_ordering: The order hosts are scanned in
            schedule_id: UUID of a schedule when the task should be run.
            schedule_periods: A limit to the number of times the task will be
                scheduled, or 0 for no limit.
                observe this task
            preferences: Name/Value pairs of scanner preferences.
        """
        return self._send_request_and_transform_response(
            Tasks.modify_task(
                task_id=task_id,
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
                hosts_ordering=hosts_ordering,
                schedule_id=schedule_id,
                alert_ids=alert_ids,
                comment=comment,
                schedule_periods=schedule_periods,
                preferences=preferences,
            )
        )

    def move_task(
        self, task_id: EntityID, *, slave_id: EntityID | None = None
    ) -> T:
        """Move an existing task to another GMP slave scanner or the master

        Args:
            task_id: UUID of the task to be moved
            slave_id: UUID of the sensor to reassign the task to, empty for master.
        """
        return self._send_request_and_transform_response(
            Tasks.move_task(
                task_id=task_id,
                slave_id=slave_id,
            )
        )

    def start_task(self, task_id: EntityID) -> T:
        """Start an existing task

        Args:
            task_id: UUID of the task to be started
        """
        return self._send_request_and_transform_response(
            Tasks.start_task(task_id=task_id)
        )

    def stop_task(self, task_id: EntityID) -> T:
        """Stop an existing running task

        Args:
            task_id: UUID of the task to be stopped
        """
        return self._send_request_and_transform_response(
            Tasks.stop_task(task_id=task_id)
        )

    def get_integration_config(
        self, integration_config_id: EntityID, *, details: bool | None = None
    ) -> T:
        """Request a single Integration Configuration.

        Args:
           integration_config_id: UUID of the integration config to request.
           details: Whether to include detail information.
        """
        return self._send_request_and_transform_response(
            IntegrationConfigs.get_integration_config(
                integration_config_id=integration_config_id, details=details
            )
        )

    def get_integration_configs(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
    ) -> T:
        """Request a list of Integration Configurations.

        Args:
            filter_string: Filter term to use for the query.
            filter_id: UUID of an existing filter to use for the query.
        """
        return self._send_request_and_transform_response(
            IntegrationConfigs.get_integration_configs(
                filter_string=filter_string,
                filter_id=filter_id,
            )
        )

    def modify_integration_config(
        self,
        integration_config_id: EntityID,
        *,
        service_url: str | None = None,
        service_cacert: str | None = None,
        oidc_provider_url: str | None = None,
        oidc_provider_client_id: str | None = None,
        oidc_provider_client_secret: str | None = None,
    ) -> T:
        """Modify an existing Integration Configuration.

        Args:
            integration_config_id: UUID of configuration to modify.
            service_url: Integration Service URL.
            service_cacert: Integration Service Certificate.
            oidc_provider_url: OIDC Provider URL.
            oidc_provider_client_id: OIDC Provider Client ID.
            oidc_provider_client_secret: OIDC Provider Client Secret.
        """
        return self._send_request_and_transform_response(
            IntegrationConfigs.modify_integration_config(
                integration_config_id=integration_config_id,
                service_url=service_url,
                service_cacert=service_cacert,
                oidc_provider_url=oidc_provider_url,
                oidc_provider_client_id=oidc_provider_client_id,
                oidc_provider_client_secret=oidc_provider_client_secret,
            )
        )
