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
    CredentialStoreCredentialType,
    CredentialStores,
    IntegrationConfigs,
    ReportApplications,
    ReportCVEs,
    ReportErrors,
    ReportHosts,
    ReportOperatingSystems,
    ReportPorts,
    ReportTlsCertificates,
    ReportVulnerabilities,
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

    def create_credential_store_credential(
        self,
        name: str,
        credential_type: CredentialStoreCredentialType | str,
        *,
        comment: str | None = None,
        credential_store_id: EntityID | None = None,
        vault_id: str | None = None,
        host_identifier: str | None = None,
    ) -> T:
        """Create a new credential store type credential

        Args:
            name: Name of the credential
            credential_type: Type of the credential
            comment: Optional comment for the credential object
            credential_store_id: Optional credential store id to fetch the credential from
            vault_id: Vault id used to fetch the credential from credential store
            host_identifier: Host identifier used to fetch the credential from credential store
        """
        return self._send_request_and_transform_response(
            Credentials.create_credential_store_credential(
                name=name,
                credential_type=credential_type,
                comment=comment,
                credential_store_id=credential_store_id,
                vault_id=vault_id,
                host_identifier=host_identifier,
            )
        )

    def modify_credential_store_credential(
        self,
        credential_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        credential_store_id: EntityID | None = None,
        vault_id: str | None = None,
        host_identifier: str | None = None,
    ) -> T:
        """Modify an existing credential stored in a credential store

        Args:
            credential_id: UUID of the credential to modify
            name: Name of the credential
            comment: Optional comment for the credential object
            credential_store_id: Optional credential store id to fetch the credential from
            vault_id: Vault id used to fetch the credential from credential store
            host_identifier: Host identifier used to fetch the credential from credential store
        """
        return self._send_request_and_transform_response(
            Credentials.modify_credential_store_credential(
                credential_id=credential_id,
                name=name,
                comment=comment,
                credential_store_id=credential_store_id,
                vault_id=vault_id,
                host_identifier=host_identifier,
            )
        )

    def get_credential_store(
        self,
        credential_store_id: EntityID,
        *,
        details: bool | None = None,
    ) -> T:
        """Request a credential store

        Args:
            credential_store_id: ID of credential store to fetch
            details: True to request all details
        """
        return self._send_request_and_transform_response(
            CredentialStores.get_credential_store(
                credential_store_id=credential_store_id,
                details=details,
            )
        )

    def get_credential_stores(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of credential stores

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            details: True to request all details
        """
        return self._send_request_and_transform_response(
            CredentialStores.get_credential_stores(
                filter_string=filter_string,
                filter_id=filter_id,
                details=details,
            )
        )

    def modify_credential_store(
        self,
        credential_store_id: EntityID,
        *,
        active: bool | None = None,
        host: str | None = None,
        port: int | None = None,
        path: str | None = None,
        app_id: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        client_pkcs12_file: str | None = None,
        passphrase: str | None = None,
        server_ca_cert: str | None = None,
        comment: str | None = None,
    ) -> T:
        """Modify an existing credential store

        Args:
            credential_store_id: ID of credential store to fetch
            active: Whether the credential store is active
            host: The host to use for reaching the credential store
            port: The port to use for reaching the credential store
            path: The URI path the credential store is using
            app_id: Depends on the credential store used. Usually called the same in the credential store
            client_cert: The client certificate to use for authorization, as a plain string
            client_key: The client key to use for authorization, as a plain string
            client_pkcs12_file: The pkcs12 file contents to use for authorization, as a plain string
                (alternative to using client_cert and client_key)
            passphrase: The passphrase to use to decrypt client_pkcs12_file or client_key file
            server_ca_cert: The server certificate, so the credential store can be trusted
            comment: An optional comment to store alongside the credential store
        """
        return self._send_request_and_transform_response(
            CredentialStores.modify_credential_store(
                credential_store_id=credential_store_id,
                active=active,
                host=host,
                port=port,
                path=path,
                app_id=app_id,
                client_cert=client_cert,
                client_key=client_key,
                client_pkcs12_file=client_pkcs12_file,
                passphrase=passphrase,
                server_ca_cert=server_ca_cert,
                comment=comment,
            )
        )

    def verify_credential_store(
        self,
        credential_store_id: EntityID,
    ) -> T:
        """Verify that the connection to an existing credential store works

        Args:
            credential_store_id: The uuid of the credential store to verify
        """
        return self._send_request_and_transform_response(
            CredentialStores.verify_credential_store(
                credential_store_id=credential_store_id,
            )
        )

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

    def get_report_hosts(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request hosts of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report host information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportHosts.get_report_hosts(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_operating_systems(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request operating systems of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report operating system information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportOperatingSystems.get_report_operating_systems(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_ports(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request ports of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report port information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportPorts.get_report_ports(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_tls_certificates(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request TLS certificates of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report TLS certificate information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportTlsCertificates.get_report_tls_certificates(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_applications(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request applications of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report application information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportApplications.get_report_applications(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_cves(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request CVEs of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report CVE information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportCVEs.get_report_cves(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_errors(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request errors of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report error information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportErrors.get_report_errors(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_report_vulnerabilities(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request vulnerabilities of a single report.

        Args:
            report_id: UUID of an existing report.
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report vulnerability information details.
                Defaults to True.
        """
        return self._send_request_and_transform_response(
            ReportVulnerabilities.get_report_vulnerabilities(
                report_id=report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )
