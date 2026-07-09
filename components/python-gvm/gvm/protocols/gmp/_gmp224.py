# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Greenbone Management Protocol (GMP) version 22.4
"""

from collections.abc import Iterable, Mapping, Sequence

from gvm.utils import SupportsStr, to_dotted_types_dict

from .._protocol import GvmProtocol, T
from .requests.v224 import (
    Aggregates,
    AggregateStatistic,
    AlertCondition,
    AlertEvent,
    AlertMethod,
    Alerts,
    AliveTest,
    Authentication,
    CertBundAdvisories,
    Cpes,
    CredentialFormat,
    Credentials,
    CredentialType,
    Cves,
    DfnCertAdvisories,
    EntityID,
    EntityType,
    Feed,
    FeedType,
    Filters,
    FilterType,
    Help,
    HelpFormat,
    Hosts,
    HostsOrdering,
    InfoType,
    Nvts,
    OperatingSystems,
    Overrides,
    PortLists,
    PortRangeType,
    ReportFormats,
    ReportFormatType,
    Reports,
    Results,
    ScanConfigs,
    Scanners,
    ScannerType,
    Schedules,
    SecInfo,
    Severity,
    SnmpAuthAlgorithm,
    SnmpPrivacyAlgorithm,
    SortOrder,
    SystemReports,
    Targets,
    Tasks,
    TLSCertificates,
    TrashCan,
    UserAuthType,
    Users,
    UserSettings,
    Version,
    Vulnerabilities,
)

_TYPE_FIELDS = [
    AggregateStatistic,
    AlertCondition,
    AlertEvent,
    AlertMethod,
    AliveTest,
    CredentialFormat,
    CredentialType,
    EntityType,
    FeedType,
    FilterType,
    HostsOrdering,
    InfoType,
    HelpFormat,
    PortRangeType,
    ReportFormatType,
    ScannerType,
    SnmpAuthAlgorithm,
    SnmpPrivacyAlgorithm,
    SortOrder,
    UserAuthType,
]


class GMPv224(GvmProtocol[T]):
    """
    A class implementing the Greenbone Management Protocol (GMP) version 22.4

    Example:

        .. code-block:: python

            from gvm.protocols.gmp import GMPv224 as GMP

            with GMP(connection) as gmp:
                resp = gmp.get_tasks()
    """

    _authenticated = False

    def __init__(self, *args, **kwargs):
        """
        Create a new GMP protocol instance.

        Args:
            connection: Connection to use to talk with the remote daemon. See
                :mod:`gvm.connections` for possible connection types.
            transform: Optional transform `callable <https://docs.python.org/3/library/functions.html#callable>`_
                to convert response data.
                After each request the callable gets passed the plain response data
                which can be used to check the data and/or conversion into different
                representations like a xml dom.

                See :mod:`gvm.transforms` for existing transforms.
        """
        super().__init__(*args, **kwargs)
        self.types = to_dotted_types_dict(_TYPE_FIELDS)

    @staticmethod
    def get_protocol_version() -> tuple[int, int]:
        """
        Return the supported GMP version as major, minor version tuple
        """
        return (22, 4)

    def is_authenticated(self) -> bool:
        """Checks if the user is authenticated

        If the user is authenticated privileged GMP commands like get_tasks
        may be send to gvmd.

        Returns:
            bool: True if an authenticated connection to gvmd has been
            established.
        """
        return self._authenticated

    def authenticate(self, username: str, password: str) -> T:
        """Authenticate to gvmd.

        The generated authenticate command will be send to server.
        Afterwards the response is read, transformed and returned.

        Args:
            username: Username
            password: Password
        """
        response = self._send_request(
            Authentication.authenticate(username=username, password=password)
        )

        if response.is_success:
            self._authenticated = True

        return self._transform(response)

    def describe_auth(self) -> T:
        """Describe authentication methods

        Returns a list of all used authentication methods if such a list is
        available.
        """
        return self._send_request_and_transform_response(
            Authentication.describe_auth()
        )

    def modify_auth(
        self, group_name: str, auth_conf_settings: dict[str, str]
    ) -> T:
        """Modifies an existing auth.

        Args:
            group_name: Name of the group to be modified.
            auth_conf_settings: The new auth config.
        """
        return self._send_request_and_transform_response(
            Authentication.modify_auth(group_name, auth_conf_settings)
        )

    def get_version(self) -> T:
        """Get the Greenbone Vulnerability Management Protocol (GMP) version
        used by the remote gvmd.
        """
        return self._send_request_and_transform_response(Version.get_version())

    def get_port_lists(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        details: bool | None = None,
        targets: bool | None = None,
        trash: bool | None = None,
    ) -> T:
        """Request a list of port lists

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            details: Whether to include full port list details
            targets: Whether to include targets using this port list
            trash: Whether to get port lists in the trashcan instead
        """
        return self._send_request_and_transform_response(
            PortLists.get_port_lists(
                filter_string=filter_string,
                filter_id=filter_id,
                details=details,
                targets=targets,
                trash=trash,
            )
        )

    def get_aggregates(
        self,
        resource_type: EntityType | str,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        sort_criteria: Iterable[dict[str, str | SortOrder | AggregateStatistic]]
        | None = None,
        data_columns: Iterable[str] | None = None,
        group_column: str | None = None,
        subgroup_column: str | None = None,
        text_columns: Iterable[str] | None = None,
        first_group: int | None = None,
        max_groups: int | None = None,
        mode: int | None = None,
        **kwargs,
    ) -> T:
        """Request aggregated information on a resource / entity type

        Additional arguments can be set via the kwargs parameter for backward
        compatibility with older versions of python-gvm, but are not validated.

        Args:
            resource_type: The entity type to gather data from
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            sort_criteria: List of sort criteria (dicts that can contain
                a field, stat and order)
            data_columns: List of fields to aggregate data from
            group_column: The field to group the entities by
            subgroup_column: The field to further group the entities
                inside groups by
            text_columns: List of simple text columns which no statistics
                are calculated for
            first_group: The index of the first aggregate group to return
            max_groups: The maximum number of aggregate groups to return,
                -1 for all
            mode: Special mode for aggregation
        """
        return self._send_request_and_transform_response(
            Aggregates.get_aggregates(
                resource_type,
                filter_string=filter_string,
                filter_id=filter_id,
                sort_criteria=sort_criteria,
                data_columns=data_columns,
                group_column=group_column,
                subgroup_column=subgroup_column,
                text_columns=text_columns,
                first_group=first_group,
                max_groups=max_groups,
                mode=mode,
                **kwargs,
            )
        )

    def get_feeds(self) -> T:
        """Request the list of feeds"""
        return self._send_request_and_transform_response(Feed.get_feeds())

    def get_feed(self, feed_type: FeedType | str) -> T:
        """Request a single feed

        Args:
            feed_type: Type of single feed to get: NVT, CERT or SCAP
        """
        return self._send_request_and_transform_response(
            Feed.get_feed(feed_type)
        )

    def help(
        self,
        *,
        help_format: HelpFormat | str | None = None,
        brief: bool | None = None,
    ) -> T:
        """Get the help text

        Args:
            help_format: Format of of the help:
                "html", "rnc", "text" or "xml
            brief: If True help is brief
        """
        return self._send_request_and_transform_response(
            Help.help(help_format=help_format, brief=brief)
        )

    def get_system_reports(
        self,
        *,
        name: str | None = None,
        duration: int | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        brief: bool | None = None,
        slave_id: EntityID | None = None,
    ) -> T:
        """Request a list of system reports

        Args:
            name: A string describing the required system report
            duration: The number of seconds into the past that the system report
                should include
            start_time: The start of the time interval the system report should
                include in ISO time format
            end_time: The end of the time interval the system report should
                include in ISO time format
            brief: Whether to include the actual system reports
            slave_id: UUID of GMP scanner from which to get the system reports
        """
        return self._send_request_and_transform_response(
            SystemReports.get_system_reports(
                name=name,
                duration=duration,
                start_time=start_time,
                end_time=end_time,
                brief=brief,
                slave_id=slave_id,
            )
        )

    def empty_trashcan(self) -> T:
        """Empty the trashcan

        Remove all entities from the trashcan. **Attention:** this command can
        not be reverted
        """
        return self._send_request_and_transform_response(
            TrashCan.empty_trashcan()
        )

    def restore_from_trashcan(self, entity_id: EntityID) -> T:
        """Restore an entity from the trashcan

        Args:
            entity_id: ID of the entity to be restored from the trashcan
        """
        return self._send_request_and_transform_response(
            TrashCan.restore_from_trashcan(entity_id)
        )

    def get_user_settings(self, *, filter_string: str | None = None) -> T:
        """Request a list of user settings

        Args:
            filter_string: Filter term to use for the query
        """
        return self._send_request_and_transform_response(
            UserSettings.get_user_settings(filter_string=filter_string)
        )

    def get_user_setting(self, setting_id: EntityID) -> T:
        """Request a single user setting

        Args:
            setting_id: UUID of an existing setting
        """
        return self._send_request_and_transform_response(
            UserSettings.get_user_setting(setting_id)
        )

    def modify_user_setting(
        self,
        *,
        setting_id: EntityID | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> T:
        """Modifies an existing user setting.

        Args:
            setting_id: UUID of the setting to be changed.
            name: The name of the setting. Either setting_id or name must be
                passed.
            value: The value of the setting.
        """
        return self._send_request_and_transform_response(
            UserSettings.modify_user_setting(
                setting_id=setting_id, name=name, value=value
            )
        )

    def create_scan_config(
        self,
        config_id: EntityID,
        name: str,
        *,
        comment: str | None = None,
    ) -> T:
        """Create a new scan config

        Args:
            config_id: UUID of the existing scan config
            name: Name of the new scan config
            comment: A comment on the config
        """
        return self._send_request_and_transform_response(
            ScanConfigs.create_scan_config(config_id, name, comment=comment)
        )

    def delete_scan_config(
        self, config_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Deletes an existing config

        Args:
            config_id: UUID of the config to be deleted.
            ultimate: Whether to remove entirely, or to the trashcan.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.delete_scan_config(config_id, ultimate=ultimate)
        )

    def get_scan_configs(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        details: bool | None = None,
        families: bool | None = None,
        preferences: bool | None = None,
        tasks: bool | None = None,
    ) -> T:
        """Request a list of scan configs

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan scan configs instead
            details: Whether to get config families, preferences, nvt selectors
                and tasks.
            families: Whether to include the families if no details are
                requested
            preferences: Whether to include the preferences if no details are
                requested
            tasks: Whether to get tasks using this config
        """
        return self._send_request_and_transform_response(
            ScanConfigs.get_scan_configs(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                details=details,
                families=families,
                preferences=preferences,
                tasks=tasks,
            )
        )

    def get_scan_config(
        self, config_id: EntityID, *, tasks: bool | None = None
    ) -> T:
        """Request a single scan config

        Args:
            config_id: UUID of an existing scan config
            tasks: Whether to get tasks using this config
        """
        return self._send_request_and_transform_response(
            ScanConfigs.get_scan_config(config_id, tasks=tasks)
        )

    def get_scan_config_preferences(
        self,
        *,
        nvt_oid: str | None = None,
        config_id: EntityID | None = None,
    ) -> T:
        """Request a list of scan_config preferences

        When the command includes a config_id attribute, the preference element
        includes the preference name, type and value, and the NVT to which the
        preference applies.
        If the command includes a config_id and an nvt_oid, the preferences for
        the given nvt in the config will be shown.

        Args:
            nvt_oid: OID of nvt
            config_id: UUID of scan config of which to show preference values
        """
        return self._send_request_and_transform_response(
            ScanConfigs.get_scan_config_preferences(
                nvt_oid=nvt_oid, config_id=config_id
            )
        )

    def get_scan_config_preference(
        self,
        name: str,
        *,
        nvt_oid: str | None = None,
        config_id: EntityID | None = None,
    ) -> T:
        """Request a nvt preference

        Args:
            name: name of a particular preference
            nvt_oid: OID of nvt
            config_id: UUID of scan config of which to show preference values
        """
        return self._send_request_and_transform_response(
            ScanConfigs.get_scan_config_preference(
                name, nvt_oid=nvt_oid, config_id=config_id
            )
        )

    def import_scan_config(self, config: str) -> T:
        """Import a scan config from XML

        Args:
            config: Scan Config XML as string to import. This XML must
                contain a :code:`<get_configs_response>` root element.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.import_scan_config(config)
        )

    def modify_scan_config_set_nvt_preference(
        self,
        config_id: EntityID,
        name: str,
        nvt_oid: str,
        *,
        value: str | None = None,
    ) -> T:
        """Modifies the nvt preferences of an existing scan config.

        Args:
            config_id: UUID of scan config to modify.
            name: Name for nvt preference to change.
            nvt_oid: OID of the NVT associated with preference to modify
            value: New value for the preference. None to delete the preference
                and to use the default instead.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.modify_scan_config_set_nvt_preference(
                config_id, name, nvt_oid, value=value
            )
        )

    def modify_scan_config_set_name(self, config_id: EntityID, name: str) -> T:
        """Modifies the name of an existing scan config

        Args:
            config_id: UUID of scan config to modify.
            name: New name for the config.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.modify_scan_config_set_name(config_id, name)
        )

    def modify_scan_config_set_comment(
        self, config_id: EntityID, *, comment: str | None = None
    ) -> T:
        """Modifies the comment of an existing scan config

        Args:
            config_id: UUID of scan config to modify.
            comment: Comment to set on a config. Default is an
                empty comment and the previous comment will be
                removed.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.modify_scan_config_set_comment(
                config_id, comment=comment
            )
        )

    def modify_scan_config_set_scanner_preference(
        self,
        config_id: EntityID,
        name: str,
        *,
        value: str | None = None,
    ) -> T:
        """Modifies the scanner preferences of an existing scan config

        Args:
            config_id: UUID of scan config to modify.
            name: Name of the scanner preference to change
            value: New value for the preference. None to delete the preference
                and to use the default instead.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.modify_scan_config_set_scanner_preference(
                config_id, name, value=value
            )
        )

    def modify_scan_config_set_nvt_selection(
        self,
        config_id: EntityID,
        family: str,
        nvt_oids: tuple[str] | list[str],
    ) -> T:
        """Modifies the selected nvts of an existing scan config

        The manager updates the given family in the config to include only the
        given NVTs.

        Arguments:
            config_id: UUID of scan config to modify.
            family: Name of the NVT family to include NVTs from
            nvt_oids: List of NVTs to select for the family.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.modify_scan_config_set_nvt_selection(
                config_id, family, nvt_oids
            )
        )

    def modify_scan_config_set_family_selection(
        self,
        config_id: EntityID,
        families: list[tuple[str, bool, bool]],
        *,
        auto_add_new_families: bool | None = True,
    ) -> T:
        """
        Selected the NVTs of a scan config at a family level.

        Args:
            config_id: UUID of scan config to modify.
            families: A list of tuples (str, bool, bool):
                str: the name of the NVT family selected,
                bool: add new NVTs  to the family automatically,
                bool: include all NVTs from the family
            auto_add_new_families: Whether new families should be added to the
                scan config automatically. Default: True.
        """
        return self._send_request_and_transform_response(
            ScanConfigs.modify_scan_config_set_family_selection(
                config_id, families, auto_add_new_families=auto_add_new_families
            )
        )

    def create_scanner(
        self,
        name: str,
        host: str,
        port: str | int,
        scanner_type: ScannerType,
        credential_id: str,
        *,
        ca_pub: str | None = None,
        comment: str | None = None,
    ) -> T:
        """Create a new scanner

        Args:
            name: Name of the new scanner
            host: Hostname or IP address of the scanner
            port: Port of the scanner
            scanner_type: Type of the scanner
            credential_id: UUID of client certificate credential for the
                scanner
            ca_pub: Certificate of CA to verify scanner certificate
            comment: Comment for the scanner
        """
        return self._send_request_and_transform_response(
            Scanners.create_scanner(
                name,
                host,
                port,
                scanner_type,
                credential_id,
                ca_pub=ca_pub,
                comment=comment,
            )
        )

    def modify_scanner(
        self,
        scanner_id: EntityID,
        *,
        name: str | None = None,
        host: str | None = None,
        port: int | None = None,
        scanner_type: ScannerType | None = None,
        credential_id: EntityID | None = None,
        ca_pub: str | None = None,
        comment: str | None = None,
    ) -> T:
        """Modify an existing scanner

        Args:
            scanner_id: UUID of the scanner to modify
            name: New name of the scanner
            host: New hostname or IP address of the scanner
            port: New port of the scanner
            scanner_type: New type of the scanner
            credential_id: New UUID of client certificate credential for the
                scanner
            ca_pub: New certificate of CA to verify scanner certificate
            comment: New comment for the scanner
        """
        return self._send_request_and_transform_response(
            Scanners.modify_scanner(
                scanner_id,
                name=name,
                host=host,
                port=port,
                scanner_type=scanner_type,
                credential_id=credential_id,
                ca_pub=ca_pub,
                comment=comment,
            )
        )

    def get_scanners(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of scanners

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan scanners instead
            details: Whether to include extra details like tasks using this
                scanner
        """
        return self._send_request_and_transform_response(
            Scanners.get_scanners(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                details=details,
            )
        )

    def verify_scanner(self, scanner_id: EntityID) -> T:
        """Verify an existing scanner

        Args:
            scanner_id: UUID of an existing scanner
        """
        return self._send_request_and_transform_response(
            Scanners.verify_scanner(scanner_id)
        )

    def clone_scanner(self, scanner_id: EntityID) -> T:
        """Clone an existing scanner

        Args:
            scanner_id: UUID of an existing scanner
        """
        return self._send_request_and_transform_response(
            Scanners.clone_scanner(scanner_id)
        )

    def delete_scanner(
        self, scanner_id: EntityID, ultimate: bool | None = False
    ) -> T:
        """Delete an existing scanner

        Args:
            scanner_id: UUID of an existing scanner
        """
        return self._send_request_and_transform_response(
            Scanners.delete_scanner(scanner_id, ultimate=ultimate)
        )

    def create_user(
        self,
        name: str,
        *,
        password: str | None = None,
    ) -> T:
        """Create a new user

        Args:
            name: Name of the user
            password: Password of the user
        """
        return self._send_request_and_transform_response(
            Users.create_user(
                name,
                password=password,
            )
        )

    def modify_user(
        self,
        user_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        password: str | None = None,
        auth_source: UserAuthType | None = None,
    ) -> T:
        """Modify an existing user.

        Most of the fields need to be supplied
        for changing a single field even if no change is wanted for those.
        Else empty values are inserted for the missing fields instead.

        Args:
            user_id: UUID of the user to be modified.
            name: The new name for the user.
            comment: Comment on the user.
            password: The password for the user.
            auth_source: Source allowed for authentication for this user.
        """
        return self._send_request_and_transform_response(
            Users.modify_user(
                user_id,
                name=name,
                comment=comment,
                password=password,
                auth_source=auth_source,
            )
        )

    def clone_user(self, user_id: EntityID) -> T:
        """Clone an existing user.

        Args:
            user_id: UUID of the user to be cloned.
        """
        return self._send_request_and_transform_response(
            Users.clone_user(user_id)
        )

    def delete_user(
        self,
        user_id: EntityID | None = None,
        *,
        name: str | None = None,
        inheritor_id: EntityID | None = None,
        inheritor_name: str | None = None,
    ) -> T:
        """Delete an existing user

        Either user_id or name must be passed.

        Args:
            user_id: UUID of the task to be deleted.
            name: The name of the user to be deleted.
            inheritor_id: The UUID of the inheriting user or "self". Overrides
                inheritor_name.
            inheritor_name: The name of the inheriting user.
        """
        return self._send_request_and_transform_response(
            Users.delete_user(
                user_id=user_id,
                name=name,
                inheritor_id=inheritor_id,
                inheritor_name=inheritor_name,
            )
        )

    def get_users(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
    ) -> T:
        """Request a list of users

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
        """
        return self._send_request_and_transform_response(
            Users.get_users(filter_string=filter_string, filter_id=filter_id)
        )

    def get_user(self, user_id: EntityID) -> T:
        """Request a single user

        Args:
            user_id: UUID of the user to be requested.
        """
        return self._send_request_and_transform_response(
            Users.get_user(user_id)
        )

    def create_override(
        self,
        text: str,
        nvt_oid: str,
        *,
        days_active: int | None = None,
        hosts: list[str] | None = None,
        port: str | None = None,
        result_id: EntityID | None = None,
        severity: Severity | None = None,
        new_severity: Severity | None = None,
        task_id: EntityID | None = None,
    ) -> T:
        """Create a new override

        Args:
            text: Text of the new override
            nvt_oid: OID of the nvt to which override applies
            days_active: Days override will be active. -1 on always, 0 off
            hosts: A list of host addresses
            port: Port to which the override applies, needs to be a string
                  in the form {number}/{protocol}
            result_id: UUID of a result to which override applies
            severity: Severity to which override applies
            new_severity: New severity for result
            task_id: UUID of task to which override applies
        """
        return self._send_request_and_transform_response(
            Overrides.create_override(
                text,
                nvt_oid,
                days_active=days_active,
                hosts=hosts,
                port=port,
                result_id=result_id,
                severity=severity,
                new_severity=new_severity,
                task_id=task_id,
            )
        )

    def modify_override(
        self,
        override_id: EntityID,
        text: str,
        *,
        days_active: int | None = None,
        hosts: list[str] | None = None,
        port: str | None = None,
        result_id: EntityID | None = None,
        severity: Severity | None = None,
        new_severity: Severity | None = None,
        task_id: EntityID | None = None,
    ) -> T:
        """Modify an existing override.

        Args:
            override_id: UUID of override to modify.
            text: The text of the override.
            days_active: Days override will be active. -1 on always,
                0 off.
            hosts: A list of host addresses
            port: Port to which the override applies, needs to be a string
                  in the form {number}/{protocol}
            result_id: Result to which override applies.
            severity: Severity to which override applies.
            new_severity: New severity score for result.
            task_id: Task to which override applies.
        """
        return self._send_request_and_transform_response(
            Overrides.modify_override(
                override_id,
                text,
                days_active=days_active,
                hosts=hosts,
                port=port,
                result_id=result_id,
                severity=severity,
                new_severity=new_severity,
                task_id=task_id,
            )
        )

    def clone_override(self, override_id: EntityID) -> T:
        """Clone an existing override

        Args:
            override_id: UUID of an existing override to clone from
        """
        return self._send_request_and_transform_response(
            Overrides.clone_override(override_id)
        )

    def delete_override(
        self, override_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Delete an existing override

        Args:
            override_id: UUID of an existing override to delete
            ultimate: Whether to remove entirely, or to the trashcan.
        """
        return self._send_request_and_transform_response(
            Overrides.delete_override(override_id, ultimate=ultimate)
        )

    def get_overrides(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        details: bool | None = None,
        result: bool | None = None,
    ) -> T:
        """Request a list of overrides

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            details: Whether to include full details
            result: Whether to include results using the override
        """
        return self._send_request_and_transform_response(
            Overrides.get_overrides(
                filter_string=filter_string,
                filter_id=filter_id,
                details=details,
                result=result,
            )
        )

    def create_target(
        self,
        name: str,
        *,
        asset_hosts_filter: str | None = None,
        hosts: list[str] | None = None,
        comment: str | None = None,
        exclude_hosts: list[str] | None = None,
        ssh_credential_id: EntityID | None = None,
        ssh_credential_port: int | str | None = None,
        smb_credential_id: EntityID | None = None,
        esxi_credential_id: EntityID | None = None,
        snmp_credential_id: EntityID | None = None,
        alive_test: str | AliveTest | None = None,
        allow_simultaneous_ips: bool | None = None,
        reverse_lookup_only: bool | None = None,
        reverse_lookup_unify: bool | None = None,
        port_range: str | None = None,
        port_list_id: EntityID | None = None,
    ) -> T:
        """Create a new target

        Args:
            name: Name of the target
            asset_hosts_filter: Filter to select target host from assets hosts
            hosts: List of hosts addresses to scan
            exclude_hosts: List of hosts addresses to exclude from scan
            comment: Comment for the target
            ssh_credential_id: UUID of a ssh credential to use on target
            ssh_credential_port: The port to use for ssh credential
            smb_credential_id: UUID of a smb credential to use on target
            snmp_credential_id: UUID of a snmp credential to use on target
            esxi_credential_id: UUID of a esxi credential to use on target
            alive_test: Which alive test to use
            allow_simultaneous_ips: Whether to scan multiple IPs of the
                same host simultaneously
            reverse_lookup_only: Whether to scan only hosts that have names
            reverse_lookup_unify: Whether to scan only one IP when multiple IPs
                have the same name.
            port_range: Port range for the target
            port_list_id: UUID of the port list to use on target
        """
        return self._send_request_and_transform_response(
            Targets.create_target(
                name,
                asset_hosts_filter=asset_hosts_filter,
                hosts=hosts,
                comment=comment,
                exclude_hosts=exclude_hosts,
                ssh_credential_id=ssh_credential_id,
                ssh_credential_port=ssh_credential_port,
                smb_credential_id=smb_credential_id,
                esxi_credential_id=esxi_credential_id,
                snmp_credential_id=snmp_credential_id,
                alive_test=alive_test,
                allow_simultaneous_ips=allow_simultaneous_ips,
                reverse_lookup_only=reverse_lookup_only,
                reverse_lookup_unify=reverse_lookup_unify,
                port_range=port_range,
                port_list_id=port_list_id,
            )
        )

    def modify_target(
        self,
        target_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        hosts: list[str] | None = None,
        exclude_hosts: list[str] | None = None,
        ssh_credential_id: EntityID | None = None,
        ssh_credential_port: str | int | None = None,
        smb_credential_id: EntityID | None = None,
        esxi_credential_id: EntityID | None = None,
        snmp_credential_id: EntityID | None = None,
        alive_test: AliveTest | str | None = None,
        allow_simultaneous_ips: bool | None = None,
        reverse_lookup_only: bool | None = None,
        reverse_lookup_unify: bool | None = None,
        port_list_id: EntityID | None = None,
    ) -> T:
        """Modify an existing target.

        Args:
            target_id: UUID of target to modify.
            comment: Comment on target.
            name: Name of target.
            hosts: List of target hosts.
            exclude_hosts: A list of hosts to exclude.
            ssh_credential_id: UUID of SSH credential to use on target.
            ssh_credential_port: The port to use for ssh credential
            smb_credential_id: UUID of SMB credential to use on target.
            esxi_credential_id: UUID of ESXi credential to use on target.
            snmp_credential_id: UUID of SNMP credential to use on target.
            port_list_id: UUID of port list describing ports to scan.
            alive_test: Which alive tests to use.
            allow_simultaneous_ips: Whether to scan multiple IPs of the
                same host simultaneously
            reverse_lookup_only: Whether to scan only hosts that have names.
            reverse_lookup_unify: Whether to scan only one IP when multiple IPs
                have the same name.
        """
        return self._send_request_and_transform_response(
            Targets.modify_target(
                target_id,
                name=name,
                comment=comment,
                hosts=hosts,
                exclude_hosts=exclude_hosts,
                ssh_credential_id=ssh_credential_id,
                ssh_credential_port=ssh_credential_port,
                smb_credential_id=smb_credential_id,
                esxi_credential_id=esxi_credential_id,
                snmp_credential_id=snmp_credential_id,
                alive_test=alive_test,
                allow_simultaneous_ips=allow_simultaneous_ips,
                reverse_lookup_only=reverse_lookup_only,
                reverse_lookup_unify=reverse_lookup_unify,
                port_list_id=port_list_id,
            )
        )

    def clone_target(self, target_id: EntityID) -> T:
        """Clone an existing target.

        Args:
            target_id: UUID of an existing target to clone.
        """
        return self._send_request_and_transform_response(
            Targets.clone_target(target_id)
        )

    def delete_target(
        self, target_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Delete an existing target.

        Args:
            target_id: UUID of an existing target to delete.
            ultimate: Whether to remove entirely or to the trashcan.
        """
        return self._send_request_and_transform_response(
            Targets.delete_target(target_id, ultimate=ultimate)
        )

    def get_target(
        self, target_id: EntityID, *, tasks: bool | None = None
    ) -> T:
        """Request a single target.

        Args:
            target_id: UUID of the target to request.
            tasks: Whether to include list of tasks that use the target
        """
        return self._send_request_and_transform_response(
            Targets.get_target(target_id, tasks=tasks)
        )

    def get_targets(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        tasks: bool | None = None,
    ) -> T:
        """Request a list of targets.

        Args:
            filter_string: Filter term to use for the query.
            filter_id: UUID of an existing filter to use for the query.
            trash: Whether to include targets in the trashcan.
            tasks: Whether to include list of tasks that use the target.
        """
        return self._send_request_and_transform_response(
            Targets.get_targets(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                tasks=tasks,
            )
        )

    def create_alert(
        self,
        name: str,
        condition: AlertCondition,
        event: AlertEvent,
        method: AlertMethod,
        *,
        method_data: dict[str, str] | None = None,
        event_data: dict[str, str] | None = None,
        condition_data: dict[str, str] | None = None,
        filter_id: EntityID | None = None,
        comment: str | None = None,
    ) -> T:
        """Create a new alert

        Args:
            name: Name of the new Alert
            condition: The condition that must be satisfied for the alert
                to occur; if the event is either 'Updated SecInfo arrived' or
                'New SecInfo arrived', condition must be 'Always'. Otherwise,
                condition can also be on of 'Severity at least', 'Filter count
                changed' or 'Filter count at least'.
            event: The event that must happen for the alert to occur, one
                of 'Task run status changed', 'Updated SecInfo arrived' or 'New
                SecInfo arrived'
            method: The method by which the user is alerted, one of 'SCP',
                'Send', 'SMB', 'SNMP', 'Syslog' or 'Email'; if the event is
                neither 'Updated SecInfo arrived' nor 'New SecInfo arrived',
                method can also be one of 'Start Task', 'HTTP Get', 'Sourcefire
                Connector' or 'verinice Connector'.
            condition_data: Data that defines the condition
            event_data: Data that defines the event
            method_data: Data that defines the method
            filter_id: Filter to apply when executing alert
            comment: Comment for the alert
        """
        return self._send_request_and_transform_response(
            Alerts.create_alert(
                name,
                condition,
                event,
                method,
                method_data=method_data,
                event_data=event_data,
                condition_data=condition_data,
                filter_id=filter_id,
                comment=comment,
            )
        )

    def modify_alert(
        self,
        alert_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        filter_id: EntityID | None = None,
        event: AlertEvent | str | None = None,
        event_data: dict | None = None,
        condition: AlertCondition | str | None = None,
        condition_data: dict[str, str] | None = None,
        method: AlertMethod | str | None = None,
        method_data: dict[str, str] | None = None,
    ) -> T:
        """Modify an existing alert.

        Args:
            alert_id: UUID of the alert to be modified.
            name: Name of the Alert.
            condition: The condition that must be satisfied for the alert to
                occur. If the event is either 'Updated SecInfo
                arrived' or 'New SecInfo arrived', condition must be 'Always'.
                Otherwise, condition can also be on of 'Severity at least',
                'Filter count changed' or 'Filter count at least'.
            condition_data: Data that defines the condition
            event: The event that must happen for the alert to occur, one of
                'Task run status changed', 'Updated SecInfo arrived' or
                'New SecInfo arrived'
            event_data: Data that defines the event
            method: The method by which the user is alerted, one of 'SCP',
                'Send', 'SMB', 'SNMP', 'Syslog' or 'Email';
                if the event is neither 'Updated SecInfo arrived' nor
                'New SecInfo arrived', method can also be one of 'Start Task',
                'HTTP Get', 'Sourcefire Connector' or 'verinice Connector'.
            method_data: Data that defines the method
            filter_id: Filter to apply when executing alert
            comment: Comment for the alert
        """
        return self._send_request_and_transform_response(
            Alerts.modify_alert(
                alert_id,
                name=name,
                comment=comment,
                filter_id=filter_id,
                event=event,
                event_data=event_data,
                condition=condition,
                condition_data=condition_data,
                method=method,
                method_data=method_data,
            )
        )

    def clone_alert(self, alert_id: EntityID) -> T:
        """Clone an existing alert

        Args:
            alert_id: UUID of the alert to clone from
        """
        return self._send_request_and_transform_response(
            Alerts.clone_alert(alert_id)
        )

    def delete_alert(
        self, alert_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Delete an existing alert

        Args:
            alert_id: UUID of the alert to delete
            ultimate: Whether to remove entirely or to the trashcan.
        """
        return self._send_request_and_transform_response(
            Alerts.delete_alert(alert_id, ultimate=ultimate)
        )

    def test_alert(self, alert_id: EntityID) -> T:
        """Run an alert

        Invoke a test run of an alert

        Args:
            alert_id: UUID of the alert to be tested
        """
        return self._send_request_and_transform_response(
            Alerts.test_alert(alert_id)
        )

    def trigger_alert(
        self,
        alert_id: EntityID,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        report_format_id: EntityID | ReportFormatType | None = None,
    ) -> T:
        """Run an alert by ignoring its event and conditions

        The alert is triggered to run immediately with the provided filtered
        report by ignoring the even and condition settings.

        Args:
            alert_id: UUID of the alert to be run
            report_id: UUID of the report to be provided to the alert
            filter: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            report_format_id: UUID of report format to use                              or ReportFormatType (enum)
        """
        return self._send_request_and_transform_response(
            Alerts.trigger_alert(
                alert_id,
                report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                report_format_id=report_format_id,
            )
        )

    def get_alerts(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        tasks: bool | None = None,
    ) -> T:
        """Request a list of alerts

        Args:
            filter: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: True to request the alerts in the trashcan
            tasks: Whether to include the tasks using the alerts
        """
        return self._send_request_and_transform_response(
            Alerts.get_alerts(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                tasks=tasks,
            )
        )

    def get_alert(self, alert_id: EntityID, *, tasks: bool | None = None) -> T:
        """Request a single alert

        Arguments:
            alert_id: UUID of an existing alert
            tasks: Whether to include the tasks using the alert
        """
        return self._send_request_and_transform_response(
            Alerts.get_alert(alert_id, tasks=tasks)
        )

    def clone_credential(self, credential_id: EntityID) -> T:
        """Clone an existing credential

        Args:
            credential_id: UUID of the credential to clone
        """
        return self._send_request_and_transform_response(
            Credentials.clone_credential(credential_id)
        )

    def create_credential(
        self,
        name: str,
        credential_type: CredentialType | str,
        *,
        comment: str | None = None,
        allow_insecure: bool | None = None,
        certificate: str | None = None,
        key_phrase: str | None = None,
        private_key: str | None = None,
        login: str | None = None,
        password: str | None = None,
        auth_algorithm: SnmpAuthAlgorithm | str | None = None,
        community: str | None = None,
        privacy_algorithm: SnmpPrivacyAlgorithm | str | None = None,
        privacy_password: str | None = None,
        public_key: str | None = None,
    ) -> T:
        """Create a new credential

        Create a new credential e.g. to be used in the method of an alert.

        Currently the following credential types are supported:

            - Username + Password
            - Username + SSH-Key
            - Client Certificates
            - SNMPv1 or SNMPv2c protocol
            - S/MIME Certificate
            - OpenPGP Key
            - Password only

        Args:
            name: Name of the new credential
            credential_type: The credential type.
            comment: Comment for the credential
            allow_insecure: Whether to allow insecure use of the credential
            certificate: Certificate for the credential.
                Required for client-certificate and smime credential types.
            key_phrase: Key passphrase for the private key.
                Used for the username+ssh-key credential type.
            private_key: Private key to use for login. Required
                for usk credential type. Also used for the cc credential type.
                The supported key types (dsa, rsa, ecdsa, ...) and formats (PEM,
                PKC#12, OpenSSL, ...) depend on your installed GnuTLS version.
            login: Username for the credential. Required for username+password,
                username+ssh-key and snmp credential type.
            password: Password for the credential. Used for username+password
                and snmp credential types.
            community: The SNMP community
            auth_algorithm: The SNMP authentication algorithm. Required for snmp
                credential type.
            privacy_algorithm: The SNMP privacy algorithm
            privacy_password: The SNMP privacy password
            public_key: PGP public key in *armor* plain text format. Required
                for pgp credential type.

        Examples:
            Creating a Username + Password credential

            .. code-block:: python

                gmp.create_credential(
                    name="UP Credential",
                    credential_type=CredentialType.USERNAME_PASSWORD,
                    login="foo",
                    password="bar",
                )

            Creating a Username + SSH Key credential

            .. code-block:: python

                with open("path/to/private-ssh-key") as f:
                    key = f.read()

                gmp.create_credential(
                    name="USK Credential",
                    credential_type=CredentialType.USERNAME_SSH_KEY,
                    login="foo",
                    key_phrase="foobar",
                    private_key=key,
                )

            Creating a PGP credential

            .. note::

                A compatible public pgp key file can be exported with GnuPG via
                ::

                    $ gpg --armor --export alice@cyb.org > alice.asc

            .. code-block:: python

                with open("path/to/pgp.key.asc") as f:
                    key = f.read()

                gmp.create_credential(
                    name="PGP Credential",
                    credential_type=CredentialType.PGP_ENCRYPTION_KEY,
                    public_key=key,
                )

            Creating a S/MIME credential

            .. code-block:: python

                with open("path/to/smime-cert") as f:
                    cert = f.read()

                gmp.create_credential(
                    name="SMIME Credential",
                    credential_type=CredentialType.SMIME_CERTIFICATE,
                    certificate=cert,
                )

            Creating a Password-Only credential

            .. code-block:: python

                gmp.create_credential(
                    name="Password-Only Credential",
                    credential_type=CredentialType.PASSWORD_ONLY,
                    password="foo",
                )
        """
        return self._send_request_and_transform_response(
            Credentials.create_credential(
                name,
                credential_type,
                comment=comment,
                allow_insecure=allow_insecure,
                certificate=certificate,
                key_phrase=key_phrase,
                private_key=private_key,
                login=login,
                password=password,
                auth_algorithm=auth_algorithm,
                community=community,
                privacy_algorithm=privacy_algorithm,
                privacy_password=privacy_password,
                public_key=public_key,
            )
        )

    def delete_credential(
        self, credential_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Delete an existing credential

        Args:
            credential_id: UUID of the credential to delete
            ultimate: Whether to remove entirely or to the trashcan.
        """
        return self._send_request_and_transform_response(
            Credentials.delete_credential(credential_id, ultimate=ultimate)
        )

    def get_credentials(
        self,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        scanners: bool | None = None,
        trash: bool | None = None,
        targets: bool | None = None,
    ) -> T:
        """Request a list of credentials

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            scanners: Whether to include a list of scanners using the
                credentials
            trash: Whether to get the trashcan credentials instead
            targets: Whether to include a list of targets using the credentials
        """
        return self._send_request_and_transform_response(
            Credentials.get_credentials(
                filter_string=filter_string,
                filter_id=filter_id,
                scanners=scanners,
                trash=trash,
                targets=targets,
            )
        )

    def get_credential(
        self,
        credential_id: str,
        *,
        scanners: bool | None = None,
        targets: bool | None = None,
        credential_format: CredentialFormat | str | None = None,
    ) -> T:
        """Request a single credential

        Args:
            credential_id: UUID of an existing credential
            scanners: Whether to include a list of scanners using the
                credentials
            targets: Whether to include a list of targets using the credentials
            credential_format: One of "key", "rpm", "deb", "exe" or "pem"
        """
        return self._send_request_and_transform_response(
            Credentials.get_credential(
                credential_id,
                scanners=scanners,
                targets=targets,
                credential_format=credential_format,
            )
        )

    def modify_credential(
        self,
        credential_id: str,
        *,
        name: str | None = None,
        comment: str | None = None,
        allow_insecure: bool | None = None,
        certificate: str | None = None,
        key_phrase: str | None = None,
        private_key: str | None = None,
        login: str | None = None,
        password: str | None = None,
        auth_algorithm: SnmpAuthAlgorithm | str | None = None,
        community: str | None = None,
        privacy_algorithm: SnmpPrivacyAlgorithm | str | None = None,
        privacy_password: str | None = None,
        public_key: str | None = None,
    ) -> T:
        """Modifies an existing credential.

        Args:
            credential_id: UUID of the credential
            name: Name of the credential
            comment: Comment for the credential
            allow_insecure: Whether to allow insecure use of the credential
            certificate: Certificate for the credential
            key_phrase: Key passphrase for the private key
            private_key: Private key to use for login
            login: Username for the credential
            password: Password for the credential
            auth_algorithm: The authentication algorithm for SNMP
            community: The SNMP community
            privacy_algorithm: The privacy algorithm for SNMP
            privacy_password: The SNMP privacy password
            public_key: PGP public key in *armor* plain text format
        """
        return self._send_request_and_transform_response(
            Credentials.modify_credential(
                credential_id,
                name=name,
                comment=comment,
                allow_insecure=allow_insecure,
                certificate=certificate,
                key_phrase=key_phrase,
                private_key=private_key,
                login=login,
                password=password,
                auth_algorithm=auth_algorithm,
                community=community,
                privacy_algorithm=privacy_algorithm,
                privacy_password=privacy_password,
                public_key=public_key,
            )
        )

    def create_filter(
        self,
        name: str,
        *,
        filter_type: FilterType | None = None,
        comment: str | None = None,
        term: str | None = None,
    ) -> T:
        """Create a new filter

        Args:
            name: Name of the new filter
            filter_type: Filter for entity type
            comment: Comment for the filter
            term: Filter term e.g. 'name=foo'
        """
        return self._send_request_and_transform_response(
            Filters.create_filter(
                name, filter_type=filter_type, comment=comment, term=term
            )
        )

    def delete_filter(
        self, filter_id: EntityID, *, ultimate: bool | None = False
    ) -> T:
        """Deletes an existing filter

        Args:
            filter_id: UUID of the filter to be deleted.
            ultimate: Whether to remove entirely, or to the trashcan.
        """
        return self._send_request_and_transform_response(
            Filters.delete_filter(filter_id, ultimate=ultimate)
        )

    def get_filters(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        alerts: bool | None = None,
    ) -> T:
        """Request a list of filters

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan filters instead
            alerts: Whether to include list of alerts that use the filter.
        """
        return self._send_request_and_transform_response(
            Filters.get_filters(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                alerts=alerts,
            )
        )

    def modify_filter(
        self,
        filter_id: EntityID,
        *,
        comment: str | None = None,
        name: str | None = None,
        term: str | None = None,
        filter_type: FilterType | None = None,
    ) -> T:
        """Modifies an existing filter.

        Args:
            filter_id: UUID of the filter to be modified
            comment: Comment on filter.
            name: Name of filter.
            term: Filter term.
            filter_type: Resource type filter applies to.
        """
        return self._send_request_and_transform_response(
            Filters.modify_filter(
                filter_id,
                comment=comment,
                name=name,
                term=term,
                filter_type=filter_type,
            )
        )

    def create_host(self, name: str, *, comment: str | None = None) -> T:
        """Create a new host host

        Args:
            name: Name for the new host host
            comment: Comment for the new host host
        """
        return self._send_request_and_transform_response(
            Hosts.create_host(name, comment=comment)
        )

    def delete_host(self, host_id: EntityID) -> T:
        """Deletes an existing host

        Args:
            host_id: UUID of the single host to delete.
        """
        return self._send_request_and_transform_response(
            Hosts.delete_host(host_id)
        )

    def get_hosts(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of hosts

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            details: Whether to include additional information (e.g. tags)
        """
        return self._send_request_and_transform_response(
            Hosts.get_hosts(
                filter_string=filter_string,
                filter_id=filter_id,
                details=details,
            )
        )

    def modify_host(
        self, host_id: EntityID, *, comment: str | None = None
    ) -> T:
        """Modifies an existing host.

        Args:
            host_id: UUID of the host to be modified.
            comment: Comment for the host. Not passing a comment
                arguments clears the comment for this host.
        """
        return self._send_request_and_transform_response(
            Hosts.modify_host(host_id, comment=comment)
        )

    def delete_operating_system(
        self,
        operating_system_id: EntityID,
    ) -> T:
        """Deletes an existing operating system

        Args:
            operating_system_id: UUID of the single operating_system to delete.
        """
        return self._send_request_and_transform_response(
            OperatingSystems.delete_operating_system(operating_system_id)
        )

    def get_operating_systems(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of operating systems

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            details: Whether to include additional information (e.g. tags)
        """
        return self._send_request_and_transform_response(
            OperatingSystems.get_operating_systems(
                filter_string=filter_string,
                filter_id=filter_id,
                details=details,
            )
        )

    def modify_operating_system(
        self, operating_system_id: EntityID, *, comment: str | None = None
    ) -> T:
        """Modifies an existing operating system.

        Args:
            operating_system_id: UUID of the operating_system to be modified.
            comment: Comment for the operating_system. Not passing a comment
                arguments clears the comment for this operating system.
        """
        return self._send_request_and_transform_response(
            OperatingSystems.modify_operating_system(
                operating_system_id, comment=comment
            )
        )

    def delete_report(self, report_id: EntityID) -> T:
        """Deletes an existing report

        Args:
            report_id: UUID of the report to be deleted.
        """
        return self._send_request_and_transform_response(
            Reports.delete_report(report_id)
        )

    def get_report(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        report_format_id: str | ReportFormatType | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request a single report

        Args:
            report_id: UUID of an existing report
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            report_format_id: UUID of report format to use
                              or ReportFormatType (enum)
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report information details
                     defaults to True
        """
        return self._send_request_and_transform_response(
            Reports.get_report(
                report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                report_format_id=report_format_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_reports(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        override_details: bool | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of reports

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            override_details: If overrides are included, whether to include
                override details
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Whether to exclude results
        """
        return self._send_request_and_transform_response(
                Reports.get_reports(
                    filter_string=filter_string,
                    filter_id=filter_id,
                    override_details=override_details,
                    ignore_pagination=ignore_pagination,
                    details=details,
            )
        )

    def get_results(
        self,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        task_id: str | None = None,
        note_details: bool | None = None,
        override_details: bool | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of results

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            task_id: UUID of task for override handling
            note_details: If notes are included, whether to include note
                details
            override_details: If overrides are included, whether to include
                override details
            details: Whether to include additional details of the results
        """
        return self._send_request_and_transform_response(
            Results.get_results(
                    filter_string=filter_string,
                    filter_id=filter_id,
                    task_id=task_id,
                    note_details=note_details,
                    override_details=override_details,
                    details=details,
            )
        )

    def create_schedule(
        self,
        name: str,
        icalendar: str,
        timezone: str,
        *,
        comment: str | None = None,
    ) -> T:
        """Create a new schedule based in `iCalendar <https://tools.ietf.org/html/rfc5545>`_ data.

        Example:
            Requires https://pypi.org/project/icalendar/

            .. code-block:: python

                import pytz

                from datetime import datetime

                from icalendar import Calendar, Event

                cal = Calendar()

                cal.add("prodid", "-//Foo Bar//")
                cal.add("version", "2.0")

                event = Event()
                event.add("dtstamp", datetime.now(tz=pytz.UTC))
                event.add("dtstart", datetime(2020, 1, 1, tzinfo=pytz.utc))

                cal.add_component(event)

                gmp.create_schedule(
                    name="My Schedule", icalendar=cal.to_ical(), timezone="UTC"
                )

        Args:
            name: Name of the new schedule
            icalendar: `iCalendar <https://tools.ietf.org/html/rfc5545>`_ (RFC 5545) based data.
            timezone: Timezone to use for the icalendar events e.g
                Europe/Berlin. If the datetime values in the icalendar data are
                missing timezone information this timezone gets applied.
                Otherwise the datetime values from the icalendar data are
                displayed in this timezone
            comment: Comment on schedule.
        """
        return self._send_request_and_transform_response(
            Schedules.create_schedule(
                name, icalendar, timezone, comment=comment
            )
        )

    def get_schedules(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        tasks: bool | None = None,
    ) -> T:
        """Request a list of schedules

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan schedules instead
            tasks: Whether to include tasks using the schedules
        """
        return self._send_request_and_transform_response(
            Schedules.get_schedules(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                tasks=tasks,
            )
        )

    def get_nvt_families(self, *, sort_order: str | None = None) -> T:
        """Request a list of nvt families

        Args:
            sort_order: Sort order
        """
        return self._send_request_and_transform_response(
            Nvts.get_nvt_families(sort_order=sort_order)
        )

    def get_scan_config_nvts(
        self,
        *,
        details: bool | None = None,
        preferences: bool | None = None,
        preference_count: bool | None = None,
        timeout: bool | None = None,
        config_id: EntityID | None = None,
        preferences_config_id: EntityID | None = None,
        family: str | None = None,
        sort_order: str | None = None,
        sort_field: str | None = None,
    ) -> T:
        """Request a list of nvts

        Args:
            details: Whether to include full details
            preferences: Whether to include nvt preferences
            preference_count: Whether to include preference count
            timeout: Whether to include the special timeout preference
            config_id: UUID of scan config to which to limit the NVT listing
            preferences_config_id: UUID of scan config to use for preference
                values
            family: Family to which to limit NVT listing
            sort_order: Sort order
            sort_field: Sort field
        """
        return self._send_request_and_transform_response(
            Nvts.get_scan_config_nvts(
                details=details,
                preferences=preferences,
                preference_count=preference_count,
                timeout=timeout,
                config_id=config_id,
                preferences_config_id=preferences_config_id,
                family=family,
                sort_order=sort_order,
                sort_field=sort_field,
            )
        )

    def get_scan_config_nvt(self, nvt_oid: str) -> T:
        """Request a single nvt

        Args:
            nvt_oid: OID of an existing nvt
        """
        return self._send_request_and_transform_response(
            Nvts.get_scan_config_nvt(nvt_oid)
        )

    def get_nvts(
        self,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        name: str | None = None,
        details: bool | None = None,
        extended: bool | None = None,
        preferences: bool | None = None,
        preference_count: bool | None = None,
        timeout: bool | None = None,
        config_id: str | None = None,
        preferences_config_id: str | None = None,
        family: str | None = None,
        sort_order: str | None = None,
        sort_field: str | None = None,
    ) -> T:
        """Request a list of NVTs

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
            extended: Whether to receive extended NVT information
                (calls get_nvts, instead of get_info)
            preferences: Whether to include NVT preferences (only for extended)
            preference_count: Whether to include preference count (only for extended)
            timeout: Whether to include the special timeout preference (only for extended)
            config_id: UUID of scan config to which to limit the NVT listing (only for extended)
            preferences_config_id: UUID of scan config to use for preference
                values (only for extended)
            family: Family to which to limit NVT listing (only for extended)
            sort_order: Sort order (only for extended)
            sort_field: Sort field (only for extended)
        """
        return self._send_request_and_transform_response(
            Nvts.get_nvts(
                filter_string=filter_string,
                filter_id=filter_id,
                name=name,
                details=details,
                extended=extended,
                preferences=preferences,
                preference_count=preference_count,
                timeout=timeout,
                config_id=config_id,
                preferences_config_id=preferences_config_id,
                family=family,
                sort_order=sort_order,
                sort_field=sort_field,
            )
        )

    def get_nvt(self, nvt_id: str, *, extended: bool | None = None) -> T:
        """Request a single NVT

        Args:
            nvt_id: ID of an existing NVT
            extended: Whether to receive extended NVT information
                (calls get_nvts, instead of get_info)
        """
        return self._send_request_and_transform_response(
            Nvts.get_nvt(nvt_id, extended=extended)
        )

    def get_nvt_preferences(
        self,
        *,
        nvt_oid: str | None = None,
    ) -> T:
        """Request a list of preferences

        The preference element includes just the
        name and value, with the NVT and type built into the name.

        Args:
            nvt_oid: OID of nvt
        """
        return self._send_request_and_transform_response(
            Nvts.get_nvt_preferences(nvt_oid=nvt_oid)
        )

    def get_nvt_preference(
        self,
        name: str,
        *,
        nvt_oid: str | None = None,
    ) -> T:
        """Request a nvt preference

        Args:
            name: name of a particular preference
            nvt_oid: OID of nvt
            config_id: UUID of scan config of which to show preference values
        """
        return self._send_request_and_transform_response(
            Nvts.get_nvt_preference(name, nvt_oid=nvt_oid)
        )

    def get_info(self, info_id: EntityID, info_type: InfoType) -> T:
        """Request a single secinfo

        Arguments:
            info_id: ID of an existing secinfo
            info_type: Type must be either CERT_BUND_ADV, CPE, CVE,
                DFN_CERT_ADV, OVALDEF, NVT
        """
        return self._send_request_and_transform_response(
            SecInfo.get_info(info_id, info_type)
        )

    def get_info_list(
        self,
        info_type: InfoType,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        name: str | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of security information

        Args:
            info_type: Type must be either CERT_BUND_ADV, CPE, CVE,
                DFN_CERT_ADV, OVALDEF or NVT
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
        """
        return self._send_request_and_transform_response(
            SecInfo.get_info_list(
                info_type,
                filter_string=filter_string,
                filter_id=filter_id,
                name=name,
                details=details,
            )
        )

    def get_cves(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        name: str | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of CVEs

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
        """
        return self._send_request_and_transform_response(
            Cves.get_cves(
                filter_string=filter_string,
                filter_id=filter_id,
                name=name,
                details=details,
            )
        )

    def get_cpes(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        name: str | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of CPEs

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
        """
        return self._send_request_and_transform_response(
            Cpes.get_cpes(
                filter_string=filter_string,
                filter_id=filter_id,
                name=name,
                details=details,
            )
        )

    def get_dfn_cert_advisories(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        name: str | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of DFN-CERT Advisories

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
        """
        return self._send_request_and_transform_response(
            DfnCertAdvisories.get_dfn_cert_advisories(
                filter_string=filter_string,
                filter_id=filter_id,
                name=name,
                details=details,
            )
        )

    def get_cert_bund_advisories(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        name: str | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of CERT-BUND Advisories

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
        """
        return self._send_request_and_transform_response(
            CertBundAdvisories.get_cert_bund_advisories(
                filter_string=filter_string,
                filter_id=filter_id,
                name=name,
                details=details,
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
                name,
                config_id,
                target_id,
                scanner_id,
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
            Tasks.delete_task(task_id, ultimate=ultimate)
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
            Tasks.get_task(task_id)
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
                task_id,
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
                hosts_ordering=hosts_ordering,
                schedule_id=schedule_id,
                schedule_periods=schedule_periods,
                comment=comment,
                alert_ids=alert_ids,
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
            Tasks.move_task(task_id, slave_id=slave_id)
        )

    def start_task(self, task_id: EntityID) -> T:
        """Start an existing task

        Args:
            task_id: UUID of the task to be started
        """
        return self._send_request_and_transform_response(
            Tasks.start_task(task_id)
        )

    def stop_task(self, task_id: EntityID) -> T:
        """Stop an existing running task

        Args:
            task_id: UUID of the task to be stopped
        """
        return self._send_request_and_transform_response(
            Tasks.stop_task(task_id)
        )

    def clone_tls_certificate(self, tls_certificate_id: EntityID) -> T:
        """Modifies an existing TLS certificate.

        Args:
            tls_certificate_id: The UUID of an existing TLS certificate
        """
        return self._send_request_and_transform_response(
            TLSCertificates.clone_tls_certificate(tls_certificate_id)
        )

    def create_tls_certificate(
        self,
        name: str,
        certificate: str,
        *,
        comment: str | None = None,
        trust: bool | None = None,
    ) -> T:
        """Create a new TLS certificate

        Args:
            name: Name of the TLS certificate, defaulting to the MD5
                fingerprint.
            certificate: The Base64 encoded certificate data (x.509 DER or PEM).
            comment: Comment for the TLS certificate.
            trust: Whether the certificate is trusted.
        """
        return self._send_request_and_transform_response(
            TLSCertificates.create_tls_certificate(
                name, certificate, comment=comment, trust=trust
            )
        )

    def delete_tls_certificate(self, tls_certificate_id: EntityID) -> T:
        """Deletes an existing tls certificate

        Args:
            tls_certificate_id: UUID of the tls certificate to be deleted.
        """
        return self._send_request_and_transform_response(
            TLSCertificates.delete_tls_certificate(tls_certificate_id)
        )

    def get_tls_certificates(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        include_certificate_data: bool | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of TLS certificates

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            include_certificate_data: Whether to include the certificate data in
                the response
            details: Whether to include additional details of the
                tls certificates
        """
        return self._send_request_and_transform_response(
            TLSCertificates.get_tls_certificates(
                filter_string=filter_string,
                filter_id=filter_id,
                include_certificate_data=include_certificate_data,
                details=details,
            )
        )

    def get_tls_certificate(self, tls_certificate_id: EntityID) -> T:
        """Request a single TLS certificate

        Args:
            tls_certificate_id: UUID of an existing TLS certificate
        """
        return self._send_request_and_transform_response(
            TLSCertificates.get_tls_certificate(tls_certificate_id)
        )

    def modify_tls_certificate(
        self,
        tls_certificate_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        trust: bool | None = None,
    ) -> T:
        """Modifies an existing TLS certificate.

        Args:
            tls_certificate_id: UUID of the TLS certificate to be modified.
            name: Name of the TLS certificate, defaulting to the MD5 fingerprint
            comment: Comment for the TLS certificate.
            trust: Whether the certificate is trusted.
        """
        return self._send_request_and_transform_response(
            TLSCertificates.modify_tls_certificate(
                tls_certificate_id, name=name, comment=comment, trust=trust
            )
        )

    def get_vulnerabilities(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
    ) -> T:
        """Request a list of vulnerabilities

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
        """
        return self._send_request_and_transform_response(
            Vulnerabilities.get_vulnerabilities(
                filter_string=filter_string, filter_id=filter_id
            )
        )

    def clone_report_format(
        self, report_format_id: EntityID | ReportFormatType
    ) -> T:
        """Clone a report format from an existing one

        Args:
            report_format_id: UUID of the existing report format
                              or ReportFormatType (enum)
        """
        return self._send_request_and_transform_response(
            ReportFormats.clone_report_format(report_format_id)
        )

    def delete_report_format(
        self,
        report_format_id: EntityID | ReportFormatType,
        *,
        ultimate: bool | None = False,
    ) -> T:
        """Deletes an existing report format

        Args:
            report_format_id: UUID of the report format to be deleted.
                              or ReportFormatType (enum)
            ultimate: Whether to remove entirely, or to the trashcan.
        """
        return self._send_request_and_transform_response(
            ReportFormats.delete_report_format(
                report_format_id, ultimate=ultimate
            )
        )

    def get_report_formats(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        alerts: bool | None = None,
        params: bool | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of report formats

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan report formats instead
            alerts: Whether to include alerts that use the report format
            params: Whether to include report format parameters
            details: Include report format file, signature and parameters
        """
        return self._send_request_and_transform_response(
            ReportFormats.get_report_formats(
                filter_string=filter_string,
                filter_id=filter_id,
                trash=trash,
                alerts=alerts,
                params=params,
                details=details,
            )
        )

    def get_report_format(
        self, report_format_id: EntityID | ReportFormatType
    ) -> T:
        """Request a single report format

        Args:
            report_format_id: UUID of an existing report format
                              or ReportFormatType (enum)
        """
        return self._send_request_and_transform_response(
            ReportFormats.get_report_format(report_format_id)
        )

    def import_report_format(self, report_format: str) -> T:
        """Import a report format from XML

        Args:
            report_format: Report format XML as string to import. This XML must
                contain a :code:`<get_report_formats_response>` root element.
        """
        return self._send_request_and_transform_response(
            ReportFormats.import_report_format(report_format)
        )

    def modify_report_format(
        self,
        report_format_id: EntityID | ReportFormatType,
        *,
        active: bool | None = None,
        name: str | None = None,
        summary: str | None = None,
        param_name: str | None = None,
        param_value: str | None = None,
    ) -> T:
        """Modifies an existing report format.

        Args:
            report_format_id: UUID of report format to modify
                              or ReportFormatType (enum)
            active: Whether the report format is active.
            name: The name of the report format.
            summary: A summary of the report format.
            param_name: The name of the param.
            param_value: The value of the param.
        """
        return self._send_request_and_transform_response(
            ReportFormats.modify_report_format(
                report_format_id,
                active=active,
                name=name,
                summary=summary,
                param_name=param_name,
                param_value=param_value,
            )
        )

    def verify_report_format(
        self, report_format_id: EntityID | ReportFormatType
    ) -> T:
        """Verify an existing report format

        Verifies the trust level of an existing report format. It will be
        checked whether the signature of the report format currently matches the
        report format. This includes the script and files used to generate
        reports of this format. It is *not* verified if the report format works
        as expected by the user.

        Args:
            report_format_id: UUID of the report format to be verified
                              or ReportFormatType (enum)
        """
        return self._send_request_and_transform_response(
            ReportFormats.verify_report_format(report_format_id)
        )
