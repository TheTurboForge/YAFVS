# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
from typing import Iterable, List, Optional, Set, Tuple
from uuid import NAMESPACE_URL, UUID, uuid5

from .errors import AdvisoriesLoadingError
from .loader import AdvisoriesLoader
from .messages.message import Message
from .messages.result import ResultMessage
from .messages.start import ScanStartMessage
from .messages.status import ScanStatus, ScanStatusMessage
from .messaging.publisher import Publisher, PublishError
from .models.packages import package_class_by_type
from .models.packages.package import Package, PackageAdvisories, PackageAdvisory
from .models.vulnerability import Vulnerabilities, Vulnerability

logger = logging.getLogger(__name__)

RESULT_PUBLISH_ACK_TIMEOUT = 10.0


class NotusScanner:
    def __init__(
        self,
        loader: AdvisoriesLoader,
        publisher: Publisher,
    ):
        self._loader = loader
        self._publisher = publisher

    @staticmethod
    def _message_id(group_id: str, kind: str, identity: str = "") -> UUID:
        """Derive stable identities so broker redelivery is idempotent."""
        return uuid5(
            NAMESPACE_URL,
            f"https://yafvs.local/notus/{group_id}/{kind}/{identity}",
        )

    def _publish(self, message: Message) -> Optional[PublishError]:
        """Publish a non-result message without logging its payload."""
        try:
            self._publisher.publish(message)
        except PublishError as error:
            logger.error(
                "Could not publish %s: %s",
                type(message).__name__,
                error,
            )
            return error
        except Exception:  # pylint: disable=broad-except
            logger.error("Could not publish %s", type(message).__name__)
            return PublishError(
                "unexpected publication failure", safe_to_interrupt=False
            )
        return None

    def _finish_host(
        self, scan_id: str, host_ip: str, group_id: str, result_count: int
    ) -> Optional[PublishError]:
        """Send a message to the broker to inform a host is done."""

        scan_status_message = ScanStatusMessage(
            scan_id=scan_id,
            host_ip=host_ip,
            group_id=group_id,
            message_id=self._message_id(group_id, "status", "finished"),
            status=ScanStatus.FINISHED,
            result_count=result_count,
        )
        return self._publish(scan_status_message)

    def _start_host(
        self, scan_id: str, host_ip: str, group_id: str
    ) -> Optional[PublishError]:
        """Send a message to the broker to inform a host scan has started."""
        scan_status_message = ScanStatusMessage(
            scan_id=scan_id,
            host_ip=host_ip,
            group_id=group_id,
            message_id=self._message_id(group_id, "status", "running"),
            status=ScanStatus.RUNNING,
        )
        return self._publish(scan_status_message)

    def _interrupt_host(
        self, scan_id: str, host_ip: str, group_id: str
    ) -> Optional[PublishError]:
        scan_status_message = ScanStatusMessage(
            scan_id=scan_id,
            host_ip=host_ip,
            group_id=group_id,
            message_id=self._message_id(group_id, "status", "interrupted"),
            status=ScanStatus.INTERRUPTED,
        )
        return self._publish(scan_status_message)

    def _publish_results(
        self,
        scan_id: str,
        host_ip: str,
        host_name: str,
        group_id: str,
        vulnerabilities: Vulnerabilities,
    ) -> Tuple[int, Optional[PublishError]]:
        result_count = 0
        for oid, vulnerability in vulnerabilities.get().items():
            report = ""
            fixed_packages: List[PackageAdvisory]
            for package, fixed_packages in vulnerability.get().items():
                fixed_package = fixed_packages.pop(0)
                report = (
                    report + f"\n{'Vulnerable package:':<22}{package.name}\n"
                    f"{'Installed version:':<22}{package.full_name}\n"
                    f"{'Fixed version:':<20}{fixed_package.symbol:>2}"
                    f"{fixed_package.package.full_name}\n"
                )
                for fixed_package in fixed_packages:
                    report = (
                        report + f"{'':<20}{fixed_package.symbol:>2}"
                        f"{fixed_package.package.full_name}\n"
                    )

            message = ResultMessage(
                scan_id=scan_id,
                host_ip=host_ip,
                host_name=host_name,
                group_id=group_id,
                message_id=self._message_id(group_id, "result", oid),
                oid=oid,
                value=report,
            )
            try:
                self._publisher.publish_result(
                    message, timeout=RESULT_PUBLISH_ACK_TIMEOUT
                )
            except PublishError as error:
                logger.error(
                    "Could not confirm ResultMessage PUBACK: %s", error
                )
                return result_count, error
            except Exception:  # pylint: disable=broad-except
                logger.error("Could not confirm ResultMessage PUBACK")
                return result_count, PublishError(
                    "unexpected result publication failure",
                    safe_to_interrupt=False,
                )
            result_count += 1
        return result_count, None

    def _handle_publication_failure(
        self, message: ScanStartMessage, error: PublishError
    ) -> bool:
        if not error.safe_to_interrupt:
            logger.error(
                "Terminal status withheld after an ambiguous publication failure"
            )
            return False

        interrupted_error = self._interrupt_host(
            message.scan_id, message.host_ip, message.group_id
        )
        if interrupted_error:
            logger.error("Could not publish safe INTERRUPTED status")
            return False
        return True

    @staticmethod
    def _check_package(
        package: Package, package_advisory_list: Set[PackageAdvisory]
    ) -> Optional[Vulnerability]:
        vul = Vulnerability()
        for package_advisory in package_advisory_list:
            logger.debug(
                "%s verify package %s %s %s",
                package_advisory.oid,
                package,
                package_advisory.symbol,
                package_advisory.package,
            )
            is_vulnerable = package_advisory.is_vulnerable(package)
            if is_vulnerable is None:
                continue
            elif not is_vulnerable:
                return

            vul.add(package, package_advisory)

        return vul

    def _start_scan(
        self,
        installed_packages: Iterable[Package],
        package_advisories: PackageAdvisories,
    ) -> Vulnerabilities:
        vulnerabilities = Vulnerabilities()

        for package in installed_packages:
            package_advisory_oids = (
                package_advisories.get_package_advisories_for_package(package)
            )
            for oid, package_advisory_list in package_advisory_oids.items():
                vul = self._check_package(package, package_advisory_list)
                if vul and vul.vulnerability:
                    vulnerabilities.add(oid, vul)

        return vulnerabilities

    def run_scan(
        self,
        message: ScanStartMessage,
    ) -> bool:
        """Handle the data necessary to start a scan,
        received via mqtt and run the scan."""

        # Check if all necessary information to run a scan are given
        if not message:
            logger.error("Unable to start scan: The message seems to be empty")
            return True
        if not message.os_release:
            logger.error(
                "Unable to start scan for %s: The field os_release is empty",
                message.host_ip,
            )
            return (
                self._interrupt_host(
                    message.scan_id, message.host_ip, message.group_id
                )
                is None
            )
        if not message.package_list:
            logger.error(
                "Unable to start scan for %s: The field package_list is empty",
                message.host_ip,
            )
            return (
                self._interrupt_host(
                    message.scan_id, message.host_ip, message.group_id
                )
                is None
            )

        # Get advisory information from disk
        try:
            package_advisories = self._loader.load_package_advisories(
                message.os_release
            )
        except AdvisoriesLoadingError as e:
            logger.error("Unable to load package advisories. Error was %s", e)
            return (
                self._interrupt_host(
                    message.scan_id, message.host_ip, message.group_id
                )
                is None
            )

        if not package_advisories:
            # Probably a wrong or not supported OS-release
            logger.error(
                "Unable to start scan for %s: No advisories for OS-release %s"
                " found. Check if the OS-release is correct and the"
                " corresponding advisories are given.",
                message.host_ip,
                message.os_release,
            )
            return (
                self._interrupt_host(
                    message.scan_id, message.host_ip, message.group_id
                )
                is None
            )

        logger.debug(
            "Loaded advisories for %i packages", len(package_advisories)
        )

        # Determine package type
        package_type = package_advisories.package_type

        package_class = package_class_by_type(package_type)
        if not package_class:
            logger.error(
                "Unable to start scan for %s: No package implementation for "
                "OS-release %s found. Check if the OS-release is correct.",
                message.host_ip,
                message.os_release,
            )
            return (
                self._interrupt_host(
                    message.scan_id, message.host_ip, message.group_id
                )
                is None
            )

        may_installed = [
            package_class.from_full_name(name) for name in message.package_list
        ]
        # a package in may_installed can only be None when .from_full_name fails
        # they both log a warning when they're unable to parse that hence it
        # is safe to silently remove them
        installed_packages: Iterable[Package] = (
            package for package in may_installed if package is not None
        )

        publication_error = self._start_host(
            message.scan_id, message.host_ip, message.group_id
        )
        if publication_error:
            return self._handle_publication_failure(message, publication_error)

        logger.info(
            "Start to identify vulnerable packages for %s (%s)",
            message.host_ip,
            message.host_name,
        )
        try:
            vulnerabilities = self._start_scan(
                installed_packages=installed_packages,
                package_advisories=package_advisories,
            )
            result_count, publication_error = self._publish_results(
                message.scan_id,
                message.host_ip,
                message.host_name,
                message.group_id,
                vulnerabilities,
            )

            if publication_error:
                return self._handle_publication_failure(
                    message, publication_error
                )

            logger.info(
                "Total number of vulnerable packages -> %d",
                len(vulnerabilities),
            )

            publication_error = self._finish_host(
                message.scan_id,
                message.host_ip,
                message.group_id,
                result_count,
            )
            if publication_error:
                return self._handle_publication_failure(
                    message, publication_error
                )
            return True

        except AdvisoriesLoadingError as e:
            logger.error(
                "Scan for %s %s with %s could not be started. Error was %s",
                message.host_ip,
                message.host_name or "",
                message.os_release,
                e,
            )
            return (
                self._interrupt_host(
                    message.scan_id, message.host_ip, message.group_id
                )
                is None
            )
