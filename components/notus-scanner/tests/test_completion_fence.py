# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from types import SimpleNamespace
from unittest import TestCase, mock

from notus.scanner.messages.message import Message
from notus.scanner.messages.start import ScanStartMessage
from notus.scanner.messages.status import ScanStatus
from notus.scanner.messaging.publisher import Publisher, PublishError
from notus.scanner.scanner import NotusScanner


class FakePublisher(Publisher):
    def __init__(self, result_error=None):
        self.messages = []
        self.result_error = result_error

    def publish(self, message: Message) -> None:
        self.messages.append(message)

    def publish_result(self, message: Message, timeout: float) -> None:
        self.messages.append(message)
        if self.result_error:
            raise self.result_error


class FakeVulnerabilities:
    def __init__(self, entries):
        self._entries = entries

    def get(self):
        return self._entries

    def __len__(self):
        return len(self._entries)


class FakeAdvisories:
    package_type = "test"

    def __len__(self):
        return 1


class CompletionFenceTestCase(TestCase):
    def setUp(self):
        self.publisher = FakePublisher()
        self.loader = mock.MagicMock()
        self.loader.load_package_advisories.return_value = FakeAdvisories()
        self.scanner = NotusScanner(self.loader, self.publisher)
        self.message = ScanStartMessage(
            scan_id="scan-1",
            host_ip="192.0.2.1",
            host_name="host-1",
            os_release="TestOS",
            package_list=["package-1"],
            group_id="scan-group",
        )
        self.package_class = SimpleNamespace(
            from_full_name=lambda _name: SimpleNamespace()
        )

    def run_scan(self, vulnerabilities):
        with (
            mock.patch(
                "notus.scanner.scanner.package_class_by_type",
                return_value=self.package_class,
            ),
            mock.patch.object(
                self.scanner, "_start_scan", return_value=vulnerabilities
            ),
        ):
            return self.scanner.run_scan(self.message)

    def test_zero_results_preserves_group_and_finishes_with_zero_count(self):
        self.assertTrue(self.run_scan(FakeVulnerabilities({})))

        self.assertEqual(len(self.publisher.messages), 2)
        self.assertTrue(
            all(
                message.group_id == "scan-group"
                for message in self.publisher.messages
            )
        )
        running, finished = self.publisher.messages
        self.assertEqual(running.status, ScanStatus.RUNNING)
        self.assertEqual(finished.status, ScanStatus.FINISHED)
        self.assertEqual(finished.result_count, 0)

    def test_result_puback_precedes_finished_and_preserves_group(self):
        package = mock.MagicMock(name="package")
        package.name = "package"
        package.full_name = "package-1"
        fixed = SimpleNamespace(
            symbol="=", package=SimpleNamespace(full_name="package-2")
        )
        vulnerability = SimpleNamespace(get=lambda: {package: [fixed]})
        self.assertTrue(
            self.run_scan(FakeVulnerabilities({"1.2.3": vulnerability}))
        )

        self.assertEqual(len(self.publisher.messages), 3)
        running, result, finished = self.publisher.messages
        self.assertTrue(
            all(
                message.group_id == "scan-group"
                for message in self.publisher.messages
            )
        )
        self.assertEqual(running.status, ScanStatus.RUNNING)
        self.assertEqual(result.group_id, "scan-group")
        self.assertEqual(finished.status, ScanStatus.FINISHED)
        self.assertEqual(finished.result_count, 1)

    def test_safe_result_publication_failure_interrupts_without_finished(self):
        self.publisher.result_error = PublishError(
            "broker disconnected", safe_to_interrupt=True
        )
        package = mock.MagicMock(name="package")
        package.name = "package"
        package.full_name = "package-1"
        fixed = SimpleNamespace(
            symbol="=", package=SimpleNamespace(full_name="package-2")
        )
        vulnerability = SimpleNamespace(get=lambda: {package: [fixed]})
        self.assertTrue(
            self.run_scan(FakeVulnerabilities({"1.2.3": vulnerability}))
        )

        statuses = [
            message.status
            for message in self.publisher.messages
            if hasattr(message, "status")
        ]
        self.assertEqual(statuses, [ScanStatus.RUNNING, ScanStatus.INTERRUPTED])
        self.assertNotIn(ScanStatus.FINISHED, statuses)

    def test_ambiguous_result_publication_failure_withholds_terminal_status(
        self,
    ):
        self.publisher.result_error = PublishError(
            "PUBACK timed out", safe_to_interrupt=False
        )
        package = mock.MagicMock(name="package")
        package.name = "package"
        package.full_name = "package-1"
        fixed = SimpleNamespace(
            symbol="=", package=SimpleNamespace(full_name="package-2")
        )
        vulnerability = SimpleNamespace(get=lambda: {package: [fixed]})
        self.assertFalse(
            self.run_scan(FakeVulnerabilities({"1.2.3": vulnerability}))
        )

        statuses = [
            message.status
            for message in self.publisher.messages
            if hasattr(message, "status")
        ]
        self.assertEqual(statuses, [ScanStatus.RUNNING])

    def test_redelivered_start_uses_stable_status_message_ids(self):
        self.assertTrue(self.run_scan(FakeVulnerabilities({})))
        first_ids = [message.message_id for message in self.publisher.messages]
        self.assertTrue(self.run_scan(FakeVulnerabilities({})))
        second_ids = [
            message.message_id for message in self.publisher.messages[2:]
        ]
        self.assertEqual(second_ids, first_ids)
