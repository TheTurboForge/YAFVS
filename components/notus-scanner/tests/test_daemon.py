# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from notus.scanner.daemon import run_daemon
from notus.scanner.messaging.mqtt import NOTUS_MQTT_PUBLISHER_CLIENT_ID


class DaemonTestCase(TestCase):
    def test_daemon_uses_and_stops_a_dedicated_publisher_client(self):
        subscriber_client = mock.MagicMock()
        publisher_client = mock.MagicMock()

        with (
            TemporaryDirectory() as directory,
            mock.patch("notus.scanner.daemon.hashsum_verificator"),
            mock.patch("notus.scanner.daemon.JSONAdvisoriesLoader"),
            mock.patch(
                "notus.scanner.daemon.MQTTClient",
                side_effect=[subscriber_client, publisher_client],
            ) as mqtt_client,
            mock.patch("notus.scanner.daemon.MQTTDaemon"),
            mock.patch(
                "notus.scanner.daemon.MQTTPublisherDaemon"
            ) as publisher_daemon,
            mock.patch("notus.scanner.daemon.MQTTPublisher") as publisher,
            mock.patch("notus.scanner.daemon.MQTTSubscriber") as subscriber,
        ):
            run_daemon(
                "localhost",
                1883,
                "",
                None,
                Path(directory),
                False,
            )

        self.assertEqual(mqtt_client.call_count, 2)
        self.assertTrue(
            mqtt_client.call_args_list[0].kwargs["preserve_session"]
        )
        self.assertEqual(
            mqtt_client.call_args_list[1].kwargs["client_id"],
            NOTUS_MQTT_PUBLISHER_CLIENT_ID,
        )
        publisher_daemon.assert_called_once_with(publisher_client)
        publisher_daemon.return_value.start.assert_called_once_with()
        publisher_daemon.return_value.stop.assert_called_once_with()
        publisher.assert_called_once_with(publisher_client)
        subscriber.assert_called_once_with(subscriber_client)
