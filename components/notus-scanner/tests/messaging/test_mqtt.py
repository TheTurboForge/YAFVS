# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from unittest import TestCase, mock
from uuid import UUID

from paho.mqtt import client as mqtt

from notus.scanner.messages.start import ScanStartMessage
from notus.scanner.messaging.mqtt import (
    MQTT_SESSION_EXPIRY_SECONDS,
    PUBLISH_ACK_TIMEOUT_SECONDS,
    MQTTClient,
    MQTTDaemon,
    MQTTPublisher,
    MQTTPublisherDaemon,
    MQTTSubscriber,
)
from notus.scanner.messaging.publisher import PublishError


class MQTTPublisherTestCase(TestCase):
    def test_publish(self):
        client = mock.MagicMock()
        publish_info = client.publish.return_value
        publish_info.rc = mqtt.MQTT_ERR_SUCCESS
        publish_info.is_published.return_value = True
        publisher = MQTTPublisher(client)

        created = datetime.fromtimestamp(1628512774)
        message_id = UUID("63026767-029d-417e-9148-77f4da49f49a")
        group_id = UUID("866350e8-1492-497e-b12b-c079287d51dd")
        message = ScanStartMessage(
            message_id=message_id,
            group_id=group_id,
            created=created,
            scan_id="scan_1",
            host_ip="1.1.1.1",
            host_name="foo",
            os_release="BarOS 1.0",
            package_list=["foo-1.2.3-1.x86_64"],
        )

        publisher.publish(message)

        client.publish.assert_called_with(
            "scanner/package/cmd/notus",
            '{"message_id": "63026767-029d-417e-9148-77f4da49f49a", '
            '"message_type": "scan.start", '
            '"group_id": "866350e8-1492-497e-b12b-c079287d51dd", '
            '"created": 1628512774.0, '
            '"scan_id": "scan_1", '
            '"host_ip": "1.1.1.1", '
            '"host_name": "foo", '
            '"os_release": "BarOS 1.0", '
            '"package_list": ["foo-1.2.3-1.x86_64"]}',
            qos=1,
        )
        publish_info.wait_for_publish.assert_called_once_with(
            timeout=PUBLISH_ACK_TIMEOUT_SECONDS
        )

    def test_publish_result_waits_for_puback(self):
        client = mock.MagicMock()
        publish_info = client.publish.return_value
        publish_info.rc = mqtt.MQTT_ERR_SUCCESS
        publish_info.is_published.return_value = True
        publisher = MQTTPublisher(client)
        message = mock.MagicMock(topic="scanner/scan/info")

        publisher.publish_result(message, timeout=3.0)

        publish_info.wait_for_publish.assert_called_once_with(timeout=3.0)

    def test_publish_result_with_unconfirmed_puback_is_not_interrupt_safe(self):
        client = mock.MagicMock()
        publish_info = client.publish.return_value
        publish_info.rc = mqtt.MQTT_ERR_SUCCESS
        publish_info.is_published.return_value = False
        publisher = MQTTPublisher(client)
        message = mock.MagicMock(topic="scanner/scan/info")

        with self.assertRaises(PublishError) as context:
            publisher.publish_result(message, timeout=3.0)

        self.assertFalse(context.exception.safe_to_interrupt)

    def test_publish_checks_immediate_broker_error(self):
        client = mock.MagicMock()
        client.publish.return_value.rc = mqtt.MQTT_ERR_NO_CONN
        publisher = MQTTPublisher(client)
        message = mock.MagicMock(topic="scanner/scan/info")

        with self.assertRaises(PublishError) as context:
            publisher.publish(message)

        self.assertTrue(context.exception.safe_to_interrupt)


class MQTTSubscriberTestCase(TestCase):
    def test_subscribe(self):
        client = mock.MagicMock()
        callback = mock.MagicMock()
        callback.__name__ = "callback_name"

        subscriber = MQTTSubscriber(client)

        subscriber.subscribe(ScanStartMessage, callback)

        client.subscribe.assert_called_with("scanner/package/cmd/notus", qos=1)

    def test_successful_callback_acknowledges_exact_broker_message(self):
        client = mock.MagicMock()
        client.ack.return_value = mqtt.MQTT_ERR_SUCCESS
        callback = mock.MagicMock(return_value=True)
        message = ScanStartMessage(
            scan_id="scan-1",
            host_ip="192.0.2.1",
            host_name="host",
            os_release="debian_12",
            package_list=["example=1"],
            group_id="run-1",
        )
        broker_message = mock.MagicMock(
            payload=str(message).encode(),
            topic=ScanStartMessage.topic,
            qos=1,
            mid=42,
        )

        MQTTSubscriber._handle_message(
            ScanStartMessage,
            callback,
            client,
            None,
            broker_message,
        )

        callback.assert_called_once()
        client.ack.assert_called_once_with(42, 1)

    def test_incomplete_callback_leaves_start_unacknowledged(self):
        client = mock.MagicMock()
        callback = mock.MagicMock(return_value=False)
        message = ScanStartMessage(
            scan_id="scan-1",
            host_ip="192.0.2.1",
            host_name="host",
            os_release="debian_12",
            package_list=["example=1"],
            group_id="run-1",
        )
        broker_message = mock.MagicMock(
            payload=str(message).encode(),
            topic=ScanStartMessage.topic,
            qos=1,
            mid=42,
        )

        MQTTSubscriber._handle_message(
            ScanStartMessage,
            callback,
            client,
            None,
            broker_message,
        )

        client.ack.assert_not_called()

    def test_poison_payload_is_acknowledged_without_calling_worker(self):
        client = mock.MagicMock()
        client.ack.return_value = mqtt.MQTT_ERR_SUCCESS
        callback = mock.MagicMock()
        broker_message = mock.MagicMock(
            payload=b"\xff",
            topic=ScanStartMessage.topic,
            qos=1,
            mid=43,
        )

        MQTTSubscriber._handle_message(
            ScanStartMessage,
            callback,
            client,
            None,
            broker_message,
        )

        callback.assert_not_called()
        client.ack.assert_called_once_with(43, 1)


class MQTTClientTestCase(TestCase):
    def test_preserved_session_keeps_unacknowledged_start_work(self):
        with mock.patch.object(mqtt.Client, "connect") as connect:
            client = MQTTClient(
                "localhost",
                1883,
                preserve_session=True,
            )
            client.connect()

        self.assertTrue(client._manual_ack)
        self.assertFalse(connect.call_args.kwargs["clean_start"])
        self.assertEqual(
            connect.call_args.kwargs["properties"].SessionExpiryInterval,
            MQTT_SESSION_EXPIRY_SECONDS,
        )


class MQTTDaemonTestCase(TestCase):
    def test_connect(self):
        client = mock.MagicMock()

        # pylint: disable=unused-variable
        daemon = MQTTDaemon(client)  # noqa: F841

        client.connect.assert_called_with()

    def test_run(self):
        client = mock.MagicMock()

        daemon = MQTTDaemon(client)

        daemon.run()

        client.loop_forever.assert_called_with()


class MQTTPublisherDaemonTestCase(TestCase):
    def test_lifecycle(self):
        client = mock.MagicMock()
        daemon = MQTTPublisherDaemon(client)

        daemon.start()
        daemon.stop()

        client.connect.assert_called_once_with()
        client.loop_start.assert_called_once_with()
        client.loop_stop.assert_called_once_with()
        client.disconnect.assert_called_once_with()
