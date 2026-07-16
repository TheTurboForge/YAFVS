# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import time
from datetime import datetime
from uuid import UUID

from unittest import TestCase, mock

from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.messaging.mqtt import (
    MQTT_SESSION_EXPIRY_SECONDS,
    MQTTDaemon,
    MQTTClient,
    MQTTPublisher,
    MQTTSubscriber,
)


class MQTTPublisherTestCase(TestCase):
    def test_publish(self):
        client = mock.MagicMock()
        publisher = MQTTPublisher(client)

        created = datetime.fromtimestamp(1628512774)
        message_id = UUID('63026767-029d-417e-9148-77f4da49f49a')
        group_id = UUID('866350e8-1492-497e-b12b-c079287d51dd')
        message = ResultMessage(
            created=created,
            message_id=message_id,
            group_id=group_id,
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port='42',
            uri='file://foo/bar',
        )

        publisher.publish(message)

        client.publish.assert_called_with(
            'scanner/scan/info',
            '{"message_id": "63026767-029d-417e-9148-77f4da49f49a", '
            '"message_type": "result.scan", '
            '"group_id": "866350e8-1492-497e-b12b-c079287d51dd", '
            '"created": 1628512774.0, '
            '"scan_id": "scan_1", '
            '"host_ip": "1.1.1.1", '
            '"host_name": "foo", '
            '"oid": "1.2.3.4.5", '
            '"value": "A Vulnerability has been found", '
            '"port": "42", '
            '"uri": "file://foo/bar", '
            '"result_type": "ALARM"}',
            qos=1,
        )


class MQTTClientTestCase(TestCase):
    def test_configures_credentials_when_present(self):
        with (
            mock.patch.object(MQTTClient, 'username_pw_set') as set_credentials,
            mock.patch.object(MQTTClient, 'manual_ack_set') as manual_ack,
        ):
            MQTTClient('broker', 1883, 'ospd', 'ospd', 'secret')

        manual_ack.assert_called_once_with(True)
        set_credentials.assert_called_once_with('ospd', 'secret')

    def test_connect_preserves_unacknowledged_broker_session(self):
        client = MQTTClient('broker', 1883, 'ospd')

        with mock.patch(
            'paho.mqtt.client.Client.connect', return_value=0
        ) as connect:
            client.connect()

        connect.assert_called_once()
        self.assertFalse(connect.call_args.kwargs['clean_start'])
        properties = connect.call_args.kwargs['properties']
        self.assertEqual(
            properties.SessionExpiryInterval, MQTT_SESSION_EXPIRY_SECONDS
        )


class MQTTSubscriberTestCase(TestCase):
    @staticmethod
    def message():
        return ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            uri='file://foo/bar',
        )

    def test_subscribe(self):
        client = mock.MagicMock()
        callback = mock.MagicMock()
        callback.__name__ = "callback_name"

        subscriber = MQTTSubscriber(client)

        message = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            uri='file://foo/bar',
        )

        subscriber.subscribe(message, callback)

        client.subscribe.assert_called_with('scanner/scan/info', qos=1)

    def test_acknowledges_only_after_callback_accepts_durable_message(self):
        client = mock.MagicMock()
        client.ack.return_value = 0
        callback = mock.MagicMock(return_value=True)
        mqtt_message = mock.MagicMock(
            payload=self.message().dump().encode(),
            topic='scanner/scan/info',
            qos=1,
            mid=42,
        )

        MQTTSubscriber._handle_message(
            ResultMessage, callback, client, None, mqtt_message
        )

        callback.assert_called_once()
        client.ack.assert_called_once_with(42, 1)

    def test_leaves_message_unacknowledged_after_transient_callback_failure(
        self,
    ):
        client = mock.MagicMock()
        callback = mock.MagicMock(return_value=False)
        mqtt_message = mock.MagicMock(
            payload=self.message().dump().encode(),
            topic='scanner/scan/info',
            qos=1,
            mid=42,
        )

        MQTTSubscriber._handle_message(
            ResultMessage, callback, client, None, mqtt_message
        )

        callback.assert_called_once()
        client.ack.assert_not_called()

    def test_rejects_and_acknowledges_malformed_poison_message(self):
        client = mock.MagicMock()
        client.ack.return_value = 0
        callback = mock.MagicMock()
        mqtt_message = mock.MagicMock(
            payload=b'{"message_id": null}',
            topic='scanner/scan/info',
            qos=1,
            mid=42,
        )

        MQTTSubscriber._handle_message(
            ResultMessage, callback, client, None, mqtt_message
        )

        callback.assert_not_called()
        client.ack.assert_called_once_with(42, 1)

    def test_rejects_oversized_result_before_json_parsing(self):
        client = mock.MagicMock()
        client.ack.return_value = 0
        callback = mock.MagicMock()
        mqtt_message = mock.MagicMock(
            payload=b'{' * (ResultMessage.max_payload_bytes + 1),
            topic='scanner/scan/info',
            qos=1,
            mid=43,
        )

        MQTTSubscriber._handle_message(
            ResultMessage, callback, client, None, mqtt_message
        )

        callback.assert_not_called()
        client.ack.assert_called_once_with(43, 1)

    def test_attributable_malformed_message_requires_durable_handling(self):
        client = mock.MagicMock()
        client.ack.return_value = 0
        callback = mock.MagicMock()
        malformed = mock.MagicMock(side_effect=[False, True])
        mqtt_message = mock.MagicMock(
            payload=b'{"scan_id":"scan_1","message_id":null}',
            topic='scanner/scan/info',
            qos=1,
            mid=42,
        )

        MQTTSubscriber._handle_message(
            ResultMessage,
            callback,
            client,
            None,
            mqtt_message,
            malformed_callback=malformed,
        )
        client.ack.assert_not_called()

        MQTTSubscriber._handle_message(
            ResultMessage,
            callback,
            client,
            None,
            mqtt_message,
            malformed_callback=malformed,
        )

        callback.assert_not_called()
        self.assertEqual(
            malformed.call_args_list,
            [
                mock.call('scan_1', 'Malformed Notus MQTT envelope.'),
                mock.call('scan_1', 'Malformed Notus MQTT envelope.'),
            ],
        )
        client.ack.assert_called_once_with(42, 1)


class MQTTDaemonTestCase(TestCase):
    def test_connect(self):
        client = mock.MagicMock()

        # pylint: disable=unused-variable
        daemon = MQTTDaemon(client)

    def test_run(self):
        client = mock.MagicMock(side_effect=1)
        daemon = MQTTDaemon(client)
        t_ini = time.time()

        daemon.run()
        # In some systems the spawn of the thread can take longer than expected.
        # Therefore, we wait until the thread is spawned or times out.
        while len(client.mock_calls) == 0 and time.time() - t_ini < 10:
            time.sleep(1)

        client.connect.assert_called_with()
        client.loop_start.assert_called_with()
