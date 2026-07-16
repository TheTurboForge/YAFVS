# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import logging
from functools import partial
from socket import gaierror, timeout
from threading import Thread
from time import sleep
from typing import Callable, Optional, Type

import paho.mqtt.client as mqtt
from paho.mqtt import __version__ as paho_mqtt_version

from ..messages.message import Message, MessagePayloadTooLarge
from .publisher import Publisher
from .subscriber import Subscriber

logger = logging.getLogger(__name__)

OSPD_OPENVAS_MQTT_CLIENT_ID = "ospd-openvas"

QOS_AT_LEAST_ONCE = 1
MQTT_SESSION_EXPIRY_SECONDS = 24 * 60 * 60


def is_paho_mqtt_version_2() -> bool:
    return paho_mqtt_version.startswith("2")


class MQTTClient(mqtt.Client):
    def __init__(
        self,
        mqtt_broker_address: str,
        mqtt_broker_port: int,
        client_id=OSPD_OPENVAS_MQTT_CLIENT_ID,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self._mqtt_broker_address = mqtt_broker_address
        self._mqtt_broker_port = mqtt_broker_port

        mqtt_client_args = {
            "client_id": client_id,
            "protocol": mqtt.MQTTv5,
        }

        if is_paho_mqtt_version_2():
            logger.debug("Using Paho MQTT version 2")
            # pylint: disable=no-member
            mqtt_client_args["callback_api_version"] = (
                mqtt.CallbackAPIVersion.VERSION1
            )
        else:
            logger.debug("Using Paho MQTT version 1")

        super().__init__(**mqtt_client_args)
        if not hasattr(self, 'manual_ack_set') or not hasattr(self, 'ack'):
            raise RuntimeError(
                'Paho MQTT manual acknowledgement support is required'
            )
        self.manual_ack_set(True)
        if username and password:
            self.username_pw_set(username, password)

        self.enable_logger()

    def connect(
        self,
        host=None,
        port=None,
        keepalive=60,
        bind_address="",
        bind_port=0,
        clean_start=False,
        properties=None,
    ):
        if not host:
            host = self._mqtt_broker_address
        if not port:
            port = self._mqtt_broker_port
        if properties is None:
            properties = mqtt.Properties(mqtt.PacketTypes.CONNECT)
        if getattr(properties, 'SessionExpiryInterval', None) is None:
            properties.SessionExpiryInterval = MQTT_SESSION_EXPIRY_SECONDS
        if properties.SessionExpiryInterval <= 0:
            raise ValueError(
                'MQTT session expiry must preserve unacknowledged results'
            )

        return super().connect(
            host,
            port=port,
            keepalive=keepalive,
            bind_address=bind_address,
            bind_port=bind_port,
            clean_start=clean_start,
            properties=properties,
        )


class MQTTPublisher(Publisher):
    def __init__(self, client: MQTTClient):
        self._client = client

    def publish(self, message: Message) -> None:
        logger.debug('Publish message %s', message)
        self._client.publish(message.topic, str(message), qos=QOS_AT_LEAST_ONCE)


class MQTTSubscriber(Subscriber):
    def __init__(self, client: MQTTClient):
        self.client = client
        # Save the active subscriptions on subscribe() so we can resubscribe
        # after reconnect
        self.subscriptions: dict = {}

        self.client.on_connect = self.on_connect
        self.client.user_data_set(self.subscriptions)

    def subscribe(
        self,
        message_class: Type[Message],
        callback: Callable[[Message], bool],
        malformed_callback: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        func = partial(
            self._handle_message,
            message_class,
            callback,
            malformed_callback=malformed_callback,
        )
        func.__name__ = callback.__name__

        logger.debug("Subscribing to topic %s", message_class.topic)

        self.client.subscribe(message_class.topic, qos=QOS_AT_LEAST_ONCE)
        self.client.message_callback_add(message_class.topic, func)

        self.subscriptions[message_class.topic] = func

    @staticmethod
    def on_connect(_client, _userdata, _flags, rc, _properties):
        if rc == 0:
            # If we previously had active subscription we subscribe to them
            # again because they got lost after a broker disconnect.
            # Userdata is set in __init__() and filled in subscribe()
            if _userdata:
                for topic, func in _userdata.items():
                    _client.subscribe(topic, qos=QOS_AT_LEAST_ONCE)
                    _client.message_callback_add(topic, func)

    @staticmethod
    def _handle_message(
        message_class: Type[Message],
        callback: Callable[[Message], bool],
        client,
        _userdata,
        msg: mqtt.MQTTMessage,
        *,
        malformed_callback: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        logger.debug("Incoming message for topic %s", msg.topic)

        try:
            # Load message from payload
            message = message_class.load(msg.payload)
        except MessagePayloadTooLarge:
            logger.error(
                "Rejecting oversized MQTT message for topic %s.", msg.topic
            )
            MQTTSubscriber._ack_message(client, msg)
            return
        except json.JSONDecodeError:
            logger.error(
                "Got MQTT message in non-json format for topic %s.", msg.topic
            )
            MQTTSubscriber._ack_message(client, msg)
            return
        except (AttributeError, OverflowError, TypeError, ValueError):
            logger.error(
                "Could not parse malformed message for topic %s.",
                msg.topic,
            )
            scan_id = MQTTSubscriber._safe_scan_id(msg.payload)
            if scan_id is not None and malformed_callback is not None:
                try:
                    handled = malformed_callback(
                        scan_id, 'Malformed Notus MQTT envelope.'
                    )
                except Exception:  # pylint: disable=broad-exception-caught
                    logger.exception(
                        "Malformed MQTT message handling failed for topic %s; "
                        "message remains unacknowledged.",
                        msg.topic,
                    )
                    return
                if not handled:
                    return
            MQTTSubscriber._ack_message(client, msg)
            return

        try:
            admitted = callback(message)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "MQTT callback failed for topic %s; message remains "
                "unacknowledged.",
                msg.topic,
            )
            return
        if admitted:
            MQTTSubscriber._ack_message(client, msg)

    @staticmethod
    def _safe_scan_id(payload) -> Optional[str]:
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        scan_id = data.get('scan_id')
        if (
            not isinstance(scan_id, str)
            or not scan_id
            or len(scan_id) > 128
            or not scan_id.isprintable()
        ):
            return None
        return scan_id

    @staticmethod
    def _ack_message(client, msg: mqtt.MQTTMessage) -> None:
        if msg.qos == 0:
            return
        outcome = client.ack(msg.mid, msg.qos)
        if outcome != mqtt.MQTT_ERR_SUCCESS:
            logger.warning(
                "MQTT broker acknowledgement failed for topic %s.", msg.topic
            )


class MQTTDaemon:
    """A class to start and stop the MQTT client"""

    def __init__(
        self,
        client: MQTTClient,
    ):
        self._client: MQTTClient = client

    def _try_connect_loop(self):
        while True:
            try:
                self._client.connect()
                self._client.loop_start()
                logger.info("Successfully connected to MQTT broker")
                return
            except (gaierror, ValueError) as e:
                logger.error(
                    "Could not connect to MQTT broker, error was: %s."
                    " Unable to get results from Notus.",
                    e,
                )
                return
            # ConnectionRefusedError - when mqtt declines connection
            # timeout - when address is not reachable
            # OSError - in container when address cannot be assigned
            except (ConnectionRefusedError, timeout, OSError) as e:
                logger.warning(
                    "Could not connect to MQTT broker, error was: %s."
                    " Trying again in 10s.",
                    e,
                )
                sleep(10)

    def run(self):
        Thread(target=self._try_connect_loop, daemon=True).start()
