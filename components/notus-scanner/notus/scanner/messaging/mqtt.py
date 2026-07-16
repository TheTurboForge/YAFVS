# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import logging
from functools import partial
from typing import Callable, Type

import paho.mqtt.client as mqtt
from paho.mqtt import __version__ as paho_mqtt_version

from ..errors import MessageParsingError
from ..messages.message import Message
from .publisher import Publisher, PublishError
from .subscriber import Subscriber

logger = logging.getLogger(__name__)

NOTUS_MQTT_CLIENT_ID = "notus-scanner"
NOTUS_MQTT_PUBLISHER_CLIENT_ID = "notus-scanner-publisher"

QOS_AT_LEAST_ONCE = 1
PUBLISH_ACK_TIMEOUT_SECONDS = 10.0
MQTT_SESSION_EXPIRY_SECONDS = 24 * 60 * 60


def is_paho_mqtt_version_2() -> bool:
    return paho_mqtt_version.startswith("2")


class MQTTClient(mqtt.Client):
    def __init__(
        self,
        mqtt_broker_address: str,
        mqtt_broker_port: int,
        client_id=NOTUS_MQTT_CLIENT_ID,
        preserve_session: bool = False,
    ):
        self._mqtt_broker_address = mqtt_broker_address
        self._mqtt_broker_port = mqtt_broker_port
        self._preserve_session = preserve_session

        mqtt_client_args = {
            "client_id": client_id,
            "protocol": mqtt.MQTTv5,
        }

        if is_paho_mqtt_version_2():
            logger.debug("Using Paho MQTT version 2")
            mqtt_client_args["callback_api_version"] = (
                mqtt.CallbackAPIVersion.VERSION1
            )
        else:
            logger.debug("Using Paho MQTT version 1")

        super().__init__(**mqtt_client_args)
        if preserve_session:
            if not hasattr(self, "manual_ack_set") or not hasattr(self, "ack"):
                raise RuntimeError(
                    "Paho MQTT manual acknowledgement support is required"
                )
            self.manual_ack_set(True)

        self.enable_logger()

    def connect(
        self,
        host=None,
        port=None,
        keepalive=60,
        bind_address="",
        bind_port=0,
        clean_start=None,
        properties=None,
    ):
        if not host:
            host = self._mqtt_broker_address
        if not port:
            port = self._mqtt_broker_port
        if self._preserve_session:
            clean_start = False
            if properties is None:
                properties = mqtt.Properties(mqtt.PacketTypes.CONNECT)
            if getattr(properties, "SessionExpiryInterval", None) is None:
                properties.SessionExpiryInterval = MQTT_SESSION_EXPIRY_SECONDS
            if properties.SessionExpiryInterval <= 0:
                raise ValueError(
                    "MQTT session expiry must preserve unacknowledged work"
                )
        elif clean_start is None:
            clean_start = mqtt.MQTT_CLEAN_START_FIRST_ONLY

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

    def _publish(self, message: Message) -> mqtt.MQTTMessageInfo:
        logger.debug(
            "Publishing %s to %s", type(message).__name__, message.topic
        )
        payload = str(message)
        max_payload_bytes = getattr(
            type(message), "max_payload_bytes", Message.max_payload_bytes
        )
        if len(payload.encode("utf-8")) > max_payload_bytes:
            raise PublishError(
                "MQTT payload exceeds the message byte limit",
                safe_to_interrupt=True,
            )
        publish_info = self._client.publish(
            message.topic, payload, qos=QOS_AT_LEAST_ONCE
        )
        if publish_info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise PublishError(
                f"MQTT publish returned rc={publish_info.rc}",
                safe_to_interrupt=True,
            )
        return publish_info

    def publish(self, message: Message) -> None:
        publish_info = self._publish(message)
        self._wait_for_publish(
            publish_info,
            timeout=PUBLISH_ACK_TIMEOUT_SECONDS,
            kind="message",
        )

    def publish_result(self, message: Message, timeout: float) -> None:
        publish_info = self._publish(message)
        self._wait_for_publish(publish_info, timeout=timeout, kind="result")

    @staticmethod
    def _wait_for_publish(
        publish_info: mqtt.MQTTMessageInfo,
        *,
        timeout: float,
        kind: str,
    ) -> None:
        try:
            publish_info.wait_for_publish(timeout=timeout)
            if not publish_info.is_published():
                raise PublishError(
                    f"MQTT {kind} PUBACK timed out",
                    safe_to_interrupt=False,
                )
        except PublishError:
            raise
        except (RuntimeError, ValueError) as error:
            raise PublishError(
                f"MQTT {kind} PUBACK could not be confirmed",
                safe_to_interrupt=False,
            ) from error


class MQTTSubscriber(Subscriber):
    def __init__(self, client: MQTTClient):
        self._client = client
        # Save the active subscriptions on subscribe() so we can resubscribe
        # after reconnect
        self._subscriptions: dict = {}

        self._client.on_connect = self.on_connect
        self._client.user_data_set(self._subscriptions)

    def subscribe(
        self, message_class: Type[Message], callback: Callable[[Message], bool]
    ) -> None:
        func = partial(self._handle_message, message_class, callback)
        func.__name__ = callback.__name__

        logger.debug("Subscribing to topic %s", message_class.topic)

        self._client.subscribe(message_class.topic, qos=QOS_AT_LEAST_ONCE)
        self._client.message_callback_add(message_class.topic, func)

        self._subscriptions[message_class.topic] = func

    @staticmethod
    def on_connect(_client, _userdata, _flags, rc, _properties):
        if rc == 0:
            # If we previously had active subscription we subscribe to them
            # again because they got lost after a broker disconnect.
            # Userdata was set in __init__()
            if _userdata:
                for topic, func in _userdata.items():
                    _client.subscribe(topic, qos=QOS_AT_LEAST_ONCE)
                    _client.message_callback_add(topic, func)

    @staticmethod
    def _handle_message(
        message_class: Type[Message],
        callback: Callable[[Message], None],
        _client,
        _userdata,
        msg: mqtt.MQTTMessage,
    ) -> None:
        logger.debug("Incoming message for topic %s", msg.topic)

        try:
            # Load message from payload
            message = message_class.load(msg.payload)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
            logger.error(
                "Got MQTT message in non-json format for topic %s.", msg.topic
            )
            MQTTSubscriber._ack_message(_client, msg)
            return
        except MessageParsingError as e:
            logger.error(
                "Could not parse message for topic %s. Error was %s",
                msg.topic,
                e,
            )
            MQTTSubscriber._ack_message(_client, msg)
            return

        try:
            completed = callback(message)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "Notus callback failed for topic %s; message remains "
                "unacknowledged.",
                msg.topic,
            )
            return
        if completed:
            MQTTSubscriber._ack_message(_client, msg)

    @staticmethod
    def _ack_message(client: MQTTClient, msg: mqtt.MQTTMessage) -> None:
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
        self._client = client

        self._client.connect()

    def run(self):
        self._client.loop_forever()


class MQTTPublisherDaemon:
    """Drive the publisher client outside subscriber callbacks."""

    def __init__(self, client: MQTTClient):
        self._client = client
        self._client.connect()

    def start(self) -> None:
        self._client.loop_start()

    def stop(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()
