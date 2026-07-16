# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import sys
from pathlib import Path
from typing import Callable, Dict, Optional

from .__version__ import __version__
from .cli import CliParser
from .errors import AdvisoriesLoadingError, Sha256SumLoadingError
from .loader import JSONAdvisoriesLoader
from .loader.gpg_sha_verifier import (
    ReloadConfiguration,
    VerificationResult,
    create_verify,
    reload_sha256sums,
)
from .messages.start import ScanStartMessage
from .messaging.mqtt import (
    NOTUS_MQTT_PUBLISHER_CLIENT_ID,
    MQTTClient,
    MQTTDaemon,
    MQTTPublisher,
    MQTTPublisherDaemon,
    MQTTSubscriber,
)
from .scanner import NotusScanner
from .secretfile import read_secret_file
from .utils import (
    create_pid,
    go_to_background,
    init_logging,
    init_signal_handler,
)

logger = logging.getLogger(__name__)


def hashsum_verificator(
    products_directory_path: Path, disable: bool
) -> Callable[[Path], VerificationResult]:
    if disable:
        logger.info("hashsum verification is disabled")
        return lambda _: VerificationResult.SUCCESS

    def on_hash_sum_verification_failure(
        _: Optional[Dict[str, str]],
    ) -> Dict[str, str]:
        raise Sha256SumLoadingError(
            f"Unable to verify signature of {sha_sum_file_path}"
        )

    sha_sum_file_path = products_directory_path / "sha256sums"
    sha_sum_reload_config = ReloadConfiguration(
        hash_file=sha_sum_file_path,
        on_verification_failure=on_hash_sum_verification_failure,
    )

    sums = reload_sha256sums(sha_sum_reload_config)
    return create_verify(sums)


def run_daemon(
    mqtt_broker_address: str,
    mqtt_broker_port: int,
    mqtt_broker_username: str,
    mqtt_broker_password: Optional[str],
    products_directory_path: Path,
    disable_hashsum_verification: bool,
):
    """Initialize the mqtt client, mqtt handler, notus scanner and run
    forever
    """

    if not products_directory_path.is_dir():
        raise AdvisoriesLoadingError(
            f"Can't load advisories. {products_directory_path.absolute()} is"
            " not a directory."
        )

    verifier = hashsum_verificator(
        products_directory_path, disable_hashsum_verification
    )

    loader = JSONAdvisoriesLoader(
        advisories_directory_path=products_directory_path, verify=verifier
    )
    client = MQTTClient(
        mqtt_broker_address=mqtt_broker_address,
        mqtt_broker_port=mqtt_broker_port,
        preserve_session=True,
    )
    if mqtt_broker_username and mqtt_broker_password:
        client.username_pw_set(mqtt_broker_username, mqtt_broker_password)

    publisher_client = MQTTClient(
        mqtt_broker_address=mqtt_broker_address,
        mqtt_broker_port=mqtt_broker_port,
        client_id=NOTUS_MQTT_PUBLISHER_CLIENT_ID,
    )
    if mqtt_broker_username and mqtt_broker_password:
        publisher_client.username_pw_set(
            mqtt_broker_username, mqtt_broker_password
        )

    daemon: MQTTDaemon
    try:
        daemon = MQTTDaemon(client)
    except ConnectionRefusedError:
        logger.error(
            "Could not connect to MQTT broker at %s. Connection refused.",
            mqtt_broker_address,
        )
        sys.exit(1)

    try:
        publisher_daemon = MQTTPublisherDaemon(publisher_client)
    except ConnectionRefusedError:
        logger.error(
            "Could not connect publisher to MQTT broker at %s. Connection refused.",
            mqtt_broker_address,
        )
        sys.exit(1)

    try:
        publisher_daemon.start()
        publisher = MQTTPublisher(publisher_client)
        scanner = NotusScanner(loader=loader, publisher=publisher)

        subscriber = MQTTSubscriber(client)
        subscriber.subscribe(ScanStartMessage, scanner.run_scan)

        daemon.run()
    finally:
        publisher_daemon.stop()


def main():
    parser = CliParser()
    args = parser.parse_arguments()

    init_logging(
        "notus-scanner",
        args.log_level,
        log_file=args.log_file,
        foreground=args.foreground,
    )

    if not args.foreground:
        go_to_background()

    if not create_pid(args.pid_file):
        sys.exit()

    init_signal_handler(args.pid_file)

    logger.info("Starting notus-scanner version %s.", __version__)

    run_daemon(
        args.mqtt_broker_address,
        args.mqtt_broker_port,
        args.mqtt_broker_username,
        (
            read_secret_file(args.mqtt_broker_password_file)
            if args.mqtt_broker_password_file
            else None
        ),
        args.products_directory,
        args.disable_hashsum_verification,
    )


if __name__ == "__main__":
    main()
