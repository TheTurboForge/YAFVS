# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from abc import ABC, abstractmethod

from ..messages.message import Message


class PublishError(RuntimeError):
    """A message publication failure with its terminal-status safety."""

    def __init__(self, reason: str, *, safe_to_interrupt: bool):
        super().__init__(reason)
        self.safe_to_interrupt = safe_to_interrupt


class Publisher(ABC):
    """An Abstract Base Class (ABC) for publishing Messages

    When updating to Python > 3.7 this should be converted into a
    typing.Protocol
    """

    @abstractmethod
    def publish(self, message: Message) -> None:
        raise NotImplementedError()

    @abstractmethod
    def publish_result(self, message: Message, timeout: float) -> None:
        """Publish a result and wait at most timeout seconds for its PUBACK."""
        raise NotImplementedError()
