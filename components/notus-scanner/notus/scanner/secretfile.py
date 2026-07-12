# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Strict file-backed secret loading for Notus Scanner."""

import os
import stat

from pathlib import Path

from .errors import ConfigFileError

MAX_SECRET_FILE_BYTES = 4096


def _validate_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigFileError("Secret file must be a regular file")
    if metadata.st_uid != os.geteuid():
        raise ConfigFileError(
            "Secret file must be owned by the Notus Scanner user"
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ConfigFileError(
            "Secret file must not be accessible by group or other users"
        )
    if metadata.st_size > MAX_SECRET_FILE_BYTES:
        raise ConfigFileError("Secret file exceeds the size limit")


def _read_content(descriptor: int) -> bytes:
    chunks = []
    remaining = MAX_SECRET_FILE_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    if len(content) > MAX_SECRET_FILE_BYTES or os.read(descriptor, 1):
        raise ConfigFileError("Secret file exceeds the size limit")
    return content


def _decode_secret(content: bytes) -> str:
    try:
        secret = content.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigFileError("Secret file must contain UTF-8 text") from None
    if secret.endswith("\n"):
        secret = secret[:-1]
    if not secret:
        raise ConfigFileError("Secret file must not be empty")
    if "\x00" in secret or "\n" in secret or "\r" in secret:
        raise ConfigFileError("Secret file must contain exactly one line")
    return secret


def read_secret_file(path_value: str) -> str:
    """Read an owner-only regular secret file without following symlinks."""
    path = Path(path_value)
    if not path.is_absolute():
        raise ConfigFileError("Secret file path must be absolute")

    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise ConfigFileError(
            f"Unable to open secret file {path}: {error.strerror}"
        ) from None

    try:
        metadata = os.fstat(descriptor)
        _validate_metadata(metadata)
        content = _read_content(descriptor)
    finally:
        os.close(descriptor)

    return _decode_secret(content)
