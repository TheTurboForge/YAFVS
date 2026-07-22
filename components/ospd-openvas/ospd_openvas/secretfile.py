# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Strict file-backed secret loading for ospd-openvas."""

import os
import stat

from pathlib import Path
from typing import Optional

from ospd_openvas.errors import OspdOpenvasError

MAX_SECRET_FILE_BYTES = 4096


def read_secret_file(path_value: str) -> str:
    """Read an owner-only regular secret file without following symlinks."""
    path = Path(path_value)
    if not path.is_absolute():
        raise OspdOpenvasError('Secret file path must be absolute')

    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise OspdOpenvasError(
            f'Unable to open secret file {path}: {error.strerror}'
        ) from None

    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OspdOpenvasError('Secret file must be a regular file')
        if metadata.st_uid != os.geteuid():
            raise OspdOpenvasError(
                'Secret file must be owned by the ospd-openvas user'
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise OspdOpenvasError(
                'Secret file must not be accessible by group or other users'
            )
        if metadata.st_size > MAX_SECRET_FILE_BYTES:
            raise OspdOpenvasError('Secret file exceeds the size limit')

        chunks = []
        remaining = MAX_SECRET_FILE_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b''.join(chunks)
        if len(content) > MAX_SECRET_FILE_BYTES or os.read(fd, 1):
            raise OspdOpenvasError('Secret file exceeds the size limit')
    finally:
        os.close(fd)

    try:
        secret = content.decode('utf-8')
    except UnicodeDecodeError:
        raise OspdOpenvasError('Secret file must contain UTF-8 text') from None

    if secret.endswith('\n'):
        secret = secret[:-1]
    if not secret:
        raise OspdOpenvasError('Secret file must not be empty')
    if '\x00' in secret or '\n' in secret or '\r' in secret:
        raise OspdOpenvasError('Secret file must contain exactly one line')
    return secret


def resolve_mqtt_broker_password(
    password: Optional[str], password_file: Optional[str]
) -> Optional[str]:
    """Resolve an MQTT password only from an owner-only file."""
    if password is not None:
        raise OspdOpenvasError(
            'Plaintext MQTT broker passwords are not supported'
        )
    if password_file is not None:
        return read_secret_file(password_file)
    return None
