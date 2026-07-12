# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for strict file-backed secret loading."""

import os
import tempfile
import unittest

from pathlib import Path

from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.secretfile import (
    MAX_SECRET_FILE_BYTES,
    read_secret_file,
    resolve_mqtt_broker_password,
)


class SecretFileTestCase(unittest.TestCase):
    def create_secret(self, root: Path, content: bytes) -> Path:
        path = root / 'secret'
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def test_reads_owner_only_utf8_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'secret value\n')
            self.assertEqual(read_secret_file(str(path)), 'secret value')

    def test_preserves_whitespace_other_than_one_line_ending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'  secret  \n')
            self.assertEqual(read_secret_file(str(path)), '  secret  ')

    def test_rejects_crlf_line_ending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'secret\r\n')
            with self.assertRaisesRegex(OspdOpenvasError, 'one line'):
                read_secret_file(str(path))

    def test_rejects_relative_path(self):
        with self.assertRaisesRegex(OspdOpenvasError, 'absolute'):
            read_secret_file('secret')

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self.create_secret(root, b'secret')
            link = root / 'link'
            link.symlink_to(target)
            with self.assertRaisesRegex(OspdOpenvasError, 'Unable to open'):
                read_secret_file(str(link))

    def test_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'secret')
            path.chmod(0o640)
            with self.assertRaisesRegex(OspdOpenvasError, 'group or other'):
                read_secret_file(str(path))

    def test_rejects_embedded_line_break(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'first\nsecond')
            with self.assertRaisesRegex(OspdOpenvasError, 'one line'):
                read_secret_file(str(path))

    def test_rejects_empty_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'\n')
            with self.assertRaisesRegex(OspdOpenvasError, 'must not be empty'):
                read_secret_file(str(path))

    def test_rejects_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'\xff')
            with self.assertRaisesRegex(OspdOpenvasError, 'UTF-8'):
                read_secret_file(str(path))

    def test_rejects_oversized_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(
                Path(tmp), b'x' * (MAX_SECRET_FILE_BYTES + 1)
            )
            with self.assertRaisesRegex(OspdOpenvasError, 'size limit'):
                read_secret_file(str(path))

    def test_resolves_file_and_rejects_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'from-file')
            self.assertEqual(
                resolve_mqtt_broker_password(None, str(path)), 'from-file'
            )
            self.assertIsNone(resolve_mqtt_broker_password(None, None))
            with self.assertRaisesRegex(OspdOpenvasError, 'not supported'):
                resolve_mqtt_broker_password('inline', str(path))
            with self.assertRaisesRegex(OspdOpenvasError, 'not supported'):
                resolve_mqtt_broker_password('inline', None)

    def test_rejects_non_owner(self):
        if os.geteuid() != 0:
            self.skipTest('changing file ownership requires root')
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b'secret')
            os.chown(path, 1, -1)
            with self.assertRaisesRegex(OspdOpenvasError, 'owned'):
                read_secret_file(str(path))
