# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for strict file-backed Notus secrets."""

import tempfile
import unittest

from pathlib import Path

from notus.scanner.errors import ConfigFileError
from notus.scanner.secretfile import MAX_SECRET_FILE_BYTES, read_secret_file


class SecretFileTestCase(unittest.TestCase):
    def create_secret(self, root: Path, content: bytes) -> Path:
        path = root / "secret"
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def test_reads_owner_only_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b"secret\n")
            self.assertEqual(read_secret_file(str(path)), "secret")

    def test_rejects_relative_path(self):
        with self.assertRaisesRegex(ConfigFileError, "absolute"):
            read_secret_file("secret")

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self.create_secret(root, b"secret")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(ConfigFileError, "Unable to open"):
                read_secret_file(str(link))

    def test_rejects_broad_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(Path(tmp), b"secret")
            path.chmod(0o640)
            with self.assertRaisesRegex(ConfigFileError, "group or other"):
                read_secret_file(str(path))

    def test_rejects_empty_or_multiline_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = self.create_secret(root, b"\n")
            with self.assertRaisesRegex(ConfigFileError, "must not be empty"):
                read_secret_file(str(empty))
            multiline = self.create_secret(root, b"first\nsecond")
            with self.assertRaisesRegex(ConfigFileError, "one line"):
                read_secret_file(str(multiline))
            crlf = self.create_secret(root, b"secret\r\n")
            with self.assertRaisesRegex(ConfigFileError, "one line"):
                read_secret_file(str(crlf))

    def test_rejects_oversized_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.create_secret(
                Path(tmp), b"x" * (MAX_SECRET_FILE_BYTES + 1)
            )
            with self.assertRaisesRegex(ConfigFileError, "size limit"):
                read_secret_file(str(path))
