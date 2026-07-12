# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import asyncio
import os
import shlex
import shutil
import subprocess
import unittest
from asyncio.subprocess import Process
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

from greenbone.feed.sync.errors import ConfigError, RsyncError
from greenbone.feed.sync.rsync import Rsync, exec_rsync

COMMUNITY_TEST_URL = "rsync://feed.community.greenbone.net/community/test-data"


class RsyncTestCase(unittest.IsolatedAsyncioTestCase):
    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_defaults(self, exec_mock: AsyncMock):
        rsync = Rsync()
        await rsync.sync(
            "rsync://feed.community.greenbone.net/community/baz", "/tmp/baz"
        )

        exec_mock.assert_awaited_once_with(
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
            "-q",
            "--compress-level=9",
            "--delete",
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
            "--safe-links",
            "--hard-links",
            "--",
            "rsync://feed.community.greenbone.net/community/baz",
            "/tmp/baz",
        )

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rejects_non_allowlisted_sources_before_destination(
        self, exec_mock: AsyncMock
    ):
        with TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "destination"
            urls = (
                "feed.example:/feed",
                "https://feed.community.greenbone.net/community/feed",
                "file:///tmp/feed",
                "unknown://feed.example/feed",
                "rsync://feed.example/community/feed",
                "rsync://user@feed.community.greenbone.net/community/feed",
                "rsync://user:pass@feed.community.greenbone.net/community/feed",
                "rsync://feed.community.greenbone.net:873/community/feed",
                "rsync://feed.community.greenbone.net:bad/community/feed",
                "rsync://feed.community.greenbone.net/other/feed",
                "rsync://feed.community.greenbone.net/community/feed?option=1",
            )
            for url in urls:
                with self.subTest(url=url), self.assertRaises(ConfigError):
                    await Rsync().sync(url, destination)

            self.assertFalse(destination.exists())
            exec_mock.assert_not_awaited()

    def test_rejects_invalid_timeouts(self):
        for timeout in (-1, 86_401, True):
            with self.subTest(timeout=timeout), self.assertRaises(ConfigError):
                Rsync(timeout=timeout)

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_private_subdir(self, exec_mock: AsyncMock):
        rsync = Rsync(private_subdir="private")
        await rsync.sync(
            "rsync://feed.community.greenbone.net/community/baz", "/tmp/baz"
        )

        exec_mock.assert_awaited_once_with(
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
            "-q",
            "--compress-level=9",
            "--delete",
            "--exclude",
            "private",
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
            "--safe-links",
            "--hard-links",
            "--",
            "rsync://feed.community.greenbone.net/community/baz",
            "/tmp/baz",
        )

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_verbose(self, exec_mock: AsyncMock):
        rsync = Rsync(verbose=True)
        await rsync.sync(
            "rsync://feed.community.greenbone.net/community/baz", "/tmp/baz"
        )

        exec_mock.assert_awaited_once_with(
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
            "-v",
            "--compress-level=9",
            "--delete",
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
            "--safe-links",
            "--hard-links",
            "--",
            "rsync://feed.community.greenbone.net/community/baz",
            "/tmp/baz",
        )

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_compression_level(self, exec_mock: AsyncMock):
        rsync = Rsync(compression_level=1)
        await rsync.sync(
            "rsync://feed.community.greenbone.net/community/baz", "/tmp/baz"
        )

        exec_mock.assert_awaited_once_with(
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
            "-q",
            "--compress-level=1",
            "--delete",
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
            "--safe-links",
            "--hard-links",
            "--",
            "rsync://feed.community.greenbone.net/community/baz",
            "/tmp/baz",
        )

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_exclude(self, exec_mock: AsyncMock):
        rsync = Rsync(exclude=["foo", Path("exclude/this")])
        await rsync.sync(
            "rsync://feed.community.greenbone.net/community/baz", "/tmp/baz"
        )

        exec_mock.assert_awaited_once_with(
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
            "-q",
            "--compress-level=9",
            "--delete",
            "--exclude",
            "foo",
            "--exclude",
            "exclude/this",
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
            "--safe-links",
            "--hard-links",
            "--",
            "rsync://feed.community.greenbone.net/community/baz",
            "/tmp/baz",
        )


class ExecRsyncTestCase(unittest.IsolatedAsyncioTestCase):
    @patch(
        "greenbone.feed.sync.rsync.asyncio.create_subprocess_exec",
        autospec=True,
    )
    async def test_failure(self, exec_mock: AsyncMock):
        process_mock = AsyncMock(spec=Process)
        process_mock.communicate.return_value = (None, b"An error occurred")
        process_mock.wait.return_value = 1
        exec_mock.return_value = process_mock

        with self.assertRaises(RsyncError) as cm:
            await exec_rsync("foo", "bar")

        exec_mock.assert_awaited_once_with(
            "rsync",
            "foo",
            "bar",
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        self.assertEqual(cm.exception.returncode, 1)
        self.assertEqual(cm.exception.stderr, "An error occurred")
        self.assertEqual(cm.exception.cmd, ["rsync", "foo", "bar"])
        self.assertIsNone(cm.exception.stout)
        self.assertEqual(
            str(cm.exception),
            "'rsync foo bar' returned non-zero exit status 1.",
        )

    @patch(
        "greenbone.feed.sync.rsync.asyncio.create_subprocess_exec",
        autospec=True,
    )
    async def test_success(self, exec_mock: AsyncMock):
        process_mock = AsyncMock(spec=Process)
        process_mock.communicate.return_value = (None, None)
        process_mock.wait.return_value = 0
        exec_mock.return_value = process_mock

        await exec_rsync("foo", "bar")

        exec_mock.assert_awaited_once_with(
            "rsync",
            "foo",
            "bar",
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_timeout(self, exec_mock: AsyncMock):
        rsync = Rsync(timeout=120)
        await rsync.sync(
            "rsync://feed.community.greenbone.net/community/baz", "/tmp/baz"
        )

        exec_mock.assert_awaited_once_with(
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
            "--timeout=120",
            "-q",
            "--compress-level=9",
            "--delete",
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
            "--safe-links",
            "--hard-links",
            "--",
            "rsync://feed.community.greenbone.net/community/baz",
            "/tmp/baz",
        )

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_rsync_with_ssh(self, exec_mock: AsyncMock):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ssh_key = root / "private key's value"
            ssh_key.write_text("private key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            known_hosts = root / "known hosts"
            known_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )
            known_hosts.chmod(0o644)
            ambient_home = root / "ambient-home"
            (ambient_home / ".ssh").mkdir(parents=True)
            ambient_config = ambient_home / ".ssh" / "config"
            ambient_config.write_text(
                "Host *\n  ProxyCommand unsafe-command\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "HOME": str(ambient_home),
                    "SSH_AUTH_SOCK": str(root / "ambient-agent"),
                },
            ):
                rsync = Rsync(
                    ssh_key=ssh_key,
                    ssh_known_hosts=known_hosts,
                )
            ssh_key.write_text("replacement key\n", encoding="utf-8")
            known_hosts.write_text(
                "replacement.example ssh-ed25519 BBBB\n",
                encoding="utf-8",
            )
            await rsync.sync(
                "ssh://user@foo.bar:2222/baz", root / "destination"
            )

            args = exec_mock.await_args.args
            self.assertEqual(
                args,
                (
                    "--links",
                    "--times",
                    "--omit-dir-times",
                    "--recursive",
                    "--progress",
                    "-e",
                    args[6],
                    "-q",
                    "--compress-level=9",
                    "--delete",
                    "--perms",
                    "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
                    "--safe-links",
                    "--hard-links",
                    "--",
                    "user@foo.bar:/baz",
                    str((root / "destination").absolute()),
                ),
            )
            self.assertEqual(
                shlex.split(args[6])[:3],
                ["ssh", "-F", "/dev/null"],
            )
            ssh_args = shlex.split(args[6])
            self.assertIn("BatchMode=yes", ssh_args)
            self.assertIn("IdentitiesOnly=yes", ssh_args)
            self.assertIn("StrictHostKeyChecking=yes", ssh_args)
            self.assertIn("GlobalKnownHostsFile=/dev/null", ssh_args)
            self.assertIn("UpdateHostKeys=no", ssh_args)
            self.assertIn("VerifyHostKeyDNS=no", ssh_args)
            self.assertIn("ProxyCommand=none", ssh_args)
            self.assertIn("ProxyJump=none", ssh_args)
            snapshot_key = Path(ssh_args[ssh_args.index("-i") + 1])
            known_hosts_option = next(
                value
                for value in ssh_args
                if value.startswith("UserKnownHostsFile=")
            )
            snapshot_known_hosts = Path(
                known_hosts_option.removeprefix("UserKnownHostsFile=")
            )
            self.assertNotEqual(snapshot_key, ssh_key)
            self.assertNotEqual(snapshot_known_hosts, known_hosts)
            self.assertEqual(
                snapshot_key.read_text(encoding="utf-8"), "private key\n"
            )
            self.assertEqual(
                snapshot_known_hosts.read_text(encoding="utf-8"),
                "foo.bar ssh-ed25519 AAAA\n",
            )
            self.assertNotIn("StrictHostKeyChecking=no", args[6])
            self.assertNotIn("UserKnownHostsFile=/dev/null", args[6])
            self.assertNotIn(str(ambient_config), args[6])
            self.assertNotIn("unsafe-command", args[6])
            snapshot_root = snapshot_key.parent
            rsync.close()
            self.assertFalse(snapshot_root.exists())

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_ssh_requires_both_trust_files(self, exec_mock: AsyncMock):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ssh_key = root / "id"
            ssh_key.write_text("private key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            known_hosts = root / "known_hosts"
            known_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )

            with self.assertRaises(ConfigError):
                Rsync(ssh_key=ssh_key)
            with self.assertRaises(ConfigError):
                Rsync(ssh_known_hosts=known_hosts)
            with self.assertRaises(ConfigError):
                await Rsync().sync("ssh://user@foo.bar/feed", root / "dest")

            self.assertFalse((root / "dest").exists())
            exec_mock.assert_not_awaited()

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_ssh_rejects_unsafe_trust_paths(self, exec_mock: AsyncMock):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ssh_key = root / "id"
            ssh_key.write_text("private key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            known_hosts = root / "known_hosts"
            known_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )
            empty_known_hosts = root / "empty-known-hosts"
            empty_known_hosts.touch()
            known_hosts_link = root / "known_hosts.link"
            known_hosts_link.symlink_to(known_hosts)

            cases = (
                ("relative-key", known_hosts),
                (root / "missing-key", known_hosts),
                (ssh_key, empty_known_hosts),
                (ssh_key, known_hosts_link),
            )
            for key_path, known_hosts_path in cases:
                with (
                    self.subTest(
                        key_path=key_path,
                        known_hosts_path=known_hosts_path,
                    ),
                    self.assertRaises(ConfigError),
                ):
                    Rsync(
                        ssh_key=key_path,
                        ssh_known_hosts=known_hosts_path,
                    )

            ssh_key.chmod(0o644)
            with self.assertRaises(ConfigError):
                Rsync(ssh_key=ssh_key, ssh_known_hosts=known_hosts)

            ssh_key.chmod(0o600)
            known_hosts.chmod(0o000)
            with self.assertRaises(ConfigError):
                Rsync(ssh_key=ssh_key, ssh_known_hosts=known_hosts)

            self.assertFalse((root / "dest").exists())
            exec_mock.assert_not_awaited()

    def test_ssh_rejects_writable_parent_and_symlink_parent(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            unsafe_parent = root / "unsafe"
            unsafe_parent.mkdir(mode=0o777)
            unsafe_parent.chmod(0o777)
            ssh_key = unsafe_parent / "id"
            ssh_key.write_text("private key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            known_hosts = unsafe_parent / "known_hosts"
            known_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )
            with self.assertRaises(ConfigError):
                Rsync(ssh_key=ssh_key, ssh_known_hosts=known_hosts)

            safe_parent = root / "safe"
            safe_parent.mkdir(mode=0o700)
            safe_key = safe_parent / "id"
            safe_key.write_text("private key\n", encoding="utf-8")
            safe_key.chmod(0o600)
            safe_hosts = safe_parent / "known_hosts"
            safe_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )
            parent_link = root / "parent-link"
            parent_link.symlink_to(safe_parent, target_is_directory=True)
            with self.assertRaises(ConfigError):
                Rsync(
                    ssh_key=parent_link / "id",
                    ssh_known_hosts=parent_link / "known_hosts",
                )

            with (
                patch(
                    "greenbone.feed.sync.rsync.os.geteuid",
                    return_value=os.geteuid() + 1,
                ),
                self.assertRaises(ConfigError),
            ):
                Rsync(ssh_key=safe_key, ssh_known_hosts=safe_hosts)

    @patch("greenbone.feed.sync.rsync.exec_rsync", autospec=True)
    async def test_ssh_rejects_unsafe_urls(self, exec_mock: AsyncMock):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ssh_key = root / "id"
            ssh_key.write_text("private key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            known_hosts = root / "known_hosts"
            known_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )
            known_hosts.chmod(0o644)
            rsync = Rsync(ssh_key=ssh_key, ssh_known_hosts=known_hosts)

            urls = (
                "ssh://bad%20user@foo.bar/feed",
                "ssh://-option@foo.bar/feed",
                "ssh://foo.bar/feed",
                "ssh://user:password@foo.bar/feed",
                "ssh://user@foo_bar/feed",
                "ssh://user@foo.bar/../feed",
                "ssh://user@foo.bar/feed;touch-pwned",
                "ssh://user@foo.bar:0/feed",
                "ssh://user@foo.bar/feed?option=value",
                "rsync+ssh://user@foo.bar/feed",
                "custom+ssh://user@foo.bar/feed",
            )
            for url in urls:
                with self.subTest(url=url), self.assertRaises(ConfigError):
                    await rsync.sync(url, root / "dest")

            self.assertFalse((root / "dest").exists())
            exec_mock.assert_not_awaited()
            rsync.close()

    @patch(
        "greenbone.feed.sync.rsync.asyncio.create_subprocess_exec",
        autospec=True,
    )
    @patch("greenbone.feed.sync.rsync._wait_for_process", autospec=True)
    @patch(
        "greenbone.feed.sync.rsync._wait_for_process_group_empty",
        autospec=True,
    )
    @patch("greenbone.feed.sync.rsync._process_group_exists", autospec=True)
    @patch("greenbone.feed.sync.rsync.os.killpg", autospec=True)
    async def test_cancellation_terminates_and_reaps_rsync(
        self,
        killpg_mock,
        group_exists_mock,
        group_wait_mock: AsyncMock,
        wait_mock: AsyncMock,
        exec_mock: AsyncMock,
    ):
        process_mock = AsyncMock(spec=Process)
        process_mock.pid = 4242
        process_mock.communicate.side_effect = asyncio.CancelledError
        exec_mock.return_value = process_mock
        wait_mock.side_effect = (False, True)
        group_exists_mock.return_value = True
        group_wait_mock.return_value = True

        with self.assertRaises(asyncio.CancelledError):
            await exec_rsync("source", "destination")

        self.assertEqual(
            [call.args for call in killpg_mock.call_args_list],
            [(4242, 15), (4242, 9)],
        )
        self.assertEqual(wait_mock.await_count, 2)
        group_wait_mock.assert_awaited_once_with(4242)


@unittest.skipUnless(shutil.which("rsync"), "rsync is required")
class RsyncIntegrationTestCase(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(shutil.which("ssh"), "ssh is required")
    async def test_ssh_effective_config_uses_only_pinned_trust(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ssh_key = root / "id"
            ssh_key.write_text("private key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            known_hosts = root / "known_hosts"
            known_hosts.write_text(
                "foo.bar ssh-ed25519 AAAA\n", encoding="utf-8"
            )
            known_hosts.chmod(0o644)
            ambient_home = root / "home"
            (ambient_home / ".ssh").mkdir(parents=True)
            (ambient_home / ".ssh" / "config").write_text(
                "Host *\n  ProxyCommand unsafe-command\n",
                encoding="utf-8",
            )
            ambient_config = ambient_home / ".ssh" / "config"
            ambient_result = subprocess.run(
                ["ssh", "-G", "-F", str(ambient_config), "foo.bar"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("unsafe-command", ambient_result.stdout)
            rsync = Rsync(
                ssh_key=ssh_key,
                ssh_known_hosts=known_hosts,
            )
            _, command = rsync._ssh_source_and_command(
                "ssh://user@foo.bar/feed"
            )
            ssh_args = shlex.split(command)
            result = subprocess.run(
                [*ssh_args, "-G", "-l", "user", "foo.bar"],
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "HOME": str(ambient_home)},
            )
            effective = dict(
                line.split(maxsplit=1)
                for line in result.stdout.splitlines()
                if " " in line
            )
            configured_known_hosts = next(
                value.removeprefix("UserKnownHostsFile=")
                for value in ssh_args
                if value.startswith("UserKnownHostsFile=")
            )
            self.assertEqual(effective["user"], "user")
            self.assertEqual(effective["hostname"], "foo.bar")
            self.assertEqual(effective["port"], "24")
            self.assertEqual(effective["stricthostkeychecking"], "true")
            self.assertEqual(effective["updatehostkeys"], "false")
            self.assertEqual(effective["globalknownhostsfile"], "/dev/null")
            self.assertEqual(
                effective["userknownhostsfile"], configured_known_hosts
            )
            self.assertNotIn("unsafe-command", result.stdout)
            rsync.close()

    async def test_unsafe_symlink_target_is_not_copied(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "inside.txt").write_text("inside\n", encoding="utf-8")
            (source / "inside-link").symlink_to("inside.txt")
            (root / "outside.txt").write_text("outside\n", encoding="utf-8")
            (source / "escape").symlink_to("../outside.txt")
            destination = root / "destination"

            await exec_rsync(
                "--links",
                "--recursive",
                "--safe-links",
                "--",
                f"{source}/",
                str(destination),
            )

            self.assertEqual(
                (destination / "inside.txt").read_text(encoding="utf-8"),
                "inside\n",
            )
            self.assertTrue((destination / "inside-link").is_symlink())
            self.assertFalse((destination / "escape").exists())
            self.assertFalse((destination / "escape").is_symlink())

    async def test_cancellation_kills_stubborn_process_group_without_residue(
        self,
    ):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            marker = root / "pids"
            fake_rsync = binary_dir / "rsync"
            fake_rsync.write_text(
                "#!/usr/bin/python3\n"
                "import os, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "    while True: time.sleep(1)\n"
                "with open(os.environ['RSYNC_TEST_MARKER'], 'w') as stream:\n"
                "    stream.write(f'{os.getpid()} {child}\\n')\n"
                "while True: time.sleep(1)\n",
                encoding="utf-8",
            )
            fake_rsync.chmod(0o755)
            env = {
                "PATH": f"{binary_dir}:{os.environ['PATH']}",
                "RSYNC_TEST_MARKER": str(marker),
            }
            with (
                patch.dict(os.environ, env),
                patch(
                    "greenbone.feed.sync.rsync."
                    "RSYNC_PROCESS_GROUP_GRACE_SECONDS",
                    0.1,
                ),
            ):
                task = asyncio.create_task(exec_rsync())
                for _ in range(100):
                    if marker.exists():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(marker.exists())
                pids = [
                    int(value)
                    for value in marker.read_text(encoding="utf-8").split()
                ]
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

            for _ in range(100):
                if all(not Path(f"/proc/{pid}").exists() for pid in pids):
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(
                all(not Path(f"/proc/{pid}").exists() for pid in pids)
            )

    async def test_cancellation_kills_child_after_parent_exits_on_term(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            marker = root / "pids"
            fake_rsync = binary_dir / "rsync"
            fake_rsync.write_text(
                "#!/usr/bin/python3\n"
                "import os, signal, time\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.close(2)\n"
                "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "    while True: time.sleep(1)\n"
                "with open(os.environ['RSYNC_TEST_MARKER'], 'w') as stream:\n"
                "    stream.write(f'{os.getpid()} {child}\\n')\n"
                "while True: time.sleep(1)\n",
                encoding="utf-8",
            )
            fake_rsync.chmod(0o755)
            env = {
                "PATH": f"{binary_dir}:{os.environ['PATH']}",
                "RSYNC_TEST_MARKER": str(marker),
            }
            with (
                patch.dict(os.environ, env),
                patch(
                    "greenbone.feed.sync.rsync."
                    "RSYNC_PROCESS_GROUP_GRACE_SECONDS",
                    0.5,
                ),
            ):
                task = asyncio.create_task(exec_rsync())
                for _ in range(100):
                    if marker.exists():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(marker.exists())
                pids = [
                    int(value)
                    for value in marker.read_text(encoding="utf-8").split()
                ]
                pgid = pids[0]
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

            for _ in range(100):
                if all(not Path(f"/proc/{pid}").exists() for pid in pids):
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(
                all(not Path(f"/proc/{pid}").exists() for pid in pids)
            )
            with self.assertRaises(ProcessLookupError):
                os.killpg(pgid, 0)
