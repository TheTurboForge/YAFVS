# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, call, patch

from greenbone.feed.sync.config import DEFAULT_FEED_RELEASE
from greenbone.feed.sync.errors import (
    ConfigError,
    GreenboneFeedSyncError,
    RsyncError,
)
from greenbone.feed.sync.main import (
    Sync,
    do_selftest,
    feed_sync,
    filter_syncs,
    main,
)


@contextmanager
def temp_directory():
    with TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


class FilterSyncsTestCase(unittest.TestCase):
    def test_filter_syncs(self):
        sync_a = Sync(name="a", types=["foo", "bar"], url="a", destination="a")
        sync_b = Sync(name="b", types=["foo", "baz"], url="b", destination="b")
        sync_c = Sync(name="c", types=["bar", "baz"], url="c", destination="c")

        sync_list = filter_syncs(
            "file.lock",
            "foo",
            sync_a,
            sync_b,
            sync_c,
        )

        self.assertEqual(len(sync_list.syncs), 2)
        self.assertEqual(sync_list.lock_file, "file.lock")

        self.assertEqual(sync_list.syncs[0], sync_a)
        self.assertEqual(sync_list.syncs[1], sync_b)


class DoSelftestTestCase(unittest.TestCase):
    @patch("greenbone.feed.sync.main.subprocess.run")
    def test_do_selftest_success(self, mock_subprocess_run: MagicMock):
        mock_subprocess_run.side_effect = [""]
        do_selftest()

    @patch("greenbone.feed.sync.main.subprocess.run")
    def test_do_selftest_rsync_fail(self, mock_subprocess_run: MagicMock):
        mock_subprocess_run.side_effect = [PermissionError]
        with self.assertRaisesRegex(
            GreenboneFeedSyncError, "The rsync binary could not be found."
        ):
            do_selftest()


class FeedSyncTestCase(unittest.IsolatedAsyncioTestCase):
    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    @patch("greenbone.feed.sync.main.change_user_and_group", autospec=True)
    @patch("greenbone.feed.sync.main.is_root", autospec=True)
    async def test_do_not_run_as_root(
        self,
        is_root_mock: MagicMock,
        change_user_mock: MagicMock,
        rsync_mock: MagicMock,
    ):
        is_root_mock.return_value = True
        console = MagicMock()
        rsync_mock_instance = rsync_mock.return_value

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                [
                    "greenbone-feed-sync",
                    "--type",
                    "nvt",
                ],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)
            self.assertEqual(ret, 0)

        change_user_mock.assert_called_once_with("gvm", "gvm")
        rsync_mock.assert_called_once_with(
            private_subdir=None,
            verbose=False,
            compression_level=9,
            timeout=None,
        )
        console.print.assert_has_calls(
            [
                call(
                    "Trying to acquire lock on "
                    f"{temp_dir}/openvas/feed-update.lock"
                ),
                call(f"Acquired lock on {temp_dir}/openvas/feed-update.lock"),
                call(f"Releasing lock on {temp_dir}/openvas/feed-update.lock"),
                call(),
            ]
        )
        rsync_mock_instance.close.assert_called_once_with()
        rsync_mock_instance.sync.assert_has_awaits(
            [
                call(
                    url="rsync://feed.community.greenbone.net/community/"
                    f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                    destination=temp_dir / "notus",
                ),
                call(
                    url="rsync://feed.community.greenbone.net/community/"
                    f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/nasl/",
                    destination=temp_dir / "openvas/plugins",
                ),
            ]
        )

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    @patch("greenbone.feed.sync.main.change_user_and_group", autospec=True)
    @patch("greenbone.feed.sync.main.is_root", autospec=True)
    async def test_quiet_mode_still_drops_root_privileges(
        self,
        is_root_mock: MagicMock,
        change_user_mock: MagicMock,
        rsync_mock: MagicMock,
    ):
        is_root_mock.return_value = True
        console = MagicMock()

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                ["greenbone-feed-sync", "--type", "nvt", "--quiet"],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)

        self.assertEqual(ret, 0)
        change_user_mock.assert_called_once_with("gvm", "gvm")
        console.print.assert_not_called()
        rsync_mock.return_value.close.assert_called_once_with()

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    @patch("greenbone.feed.sync.main.is_root", autospec=True)
    async def test_rsync_timeout_is_forwarded(
        self,
        is_root_mock: MagicMock,
        rsync_mock: MagicMock,
    ):
        is_root_mock.return_value = False
        console = MagicMock()
        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                [
                    "greenbone-feed-sync",
                    "--type",
                    "nvt",
                    "--rsync-timeout",
                    "120",
                ],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)

        self.assertEqual(ret, 0)
        rsync_mock.assert_called_once_with(
            private_subdir=None,
            verbose=False,
            compression_level=9,
            timeout=120,
        )
        rsync_mock.return_value.close.assert_called_once_with()

    @patch("greenbone.feed.sync.main.do_selftest", autospec=True)
    @patch("greenbone.feed.sync.main.is_root", autospec=True)
    async def test_invalid_source_fails_before_destination_or_logging(
        self,
        is_root_mock: MagicMock,
        _selftest_mock: MagicMock,
    ):
        is_root_mock.return_value = False
        console = MagicMock()
        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                [
                    "greenbone-feed-sync",
                    "--type",
                    "nvt",
                    "--nasl-url",
                    "https://feed.example/nasl",
                ],
            ),
            self.assertRaises(ConfigError),
        ):
            await feed_sync(console=console, error_console=console)

        self.assertFalse((temp_dir / "notus").exists())
        self.assertFalse((temp_dir / "openvas" / "plugins").exists())
        console.print.assert_not_called()

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    @patch("greenbone.feed.sync.main.is_root", autospec=True)
    async def test_private_ssh_trust_is_forwarded_and_preflighted(
        self,
        is_root_mock: MagicMock,
        rsync_mock: MagicMock,
    ):
        is_root_mock.return_value = False
        console = MagicMock()
        rsync_mock_instance = rsync_mock.return_value

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {
                    "GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir),
                    "GREENBONE_FEED_SYNC_URL": "ssh://feed-user@feed.example",
                    "GREENBONE_FEED_SYNC_SSH_KEY": "/run/secrets/feed-key",
                    "GREENBONE_FEED_SYNC_SSH_KNOWN_HOSTS": (
                        "/etc/turbovas/feed-known-hosts"
                    ),
                },
            ),
            patch.object(
                sys,
                "argv",
                ["greenbone-feed-sync", "--type", "nvt"],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)

        self.assertEqual(ret, 0)
        rsync_mock.assert_called_once_with(
            private_subdir=None,
            verbose=False,
            compression_level=9,
            timeout=None,
            ssh_key=Path("/run/secrets/feed-key"),
            ssh_known_hosts=Path("/etc/turbovas/feed-known-hosts"),
        )
        expected_urls = [
            "ssh://feed-user@feed.example/vulnerability-feed/"
            f"{DEFAULT_FEED_RELEASE}/vt-data/notus/",
            "ssh://feed-user@feed.example/vulnerability-feed/"
            f"{DEFAULT_FEED_RELEASE}/vt-data/nasl/",
        ]
        rsync_mock_instance.validate_url.assert_has_calls(
            [call(url) for url in expected_urls]
        )
        rsync_mock_instance.sync.assert_has_awaits(
            [
                call(url=expected_urls[0], destination=temp_dir / "notus"),
                call(
                    url=expected_urls[1],
                    destination=temp_dir / "openvas/plugins",
                ),
            ]
        )

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    async def test_sync_nvts(self, rsync_mock: MagicMock):
        console = MagicMock()
        rsync_mock_instance = rsync_mock.return_value

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                [
                    "greenbone-feed-sync",
                    "--type",
                    "nvt",
                ],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)
            self.assertEqual(ret, 0)

            rsync_mock.assert_called_once_with(
                private_subdir=None,
                verbose=False,
                compression_level=9,
                timeout=None,
            )
            console.print.assert_has_calls(
                [
                    call(
                        "Trying to acquire lock on "
                        f"{temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Acquired lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Releasing lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(),
                ]
            )

            rsync_mock_instance.sync.assert_has_awaits(
                [
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                        destination=temp_dir / "notus",
                    ),
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/nasl/",
                        destination=temp_dir / "openvas/plugins",
                    ),
                ]
            )

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    async def test_sync_nvts_verbose(self, rsync_mock: MagicMock):
        console = MagicMock()
        rsync_mock_instance = rsync_mock.return_value

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                ["greenbone-feed-sync", "--type", "nvt", "-vvv"],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)
            self.assertEqual(ret, 0)

            rsync_mock.assert_called_once_with(
                private_subdir=None,
                verbose=True,
                compression_level=9,
                timeout=None,
            )
            console.print.assert_has_calls(
                [
                    call(
                        "Trying to acquire lock on "
                        f"{temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Acquired lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        "Downloading Notus files from "
                        "rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/ "
                        f"to {temp_dir}/notus"
                    ),
                    call(),
                    call(
                        "Downloading NASL files from "
                        "rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/nasl/ "
                        f"to {temp_dir}/openvas/plugins"
                    ),
                    call(),
                    call(
                        f"Releasing lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(),
                ]
            )

            rsync_mock_instance.sync.assert_has_awaits(
                [
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                        destination=temp_dir / "notus",
                    ),
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/nasl/",
                        destination=temp_dir / "openvas/plugins",
                    ),
                ]
            )

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    async def test_sync_nvts_quiet(self, rsync_mock: MagicMock):
        console = MagicMock()
        rsync_mock_instance = rsync_mock.return_value

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                ["greenbone-feed-sync", "--type", "nvt", "--quiet"],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)
            self.assertEqual(ret, 0)

            rsync_mock.assert_called_once_with(
                private_subdir=None,
                verbose=False,
                compression_level=9,
                timeout=None,
            )
            console.print.assert_not_called()

            rsync_mock_instance.sync.assert_has_awaits(
                [
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                        destination=temp_dir / "notus",
                    ),
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/nasl/",
                        destination=temp_dir / "openvas/plugins",
                    ),
                ]
            )

    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    async def test_sync_nvts_rsync_error(self, rsync_mock: MagicMock):
        console = MagicMock()
        rsync_mock_instance = rsync_mock.return_value
        rsync_mock_instance.sync.side_effect = RsyncError(
            2, [], b"An rsync error"
        )

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                ["greenbone-feed-sync", "--type", "nvt", "--fail-fast"],
            ),
        ):
            ret = await feed_sync(console=console, error_console=console)
            self.assertEqual(ret, 1)

            rsync_mock.assert_called_once_with(
                private_subdir=None,
                verbose=False,
                compression_level=9,
                timeout=None,
            )
            console.print.assert_has_calls(
                [
                    call(
                        "Trying to acquire lock on "
                        f"{temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Acquired lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call("An rsync error"),
                    call(
                        f"Releasing lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                ]
            )

            rsync_mock_instance.sync.assert_has_awaits(
                [
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                        destination=temp_dir / "notus",
                    ),
                ]
            )


class MainFunctionTestCase(unittest.TestCase):
    @patch("greenbone.feed.sync.main.Console")
    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    def test_sync_nvts(self, rsync_mock: MagicMock, console_mock: MagicMock):
        rsync_mock_instance = rsync_mock.return_value
        console_mock_instance = console_mock.return_value

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                [
                    "greenbone-feed-sync",
                    "--type",
                    "nvt",
                ],
            ),
        ):
            with self.assertRaises(SystemExit) as cm:
                main()

            self.assertEqual(cm.exception.code, 0)

            rsync_mock.assert_called_once_with(
                private_subdir=None,
                verbose=False,
                compression_level=9,
                timeout=None,
            )
            console_mock_instance.print.assert_has_calls(
                [
                    call(
                        "Trying to acquire lock on "
                        f"{temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Acquired lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Releasing lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(),
                ]
            )

            rsync_mock_instance.sync.assert_has_awaits(
                [
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                        destination=temp_dir / "notus",
                    ),
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/nasl/",
                        destination=temp_dir / "openvas/plugins",
                    ),
                ]
            )

    @patch("greenbone.feed.sync.main.Console")
    @patch("greenbone.feed.sync.main.Rsync", autospec=True)
    def test_sync_nvts_error(
        self, rsync_mock: MagicMock, console_mock: MagicMock
    ):
        rsync_mock_instance = rsync_mock.return_value
        console_mock_instance = console_mock.return_value
        rsync_mock_instance.sync.side_effect = GreenboneFeedSyncError(
            "An error"
        )

        with (
            temp_directory() as temp_dir,
            patch.dict(
                "os.environ",
                {"GREENBONE_FEED_SYNC_DESTINATION_PREFIX": str(temp_dir)},
            ),
            patch.object(
                sys,
                "argv",
                ["greenbone-feed-sync", "--type", "nvt", "--fail-fast"],
            ),
        ):
            with self.assertRaises(SystemExit) as cm:
                main()

            self.assertEqual(cm.exception.code, 1)

            rsync_mock.assert_called_once_with(
                private_subdir=None,
                verbose=False,
                compression_level=9,
                timeout=None,
            )
            console_mock_instance.print.assert_has_calls(
                [
                    call(
                        "Trying to acquire lock on "
                        f"{temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Acquired lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call(
                        f"Releasing lock on {temp_dir}/openvas/feed-update.lock"
                    ),
                    call("[red]❌[/red]Error: An error"),
                ]
            )

            rsync_mock_instance.sync.assert_has_awaits(
                [
                    call(
                        url="rsync://feed.community.greenbone.net/community/"
                        f"vulnerability-feed/{DEFAULT_FEED_RELEASE}/vt-data/notus/",
                        destination=temp_dir / "notus",
                    ),
                ]
            )
