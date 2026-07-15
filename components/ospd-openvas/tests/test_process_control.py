# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for immutable scanner process control."""

import os
import signal
import subprocess
import sys
import unittest

from unittest import TestCase
from unittest.mock import MagicMock, call, patch

from tests.dummydaemon import DummyDaemon


class DirectProcessDaemon(DummyDaemon):
    @property
    def is_running_as_root(self):
        return True

    @property
    def sudo_available(self):
        return False


class PrivilegedProcessDaemon(DummyDaemon):
    @property
    def is_running_as_root(self):
        return False

    @property
    def sudo_available(self):
        return True


class ProcessControlTestCase(TestCase):
    @staticmethod
    def direct_process_daemon():
        return DirectProcessDaemon()

    @patch('ospd_openvas.daemon.Openvas.stop_scan_as_root')
    def test_cleanup_uses_hardened_helper_for_sudo_scan(self, mock_stop):
        daemon = PrivilegedProcessDaemon()
        kbdb = MagicMock()
        events = []
        mock_stop.side_effect = (
            lambda _scan_id: events.append('stopped') or True
        )
        kbdb.get_status.return_value = 'finished'
        kbdb.get_scan_databases.side_effect = (
            lambda: events.append('released') or []
        )

        stopped = daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        mock_stop.assert_called_once_with('scan-1')
        kbdb.get_scan_databases.assert_called_once()
        self.assertEqual(events, ['stopped', 'released'])
        self.assertTrue(stopped)

    @patch('ospd_openvas.daemon.Openvas.stop_scan_as_root')
    def test_unreadable_queue_uses_pinned_pid_for_sudo_stop(self, mock_stop):
        daemon = PrivilegedProcessDaemon()
        mock_stop.return_value = True

        stopped = daemon.stop_scan_process_without_kb('scan-1', 42)

        mock_stop.assert_called_once_with('scan-1', 42)
        self.assertTrue(stopped)

    @patch('ospd_openvas.daemon.Openvas.stop_scan_as_root')
    def test_cleanup_retains_redis_when_privileged_stop_fails(self, mock_stop):
        daemon = PrivilegedProcessDaemon()
        kbdb = MagicMock()
        mock_stop.return_value = False

        stopped = daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        kbdb.get_scan_databases.assert_not_called()
        self.assertFalse(stopped)

    @unittest.skipUnless(
        hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
        'Linux pidfd process control is unavailable',
    )
    def test_pidfd_signal_cannot_escape_the_acquired_process(self):
        process = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(60)']
        )
        process_handle = os.pidfd_open(process.pid)
        try:
            DummyDaemon.signal_openvas_process(process_handle, signal.SIGTERM)
            self.assertTrue(
                DummyDaemon.wait_for_openvas_process_exit(process_handle, 2)
            )
            process.wait(timeout=2)
        finally:
            os.close(process_handle)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    @patch('ospd_openvas.daemon.os.close')
    @patch('ospd_openvas.daemon.os.pidfd_open', create=True)
    @patch('ospd_openvas.daemon.signal.pidfd_send_signal', create=True)
    @patch('ospd_openvas.daemon.psutil.Process')
    def test_cleanup_escalates_only_on_the_acquired_handle(
        self, mock_process, mock_signal, mock_pidfd_open, mock_close
    ):
        daemon = self.direct_process_daemon()
        kbdb = MagicMock()
        process = mock_process.return_value
        process.is_running.return_value = True
        process.name.return_value = 'openvas'
        process.cmdline.return_value = ['openvas', '--scan-start', 'scan-1']
        mock_pidfd_open.return_value = 99
        daemon.wait_for_openvas_process_exit = MagicMock(
            side_effect=[False, False, False, True]
        )

        stopped = daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        mock_pidfd_open.assert_called_once_with(42)
        self.assertEqual(
            mock_signal.call_args_list,
            [
                call(99, signal.SIGUSR1),
                call(99, signal.SIGTERM),
                call(99, signal.SIGKILL),
            ],
        )
        mock_close.assert_called_once_with(99)
        kbdb.get_scan_databases.assert_not_called()
        self.assertFalse(stopped)

    @patch('ospd_openvas.daemon.os.close')
    @patch('ospd_openvas.daemon.os.pidfd_open', create=True)
    @patch('ospd_openvas.daemon.signal.pidfd_send_signal', create=True)
    @patch('ospd_openvas.daemon.psutil.Process')
    def test_cleanup_releases_redis_after_graceful_scanner_exit(
        self, mock_process, mock_signal, mock_pidfd_open, mock_close
    ):
        daemon = self.direct_process_daemon()
        kbdb = MagicMock()
        process = mock_process.return_value
        process.is_running.return_value = True
        process.name.return_value = 'openvas'
        process.cmdline.return_value = ['openvas', '--scan-start', 'scan-1']
        mock_pidfd_open.return_value = 99
        daemon.wait_for_openvas_process_exit = MagicMock(
            side_effect=[False, True]
        )
        kbdb.get_status.return_value = 'finished'

        stopped = daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        mock_signal.assert_called_once_with(99, signal.SIGUSR1)
        mock_close.assert_called_once_with(99)
        kbdb.get_scan_databases.assert_called_once()
        self.assertTrue(stopped)

    @patch('ospd_openvas.daemon.os.close')
    @patch('ospd_openvas.daemon.os.pidfd_open', create=True)
    @patch('ospd_openvas.daemon.signal.pidfd_send_signal', create=True)
    @patch('ospd_openvas.daemon.psutil.Process')
    def test_cleanup_retains_redis_without_clean_completion_marker(
        self, mock_process, _mock_signal, mock_pidfd_open, _mock_close
    ):
        daemon = self.direct_process_daemon()
        kbdb = MagicMock()
        process = mock_process.return_value
        process.is_running.return_value = True
        process.name.return_value = 'openvas'
        process.cmdline.return_value = ['openvas', '--scan-start', 'scan-1']
        mock_pidfd_open.return_value = 99
        daemon.wait_for_openvas_process_exit = MagicMock(
            side_effect=[False, True]
        )
        kbdb.get_status.return_value = 'stop_all'

        stopped = daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        kbdb.get_scan_databases.assert_not_called()
        self.assertFalse(stopped)

    @patch('ospd_openvas.daemon.os.close')
    @patch('ospd_openvas.daemon.os.pidfd_open', create=True)
    @patch('ospd_openvas.daemon.signal.pidfd_send_signal', create=True)
    @patch('ospd_openvas.daemon.psutil.Process')
    def test_cleanup_rejects_a_pid_for_another_scan(
        self, mock_process, mock_signal, mock_pidfd_open, mock_close
    ):
        daemon = self.direct_process_daemon()
        kbdb = MagicMock()
        process = mock_process.return_value
        process.is_running.return_value = True
        process.name.return_value = 'openvas'
        process.cmdline.return_value = ['openvas', '--scan-start', 'other-scan']
        mock_pidfd_open.return_value = 99
        daemon.wait_for_openvas_process_exit = MagicMock(return_value=False)

        daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        mock_signal.assert_not_called()
        mock_close.assert_called_once_with(99)
        kbdb.get_scan_databases.assert_not_called()

    @patch('ospd_openvas.daemon.os.pidfd_open', create=True)
    @patch('ospd_openvas.daemon.signal.pidfd_send_signal', create=True)
    def test_cleanup_fails_closed_without_a_process_handle(
        self, mock_signal, mock_pidfd_open
    ):
        daemon = self.direct_process_daemon()
        kbdb = MagicMock()
        mock_pidfd_open.side_effect = PermissionError('denied')

        daemon.stop_scan_cleanup(kbdb, 'scan-1', '42')

        mock_signal.assert_not_called()
        kbdb.stop_scan.assert_called_once_with('scan-1')
        kbdb.get_scan_databases.assert_not_called()

    @patch('ospd_openvas.daemon.select.poll')
    def test_exit_wait_polls_the_process_handle(self, mock_poll):
        poller = mock_poll.return_value
        poller.poll.return_value = [(99, 1)]

        exited = DummyDaemon.wait_for_openvas_process_exit(99, 0.125)

        poller.register.assert_called_once_with(99, 1)
        poller.poll.assert_called_once_with(125)
        self.assertTrue(exited)
