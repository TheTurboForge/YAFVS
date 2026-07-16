# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import threading
from unittest import TestCase, mock
from typing import Dict, Optional, Iterator
from uuid import UUID

from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.notus import (
    NOTUS_RESULT_RETRY_SECONDS,
    Cache,
    Notus,
    NotusResultHandler,
)
from ospd.result_spool import ResultSpoolCapacityError


def notus_result(scan_id: str, value: str) -> ResultMessage:
    return ResultMessage(
        scan_id=scan_id,
        host_ip='1.1.1.1',
        host_name='host',
        oid='1.2.3',
        value=value,
    )


class CacheFake(Cache):
    # pylint: disable=super-init-not-called
    def __init__(self):
        self.db = {}
        self.ctx = 'foo'

    def store_advisory(self, oid: str, value: Dict[str, str]):
        self.db[oid] = value

    def replace_advisories(self, advisories: Dict[str, Dict[str, str]]):
        self.db = dict(advisories)

    def exists(self, oid: str) -> bool:
        return True if self.db.get(oid, None) else False

    def get_advisory(self, oid: str) -> Optional[Dict[str, str]]:
        return self.db.get(oid, None)

    def get_keys(self) -> Iterator[str]:
        for key, _ in self.db:
            yield key


class NotusTestCase(TestCase):
    @mock.patch('ospd_openvas.notus.OpenvasDB')
    def test_notus_retrieve(self, mock_openvasdb):
        path_mock = mock.MagicMock()
        redis_mock = mock.MagicMock()
        mock_openvasdb.find_database_by_pattern.return_value = (redis_mock, 1)
        mock_openvasdb.get_filenames_and_oids.return_value = [
            ('filename', '1.2.3')
        ]
        notus = Notus(path_mock, Cache(redis_mock))
        notus._verifier = lambda _: True  # pylint: disable=protected-access
        oids = [x for x in notus.get_oids()]
        self.assertEqual(len(oids), 1)

    @mock.patch('ospd_openvas.notus.OpenvasDB')
    def test_notus_init(self, mock_openvasdb):
        mock_openvasdb.find_database_by_pattern.return_value = ('foo', 1)
        redis_mock = mock.MagicMock()
        path_mock = mock.MagicMock()
        notus = Notus(path_mock, Cache(redis_mock))
        self.assertEqual(mock_openvasdb.find_database_by_pattern.call_count, 1)
        self.assertEqual(notus.cache.ctx, 'foo')

    @mock.patch('ospd_openvas.notus.OpenvasDB')
    def test_notus_reload(self, mock_openvasdb):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "hi"
        adv_path.stem = "family"
        path_mock.glob.return_value = [adv_path]
        adv_path.read_bytes.return_value = b'''
        { 
            "family": "family", 
            "qod_type": "remote_app", 
            "advisories": [ 
                { "oid": "12", "file_name": "aha.txt" } 
            ] 
        }'''

        redis_mock = mock.MagicMock()
        mock_openvasdb.find_database_by_pattern.return_value = (redis_mock, 1)
        mock_openvasdb.get_keys_by_pattern.return_value = ['old']
        load_into_redis = Notus(path_mock, Cache(redis_mock))
        # pylint: disable=protected-access
        load_into_redis._verifier = lambda _: True
        load_into_redis.reload_cache()
        cache_pipeline = redis_mock.pipeline.return_value
        cache_pipeline.delete.assert_called_once_with('old')
        self.assertEqual(cache_pipeline.rpush.call_count, 1)
        self.assertTrue(load_into_redis.loaded)
        cache_pipeline.reset_mock()
        do_not_load_into_redis = Notus(path_mock, Cache(redis_mock))
        # pylint: disable=protected-access
        do_not_load_into_redis._verifier = lambda _: False
        do_not_load_into_redis.reload_cache()
        cache_pipeline.execute.assert_not_called()
        self.assertFalse(do_not_load_into_redis.loaded)

    def test_notus_reload_removes_stale_advisories(self):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "new.notus"
        adv_path.stem = "new"
        adv_path.read_bytes.return_value = b'''
        { "advisories": [{ "oid": "new" }] }'''
        path_mock.glob.return_value = [adv_path]
        cache_fake = CacheFake()
        cache_fake.store_advisory("old", {"name": "old"})
        notus = Notus(path_mock, cache_fake)
        notus._verifier = lambda _: True  # pylint: disable=protected-access

        notus.reload_cache()

        self.assertFalse(cache_fake.exists("old"))
        self.assertTrue(cache_fake.exists("new"))

    def test_notus_reload_failure_preserves_cache_and_notifies_waiters(self):
        cache_fake = CacheFake()
        cache_fake.store_advisory("old", {"name": "old"})
        notus = Notus(mock.MagicMock(), cache_fake)
        notus.loaded = True
        staging_started = threading.Event()
        continue_staging = threading.Event()
        waiter_finished = threading.Event()

        def fail_staging():
            staging_started.set()
            continue_staging.wait(1)
            raise ValueError("bad feed")

        with mock.patch.object(notus, '_stage_advisories', fail_staging):
            loader = threading.Thread(target=notus.reload_cache)
            waiter = threading.Thread(
                target=lambda: (notus.reload_cache(), waiter_finished.set())
            )
            loader.start()
            self.assertTrue(staging_started.wait(1))
            waiter.start()
            self.assertFalse(waiter_finished.wait(0.05))
            continue_staging.set()
            loader.join(1)
            waiter.join(1)

        self.assertFalse(loader.is_alive())
        self.assertFalse(waiter.is_alive())
        self.assertTrue(waiter_finished.is_set())
        self.assertFalse(notus.loading)
        self.assertTrue(notus.loaded)
        self.assertTrue(cache_fake.exists("old"))

    def test_notus_reload_duplicate_oid_preserves_cache(self):
        path_mock = mock.MagicMock()
        first = mock.MagicMock()
        first.name = "first.notus"
        first.stem = "first"
        first.read_bytes.return_value = b'''
        { "advisories": [{ "oid": "duplicate" }] }'''
        second = mock.MagicMock()
        second.name = "second.notus"
        second.stem = "second"
        second.read_bytes.return_value = b'''
        { "advisories": [{ "oid": "duplicate" }] }'''
        path_mock.glob.return_value = [first, second]
        cache_fake = CacheFake()
        cache_fake.store_advisory("old", {"name": "old"})
        notus = Notus(path_mock, cache_fake)
        notus.loaded = True
        notus._verifier = lambda _: True  # pylint: disable=protected-access

        notus.reload_cache()

        self.assertTrue(cache_fake.exists("old"))
        self.assertFalse(cache_fake.exists("duplicate"))
        self.assertTrue(notus.loaded)

    def test_notus_qod_type(self):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "hi"
        adv_path.stem = "family"
        path_mock.glob.return_value = [adv_path]
        adv_path.read_bytes.return_value = b'''
        { 
            "family": "family", 
            "advisories": [ 
                {
                    "oid": "12",
                    "qod_type": "package_unreliable",
                    "severity": {
                        "origin": "NVD",
                        "date": 1505784960,
                        "cvss_v2": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "cvss_v3": null
                    }
                } 
            ] 
        }'''
        cache_fake = CacheFake()
        notus = Notus(path_mock, cache_fake)
        notus._verifier = lambda _: True  # pylint: disable=protected-access
        notus.reload_cache()
        nm = notus.get_nvt_metadata("12")
        assert nm
        self.assertEqual("package_unreliable", nm.get("qod_type", ""))

    def test_notus_cvss_v2_v3_none(self):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "hi"
        adv_path.stem = "family"
        path_mock.glob.return_value = [adv_path]
        adv_path.read_bytes.return_value = b'''
        { 
            "family": "family", 
            "advisories": [ 
                {
                    "oid": "12",
                    "severity": {
                        "origin": "NVD",
                        "date": 1505784960,
                        "cvss_v2": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "cvss_v3": null
                    }
                } 
            ] 
        }'''
        cache_fake = CacheFake()
        notus = Notus(path_mock, cache_fake)
        notus._verifier = lambda _: True  # pylint: disable=protected-access
        notus.reload_cache()
        nm = notus.get_nvt_metadata("12")
        assert nm
        self.assertEqual(
            "AV:N/AC:M/Au:N/C:C/I:C/A:C", nm.get("severity_vector", "")
        )

    class TimerFake:
        instances = []
        fail_start = False

        def __init__(self, delay, function, args):
            self.delay = delay
            self.function = function
            self.args = args
            self.cancelled = False
            self.started = False
            type(self).instances.append(self)

        def start(self):
            self.started = True
            if type(self).fail_start:
                raise RuntimeError('timer unavailable')

        def cancel(self):
            self.cancelled = True

        @classmethod
        def reset(cls):
            cls.instances = []
            cls.fail_start = False

    def setUp(self):
        self.TimerFake.reset()

    @staticmethod
    def _result(scan_id='scan_1', message_id=None, value='result'):
        return ResultMessage(
            scan_id=scan_id,
            host_ip='1.1.1.1',
            host_name='host',
            oid='1.2.3',
            value=value,
            port='42',
            uri='file://result',
            message_id=message_id or UUID(int=1),
        )

    def test_notus_admits_before_scheduling_with_stable_message_id(self):
        events = []
        message_id = UUID(int=7)

        def admit(scan_id, received_message_id, result):
            events.append(('admit', scan_id, received_message_id, result))
            return True

        pending = mock.MagicMock(
            side_effect=lambda scan_id: events.append(('pending', scan_id))
            or True
        )
        handler = NotusResultHandler(
            admit, mock.MagicMock(), pending, mock.MagicMock()
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(self._result(message_id=message_id))

        self.assertEqual(events[0][0:3], ('admit', 'scan_1', str(message_id)))
        self.assertEqual(events[1], ('pending', 'scan_1'))
        self.assertEqual(len(self.TimerFake.instances), 1)
        self.assertTrue(self.TimerFake.instances[0].started)

    def test_notus_exact_duplicate_schedules_at_most_once(self):
        message = self._result(message_id=UUID(int=8))
        admit = mock.MagicMock(side_effect=[True, False])
        handler = NotusResultHandler(
            admit,
            mock.MagicMock(),
            mock.MagicMock(return_value=True),
            mock.MagicMock(),
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(message)
            handler.result_handler(message)

        self.assertEqual(admit.call_count, 2)
        self.assertEqual(len(self.TimerFake.instances), 1)

    def test_notus_unknown_scan_optional_none_is_ignored(self):
        admit = mock.MagicMock(return_value=None)
        pending = mock.MagicMock(return_value=True)
        handler = NotusResultHandler(
            admit, mock.MagicMock(), pending, mock.MagicMock()
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(self._result(scan_id='unknown-scan'))

        admit.assert_called_once()
        pending.assert_not_called()
        self.assertFalse(self.TimerFake.instances)

    def test_notus_terminal_rejection_requires_durable_incomplete_record(self):
        admit = mock.MagicMock(
            side_effect=ResultSpoolCapacityError('Notus capacity exhausted.')
        )
        incomplete = mock.MagicMock(side_effect=[False, True])
        handler = NotusResultHandler(
            admit, mock.MagicMock(), mock.MagicMock(), incomplete
        )

        self.assertFalse(handler.result_handler(self._result()))
        self.assertTrue(handler.result_handler(self._result()))

        self.assertEqual(incomplete.call_count, 2)
        self.assertFalse(self.TimerFake.instances)

    def test_notus_malformed_fields_require_durable_incomplete_record(self):
        admit = mock.MagicMock()
        incomplete = mock.MagicMock(side_effect=[False, True])
        handler = NotusResultHandler(
            admit, mock.MagicMock(), mock.MagicMock(), incomplete
        )
        message = self._result()
        message.oid = None

        self.assertFalse(handler.result_handler(message))
        self.assertTrue(handler.result_handler(message))

        admit.assert_not_called()
        self.assertEqual(incomplete.call_count, 2)
        self.assertFalse(self.TimerFake.instances)

    def test_notus_unsafe_scan_ids_are_rejected_before_admission(self):
        admit = mock.MagicMock(return_value=True)
        for scan_id in ('', 'unsafe\nscan', 'x' * 129):
            with self.subTest(scan_id=scan_id), self.assertRaises(ValueError):
                self._result(scan_id=scan_id)

        admit.assert_not_called()
        self.assertFalse(self.TimerFake.instances)

    def test_notus_report_failure_retries_without_deleting_durable_evidence(
        self,
    ):
        report = mock.MagicMock(side_effect=[False, True])
        pending = mock.MagicMock(return_value=True)
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True), report, pending, mock.MagicMock()
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(self._result())
            first = self.TimerFake.instances.pop(0)
            first.function(*first.args)
            self.assertEqual(len(self.TimerFake.instances), 1)
            retry = self.TimerFake.instances.pop(0)
            self.assertEqual(retry.delay, 1.0)
            retry.function(*retry.args)

        self.assertEqual(report.call_args_list, [mock.call('scan_1')] * 2)
        self.assertTrue(pending('scan_1'))

    def test_notus_retry_exhaustion_marks_incomplete_and_stops_retry(self):
        report = mock.MagicMock(return_value=False)
        pending = mock.MagicMock(return_value=True)
        incomplete = mock.MagicMock()
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True), report, pending, incomplete
        )

        with (
            mock.patch('ospd_openvas.notus.Timer', self.TimerFake),
            mock.patch('ospd_openvas.notus.MAX_NOTUS_RESULT_RETRIES', 2),
        ):
            handler.result_handler(self._result())
            self.TimerFake.instances.pop(0).function('scan_1')
            self.TimerFake.instances.pop(0).function('scan_1')

        incomplete.assert_called_once_with(
            'scan_1',
            'Notus result delivery failed after bounded retries; '
            'admitted evidence remains durable.',
        )
        self.assertEqual(report.call_count, 2)
        self.assertFalse(self.TimerFake.instances)
        self.assertTrue(pending('scan_1'))

    def test_notus_retry_exhaustion_retries_if_incomplete_marker_fails(self):
        report = mock.MagicMock(return_value=False)
        pending = mock.MagicMock(return_value=True)
        incomplete = mock.MagicMock(return_value=False)
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True), report, pending, incomplete
        )

        with (
            mock.patch('ospd_openvas.notus.Timer', self.TimerFake),
            mock.patch('ospd_openvas.notus.MAX_NOTUS_RESULT_RETRIES', 1),
        ):
            handler.result_handler(self._result())
            self.TimerFake.instances.pop(0).function('scan_1')

        incomplete.assert_called_once()
        self.assertEqual(len(self.TimerFake.instances), 1)
        self.assertEqual(
            self.TimerFake.instances[0].delay, NOTUS_RESULT_RETRY_SECONDS
        )

    def test_notus_pending_state_failure_schedules_retry(self):
        pending = mock.MagicMock(side_effect=RuntimeError('spool unavailable'))
        incomplete = mock.MagicMock(return_value=False)
        handler = NotusResultHandler(
            mock.MagicMock(), mock.MagicMock(), pending, incomplete
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            self.assertTrue(handler.resume_scan('scan_1'))

        incomplete.assert_called_once()
        self.assertEqual(len(self.TimerFake.instances), 1)
        self.assertEqual(
            self.TimerFake.instances[0].delay, NOTUS_RESULT_RETRY_SECONDS
        )

    def test_notus_arrival_during_report_schedules_later_without_overlap(self):
        report_entered = threading.Event()
        continue_report = threading.Event()
        active = 0
        max_active = 0

        def report(scan_id):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            if report.call_count == 1:
                report_entered.set()
                self.assertTrue(continue_report.wait(1))
            active -= 1
            return True

        report = mock.MagicMock(side_effect=report)
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True),
            report,
            mock.MagicMock(return_value=True),
            mock.MagicMock(),
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(self._result(message_id=UUID(int=9)))
            first = self.TimerFake.instances.pop(0)
            delivery = threading.Thread(
                target=first.function, args=tuple(first.args)
            )
            delivery.start()
            self.assertTrue(report_entered.wait(1))
            handler.result_handler(self._result(message_id=UUID(int=10)))
            self.assertFalse(self.TimerFake.instances)
            continue_report.set()
            delivery.join(1)
            self.assertFalse(delivery.is_alive())
            self.assertEqual(len(self.TimerFake.instances), 1)
            self.TimerFake.instances.pop(0).function('scan_1')

        self.assertEqual(report.call_count, 2)
        self.assertEqual(max_active, 1)

    def test_notus_timer_start_failure_marks_incomplete(self):
        incomplete = mock.MagicMock()
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True),
            mock.MagicMock(),
            mock.MagicMock(return_value=True),
            incomplete,
        )
        self.TimerFake.fail_start = True

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(self._result())

        incomplete.assert_called_once_with(
            'scan_1', 'Notus result delivery could not be scheduled.'
        )
        self.assertEqual(len(self.TimerFake.instances), 1)
        self.assertTrue(self.TimerFake.instances[0].started)

    def test_notus_discard_and_shutdown_cancel_timers_only(self):
        admit = mock.MagicMock(return_value=True)
        report = mock.MagicMock()
        handler = NotusResultHandler(
            admit, report, mock.MagicMock(return_value=True), mock.MagicMock()
        )

        with mock.patch('ospd_openvas.notus.Timer', self.TimerFake):
            handler.result_handler(self._result(scan_id='scan_1'))
            first = self.TimerFake.instances[0]
            handler.discard_scan('scan_1')
            handler.result_handler(self._result(scan_id='scan_2'))
            second = self.TimerFake.instances[1]
            handler.shutdown()

        self.assertTrue(first.cancelled)
        self.assertTrue(second.cancelled)
        self.assertEqual(admit.call_count, 2)
        report.assert_not_called()
