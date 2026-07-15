# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import threading
from datetime import datetime
from unittest import TestCase, mock
from typing import Dict, Optional, Iterator
from uuid import UUID

# These tests assert internal buffer cleanup and lock-release invariants.
# pylint: disable=protected-access

from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.notus import Cache, Notus, NotusResultHandler


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

    def test_notus_failed_reports_are_retried_without_data_loss(self):
        timers = []

        class TimerFake:
            def __init__(self, delay, function, args):
                self.delay = delay
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        mock_report_func = mock.MagicMock(side_effect=[False, True])
        notus = NotusResultHandler(mock_report_func)

        res_msg = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port="42",
            uri='file://foo/bar',
        )

        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            notus.result_handler(res_msg)
            self.assertEqual(len(timers), 1)
            timers.pop(0).function('scan_1')
            self.assertEqual(len(timers), 1)
            self.assertEqual(timers[0].delay, 1.0)
            self.assertEqual(notus._result_count, 1)
            self.assertEqual(len(notus._results['scan_1']), 1)
            timers.pop(0).function('scan_1')

        self.assertEqual(mock_report_func.call_count, 2)
        self.assertEqual(notus._result_count, 0)
        self.assertFalse(notus._results)
        self.assertFalse(notus._timers)

    def test_notus_report_exception_is_retried_without_data_loss(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        report_func = mock.MagicMock(
            side_effect=[RuntimeError('delivery failed'), True]
        )
        handler = NotusResultHandler(report_func)
        result = notus_result('scan_1', 'result')

        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            handler.result_handler(result)
            timers.pop(0).function('scan_1')
            self.assertEqual(handler._result_count, 1)
            timers.pop(0).function('scan_1')

        self.assertEqual(report_func.call_count, 2)
        self.assertEqual(handler._result_count, 0)
        self.assertFalse(handler._results)

    def test_notus_retry_exhaustion_marks_incomplete_and_releases_buffer(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                self.cancelled = False
                timers.append(self)

            def start(self):
                return None

            def cancel(self):
                self.cancelled = True

        incomplete_func = mock.MagicMock()
        handler = NotusResultHandler(
            mock.MagicMock(return_value=False),
            incomplete_func=incomplete_func,
        )

        with (
            mock.patch('ospd_openvas.notus.Timer', TimerFake),
            mock.patch('ospd_openvas.notus.MAX_NOTUS_RESULT_RETRIES', 2),
        ):
            handler.result_handler(notus_result('scan_1', 'result'))
            timers.pop(0).function('scan_1')
            timers.pop(0).function('scan_1')

        incomplete_func.assert_called_once_with(
            'scan_1',
            'Notus result delivery failed after bounded retries.',
        )
        self.assertEqual(handler._result_count, 0)
        self.assertEqual(handler._result_bytes, 0)
        self.assertFalse(handler._results)
        self.assertFalse(handler._result_sizes)
        self.assertFalse(handler._result_bytes_per_scan)
        self.assertFalse(handler._report_failures)

    def test_notus_result_arriving_during_delivery_is_not_lost(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        handler = None
        appended = False
        batches = []

        def report_func(results, scan_id):
            nonlocal appended
            batches.append(list(results))
            if not appended:
                appended = True
                handler.result_handler(notus_result(scan_id, 'second'))
            return True

        handler = NotusResultHandler(report_func)

        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            handler.result_handler(notus_result('scan_1', 'first'))
            timers.pop(0).function('scan_1')
            self.assertEqual(handler._result_count, 1)
            self.assertEqual(len(timers), 1)
            timers.pop(0).function('scan_1')

        self.assertEqual([len(batch) for batch in batches], [1, 1])
        self.assertEqual(handler._result_count, 0)
        self.assertFalse(handler._results)

    def test_notus_concurrent_delivery_does_not_overlap_batches(self):
        timers = []
        report_entered = threading.Event()
        continue_report = threading.Event()
        batches = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        def report_func(results, _):
            batches.append([result['value'] for result in results])
            if len(batches) == 1:
                report_entered.set()
                continue_report.wait(1)
            return True

        handler = NotusResultHandler(report_func)
        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            handler.result_handler(notus_result('scan_1', 'first'))
            first_delivery = threading.Thread(
                target=timers.pop(0).function, args=('scan_1',)
            )
            first_delivery.start()
            self.assertTrue(report_entered.wait(1))
            handler.result_handler(notus_result('scan_1', 'second'))
            self.assertFalse(timers)
            continue_report.set()
            first_delivery.join(1)
            self.assertFalse(first_delivery.is_alive())
            self.assertEqual(len(timers), 1)
            timers.pop(0).function('scan_1')

        self.assertEqual(batches, [['first'], ['second']])
        self.assertEqual(handler._result_count, 0)
        self.assertFalse(handler._results)
        self.assertFalse(handler._incomplete_scans)

    def test_notus_timer_failure_retains_results_and_marks_incomplete(self):
        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args

            def start(self):
                raise RuntimeError('timer unavailable')

        incomplete_func = mock.MagicMock()
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True),
            incomplete_func=incomplete_func,
        )

        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            handler.result_handler(notus_result('scan_1', 'first'))
            handler.result_handler(notus_result('scan_1', 'second'))

        self.assertEqual(handler._result_count, 2)
        self.assertEqual(len(handler._results['scan_1']), 2)
        self.assertFalse(handler._timers)
        incomplete_func.assert_called_once_with(
            'scan_1', 'Notus result delivery could not be scheduled.'
        )

    def test_notus_capacity_drop_marks_scan_incomplete_once(self):
        incomplete_func = mock.MagicMock()
        handler = NotusResultHandler(
            mock.MagicMock(return_value=True),
            incomplete_func=incomplete_func,
        )
        result = notus_result('scan_1', 'too large')

        with mock.patch('ospd_openvas.notus.MAX_NOTUS_RESULT_BYTES', 1):
            handler.result_handler(result)
            handler.result_handler(result)

        incomplete_func.assert_called_once_with(
            'scan_1', 'A Notus result exceeded the per-result byte limit.'
        )

    def test_notus_discard_and_shutdown_release_delivery_state(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                self.cancelled = False
                timers.append(self)

            def start(self):
                return None

            def cancel(self):
                self.cancelled = True

        handler = NotusResultHandler(mock.MagicMock(return_value=True))
        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            handler.result_handler(notus_result('scan_1', 'first'))
            handler.discard_scan('scan_1')
            self.assertTrue(timers[0].cancelled)
            self.assertEqual(handler._result_count, 0)
            self.assertFalse(handler._results)

            handler.result_handler(notus_result('scan_2', 'second'))
            handler.shutdown()

        self.assertTrue(timers[1].cancelled)
        self.assertEqual(handler._result_count, 0)
        self.assertEqual(handler._result_bytes, 0)
        self.assertFalse(handler._results)
        self.assertFalse(handler._timers)

    def test_notus_success_case(self):
        def start(self):
            self.function(*self.args, **self.kwargs)

        mock_report_func = mock.MagicMock(return_value=True)
        notus = NotusResultHandler(mock_report_func)

        res_msg = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port="42",
            uri='file://foo/bar',
        )

        with (
            mock.patch.object(logging.Logger, 'warning') as warning,
            mock.patch.object(threading.Timer, 'start', start),
        ):
            notus.result_handler(res_msg)

        warning.assert_not_called()

    def test_notus_result_handler_serializes_concurrent_results(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        report_func = mock.MagicMock(return_value=True)
        handler = NotusResultHandler(report_func)
        result = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='host',
            oid='1.2.3',
            value='result',
            port='42',
            uri='file://result',
        )

        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            workers = [
                threading.Thread(target=handler.result_handler, args=(result,))
                for _ in range(20)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(1)

        self.assertEqual(len(timers), 1)
        timers[0].function(*timers[0].args)
        report_func.assert_called_once()
        self.assertEqual(len(report_func.call_args.args[0]), 20)
        self.assertEqual(
            handler._result_count, 0
        )  # pylint: disable=protected-access
        self.assertEqual(
            handler._result_bytes, 0
        )  # pylint: disable=protected-access
        self.assertFalse(handler._results)  # pylint: disable=protected-access
        self.assertFalse(handler._timers)  # pylint: disable=protected-access

    def test_notus_result_handler_caps_and_reports_outside_lock(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        reported_batches = []
        handler = None

        def report_func(results, _):
            acquired = handler._lock.acquire(
                blocking=False
            )  # pylint: disable=protected-access
            reported_batches.append((len(results), acquired))
            if acquired:
                handler._lock.release()  # pylint: disable=protected-access
            return True

        handler = NotusResultHandler(report_func)

        def result(scan_id):
            return ResultMessage(
                scan_id=scan_id,
                host_ip='1.1.1.1',
                host_name='host',
                oid='1.2.3',
                value='result',
                port='42',
                uri='file://result',
            )

        with (
            mock.patch('ospd_openvas.notus.Timer', TimerFake),
            mock.patch('ospd_openvas.notus.MAX_RESULTS_PER_SCAN', 2),
            mock.patch('ospd_openvas.notus.MAX_BUFFERED_NOTUS_RESULTS', 3),
        ):
            handler.result_handler(result('scan_1'))
            handler.result_handler(result('scan_1'))
            handler.result_handler(result('scan_1'))
            handler.result_handler(result('scan_2'))
            handler.result_handler(result('scan_2'))
            handler.result_handler(result('scan_3'))

        self.assertEqual(
            handler._result_count, 3
        )  # pylint: disable=protected-access
        self.assertNotIn(
            'scan_3', handler._results
        )  # pylint: disable=protected-access
        self.assertNotIn(
            'scan_3', handler._timers
        )  # pylint: disable=protected-access
        for timer in timers:
            timer.function(*timer.args)
        self.assertEqual(
            sorted(length for length, _ in reported_batches), [1, 2]
        )
        self.assertEqual(
            [available for _, available in reported_batches], [True, True]
        )

    def test_notus_result_handler_rejects_unknown_scan_before_buffering(self):
        report_func = mock.MagicMock(return_value=True)
        scan_exists = mock.MagicMock(return_value=False)
        handler = NotusResultHandler(report_func, scan_exists)
        result = ResultMessage(
            scan_id='unknown-scan',
            host_ip='1.1.1.1',
            host_name='host',
            oid='1.2.3',
            value='result',
            port='42',
            uri='file://result',
        )

        handler.result_handler(result)

        scan_exists.assert_called_once_with('unknown-scan')
        report_func.assert_not_called()
        self.assertFalse(handler._results)  # pylint: disable=protected-access
        self.assertFalse(handler._timers)  # pylint: disable=protected-access

    def test_notus_result_handler_rejects_unsafe_scan_ids_and_byte_caps(self):
        timers = []

        class TimerFake:
            def __init__(self, _, function, args):
                self.function = function
                self.args = args
                timers.append(self)

            def start(self):
                return None

        handler = NotusResultHandler(mock.MagicMock(return_value=True))

        def result(scan_id):
            return ResultMessage(
                scan_id=scan_id,
                host_ip='1.1.1.1',
                host_name='host',
                oid='1.2.3',
                value='x' * 100,
                port='42',
                uri='file://result',
                message_id=UUID(int=1),
                group_id=UUID(int=2),
                created=datetime(2026, 1, 1),
            )

        with mock.patch('ospd_openvas.notus.Timer', TimerFake):
            handler.result_handler(result('unsafe\nscan'))
            handler.result_handler(result('x' * 129))
            self.assertFalse(timers)
            self.assertEqual(
                handler._result_count, 0
            )  # pylint: disable=protected-access

            handler.result_handler(result('scan_1'))
            result_bytes = (
                handler._result_bytes
            )  # pylint: disable=protected-access
            self.assertGreater(result_bytes, 1)

            with mock.patch(
                'ospd_openvas.notus.MAX_NOTUS_RESULT_BYTES', result_bytes - 1
            ):
                handler.result_handler(result('scan_2'))
            with mock.patch(
                'ospd_openvas.notus.MAX_NOTUS_RESULT_BYTES_PER_SCAN',
                result_bytes,
            ):
                handler.result_handler(result('scan_1'))
            with mock.patch(
                'ospd_openvas.notus.MAX_BUFFERED_NOTUS_RESULT_BYTES',
                result_bytes,
            ):
                handler.result_handler(result('scan_3'))

        self.assertEqual(
            handler._result_count, 1
        )  # pylint: disable=protected-access
        self.assertEqual(
            handler._result_bytes, result_bytes
        )  # pylint: disable=protected-access
        self.assertNotIn(
            'scan_2', handler._results
        )  # pylint: disable=protected-access
        self.assertNotIn(
            'scan_3', handler._results
        )  # pylint: disable=protected-access
        timers[0].function(*timers[0].args)
        self.assertEqual(
            handler._result_count, 0
        )  # pylint: disable=protected-access
        self.assertEqual(
            handler._result_bytes, 0
        )  # pylint: disable=protected-access
