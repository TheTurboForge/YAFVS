# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Integration tests for durable Redis-to-OSP result delivery."""

import json
import tempfile
import threading
import unittest

from pathlib import Path
from unittest.mock import MagicMock, patch

from ospd.result_spool import ClaimState, ResultSpool
from ospd.scan import ScanCollection, ScanStatus
from ospd_openvas.db import ResultClaimAck

from tests.dummydaemon import DummyDaemon, FakeDataManager


def result_row(value='started'):
    return {
        'type': 3,
        'name': 'HOST_START',
        'severity': '',
        'test_id': '',
        'value': value,
        'host': '192.0.2.1',
        'hostname': '',
        'port': '',
        'qod': '',
        'uri': '',
    }


def redis_result_row(value='started'):
    return json.dumps(
        {
            'version': 1,
            'result_type': 'HOST_START',
            'host_ip': '192.0.2.1',
            'host_name': '',
            'port': '',
            'oid': '',
            'value': value,
            'uri': '',
        },
        separators=(',', ':'),
    )


def add_scan(collection, scan_id='scan-1'):
    collection.scans_table[scan_id] = {
        'scan_id': scan_id,
        'status': ScanStatus.RUNNING,
        'credentials': {},
        'start_time': 1,
        'end_time': 0,
        'results': [],
        'temp_results': [],
        'result_batch_id': '',
        'last_result_claim_id': '',
        'progress': 0,
        'target_progress': {},
        'count_alive': 0,
        'count_dead': 0,
        'count_total': 1,
        'count_excluded': 0,
        'excluded_simplified': None,
        'evidence_incomplete': False,
        'evidence_incomplete_reason': '',
        'target': {
            'hosts': '192.0.2.1',
            'ports': '',
            'exclude_hosts': '',
            'finished_hosts': '',
            'options': {},
        },
        'options': {},
        'vts': {},
    }


class ResultSpoolDeliveryTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.path = (
            Path(self.temporary_directory.name) / 'spool' / 'results.sqlite3'
        )
        self.spool = ResultSpool(str(self.path))

    def tearDown(self):
        self.spool.close()
        self.temporary_directory.cleanup()

    def collection(self):
        collection = ScanCollection('/tmp', self.spool)
        collection.scan_collection_lock = threading.RLock()
        add_scan(collection)
        return collection

    def test_daemon_attaches_configured_spool_after_base_initialization(self):
        spool_directory = Path(self.temporary_directory.name) / 'daemon-spool'

        daemon = DummyDaemon(result_spool_dir=str(spool_directory))

        self.assertIsNotNone(daemon.result_spool)
        self.assertIs(daemon.scan_collection.result_spool, daemon.result_spool)

    def test_one_redis_claim_is_one_stable_osp_batch(self):
        collection = self.collection()
        self.assertTrue(
            collection.apply_result_batch(
                'scan-1',
                [result_row()],
                claim_id='claim-1',
                redis_db=7,
            )
        )

        batch_id, first = collection.prepare_result_batch('scan-1')
        replay_id, replay = collection.prepare_result_batch('scan-1')

        self.assertEqual(replay_id, batch_id)
        self.assertEqual(replay, first)
        self.assertEqual(first, [result_row()])
        self.assertFalse(collection.ack_result_batch('scan-1', batch_id))
        claim = self.spool.get_batch('scan-1', batch_id)
        self.assertEqual(claim.state, ClaimState.EXPOSED)

    def test_pending_batch_restores_an_interrupted_result_view(self):
        collection = self.collection()
        collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
            total_dead=2,
            count_total=3,
        )
        batch_id, _ = collection.prepare_result_batch('scan-1')

        reopened = ResultSpool(str(self.path))
        recovered = ScanCollection('/tmp', reopened)
        recovered.data_manager = FakeDataManager()
        recovered.scan_collection_lock = threading.RLock()
        recovered.restore_spooled_scans()

        self.assertTrue(recovered.id_exists('scan-1'))
        self.assertEqual(recovered.get_status('scan-1'), ScanStatus.INTERRUPTED)
        self.assertTrue(recovered.evidence_is_incomplete('scan-1'))
        self.assertEqual(recovered.get_count_dead('scan-1'), 2)
        self.assertEqual(recovered.prepare_result_batch('scan-1')[0], batch_id)

    @patch('ospd_openvas.daemon.KbDB')
    def test_gvmd_ack_releases_redis_then_completes_tombstone(self, kbdb_class):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        daemon.scan_collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
        )
        batch_id, _ = daemon.scan_collection.prepare_result_batch('scan-1')
        kbdb_class.return_value.ack_result_claim_state.return_value = (
            ResultClaimAck.RELEASED
        )

        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))
        kbdb_class.assert_called_once_with(7)
        kbdb_class.return_value.ack_result_claim_state.assert_called_once_with(
            'claim-1'
        )
        self.assertFalse(self.spool.has_pending('scan-1'))
        self.assertEqual(
            self.spool.get_batch('scan-1', batch_id).state,
            ClaimState.ACKED,
        )
        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))
        self.assertEqual(kbdb_class.call_count, 1)

    @patch('ospd_openvas.daemon.KbDB')
    def test_startup_finishes_crash_interrupted_ack(self, kbdb_class):
        collection = self.collection()
        collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
        )
        batch_id, _ = collection.prepare_result_batch('scan-1')
        self.spool.begin_ack('scan-1', batch_id, 7, 'claim-1')
        kbdb_class.return_value.ack_result_claim_state.return_value = (
            ResultClaimAck.MISSING
        )
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        daemon.scan_collection.scans_table['scan-1'][
            'last_result_claim_id'
        ] = 'claim-1'

        daemon.reconcile_result_spool()

        self.assertFalse(self.spool.has_pending('scan-1'))
        self.assertEqual(
            daemon.scan_collection.scans_table['scan-1'][
                'last_result_claim_id'
            ],
            '',
        )

    @patch('ospd_openvas.daemon.KbDB')
    def test_rejected_redis_ack_retains_durable_acking_claim(self, kbdb_class):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)

        for sequence, outcome in enumerate(
            (ResultClaimAck.MISMATCH, ResultClaimAck.CORRUPT), start=1
        ):
            scan_id = f'scan-{sequence}'
            claim_id = f'claim-{sequence}'
            add_scan(daemon.scan_collection, scan_id)
            daemon.scan_collection.apply_result_batch(
                scan_id,
                [result_row()],
                claim_id=claim_id,
                redis_db=sequence,
            )
            batch_id, _ = daemon.scan_collection.prepare_result_batch(scan_id)
            kbdb_class.return_value.ack_result_claim_state.return_value = (
                outcome
            )

            self.assertFalse(daemon.ack_result_batch(scan_id, batch_id))
            self.assertEqual(
                self.spool.get_batch(scan_id, batch_id).state,
                ClaimState.ACKING,
            )

    @patch('ospd_openvas.daemon.KbDB')
    def test_redis_claim_is_not_released_before_gvmd_ack(self, kbdb_class):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        redis_db = MagicMock(index=7)
        redis_db.claim_results.return_value = (
            'claim-1',
            [redis_result_row()],
        )

        self.assertTrue(daemon.report_openvas_results(redis_db, 'scan-1'))
        redis_db.ack_result_claim.assert_not_called()
        batch_id, results = daemon.scan_collection.prepare_result_batch(
            'scan-1'
        )
        self.assertEqual(len(results), 1)
        kbdb_class.return_value.ack_result_claim_state.return_value = (
            ResultClaimAck.RELEASED
        )

        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))
        kbdb_class.return_value.ack_result_claim_state.assert_called_once_with(
            'claim-1'
        )


if __name__ == '__main__':
    unittest.main()
