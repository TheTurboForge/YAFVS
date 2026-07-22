# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Integration tests for durable Redis-to-OSP result delivery."""

import json
import sqlite3
import tempfile
import threading
import unittest

from pathlib import Path
from unittest.mock import MagicMock, patch

import redis

from ospd.result_spool import (
    ClaimState,
    ResultSpool,
    ResultSpoolStateError,
    SourceKind,
)
from ospd.scan import ScanCollection, ScanStatus
from ospd_openvas.db import ResultClaimAck
from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.messages.start import ScanStartMessage
from ospd_openvas.messages.status import (
    ScanStatus as NotusScanStatus,
    ScanStatusMessage,
)

from tests.dummydaemon import DummyDaemon, FakeDataManager

OWNER_TOKEN = 'owner-token'


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


def notus_result_row(message_id='message-1', value='vulnerable package'):
    return {
        'message_id': message_id,
        'message_type': 'result.scan',
        'group_id': 'group-1',
        'created': 1.0,
        'host_ip': '192.0.2.1',
        'host_name': 'host',
        'oid': '1.3.6.1.4.1.25623.1.0.100061',
        'value': value,
        'port': 'package',
        'uri': 'pkg://example',
        'result_type': 'ALARM',
    }


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

    @staticmethod
    def configure_notus_metadata(daemon):
        daemon.nvti.QOD_TYPES = {'remote_banner': '80'}

    def test_daemon_attaches_configured_spool_after_base_initialization(self):
        spool_directory = Path(self.temporary_directory.name) / 'daemon-spool'

        daemon = DummyDaemon(result_spool_dir=str(spool_directory))

        self.assertIsNotNone(daemon.result_spool)
        self.assertIs(daemon.scan_collection.result_spool, daemon.result_spool)

    def test_daemon_acks_only_durable_exact_notus_completion(self):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        self.spool.register_scan('scan-1')
        start = ScanStartMessage(
            scan_id='scan-1',
            host_ip='192.0.2.1',
            host_name='host',
            os_release='debian_12',
            package_list=['example=1'],
            group_id='run-1',
        )
        finish = ScanStatusMessage(
            scan_id='scan-1',
            host_ip='192.0.2.1',
            status=NotusScanStatus.FINISHED,
            result_count=0,
            group_id='run-1',
        )

        self.assertTrue(daemon.handle_notus_start(start))
        self.assertTrue(daemon.handle_notus_start(start))
        self.assertTrue(daemon.handle_notus_status(finish))
        self.assertTrue(daemon.handle_notus_status(finish))
        kbdb = MagicMock()
        kbdb.get_notus_manifest.return_value = (
            'mqtt',
            [
                {
                    'run_id': 'run-1',
                    'start_message_id': str(start.message_id),
                    'host_ip': '192.0.2.1',
                }
            ],
        )
        self.assertTrue(daemon.wait_for_notus_completion(kbdb, 'scan-1'))

    def test_notus_completion_timeout_marks_operator_visible_incomplete_state(
        self,
    ):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        self.spool.register_scan('scan-1')
        start = ScanStartMessage(
            scan_id='scan-1',
            host_ip='192.0.2.1',
            host_name='host',
            os_release='debian_12',
            package_list=['example=1'],
            group_id='run-1',
        )
        daemon.handle_notus_start(start)

        kbdb = MagicMock()
        kbdb.get_notus_manifest.return_value = (
            'mqtt',
            [
                {
                    'run_id': 'run-1',
                    'start_message_id': str(start.message_id),
                    'host_ip': '192.0.2.1',
                }
            ],
        )
        with patch('ospd_openvas.daemon.NOTUS_COMPLETION_TIMEOUT_SECONDS', 0):
            self.assertFalse(daemon.wait_for_notus_completion(kbdb, 'scan-1'))
        self.assertTrue(daemon.scan_collection.evidence_is_incomplete('scan-1'))
        self.assertIn(
            'could not be proven',
            self.spool.scan_incomplete_reason('scan-1'),
        )

    def test_one_redis_claim_is_one_stable_osp_batch(self):
        collection = self.collection()
        self.assertTrue(
            collection.apply_result_batch(
                'scan-1',
                [result_row()],
                claim_id='claim-1',
                redis_db=7,
                owner_token=OWNER_TOKEN,
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
            owner_token=OWNER_TOKEN,
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

    def test_marker_only_scan_restores_reason_as_interrupted_error(self):
        self.spool.register_scan('scan-1')
        self.spool.mark_scan_incomplete(
            'scan-1', 'Scanner evidence is incomplete.'
        )
        recovered = ScanCollection('/tmp', self.spool)
        recovered.data_manager = FakeDataManager()
        recovered.scan_collection_lock = threading.RLock()

        recovered.restore_spooled_scans()

        self.assertEqual(recovered.get_status('scan-1'), ScanStatus.INTERRUPTED)
        self.assertTrue(recovered.evidence_is_incomplete('scan-1'))
        self.assertEqual(
            recovered.scans_table['scan-1']['evidence_incomplete_reason'],
            'Scanner evidence is incomplete.',
        )
        errors = list(recovered.results_iterator('scan-1'))
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['value'], 'Scanner evidence is incomplete.')

    def test_gvmd_ack_releases_redis_then_completes_tombstone(self):
        daemon = DummyDaemon()
        self.configure_notus_metadata(daemon)
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        daemon.scan_collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
            owner_token=OWNER_TOKEN,
        )
        batch_id, _ = daemon.scan_collection.prepare_result_batch('scan-1')
        database = daemon.main_db.open_owned_parent_database.return_value
        database.ack_result_claim_state.return_value = ResultClaimAck.RELEASED
        database.has_pending_results.return_value = False

        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))
        daemon.main_db.open_owned_parent_database.assert_called_with(
            7, OWNER_TOKEN, 'scan-1'
        )
        database.ack_result_claim_state.assert_called_once_with('claim-1')
        self.assertFalse(self.spool.has_pending('scan-1'))
        self.assertEqual(
            self.spool.get_batch('scan-1', batch_id).state,
            ClaimState.ACKED,
        )
        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))
        self.assertEqual(database.ack_result_claim_state.call_count, 1)

    def test_redis_ack_hands_claim_slot_to_waiting_notus_ingress(self):
        daemon = DummyDaemon()
        self.configure_notus_metadata(daemon)
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        daemon.scan_collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
            owner_token=OWNER_TOKEN,
        )
        self.assertTrue(
            daemon.scan_collection.admit_notus_result(
                'scan-1', 'message-1', notus_result_row()
            )
        )
        self.assertFalse(self.spool.has_materializable_notus('scan-1'))
        self.assertTrue(daemon.report_pending_notus_results('scan-1'))
        redis_batch, _ = daemon.scan_collection.prepare_result_batch('scan-1')
        database = daemon.main_db.open_owned_parent_database.return_value
        database.ack_result_claim_state.return_value = ResultClaimAck.RELEASED
        database.has_pending_results.return_value = False

        self.assertTrue(daemon.ack_result_batch('scan-1', redis_batch))

        self.assertFalse(self.spool.has_pending_redis('scan-1'))
        notus_batch, results = daemon.scan_collection.prepare_result_batch(
            'scan-1'
        )
        self.assertNotEqual(notus_batch, redis_batch)
        self.assertEqual(len(results), 1)
        self.assertEqual(
            self.spool.get_batch('scan-1', notus_batch).source_kind,
            SourceKind.NOTUS,
        )

    def test_notus_ack_hands_claim_slot_to_waiting_redis_results(self):
        daemon = DummyDaemon()
        self.configure_notus_metadata(daemon)
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        self.spool.register_scan('scan-1')
        self.spool.admit_notus_result('scan-1', 'message-1', notus_result_row())
        self.assertTrue(daemon.report_pending_notus_results('scan-1'))
        notus_batch, _ = daemon.scan_collection.prepare_result_batch('scan-1')
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        database.has_pending_results.return_value = True
        database.claim_results.return_value = (
            'claim-redis',
            [redis_result_row('after-notus')],
        )
        daemon.main_db.reserved_parent_databases.return_value = [
            ('scan-1', database)
        ]

        self.assertTrue(daemon.ack_result_batch('scan-1', notus_batch))

        redis_batch, results = daemon.scan_collection.prepare_result_batch(
            'scan-1'
        )
        self.assertNotEqual(redis_batch, notus_batch)
        self.assertEqual(results[0]['value'], 'after-notus')
        self.assertEqual(
            self.spool.get_batch('scan-1', redis_batch).source_kind,
            SourceKind.REDIS,
        )
        daemon.main_db.open_owned_parent_database.assert_not_called()

    def test_startup_finishes_crash_interrupted_ack(self):
        collection = self.collection()
        collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
            owner_token=OWNER_TOKEN,
        )
        batch_id, _ = collection.prepare_result_batch('scan-1')
        self.spool.begin_ack('scan-1', batch_id, 7, 'claim-1')
        daemon = DummyDaemon()
        database = daemon.main_db.open_owned_parent_database.return_value
        database.ack_result_claim_state.return_value = ResultClaimAck.MISSING
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

    def test_notus_ack_never_enters_redis_release_path(self):
        daemon = DummyDaemon()
        self.configure_notus_metadata(daemon)
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        self.spool.register_scan('scan-1')
        self.spool.admit_notus_start(
            'scan-1', 'group-1', 'start-1', '192.0.2.1'
        )
        self.assertTrue(
            daemon.scan_collection.admit_notus_result(
                'scan-1', 'message-1', notus_result_row()
            )
        )
        self.spool.admit_notus_status(
            'scan-1',
            'group-1',
            'finish-1',
            '192.0.2.1',
            'finished',
            1,
        )
        self.assertTrue(daemon.report_pending_notus_results('scan-1'))
        batch_id, results = daemon.scan_collection.prepare_result_batch(
            'scan-1'
        )
        self.assertEqual(len(results), 1)
        claim = self.spool.get_batch('scan-1', batch_id)
        self.assertEqual(claim.source_kind, SourceKind.NOTUS)

        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))

        daemon.main_db.open_owned_parent_database.assert_not_called()
        daemon.main_db.ack_owned_result_claim_state.assert_not_called()
        self.assertFalse(self.spool.has_pending('scan-1'))
        self.assertFalse(self.spool.has_pending_notus('scan-1'))
        self.assertEqual(
            self.spool.get_batch('scan-1', batch_id).state,
            ClaimState.ACKED,
        )

    def test_startup_completes_crash_interrupted_notus_ack_locally(self):
        daemon = DummyDaemon()
        self.configure_notus_metadata(daemon)
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        self.spool.register_scan('scan-1')
        self.spool.admit_notus_start(
            'scan-1', 'group-1', 'start-1', '192.0.2.1'
        )
        self.spool.admit_notus_result('scan-1', 'message-1', notus_result_row())
        self.spool.admit_notus_status(
            'scan-1',
            'group-1',
            'finish-1',
            '192.0.2.1',
            'finished',
            1,
        )
        self.assertTrue(daemon.report_pending_notus_results('scan-1'))
        batch_id, _ = daemon.scan_collection.prepare_result_batch('scan-1')
        claim = self.spool.get_batch('scan-1', batch_id)
        self.spool.begin_ack(
            'scan-1',
            batch_id,
            claim.redis_db,
            claim.source_claim_id,
        )

        recovered = DummyDaemon()
        self.configure_notus_metadata(recovered)
        recovered.result_spool = self.spool
        recovered.scan_collection.set_result_spool(self.spool)
        add_scan(recovered.scan_collection)
        recovered.scan_collection.scans_table['scan-1'][
            'last_result_claim_id'
        ] = claim.source_claim_id
        recovered.reconcile_result_spool()

        recovered.main_db.open_owned_parent_database.assert_not_called()
        recovered.main_db.ack_owned_result_claim_state.assert_not_called()
        self.assertFalse(self.spool.has_pending('scan-1'))
        self.assertFalse(self.spool.has_pending_notus('scan-1'))
        self.assertEqual(
            recovered.scan_collection.scans_table['scan-1'][
                'last_result_claim_id'
            ],
            '',
        )

    def test_startup_materializes_ingress_only_notus_evidence(self):
        self.spool.register_scan('scan-1')
        self.spool.admit_notus_result('scan-1', 'message-1', notus_result_row())
        daemon = DummyDaemon()
        self.configure_notus_metadata(daemon)
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        daemon.scan_collection.restore_spooled_scans()

        daemon.reconcile_result_spool()

        self.assertTrue(daemon.scan_collection.id_exists('scan-1'))
        claim = self.spool.pending_records('scan-1')[0]
        self.assertEqual(claim.source_kind, SourceKind.NOTUS)
        self.assertEqual(len(claim.results), 1)
        daemon.main_db.open_owned_parent_database.assert_not_called()

    def test_scan_deletion_serializes_with_notus_admission_without_resurrection(
        self,
    ):
        collection = self.collection()
        self.spool.register_scan('scan-1')
        collection.set_status('scan-1', ScanStatus.STOPPED)
        outcome = []

        with collection.scan_collection_lock:
            worker = threading.Thread(
                target=lambda: outcome.append(
                    collection.admit_notus_result(
                        'scan-1', 'message-1', notus_result_row()
                    )
                )
            )
            worker.start()
            self.assertTrue(collection.delete_scan('scan-1'))
        worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, [None])
        self.assertFalse(collection.id_exists('scan-1'))
        self.assertIsNone(self.spool.scan_incomplete_reason('scan-1'))

    def test_durable_delete_failure_keeps_in_memory_scan(self):
        collection = self.collection()
        self.spool.register_scan('scan-1')
        self.spool.admit_notus_result('scan-1', 'message-1', notus_result_row())
        collection.set_status('scan-1', ScanStatus.STOPPED)

        with self.assertRaises(ResultSpoolStateError):
            collection.delete_scan('scan-1')

        self.assertTrue(collection.id_exists('scan-1'))
        self.assertTrue(self.spool.has_pending_notus('scan-1'))

    def test_rejected_redis_ack_retains_durable_acking_claim(self):
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
                owner_token=OWNER_TOKEN,
            )
            batch_id, _ = daemon.scan_collection.prepare_result_batch(scan_id)
            database = daemon.main_db.open_owned_parent_database.return_value
            database.ack_result_claim_state.return_value = outcome

            self.assertFalse(daemon.ack_result_batch(scan_id, batch_id))
            self.assertEqual(
                self.spool.get_batch(scan_id, batch_id).state,
                ClaimState.ACKING,
            )

    def test_redis_claim_is_not_released_before_gvmd_ack(self):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        redis_db = MagicMock(index=7, owner_token=OWNER_TOKEN)
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
        database = daemon.main_db.open_owned_parent_database.return_value
        database.ack_result_claim_state.return_value = ResultClaimAck.RELEASED
        database.has_pending_results.return_value = False

        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))
        database.ack_result_claim_state.assert_called_once_with('claim-1')

    def test_startup_stages_redis_only_claim_before_serving_osp(self):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        database.get_status.return_value = 'finished'
        database.has_pending_results.return_value = True
        database.claim_results.return_value = (
            'claim-redis-only',
            [redis_result_row('recovered')],
        )
        daemon.main_db.reserved_parent_databases.return_value = [
            ('scan-recovered', database)
        ]

        daemon.reconcile_result_spool()

        self.assertTrue(daemon.scan_collection.id_exists('scan-recovered'))
        self.assertEqual(
            daemon.scan_collection.get_status('scan-recovered'),
            ScanStatus.INTERRUPTED,
        )
        claim = self.spool.pending_records('scan-recovered')[0]
        self.assertEqual(claim.source_claim_id, 'claim-redis-only')
        self.assertEqual(claim.owner_token, OWNER_TOKEN)
        database.ack_result_claim_state.assert_not_called()

    def test_migrated_claim_rejects_replacement_owner_without_exact_claim(self):
        collection = self.collection()
        collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='old-claim',
            redis_db=7,
            owner_token=OWNER_TOKEN,
        )
        connection = sqlite3.connect(self.path)
        connection.execute(
            'UPDATE claims SET owner_token = NULL WHERE source_claim_id = ?',
            ('old-claim',),
        )
        connection.commit()
        connection.close()
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        database = MagicMock(index=7, owner_token='replacement-owner')
        database.current_result_claim_id.return_value = 'replacement-claim'
        daemon.main_db.reserved_parent_databases.return_value = [
            ('scan-1', database)
        ]

        with self.assertRaises(OspdOpenvasError):
            daemon.reconcile_result_spool()

        claim = self.spool.pending_records('scan-1')[0]
        self.assertIsNone(claim.owner_token)

    def test_migrated_claim_binds_only_matching_owned_redis_claim(self):
        collection = self.collection()
        collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='old-claim',
            redis_db=7,
            owner_token=OWNER_TOKEN,
        )
        connection = sqlite3.connect(self.path)
        connection.execute(
            'UPDATE claims SET owner_token = NULL WHERE source_claim_id = ?',
            ('old-claim',),
        )
        connection.commit()
        connection.close()
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        database.current_result_claim_id.return_value = 'old-claim'
        database.get_status.return_value = 'finished'
        database.has_pending_results.return_value = True
        daemon.main_db.reserved_parent_databases.return_value = [
            ('scan-1', database)
        ]

        daemon.reconcile_result_spool()

        claim = self.spool.pending_records('scan-1')[0]
        self.assertEqual(claim.owner_token, OWNER_TOKEN)

    def test_legacy_owner_claim_rebinds_after_exact_redis_migration(self):
        collection = self.collection()
        collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='old-claim',
            redis_db=7,
            owner_token='1',
        )
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        database.current_result_claim_id.return_value = 'old-claim'
        database.get_status.return_value = 'finished'
        database.has_pending_results.return_value = True
        daemon.main_db.reserved_parent_databases.return_value = [
            ('scan-1', database)
        ]

        daemon.reconcile_result_spool()

        daemon.main_db.migrate_verified_legacy_reservations.assert_called_once()
        claim = self.spool.pending_records('scan-1')[0]
        self.assertEqual(claim.owner_token, OWNER_TOKEN)

    def test_recovered_ack_stages_next_batch_then_releases_terminal_source(
        self,
    ):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        daemon.set_scan_status('scan-1', ScanStatus.INTERRUPTED)
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        database.claim_results.side_effect = [
            ('claim-1', [redis_result_row('first')]),
            ('claim-2', [redis_result_row('second')]),
        ]
        database.ack_result_claim_state.return_value = ResultClaimAck.RELEASED
        database.has_pending_results.side_effect = [True, False, False]
        database.get_status.return_value = 'finished'
        database.get_scan_databases.return_value = []
        daemon.main_db.open_owned_parent_database.return_value = database

        self.assertTrue(daemon.report_openvas_results(database, 'scan-1'))
        first_batch, first_results = (
            daemon.scan_collection.prepare_result_batch('scan-1')
        )
        self.assertEqual(first_results[0]['value'], 'first')

        self.assertTrue(daemon.ack_result_batch('scan-1', first_batch))
        second_batch, second_results = (
            daemon.scan_collection.prepare_result_batch('scan-1')
        )
        self.assertNotEqual(second_batch, first_batch)
        self.assertEqual(second_results[0]['value'], 'second')
        daemon.main_db.release_database.assert_not_called()

        self.assertTrue(daemon.ack_result_batch('scan-1', second_batch))
        self.assertFalse(self.spool.has_pending('scan-1'))
        daemon.main_db.release_database.assert_called_once_with(database)

    def test_delete_refuses_owned_recovery_source(self):
        daemon = DummyDaemon()
        add_scan(daemon.scan_collection)
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        daemon.main_db.reserved_parent_databases.return_value = [
            ('scan-1', database)
        ]

        self.assertEqual(daemon.delete_scan('scan-1'), 0)
        self.assertTrue(daemon.scan_collection.id_exists('scan-1'))

    def test_continuation_failure_retries_ack_but_released_source_settles(self):
        daemon = DummyDaemon()
        daemon.result_spool = self.spool
        daemon.scan_collection.set_result_spool(self.spool)
        add_scan(daemon.scan_collection)
        daemon.scan_collection.apply_result_batch(
            'scan-1',
            [result_row()],
            claim_id='claim-1',
            redis_db=7,
            owner_token=OWNER_TOKEN,
        )
        batch_id, _ = daemon.scan_collection.prepare_result_batch('scan-1')
        database = MagicMock(index=7, owner_token=OWNER_TOKEN)
        database.ack_result_claim_state.return_value = ResultClaimAck.RELEASED
        database.has_pending_results.side_effect = redis.ConnectionError(
            'temporary outage'
        )
        daemon.main_db.open_owned_parent_database.return_value = database

        self.assertFalse(daemon.ack_result_batch('scan-1', batch_id))
        self.assertEqual(
            self.spool.get_batch('scan-1', batch_id).state, ClaimState.ACKED
        )

        daemon.main_db.open_owned_parent_database.side_effect = (
            OspdOpenvasError('released')
        )
        daemon.main_db.reservation_token_if_present.return_value = None
        self.assertTrue(daemon.ack_result_batch('scan-1', batch_id))


if __name__ == '__main__':
    unittest.main()
