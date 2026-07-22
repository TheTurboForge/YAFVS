# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Focused durability and state-machine tests for the standalone result spool."""

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ospd.result_spool import (
    ClaimState,
    NOTUS_REDIS_DB,
    ResultSpool,
    ResultSpoolCapacityError,
    ResultSpoolConflictError,
    ResultSpoolCorruptionError,
    ResultSpoolIOError,
    ResultSpoolSerializationError,
    ResultSpoolStateError,
    ResultSpoolValidationError,
    SourceKind,
    SpoolLimits,
)

OWNER_TOKEN = 'owner-token'


class ResultSpoolTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / 'spool'
        self.path = self.root / 'results.sqlite3'

    def tearDown(self):
        self.temporary_directory.cleanup()

    def spool(self, limits=None):
        return ResultSpool(str(self.path), limits=limits)

    @staticmethod
    def results(value='first'):
        return [{'name': value, 'severity': '5.0'}]

    @staticmethod
    def notus_result(message_id='message-1', value='first'):
        return {
            'message_id': message_id,
            'group_id': 'run-1',
            'host_ip': '192.0.2.1',
            'name': 'Notus result',
            'value': value,
        }

    @staticmethod
    def notus_manifest(
        run_id='run-1',
        start_message_id='start-1',
        host_ip='192.0.2.1',
    ):
        return [
            {
                'run_id': run_id,
                'start_message_id': start_message_id,
                'host_ip': host_ip,
            }
        ]

    @staticmethod
    def admit_notus(spool, scan_id, message_id, result):
        spool.register_scan(scan_id)
        return spool.admit_notus_result(scan_id, message_id, result)

    @staticmethod
    def stage_notus(spool, scan_id):
        batch = spool.prepare_next_notus_batch(scan_id)
        return spool.stage_notus_claim(scan_id, batch.batch_id, batch.results)

    def create_historical_schema(self, version):
        """Create the exact result-spool tables retained by one release."""
        if version not in range(6):
            raise ValueError(f'unsupported historical schema version {version}')

        self.root.mkdir(mode=0o700)
        connection = sqlite3.connect(self.path)
        scan_columns = [
            'scan_id TEXT PRIMARY KEY',
            'count_dead INTEGER NOT NULL DEFAULT 0',
            'count_total INTEGER',
            'count_excluded INTEGER',
        ]
        claim_columns = [
            'sequence INTEGER PRIMARY KEY AUTOINCREMENT',
            'scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE',
        ]
        if version >= 3:
            scan_columns.append('incomplete_reason TEXT')
            claim_columns.append(
                "source_kind TEXT NOT NULL DEFAULT 'redis' "
                "CHECK(source_kind IN ('redis', 'notus'))"
            )
        if version >= 5:
            scan_columns.extend(
                [
                    "notus_manifest_mode TEXT CHECK(notus_manifest_mode IN ("
                    "'mqtt', 'none'))",
                    'notus_manifest_json TEXT',
                    'notus_manifest_digest TEXT',
                ]
            )
        claim_columns.extend(
            [
                'redis_db INTEGER NOT NULL',
                *(['owner_token TEXT'] if version >= 2 else []),
                'source_claim_id TEXT NOT NULL',
                'osp_batch_id TEXT NOT NULL UNIQUE',
                "state TEXT NOT NULL CHECK(state IN ('STAGED', 'EXPOSED', "
                "'ACKING', 'ACKED'))",
                'payload_json TEXT',
                'row_count INTEGER NOT NULL',
                'payload_bytes INTEGER NOT NULL',
                'count_dead INTEGER NOT NULL',
                'count_total INTEGER',
                'count_excluded INTEGER',
                'incomplete_reason TEXT',
                'digest TEXT NOT NULL',
                'acked_sequence INTEGER',
                'UNIQUE(redis_db, source_claim_id)',
            ]
        )
        connection.execute(f"CREATE TABLE scans ({', '.join(scan_columns)})")
        connection.execute(f"CREATE TABLE claims ({', '.join(claim_columns)})")
        connection.executescript("""
            CREATE INDEX claims_pending_scan_sequence
                ON claims(scan_id, state, sequence);
            CREATE INDEX claims_acked_sequence
                ON claims(state, acked_sequence, sequence);
            CREATE UNIQUE INDEX claims_one_pending_per_scan
                ON claims(scan_id) WHERE state != 'ACKED';
            """)
        if version >= 3:
            notus_columns = [
                'sequence INTEGER PRIMARY KEY AUTOINCREMENT',
                'scan_id TEXT NOT NULL REFERENCES scans(scan_id) '
                'ON DELETE CASCADE',
                'message_id TEXT NOT NULL',
                *(['run_id TEXT'] if version >= 4 else []),
                'batch_id TEXT',
                'payload_json TEXT',
                'payload_bytes INTEGER NOT NULL',
                'digest TEXT NOT NULL',
                'acked INTEGER NOT NULL DEFAULT 0 CHECK(acked IN (0, 1))',
                'acked_sequence INTEGER',
                'UNIQUE(message_id)',
            ]
            connection.execute(
                f"CREATE TABLE notus_ingress ({', '.join(notus_columns)})"
            )
            connection.executescript("""
                CREATE INDEX notus_ingress_pending_scan_sequence
                    ON notus_ingress(scan_id, acked, sequence);
                CREATE INDEX notus_ingress_batch
                    ON notus_ingress(scan_id, batch_id, acked, sequence);
                CREATE INDEX notus_ingress_acked_sequence
                    ON notus_ingress(acked, acked_sequence, sequence);
                """)
        if version >= 4:
            connection.executescript("""
                CREATE TABLE notus_runs (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL REFERENCES scans(scan_id)
                        ON DELETE CASCADE,
                    run_id TEXT NOT NULL,
                    host_ip TEXT NOT NULL,
                    start_message_id TEXT UNIQUE,
                    start_digest TEXT,
                    state TEXT NOT NULL CHECK(state IN (
                        'PENDING_START', 'STARTED', 'RUNNING', 'FINISHED',
                        'INTERRUPTED'
                    )),
                    expected_result_count INTEGER CHECK(
                        expected_result_count IS NULL
                        OR expected_result_count >= 0
                    ),
                    admitted_result_count INTEGER NOT NULL DEFAULT 0 CHECK(
                        admitted_result_count >= 0
                    ),
                    terminal_message_id TEXT UNIQUE,
                    terminal_digest TEXT,
                    UNIQUE(scan_id, run_id)
                );
                CREATE INDEX notus_runs_scan_state
                    ON notus_runs(scan_id, state, sequence);
                """)

        self._seed_historical_claim(connection, version)
        if version >= 3:
            self._seed_historical_notus(connection, version)
        connection.execute(f'PRAGMA user_version = {version}')
        connection.commit()
        connection.close()
        self.path.chmod(0o600)

    def _seed_historical_claim(self, connection, version):
        payload_json = ResultSpool._canonical_json(self.results('retained'))
        metadata = (2, 5, 1, 'Retained legacy claim evidence.')
        values = {
            'scan_id': 'legacy-redis-scan',
            'redis_db': 0,
            'source_claim_id': 'legacy-redis-claim',
            'osp_batch_id': 'legacy-osp-batch',
            'state': ClaimState.STAGED.value,
            'payload_json': payload_json,
            'row_count': 1,
            'payload_bytes': len(payload_json.encode('utf-8')),
            'count_dead': metadata[0],
            'count_total': metadata[1],
            'count_excluded': metadata[2],
            'incomplete_reason': metadata[3],
            'digest': ResultSpool._digest(payload_json, metadata),
        }
        connection.execute(
            'INSERT INTO scans (scan_id, count_dead, count_total, '
            'count_excluded) VALUES (?, ?, ?, ?)',
            ('legacy-redis-scan', 2, 5, 1),
        )
        columns = list(values)
        if version >= 2:
            values['owner_token'] = 'legacy-owner'
            columns.insert(2, 'owner_token')
        if version >= 3:
            values['source_kind'] = SourceKind.REDIS.value
            columns.insert(1, 'source_kind')
        connection.execute(
            f"INSERT INTO claims ({', '.join(columns)}) VALUES "
            f"({', '.join('?' for _ in columns)})",
            [values[column] for column in columns],
        )

    def _seed_historical_notus(self, connection, version):
        payload_json = ResultSpool._canonical_json(self.notus_result())
        values = {
            'scan_id': 'legacy-notus-scan',
            'message_id': 'message-1',
            'batch_id': None,
            'payload_json': payload_json,
            'payload_bytes': len(payload_json.encode('utf-8')),
            'digest': hashlib.sha256(payload_json.encode('utf-8')).hexdigest(),
            'acked': 0,
            'acked_sequence': None,
        }
        connection.execute(
            'INSERT INTO scans (scan_id, count_dead, count_total, '
            'count_excluded, incomplete_reason) VALUES (?, 0, NULL, NULL, NULL)',
            ('legacy-notus-scan',),
        )
        columns = list(values)
        if version >= 4:
            values['run_id'] = 'run-1'
            columns.insert(2, 'run_id')
        connection.execute(
            f"INSERT INTO notus_ingress ({', '.join(columns)}) VALUES "
            f"({', '.join('?' for _ in columns)})",
            [values[column] for column in columns],
        )
        if version >= 4:
            connection.execute(
                'INSERT INTO notus_runs '
                '(scan_id, run_id, host_ip, state, admitted_result_count) '
                'VALUES (?, ?, ?, ?, ?)',
                (
                    'legacy-notus-scan',
                    'run-1',
                    '192.0.2.1',
                    'PENDING_START',
                    1,
                ),
            )

    def assert_historical_claim_preserved(self, spool, owner_token):
        self.assertEqual(spool.health()['user_version'], 6)
        claim = spool.expose_next('legacy-redis-scan')
        self.assertEqual(claim.source_kind, SourceKind.REDIS)
        self.assertEqual(claim.owner_token, owner_token)
        self.assertEqual(claim.source_claim_id, 'legacy-redis-claim')
        self.assertEqual(claim.osp_batch_id, 'legacy-osp-batch')
        self.assertEqual(claim.results, self.results('retained'))
        self.assertEqual(claim.count_dead, 2)
        self.assertEqual(claim.count_total, 5)
        self.assertEqual(claim.count_excluded, 1)
        self.assertEqual(
            claim.incomplete_reason, 'Retained legacy claim evidence.'
        )

    def stage(
        self, spool, scan_id='scan-1', claim_id='redis-claim-1', **kwargs
    ):
        count_dead = kwargs.pop('count_dead', 2)
        return spool.stage_claim(
            scan_id,
            0,
            claim_id,
            OWNER_TOKEN,
            self.results(),
            count_dead=count_dead,
            **kwargs,
        )

    def acknowledge(self, spool, claim):
        exposed = spool.expose_next(claim.scan_id)
        self.assertEqual(exposed.osp_batch_id, claim.osp_batch_id)
        acking = spool.begin_ack(
            claim.scan_id,
            claim.osp_batch_id,
            claim.redis_db,
            claim.source_claim_id,
        )
        self.assertEqual(acking.state, ClaimState.ACKING)
        return spool.complete_ack(
            claim.scan_id,
            claim.osp_batch_id,
            claim.redis_db,
            claim.source_claim_id,
        )

    def test_stage_expose_ack_and_reopen_all_states(self):
        with self.spool() as spool:
            staged = self.stage(spool, claim_id='staged')
            acking = self.stage(spool, 'scan-2', 'acking')
            exposed = self.stage(spool, 'scan-3', 'exposed')
            completed = self.stage(spool, 'scan-4', 'acked')
            acking = spool.expose_next('scan-2')
            spool.begin_ack(
                'scan-2', acking.osp_batch_id, acking.redis_db, 'acking'
            )
            exposed = spool.expose_next('scan-3')
            self.assertEqual(exposed.state, ClaimState.EXPOSED)
            acked = self.acknowledge(spool, completed)
            self.assertEqual(acked.state, ClaimState.ACKED)

        with self.spool() as reopened:
            records = {
                record.source_claim_id: record
                for record in reopened.recovery_records()
            }
            self.assertEqual(records['staged'].state, ClaimState.STAGED)
            self.assertEqual(records['acking'].state, ClaimState.ACKING)
            self.assertEqual(records['exposed'].state, ClaimState.EXPOSED)
            self.assertFalse(reopened.has_pending('scan-4'))
            self.assertTrue(reopened.has_pending('scan-1'))
            duplicate = reopened.complete_ack(
                'scan-4', acked.osp_batch_id, acked.redis_db, 'acked'
            )
            self.assertEqual(duplicate.state, ClaimState.ACKED)

    def test_late_ack_does_not_prune_its_own_tombstone(self):
        limits = SpoolLimits(max_acked_tombstones=2)
        with self.spool(limits) as spool:
            oldest = self.stage(spool, scan_id='old', claim_id='old')
            spool.expose_next('old')
            spool.begin_ack('old', oldest.osp_batch_id, 0, 'old')
            newer = []
            for scan_id in ('new-1', 'new-2'):
                claim = self.stage(spool, scan_id=scan_id, claim_id=scan_id)
                newer.append(claim)
                self.acknowledge(spool, claim)

            completed = spool.complete_ack('old', oldest.osp_batch_id, 0, 'old')

            self.assertEqual(completed.state, ClaimState.ACKED)
            self.assertIsNotNone(spool.get_batch('old', oldest.osp_batch_id))
            self.assertIsNone(spool.get_batch('new-1', newer[0].osp_batch_id))
            self.assertIsNotNone(
                spool.get_batch('new-2', newer[1].osp_batch_id)
            )

    def test_concurrent_duplicate_complete_ack_is_idempotent(self):
        with self.spool() as spool:
            claim = self.stage(spool)
            spool.expose_next('scan-1')
            spool.begin_ack(
                'scan-1',
                claim.osp_batch_id,
                0,
                claim.source_claim_id,
            )

            def complete(_):
                return spool.complete_ack(
                    'scan-1',
                    claim.osp_batch_id,
                    0,
                    claim.source_claim_id,
                ).state

            with ThreadPoolExecutor(max_workers=6) as executor:
                states = list(executor.map(complete, range(12)))

            self.assertEqual(states, [ClaimState.ACKED] * 12)

    def test_idempotent_stage_normalizes_mapping_order_and_rejects_conflict(
        self,
    ):
        with self.spool() as spool:
            first = spool.stage_claim(
                'scan-1',
                0,
                'claim-1',
                OWNER_TOKEN,
                [{'b': 2, 'a': {'x': True}}],
            )
            same = spool.stage_claim(
                'scan-1',
                0,
                'claim-1',
                OWNER_TOKEN,
                [{'a': {'x': True}, 'b': 2}],
            )
            self.assertEqual(first.osp_batch_id, same.osp_batch_id)
            self.assertEqual(same.results, [{'a': {'x': True}, 'b': 2}])
            with self.assertRaises(ResultSpoolConflictError):
                spool.stage_claim(
                    'scan-1', 0, 'claim-1', OWNER_TOKEN, self.results('other')
                )
            with self.assertRaises(ResultSpoolConflictError):
                spool.stage_claim(
                    'other-scan', 0, 'claim-1', OWNER_TOKEN, self.results()
                )
            with self.assertRaises(ResultSpoolConflictError):
                spool.stage_claim(
                    'scan-1', 0, 'claim-1', 'other-owner', self.results()
                )

    def test_concurrent_duplicate_stage_gets_one_stable_batch(self):
        with self.spool() as spool:

            def stage_once(_):
                return spool.stage_claim(
                    'scan-1', 0, 'claim-1', OWNER_TOKEN, self.results()
                )

            with ThreadPoolExecutor(max_workers=6) as executor:
                claims = list(executor.map(stage_once, range(12)))
        self.assertEqual(len({claim.osp_batch_id for claim in claims}), 1)
        with self.spool() as spool:
            self.assertEqual(len(spool.recovery_records()), 1)

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX process forking')
    def test_inherited_spool_object_reopens_connection_after_fork(self):
        with self.spool() as spool:
            child = os.fork()
            if child == 0:
                try:
                    spool.stage_claim(
                        'scan-1', 0, 'claim-1', OWNER_TOKEN, self.results()
                    )
                except Exception:  # pragma: no cover - child status is proof
                    os._exit(1)
                os._exit(0)

            _, status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
            replay = spool.stage_claim(
                'scan-1', 0, 'claim-1', OWNER_TOKEN, self.results()
            )
            self.assertEqual(replay.state, ClaimState.STAGED)
            self.assertEqual(len(spool.recovery_records()), 1)

    def test_exact_acknowledgements_fail_closed_without_state_change(self):
        with self.spool() as spool:
            claim = self.stage(spool)
            exposed = spool.expose_next('scan-1')
            with self.assertRaises(ResultSpoolStateError):
                spool.begin_ack(
                    'wrong', exposed.osp_batch_id, 0, 'redis-claim-1'
                )
            with self.assertRaises(ResultSpoolStateError):
                spool.begin_ack('scan-1', 'wrong', 0, 'redis-claim-1')
            with self.assertRaises(ResultSpoolStateError):
                spool.begin_ack(
                    'scan-1', exposed.osp_batch_id, 1, 'redis-claim-1'
                )
            with self.assertRaises(ResultSpoolStateError):
                spool.begin_ack('scan-1', exposed.osp_batch_id, 0, 'wrong')
            current = spool.pending_records('scan-1')[0]
            self.assertEqual(current.state, ClaimState.EXPOSED)
            self.assertEqual(
                spool.get_batch('scan-1', current.osp_batch_id), current
            )
            self.assertIsNone(spool.get_batch('scan-1', 'missing'))
            with self.assertRaises(ResultSpoolStateError):
                spool.complete_ack(
                    'scan-1', claim.osp_batch_id, 0, 'redis-claim-1'
                )
            self.assertEqual(
                spool.pending_records('scan-1')[0].state, ClaimState.EXPOSED
            )

    def test_capacity_bounds_at_and_beyond_boundary(self):
        limits = SpoolLimits(
            max_result_row_bytes=64,
            max_claim_rows=2,
            max_claim_bytes=64,
            max_scan_pending_rows=2,
            max_scan_pending_bytes=64,
            max_scan_pending_claims=1,
            max_global_pending_rows=3,
            max_global_pending_bytes=96,
            max_global_pending_claims=2,
            max_acked_tombstones=2,
        )
        with self.spool(limits) as spool:
            exact = [{'name': 'a'}, {'name': 'b'}]
            claim = spool.stage_claim('scan-1', 0, 'one', OWNER_TOKEN, exact)
            self.assertEqual(len(claim.results), 2)
            with self.assertRaises(ResultSpoolCapacityError):
                spool.stage_claim(
                    'scan-1', 0, 'two', OWNER_TOKEN, self.results()
                )
            with self.assertRaises(ResultSpoolCapacityError):
                spool.stage_claim(
                    'scan-2', 0, 'three', OWNER_TOKEN, [{'value': 'x' * 63}]
                )
            self.acknowledge(spool, claim)
            accepted = spool.stage_claim(
                'scan-1', 0, 'two', OWNER_TOKEN, self.results()
            )
            self.assertEqual(accepted.state, ClaimState.STAGED)

    def test_count_metadata_and_pending_scan_state(self):
        with self.spool() as spool:
            first = self.stage(spool, count_total=10, count_excluded=1)
            self.acknowledge(spool, first)
            self.stage(
                spool,
                claim_id='redis-claim-2',
                count_dead=3,
                count_total=12,
            )
            state = spool.pending_scan_states()[0]
            self.assertEqual(state.count_dead, 5)
            self.assertEqual(state.count_total, 12)
            self.assertEqual(state.count_excluded, 1)
            self.assertEqual(state.pending_claims, 1)
            self.assertEqual(state.pending_rows, 1)

    def test_marker_only_state_survives_clean_registry_pruning(self):
        with self.spool() as spool:
            spool.register_scan('clean-scan')
            spool.seal_notus_manifest('clean-scan', 'none', [])
            spool.register_scan('unsealed-scan')
            spool.register_scan('incomplete-scan')
            spool.mark_scan_incomplete(
                'incomplete-scan', 'Scanner evidence is incomplete.'
            )

            states = {
                state.scan_id: state for state in spool.pending_scan_states()
            }
            self.assertEqual(
                states['incomplete-scan'].incomplete_reason,
                'Scanner evidence is incomplete.',
            )
            self.assertIn('unsealed-scan', states)
            self.assertEqual(states['incomplete-scan'].pending_rows, 0)
            self.assertEqual(spool.prune_clean_scan_rows(), 1)
            self.assertFalse(spool.delete_scan('clean-scan'))
            self.assertTrue(spool.delete_scan('unsealed-scan'))
            self.assertTrue(spool.delete_scan('incomplete-scan'))

    def test_clean_registry_pruning_preserves_pending_sources(self):
        with self.spool() as spool:
            self.stage(spool)
            spool.register_scan('notus-scan')
            spool.admit_notus_result(
                'notus-scan',
                'message-1',
                self.notus_result('message-1'),
            )

            self.assertEqual(spool.prune_clean_scan_rows(), 0)
            self.assertTrue(spool.has_pending('scan-1'))
            self.assertTrue(spool.has_pending_notus('notus-scan'))

    def test_notus_terminal_count_is_bounded_by_admission_limit(self):
        limits = SpoolLimits(max_notus_scan_pending_rows=1)
        with self.spool(limits) as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start('scan-1', 'run-1', 'start-1', '192.0.2.1')
            with self.assertRaisesRegex(
                ResultSpoolValidationError, 'supported range'
            ):
                spool.admit_notus_status(
                    'scan-1',
                    'run-1',
                    'finish-1',
                    '192.0.2.1',
                    'finished',
                    2,
                )

    def test_acked_tombstones_are_small_and_pruned_oldest_first(self):
        limits = SpoolLimits(max_acked_tombstones=2)
        with self.spool(limits) as spool:
            first = self.stage(spool, claim_id='one')
            self.acknowledge(spool, first)
            second = self.stage(spool, claim_id='two')
            self.acknowledge(spool, second)
            third = self.stage(spool, claim_id='three')
            acked = self.acknowledge(spool, third)
            self.assertEqual(acked.results, [])
            with self.assertRaises(ResultSpoolStateError):
                spool.complete_ack('scan-1', first.osp_batch_id, 0, 'one')
            duplicate = spool.complete_ack(
                'scan-1', third.osp_batch_id, 0, 'three'
            )
            self.assertEqual(duplicate.state, ClaimState.ACKED)

    def test_empty_claims_are_bounded_by_claim_count(self):
        limits = SpoolLimits(
            max_scan_pending_claims=1,
            max_global_pending_claims=2,
        )
        with self.spool(limits) as spool:
            first = spool.stage_claim('scan-1', 0, 'one', OWNER_TOKEN, [])
            with self.assertRaises(ResultSpoolCapacityError):
                spool.stage_claim('scan-1', 0, 'two', OWNER_TOKEN, [])
            spool.stage_claim('scan-2', 0, 'three', OWNER_TOKEN, [])
            with self.assertRaises(ResultSpoolCapacityError):
                spool.stage_claim('scan-3', 0, 'four', OWNER_TOKEN, [])
            self.acknowledge(spool, first)
            accepted = spool.stage_claim('scan-3', 0, 'four', OWNER_TOKEN, [])
            self.assertEqual(accepted.state, ClaimState.STAGED)

    def test_delete_requires_no_pending_claims(self):
        with self.spool() as spool:
            claim = self.stage(spool)
            with self.assertRaises(ResultSpoolStateError):
                spool.delete_scan('scan-1')
            self.acknowledge(spool, claim)
            self.assertTrue(spool.delete_scan('scan-1'))
            self.assertFalse(spool.delete_scan('scan-1'))

    def test_notus_ingress_survives_reopen_and_exact_ack(self):
        result = self.notus_result()
        with self.spool() as spool:
            spool.register_scan('scan-1')
            self.assertTrue(
                spool.admit_notus_start(
                    'scan-1',
                    'run-1',
                    'start-1',
                    '192.0.2.1',
                )
            )
            self.assertTrue(
                self.admit_notus(spool, 'scan-1', 'message-1', result)
            )
            self.assertTrue(
                spool.admit_notus_status(
                    'scan-1',
                    'run-1',
                    'finish-1',
                    '192.0.2.1',
                    'finished',
                    1,
                )
            )
            self.assertTrue(spool.has_pending_notus('scan-1'))
            self.assertEqual(spool.pending_notus_scan_ids(), ['scan-1'])
            with self.assertRaises(ResultSpoolStateError):
                spool.delete_scan('scan-1')

        with self.spool() as reopened:
            claim = self.stage_notus(reopened, 'scan-1')
            self.assertEqual(claim.source_kind, SourceKind.NOTUS)
            self.assertEqual(claim.redis_db, NOTUS_REDIS_DB)
            self.assertIsNone(claim.owner_token)
            self.assertEqual(claim.results, [result])
            exposed = reopened.expose_next('scan-1')
            self.assertEqual(exposed.osp_batch_id, claim.osp_batch_id)
            reopened.begin_ack(
                'scan-1',
                claim.osp_batch_id,
                NOTUS_REDIS_DB,
                claim.source_claim_id,
            )
            acked = reopened.complete_ack(
                'scan-1',
                claim.osp_batch_id,
                NOTUS_REDIS_DB,
                claim.source_claim_id,
            )
            self.assertEqual(acked.state, ClaimState.ACKED)
            self.assertEqual(
                reopened.complete_notus_batch('scan-1', claim.source_claim_id),
                1,
            )
            self.assertFalse(reopened.has_pending_notus('scan-1'))
            self.assertFalse(reopened.has_pending('scan-1'))

    def test_notus_terminal_count_fences_materialized_results(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start('scan-1', 'run-1', 'start-1', '192.0.2.1')
            spool.admit_notus_result('scan-1', 'message-1', self.notus_result())
            spool.admit_notus_status(
                'scan-1',
                'run-1',
                'finish-1',
                '192.0.2.1',
                'finished',
                1,
            )
            spool.seal_notus_manifest('scan-1', 'mqtt', self.notus_manifest())
            self.assertFalse(spool.notus_completion_ready('scan-1'))
            self.stage_notus(spool, 'scan-1')
            self.assertTrue(spool.notus_completion_ready('scan-1'))

        with self.spool() as reopened:
            self.assertTrue(reopened.notus_completion_ready('scan-1'))

    def test_notus_zero_result_run_has_exact_terminal_fence(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start('scan-1', 'run-1', 'start-1', '192.0.2.1')
            spool.admit_notus_status(
                'scan-1',
                'run-1',
                'finish-1',
                '192.0.2.1',
                'finished',
                0,
            )
            spool.seal_notus_manifest('scan-1', 'mqtt', self.notus_manifest())
            self.assertTrue(spool.notus_completion_ready('scan-1'))

    def test_finished_notus_run_survives_restart_until_manifest_is_sealed(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start('scan-1', 'run-1', 'start-1', '192.0.2.1')
            spool.admit_notus_status(
                'scan-1',
                'run-1',
                'finish-1',
                '192.0.2.1',
                'finished',
                0,
            )

        with self.spool() as reopened:
            self.assertEqual(reopened.pending_notus_scan_ids(), ['scan-1'])
            self.assertEqual(
                [state.scan_id for state in reopened.pending_scan_states()],
                ['scan-1'],
            )
            self.assertEqual(reopened.prune_clean_scan_rows(), 0)
            self.assertTrue(
                reopened.seal_notus_manifest(
                    'scan-1', 'mqtt', self.notus_manifest()
                )
            )
            self.assertTrue(reopened.notus_completion_ready('scan-1'))
            self.assertEqual(reopened.pending_notus_scan_ids(), [])
            self.assertEqual(reopened.prune_clean_scan_rows(), 1)

    def test_notus_terminal_count_mismatch_stays_incomplete(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start('scan-1', 'run-1', 'start-1', '192.0.2.1')
            spool.admit_notus_status(
                'scan-1',
                'run-1',
                'finish-1',
                '192.0.2.1',
                'finished',
                1,
            )
            spool.seal_notus_manifest('scan-1', 'mqtt', self.notus_manifest())
            self.assertFalse(spool.notus_completion_ready('scan-1'))
            self.assertTrue(spool.has_pending('scan-1'))

    def test_notus_run_registry_is_bounded_and_fails_closed(self):
        limits = SpoolLimits(max_notus_scan_pending_rows=1)
        with self.spool(limits) as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start('scan-1', 'run-1', 'start-1', '192.0.2.1')
            with self.assertRaises(ResultSpoolCapacityError):
                spool.admit_notus_start(
                    'scan-1', 'run-2', 'start-2', '192.0.2.2'
                )
            self.assertIn(
                'run capacity was exhausted',
                spool.scan_incomplete_reason('scan-1'),
            )

    def test_notus_terminal_before_start_is_reconciled_idempotently(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            self.assertTrue(
                spool.admit_notus_status(
                    'scan-1',
                    'run-1',
                    'finish-1',
                    '192.0.2.1',
                    'finished',
                    0,
                )
            )
            self.assertFalse(spool.notus_completion_ready('scan-1'))
            self.assertTrue(
                spool.admit_notus_start(
                    'scan-1',
                    'run-1',
                    'start-1',
                    '192.0.2.1',
                )
            )
            self.assertFalse(
                spool.admit_notus_start(
                    'scan-1',
                    'run-1',
                    'start-1',
                    '192.0.2.1',
                )
            )
            spool.seal_notus_manifest('scan-1', 'mqtt', self.notus_manifest())
            self.assertTrue(spool.notus_completion_ready('scan-1'))

    def test_notus_manifest_distinguishes_zero_work_from_missed_stream(self):
        with self.spool() as spool:
            spool.register_scan('zero-scan')
            self.assertTrue(spool.seal_notus_manifest('zero-scan', 'mqtt', []))
            self.assertTrue(spool.notus_completion_ready('zero-scan'))

            spool.register_scan('missed-scan')
            spool.seal_notus_manifest(
                'missed-scan', 'mqtt', self.notus_manifest()
            )
            self.assertFalse(spool.notus_completion_ready('missed-scan'))

    def test_general_incomplete_evidence_does_not_block_notus_completion(self):
        reason = 'Malformed scanner result rows were discarded.'
        with self.spool() as spool:
            spool.register_scan('scan-1')
            spool.mark_scan_incomplete('scan-1', reason)
            spool.seal_notus_manifest('scan-1', 'none', [])

            self.assertEqual(spool.scan_incomplete_reason('scan-1'), reason)
            self.assertIsNone(spool.notus_completion_issue('scan-1'))
            self.assertTrue(spool.notus_completion_ready('scan-1'))

    def test_notus_manifest_rejects_removed_openvasd_transport(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            with self.assertRaisesRegex(
                ResultSpoolValidationError, 'unsupported Notus manifest mode'
            ):
                spool.seal_notus_manifest('scan-1', 'openvasd', [])

    def test_notus_manifest_rejects_wrong_observed_identity(self):
        with self.spool() as spool:
            spool.register_scan('scan-1')
            spool.admit_notus_start(
                'scan-1', 'run-1', 'unexpected-start', '192.0.2.1'
            )
            with self.assertRaisesRegex(
                ResultSpoolConflictError, 'does not match'
            ):
                spool.seal_notus_manifest(
                    'scan-1', 'mqtt', self.notus_manifest()
                )
            self.assertIn(
                'does not match', spool.scan_incomplete_reason('scan-1')
            )
            self.assertIn(
                'does not match', spool.notus_completion_issue('scan-1')
            )

    def test_notus_duplicate_is_idempotent_and_conflict_fails_closed(self):
        result = self.notus_result()
        with self.spool() as spool:
            self.assertTrue(
                self.admit_notus(spool, 'scan-1', 'message-1', result)
            )
            self.assertFalse(
                spool.admit_notus_result('scan-1', 'message-1', result)
            )
            spool.register_scan('scan-2')
            with self.assertRaises(ResultSpoolConflictError):
                spool.admit_notus_result(
                    'scan-2',
                    'message-1',
                    self.notus_result(value='conflicting'),
                )
            self.assertIn(
                'reused with conflicting data',
                spool.scan_incomplete_reason('scan-1'),
            )
            self.assertIn(
                'reused with conflicting data',
                spool.scan_incomplete_reason('scan-2'),
            )
            claim = self.stage_notus(spool, 'scan-1')
            self.assertEqual(claim.results, [result])

    def test_notus_capacity_failure_is_durable_and_preserves_admitted_rows(
        self,
    ):
        limits = SpoolLimits(
            max_notus_scan_pending_rows=1,
            max_notus_global_pending_rows=2,
            max_notus_pending_scans=1,
        )
        with self.spool(limits) as spool:
            first = self.notus_result()
            self.admit_notus(spool, 'scan-1', 'message-1', first)
            with self.assertRaises(ResultSpoolCapacityError):
                spool.register_scan('scan-2')
                spool.admit_notus_result(
                    'scan-1',
                    'message-2',
                    self.notus_result('message-2', 'second'),
                )
            with self.assertRaises(ResultSpoolCapacityError):
                spool.admit_notus_result(
                    'scan-2',
                    'message-3',
                    self.notus_result('message-3', 'third'),
                )
            self.assertIn(
                'capacity was exhausted',
                spool.scan_incomplete_reason('scan-1'),
            )
            self.assertIn(
                'capacity was exhausted',
                spool.scan_incomplete_reason('scan-2'),
            )
            self.assertEqual(
                self.stage_notus(spool, 'scan-1').results,
                [first],
            )

        with self.spool(limits) as reopened:
            states = {
                state.scan_id: state for state in reopened.pending_scan_states()
            }
            self.assertEqual(states['scan-1'].pending_rows, 1)
            self.assertIn(
                'capacity was exhausted',
                states['scan-1'].incomplete_reason,
            )

    def test_notus_batch_identity_and_tombstones_are_stable_and_bounded(self):
        limits = SpoolLimits(
            max_claim_rows=1,
            max_notus_acked_tombstones=1,
        )
        with self.spool(limits) as spool:
            for index in range(2):
                message_id = f'message-{index}'
                self.admit_notus(
                    spool,
                    'scan-1',
                    message_id,
                    self.notus_result(message_id, str(index)),
                )
            first_batch = spool.prepare_next_notus_batch('scan-1')
            first = spool.stage_notus_claim(
                'scan-1', first_batch.batch_id, first_batch.results
            )
            self.assertEqual(
                spool.stage_notus_claim(
                    'scan-1', first_batch.batch_id, first_batch.results
                ).osp_batch_id,
                first.osp_batch_id,
            )
            spool.expose_next('scan-1')
            spool.begin_ack(
                'scan-1',
                first.osp_batch_id,
                NOTUS_REDIS_DB,
                first.source_claim_id,
            )
            spool.complete_ack(
                'scan-1',
                first.osp_batch_id,
                NOTUS_REDIS_DB,
                first.source_claim_id,
            )
            self.assertEqual(
                spool.complete_notus_batch('scan-1', first.source_claim_id),
                1,
            )
            second = self.stage_notus(spool, 'scan-1')
            self.assertNotEqual(second.source_claim_id, first.source_claim_id)
            spool.expose_next('scan-1')
            spool.begin_ack(
                'scan-1',
                second.osp_batch_id,
                NOTUS_REDIS_DB,
                second.source_claim_id,
            )
            spool.complete_ack(
                'scan-1',
                second.osp_batch_id,
                NOTUS_REDIS_DB,
                second.source_claim_id,
            )
            spool.complete_notus_batch('scan-1', second.source_claim_id)

        with sqlite3.connect(self.path) as connection:
            self.assertEqual(
                connection.execute(
                    'SELECT COUNT(*) FROM notus_ingress WHERE acked = 1'
                ).fetchone()[0],
                1,
            )

    def test_rejects_malformed_results_and_corrupt_digest(self):
        with self.spool() as spool:
            with self.assertRaises(ResultSpoolSerializationError):
                spool.stage_claim(
                    'scan-1', 0, 'bad', OWNER_TOKEN, [{'bad': {1, 2}}]
                )
            claim = self.stage(spool)
        connection = sqlite3.connect(str(self.path))
        connection.execute(
            "UPDATE claims SET digest = 'bad' WHERE osp_batch_id = ?",
            (claim.osp_batch_id,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ResultSpoolCorruptionError):
            self.spool()

    def test_verified_migration_rebinds_only_null_or_legacy_owner(self):
        with self.spool() as spool:
            claim = self.stage(spool)
            with sqlite3.connect(self.path) as connection:
                connection.execute(
                    'UPDATE claims SET owner_token = ? '
                    'WHERE source_claim_id = ?',
                    ('1', claim.source_claim_id),
                )
            migrated_owner = 'verified-unique-owner'
            rebound = spool.bind_owner_token(
                claim.redis_db, claim.source_claim_id, migrated_owner
            )
            self.assertEqual(rebound.owner_token, migrated_owner)
            with self.assertRaises(ResultSpoolValidationError):
                spool.bind_owner_token(
                    claim.redis_db, claim.source_claim_id, '1'
                )
            with self.assertRaises(ResultSpoolConflictError):
                spool.bind_owner_token(
                    claim.redis_db,
                    claim.source_claim_id,
                    'different-owner',
                )

    def test_wal_full_durability_and_owner_only_permissions(self):
        with self.spool() as spool:
            self.stage(spool)
            health = spool.health()
            self.assertEqual(health['quick_check'], 'ok')
            self.assertEqual(health['journal_mode'], 'wal')
            self.assertEqual(health['synchronous'], 2)
            self.assertEqual(health['foreign_keys'], 1)
            self.assertEqual(health['user_version'], 6)
            for candidate in (self.root, self.path):
                self.assertEqual(
                    stat.S_IMODE(candidate.stat().st_mode) & 0o077, 0
                )
            for candidate in (
                Path(f'{self.path}-wal'),
                Path(f'{self.path}-shm'),
            ):
                if candidate.exists():
                    self.assertEqual(
                        stat.S_IMODE(candidate.stat().st_mode) & 0o077, 0
                    )
        self.path.chmod(0o644)
        with self.assertRaises(ResultSpoolIOError):
            self.spool()

    def test_version_one_schema_migrates_owner_token_column(self):
        self.create_historical_schema(1)

        with self.spool() as spool:
            self.assert_historical_claim_preserved(spool, None)
        connection = sqlite3.connect(self.path)
        columns = {
            row[1] for row in connection.execute('PRAGMA table_info(claims)')
        }
        connection.close()
        self.assertIn('owner_token', columns)

    def test_version_two_schema_migrates_to_version_three(self):
        self.create_historical_schema(2)

        with self.spool() as spool:
            self.assert_historical_claim_preserved(spool, 'legacy-owner')

        with sqlite3.connect(self.path) as connection:
            claim_columns = {
                row[1]
                for row in connection.execute('PRAGMA table_info(claims)')
            }
            scan_columns = {
                row[1] for row in connection.execute('PRAGMA table_info(scans)')
            }
            self.assertIn('source_kind', claim_columns)
            self.assertIn('incomplete_reason', scan_columns)
            self.assertIsNotNone(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'notus_ingress'"
                ).fetchone()
            )

    def test_crash_created_version_zero_old_schema_migrates(self):
        self.create_historical_schema(0)

        with self.spool() as spool:
            self.assert_historical_claim_preserved(spool, None)

    def test_version_three_notus_ingress_migrates_fail_closed(self):
        self.create_historical_schema(3)
        with sqlite3.connect(self.path) as connection:
            columns = {
                row[1]
                for row in connection.execute(
                    'PRAGMA table_info(notus_ingress)'
                )
            }
            self.assertNotIn('run_id', columns)

        with self.spool() as migrated:
            self.assert_historical_claim_preserved(migrated, 'legacy-owner')
            self.assertIn(
                'no terminal completion fence',
                migrated.scan_incomplete_reason('legacy-notus-scan'),
            )
            self.assertFalse(
                migrated.notus_completion_ready('legacy-notus-scan')
            )
            batch = migrated.prepare_next_notus_batch('legacy-notus-scan')
            self.assertEqual(batch.results, [self.notus_result()])
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(
                connection.execute(
                    'SELECT run_id FROM notus_ingress'
                ).fetchone()[0],
                'run-1',
            )
            self.assertEqual(
                connection.execute(
                    'SELECT admitted_result_count FROM notus_runs'
                ).fetchone()[0],
                1,
            )

    def test_version_five_general_failure_does_not_become_notus_failure(self):
        self.create_historical_schema(5)
        reason = 'Malformed scanner result rows were discarded.'
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                'UPDATE scans SET incomplete_reason = ? '
                "WHERE scan_id = 'legacy-redis-scan'",
                (reason,),
            )

        with self.spool() as migrated:
            migrated.seal_notus_manifest('legacy-redis-scan', 'none', [])
            self.assertEqual(
                migrated.scan_incomplete_reason('legacy-redis-scan'), reason
            )
            self.assertIsNone(
                migrated.notus_completion_issue('legacy-redis-scan')
            )
            self.assertTrue(
                migrated.notus_completion_ready('legacy-redis-scan')
            )

    def test_version_four_notus_rows_migrate_with_manifest_marker(self):
        self.create_historical_schema(4)

        with sqlite3.connect(self.path) as connection:
            columns = {
                row[1] for row in connection.execute('PRAGMA table_info(scans)')
            }
            self.assertNotIn('notus_manifest_mode', columns)

        with self.spool() as migrated:
            self.assert_historical_claim_preserved(migrated, 'legacy-owner')
            self.assertIn(
                'no sealed expectation manifest',
                migrated.scan_incomplete_reason('legacy-notus-scan'),
            )
            self.assertFalse(
                migrated.notus_completion_ready('legacy-notus-scan')
            )
            batch = migrated.prepare_next_notus_batch('legacy-notus-scan')
            self.assertEqual(batch.results, [self.notus_result()])

    def test_version_two_schema_missing_owner_column_fails_closed(self):
        self.root.mkdir(mode=0o700)
        connection = sqlite3.connect(self.path)
        connection.executescript(
            ResultSpool._SCHEMA.replace('        owner_token TEXT,\n', '')
        )
        connection.execute('PRAGMA user_version = 2')
        connection.commit()
        connection.close()
        self.path.chmod(0o600)

        with self.assertRaises(ResultSpoolCorruptionError):
            self.spool()

    def test_rejects_invalid_state_and_identity_inputs(self):
        with self.spool() as spool:
            with self.assertRaises(ResultSpoolValidationError):
                spool.stage_claim('', 0, 'claim', OWNER_TOKEN, [])
            with self.assertRaises(ResultSpoolValidationError):
                spool.stage_claim('scan', -1, 'claim', OWNER_TOKEN, [])
            with self.assertRaises(ResultSpoolValidationError):
                spool.stage_claim('scan', 0, '', OWNER_TOKEN, [])


if __name__ == '__main__':
    unittest.main()
