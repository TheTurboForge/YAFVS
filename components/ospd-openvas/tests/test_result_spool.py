# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Focused durability and state-machine tests for the standalone result spool."""

import os
import sqlite3
import stat
import tempfile
import unittest

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ospd.result_spool import (
    ClaimState,
    ResultSpool,
    ResultSpoolCapacityError,
    ResultSpoolConflictError,
    ResultSpoolCorruptionError,
    ResultSpoolIOError,
    ResultSpoolSerializationError,
    ResultSpoolStateError,
    ResultSpoolValidationError,
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

    def test_wal_full_durability_and_owner_only_permissions(self):
        with self.spool() as spool:
            self.stage(spool)
            health = spool.health()
            self.assertEqual(health['quick_check'], 'ok')
            self.assertEqual(health['journal_mode'], 'wal')
            self.assertEqual(health['synchronous'], 2)
            self.assertEqual(health['foreign_keys'], 1)
            self.assertEqual(health['user_version'], 2)
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
        self.root.mkdir(mode=0o700)
        connection = sqlite3.connect(self.path)
        connection.executescript(
            ResultSpool._SCHEMA.replace('        owner_token TEXT,\n', '')
        )
        connection.execute('PRAGMA user_version = 1')
        connection.commit()
        connection.close()
        self.path.chmod(0o600)

        with self.spool() as spool:
            self.assertEqual(spool.health()['user_version'], 2)
        connection = sqlite3.connect(self.path)
        columns = {
            row[1] for row in connection.execute('PRAGMA table_info(claims)')
        }
        connection.close()
        self.assertIn('owner_token', columns)

    def test_crash_created_version_zero_old_schema_migrates(self):
        self.root.mkdir(mode=0o700)
        connection = sqlite3.connect(self.path)
        connection.executescript(
            ResultSpool._SCHEMA.replace('        owner_token TEXT,\n', '')
        )
        connection.commit()
        connection.close()
        self.path.chmod(0o600)

        with self.spool() as spool:
            self.assertEqual(spool.health()['user_version'], 2)
            claim = self.stage(spool)
            self.assertEqual(claim.owner_token, OWNER_TOKEN)

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
