# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-2.0-or-later

import ast
import re
import shutil
import subprocess
import tempfile
import time
import uuid

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import TestCase, skipUnless
from unittest.mock import patch

import redis

from ospd_openvas.db import (
    ACK_RESULT_CLAIM_SCRIPT,
    CLAIM_RESULT_ITEMS_SCRIPT,
    DBINDEX_NAME,
    KbDB,
    MainDB,
    OpenvasDB,
    ResultClaimAck,
)
from ospd_openvas.errors import OspdOpenvasError

REDIS_SERVER = shutil.which('redis-server')
ROOT = Path(__file__).resolve().parents[3]


def load_c_admission_script() -> str:
    source = (ROOT / 'components/gvm-libs/util/kb.c').read_text(
        encoding='utf-8'
    )
    block = re.search(
        r'SCANNER_RESULT_ADMISSION_SCRIPT\s*=\s*(.*?);\n\nstatic const struct',
        source,
        re.DOTALL,
    )
    if block is None:
        raise AssertionError('scanner result admission script is missing')
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"', block.group(1))
    return ''.join(ast.literal_eval(token) for token in tokens)


@skipUnless(REDIS_SERVER, 'redis-server executable is not available')
class ResultQueueRedisIntegrationTestCase(TestCase):
    SOURCE = 'internal/results'
    CLAIM = 'internal/results.ospd-claim'
    CLAIM_ID = 'internal/results.ospd-claim-id'
    FAILURE = 'internal/results.admission-failure'
    PENDING_COUNT = 'internal/results.pending-count'
    PENDING_BYTES = 'internal/results.pending-bytes'
    ADMISSION_IDS = 'internal/results.admission-ids'
    CLAIM_ADMISSION_IDS = 'internal/results.ospd-claim-admission-ids'
    RESULT_SIZES = 'internal/results.sizes'
    CLAIM_RESULT_SIZES = 'internal/results.ospd-claim-sizes'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.admission_script = load_c_admission_script()
        cls.redis_directory = tempfile.TemporaryDirectory(
            prefix='turbovas-result-queue-redis-'
        )
        cls.socket_path = Path(cls.redis_directory.name) / 'redis.sock'
        cls.redis_url = f'unix://{cls.socket_path}'
        cls.redis_process = subprocess.Popen(
            [
                REDIS_SERVER,
                '--port',
                '0',
                '--protected-mode',
                'yes',
                '--unixsocket',
                str(cls.socket_path),
                '--unixsocketperm',
                '700',
                '--save',
                '',
                '--appendonly',
                'no',
                '--dir',
                cls.redis_directory.name,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5
        while True:
            if cls.redis_process.poll() is not None:
                cls.redis_directory.cleanup()
                raise RuntimeError('temporary redis-server failed to start')
            try:
                redis.Redis.from_url(cls.redis_url).ping()
                break
            except redis.RedisError:
                if time.monotonic() >= deadline:
                    cls.redis_process.terminate()
                    cls.redis_process.wait(timeout=5)
                    cls.redis_directory.cleanup()
                    raise RuntimeError(
                        'temporary redis-server did not become ready'
                    )
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.redis_process.terminate()
        try:
            cls.redis_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.redis_process.kill()
            cls.redis_process.wait(timeout=5)
        cls.redis_directory.cleanup()
        super().tearDownClass()

    def setUp(self):
        self.ctx = redis.Redis.from_url(self.redis_url, decode_responses=True)
        for index in range(16):
            self.redis_db(index).flushdb()

    def tearDown(self):
        for index in range(16):
            self.redis_db(index).flushdb()

    def redis_db(self, index: int):
        return redis.Redis(
            unix_socket_path=str(self.socket_path),
            db=index,
            decode_responses=True,
        )

    def redis_db_raw(self, index: int):
        return redis.Redis(
            unix_socket_path=str(self.socket_path),
            db=index,
            decode_responses=False,
        )

    def admit(
        self,
        value: str,
        *,
        max_item_bytes: int = 4 * 1024 * 1024,
        max_items: int = 10_000,
        max_bytes: int = 64 * 1024 * 1024,
        admission_id: str = None,
        ctx=None,
    ) -> int:
        target = ctx or self.ctx
        admission_id = admission_id or str(uuid.uuid4())
        return target.eval(
            self.admission_script,
            9,
            self.SOURCE,
            self.CLAIM,
            self.FAILURE,
            self.PENDING_COUNT,
            self.PENDING_BYTES,
            self.ADMISSION_IDS,
            self.CLAIM_ADMISSION_IDS,
            self.RESULT_SIZES,
            self.CLAIM_RESULT_SIZES,
            admission_id,
            value,
            max_item_bytes,
            max_items,
            max_bytes,
        )

    def test_owner_token_prevents_stale_flush_and_release(self):
        stale_token = str(uuid.uuid4())
        current_token = str(uuid.uuid4())
        child = self.redis_db(1)
        child.set('sentinel', 'current-owner-data')
        self.ctx.hset(DBINDEX_NAME, 1, current_token)
        maindb = MainDB(self.ctx)

        with self.assertRaises(OspdOpenvasError):
            maindb.release_database(KbDB(1, child, owner_token=stale_token))

        self.assertEqual(child.get('sentinel'), 'current-owner-data')
        self.assertEqual(self.ctx.hget(DBINDEX_NAME, 1), current_token)

        maindb.release_database(KbDB(1, child, owner_token=current_token))
        self.assertEqual(child.dbsize(), 0)
        self.assertIsNone(self.ctx.hget(DBINDEX_NAME, 1))

    def test_reserved_parent_discovery_requires_exact_owner_metadata(self):
        owner_token = str(uuid.uuid4())
        parent = self.redis_db(1)
        self.ctx.hset(DBINDEX_NAME, 1, owner_token)
        parent.rpush('internal/turbovas.owner-token', owner_token)
        parent.rpush('internal/turbovas.db-kind', 'parent')
        parent.rpush('internal/scanid', 'scan-recovery')
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (
            self.redis_url
        )  # pylint: disable=protected-access
        try:
            discovered = list(MainDB(self.ctx).reserved_parent_databases())
            self.assertEqual(len(discovered), 1)
            self.assertEqual(discovered[0][0], 'scan-recovery')
            self.assertEqual(discovered[0][1].owner_token, owner_token)

            parent.lset('internal/turbovas.owner-token', 0, str(uuid.uuid4()))
            with self.assertRaises(OspdOpenvasError):
                list(MainDB(self.ctx).reserved_parent_databases())
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )

    def test_legacy_migration_preserves_concurrent_reference_change(self):
        self.ctx.hset(DBINDEX_NAME, mapping={3: '1', 4: '1'})
        parent = self.redis_db(3)
        child = self.redis_db(4)
        parent.rpush('internal/scanid', 'scan-recovery')
        parent.rpush('internal/dbindex', '4')
        child.rpush('internal/scan_id', 'scan-recovery')
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (
            self.redis_url
        )  # pylint: disable=protected-access
        main = MainDB(self.ctx)
        original_plan = main._legacy_reservation_migration_plan
        plan_calls = 0

        def race_after_planning(reservations):
            nonlocal plan_calls
            plan = original_plan(reservations)
            plan_calls += 1
            if plan_calls == 1:
                parent.rpush('internal/dbindex', '4')
            return plan

        try:
            with patch.object(
                main,
                '_legacy_reservation_migration_plan',
                side_effect=race_after_planning,
            ):
                with self.assertRaisesRegex(
                    OspdOpenvasError, 'duplicate legacy children'
                ):
                    main.migrate_verified_legacy_reservations()

            self.assertEqual(self.ctx.hgetall(DBINDEX_NAME), {'3': '1', '4': '1'})
            self.assertEqual(
                parent.lrange('internal/dbindex', 0, -1), ['4', '4']
            )
            for index in (3, 4):
                self.assertEqual(
                    self.redis_db(index).type(
                        'internal/turbovas.owner-token'
                    ),
                    'none',
                )
                self.assertEqual(
                    self.redis_db(index).type('internal/turbovas.db-kind'),
                    'none',
                )
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )

    def test_legacy_reservation_graph_migrates_atomically_and_idempotently(
        self,
    ):
        first_scan = 'scan-recovery-one'
        second_scan = 'scan-recovery-two'
        self.ctx.hset(
            DBINDEX_NAME,
            mapping={index: '1' for index in range(1, 16)},
        )
        self.redis_db(1).rpush('notuscache', 'notus-cache-evidence')
        self.redis_db(1).rpush('internal/notus/advisories/oid', 'advisory')
        self.redis_db(2).rpush('nvticache', 'nvt-cache-evidence')
        self.redis_db(2).rpush('nvt:oid', 'metadata')
        self.redis_db(3).rpush('internal/scanid', first_scan)
        self.redis_db(3).rpush(
            'internal/dbindex', *[str(index) for index in range(4, 13)]
        )
        for index in range(4, 13):
            self.redis_db(index).rpush('internal/scan_id', first_scan)
            self.redis_db(index).set('retained-evidence', f'child-{index}')
        self.redis_db(13).rpush('internal/scanid', second_scan)
        self.redis_db(13).rpush('internal/dbindex', '14', '15')
        for index in (14, 15):
            self.redis_db(index).rpush('internal/scan_id', second_scan)
            self.redis_db(index).set('retained-evidence', f'child-{index}')
        cache_dumps = {
            index: {
                key: self.redis_db_raw(index).dump(key)
                for key in self.redis_db_raw(index).scan_iter()
            }
            for index in (1, 2)
        }
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (
            self.redis_url
        )  # pylint: disable=protected-access
        try:
            main = MainDB(self.ctx)
            self.assertEqual(main.migrate_verified_legacy_reservations(), 13)

            reservations = self.ctx.hgetall(DBINDEX_NAME)
            self.assertEqual(reservations['1'], '1')
            self.assertEqual(reservations['2'], '1')
            migrated_tokens = {
                index: reservations[str(index)] for index in range(3, 16)
            }
            self.assertEqual(len(set(migrated_tokens.values())), 13)
            for token in migrated_tokens.values():
                self.assertEqual(str(uuid.UUID(token)), token)
            for index in (3, 13):
                self.assertEqual(
                    self.redis_db(index).lindex(
                        'internal/turbovas.owner-token', 0
                    ),
                    migrated_tokens[index],
                )
                self.assertEqual(
                    self.redis_db(index).lindex(
                        'internal/turbovas.db-kind', 0
                    ),
                    'parent',
                )
            expected_first_refs = [
                f'{index}:{migrated_tokens[index]}'
                for index in range(4, 13)
            ]
            self.assertEqual(
                self.redis_db(3).lrange('internal/dbindex', 0, -1),
                expected_first_refs,
            )
            self.assertEqual(
                self.redis_db(13).lrange('internal/dbindex', 0, -1),
                [
                    f'14:{migrated_tokens[14]}',
                    f'15:{migrated_tokens[15]}',
                ],
            )
            for index in list(range(4, 13)) + [14, 15]:
                self.assertEqual(
                    self.redis_db(index).lindex(
                        'internal/turbovas.owner-token', 0
                    ),
                    migrated_tokens[index],
                )
                self.assertEqual(
                    self.redis_db(index).lindex(
                        'internal/turbovas.db-kind', 0
                    ),
                    'child',
                )
                self.assertEqual(
                    self.redis_db(index).get('retained-evidence'),
                    f'child-{index}',
                )
            self.assertEqual(
                {
                    index: {
                        key: self.redis_db_raw(index).dump(key)
                        for key in self.redis_db_raw(index).scan_iter()
                    }
                    for index in (1, 2)
                },
                cache_dumps,
            )
            self.assertEqual(main.migrate_verified_legacy_reservations(), 0)
            self.assertEqual(self.ctx.hgetall(DBINDEX_NAME), reservations)
            self.assertFalse(main.release_database_by_index(3, '1'))
            self.assertEqual(
                self.redis_db(3).lindex('internal/scanid', 0), first_scan
            )
            discovered = list(main.reserved_parent_databases())
            self.assertEqual(
                [(scan_id, database.index) for scan_id, database in discovered],
                [(first_scan, 3), (second_scan, 13)],
            )
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )

    def test_legacy_reservation_migration_rejects_invalid_graphs(self):
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (
            self.redis_url
        )  # pylint: disable=protected-access
        invalid_graphs = (
            (
                'orphan child',
                lambda: (
                    self.ctx.hset(DBINDEX_NAME, 3, '1'),
                    self.redis_db(3).rpush(
                        'internal/scan_id', 'scan-recovery'
                    ),
                ),
            ),
            (
                'duplicate child',
                lambda: (
                    self.ctx.hset(DBINDEX_NAME, mapping={3: '1', 4: '1'}),
                    self.redis_db(3).rpush(
                        'internal/scanid', 'scan-recovery'
                    ),
                    self.redis_db(3).rpush('internal/dbindex', '4', '4'),
                    self.redis_db(4).rpush(
                        'internal/scan_id', 'scan-recovery'
                    ),
                ),
            ),
            (
                'mismatched child',
                lambda: (
                    self.ctx.hset(DBINDEX_NAME, mapping={3: '1', 4: '1'}),
                    self.redis_db(3).rpush(
                        'internal/scanid', 'scan-recovery'
                    ),
                    self.redis_db(3).rpush('internal/dbindex', '4'),
                    self.redis_db(4).rpush('internal/scan_id', 'other-scan'),
                ),
            ),
            (
                'cache conflict',
                lambda: (
                    self.ctx.hset(DBINDEX_NAME, 1, '1'),
                    self.redis_db(1).rpush('notuscache', 'cache'),
                    self.redis_db(1).rpush(
                        'internal/scanid', 'scan-recovery'
                    ),
                ),
            ),
            (
                'mixed metadata',
                lambda: (
                    self.ctx.hset(DBINDEX_NAME, 3, '1'),
                    self.redis_db(3).rpush(
                        'internal/scanid', 'scan-recovery'
                    ),
                    self.redis_db(3).rpush(
                        'internal/turbovas.owner-token', '1'
                    ),
                ),
            ),
            (
                'malformed references',
                lambda: (
                    self.ctx.hset(DBINDEX_NAME, 3, '1'),
                    self.redis_db(3).rpush(
                        'internal/scanid', 'scan-recovery'
                    ),
                    self.redis_db(3).set('internal/dbindex', 'not-a-list'),
                ),
            ),
        )
        try:
            for label, configure in invalid_graphs:
                with self.subTest(label=label):
                    for index in range(16):
                        self.redis_db(index).flushdb()
                    configure()
                    reservations = self.ctx.hgetall(DBINDEX_NAME)
                    database_dumps = {
                        index: {
                            key: self.redis_db_raw(index).dump(key)
                            for key in self.redis_db_raw(index).scan_iter()
                        }
                        for index in range(1, 16)
                    }
                    with self.assertRaises(OspdOpenvasError):
                        MainDB(self.ctx).migrate_verified_legacy_reservations()
                    self.assertEqual(
                        self.ctx.hgetall(DBINDEX_NAME), reservations
                    )
                    self.assertEqual(
                        {
                            index: {
                                key: self.redis_db_raw(index).dump(key)
                                for key in self.redis_db_raw(index).scan_iter()
                            }
                            for index in range(1, 16)
                        },
                        database_dumps,
                    )
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )

    def test_recovery_retains_unreserved_child_that_still_has_data(self):
        child_token = str(uuid.uuid4())
        parent = self.redis_db(1)
        child = self.redis_db(2)
        parent.rpush('internal/scanid', 'scan-recovery')
        parent.rpush('internal/dbindex', f'2:{child_token}')
        child.set('retained', 'evidence')
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (
            self.redis_url
        )  # pylint: disable=protected-access
        try:
            recovered_parent = KbDB(1, parent, owner_token='parent')
            with self.assertRaises(OspdOpenvasError):
                list(recovered_parent.get_scan_databases())
            self.assertEqual(
                parent.lrange('internal/dbindex', 0, -1),
                [f'2:{child_token}'],
            )
            self.assertEqual(child.get('retained'), 'evidence')
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )

    def test_result_claim_and_ack_are_fenced_by_db_zero_owner(self):
        owner_token = str(uuid.uuid4())
        replacement_token = str(uuid.uuid4())
        parent = self.redis_db(1)
        self.ctx.hset(DBINDEX_NAME, 1, owner_token)
        database = KbDB(1, parent, owner_token=owner_token)
        self.assertEqual(self.admit('evidence', ctx=parent), 1)
        main = MainDB(self.ctx)

        claim_id, rows = main.claim_owned_results(
            database,
            max_items=1000,
            max_bytes=16 * 1024 * 1024,
            max_item_bytes=4 * 1024 * 1024,
        )
        self.assertEqual(rows, ['evidence'])
        self.assertEqual(main.current_owned_result_claim_id(database), claim_id)

        self.ctx.hset(DBINDEX_NAME, 1, replacement_token)
        with self.assertRaises(OspdOpenvasError):
            main.current_owned_result_claim_id(database)
        with self.assertRaises(OspdOpenvasError):
            main.ack_owned_result_claim_state(database, claim_id)
        self.assertEqual(parent.lrange(self.CLAIM, 0, -1), ['evidence'])

        self.ctx.hset(DBINDEX_NAME, 1, owner_token)
        self.assertEqual(
            main.ack_owned_result_claim_state(database, claim_id),
            ResultClaimAck.RELEASED,
        )
        self.assertEqual(parent.llen(self.CLAIM), 0)

        self.assertEqual(self.admit('later', ctx=parent), 1)
        self.ctx.hset(DBINDEX_NAME, 1, replacement_token)
        with self.assertRaises(OspdOpenvasError):
            main.claim_owned_results(
                database,
                max_items=1000,
                max_bytes=16 * 1024 * 1024,
                max_item_bytes=4 * 1024 * 1024,
            )
        self.assertEqual(parent.lrange(self.SOURCE, 0, -1), ['later'])

    def test_recovery_removes_reference_to_already_released_empty_child(self):
        parent_token = str(uuid.uuid4())
        child_token = str(uuid.uuid4())
        parent = self.redis_db(1)
        child = self.redis_db(2)
        self.ctx.hset(DBINDEX_NAME, mapping={1: parent_token, 2: child_token})
        parent.rpush('internal/scanid', 'scan-recovery')
        parent.rpush('internal/dbindex', f'2:{child_token}')
        child.rpush('internal/turbovas.owner-token', child_token)
        child.rpush('internal/turbovas.db-kind', 'child')
        child.rpush('internal/scan_id', 'scan-recovery')
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (
            self.redis_url
        )  # pylint: disable=protected-access
        try:
            main = MainDB(self.ctx)
            main.release_database(KbDB(2, child, owner_token=child_token))
            self.assertEqual(
                parent.lrange('internal/dbindex', 0, -1), [f'2:{child_token}']
            )

            recovered_parent = KbDB(1, parent, owner_token=parent_token)
            self.assertEqual(list(recovered_parent.get_scan_databases()), [])
            self.assertEqual(parent.lrange('internal/dbindex', 0, -1), [])
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )

    def test_duplicate_cleanup_has_one_atomic_winner(self):
        owner_token = str(uuid.uuid4())
        child = self.redis_db(1)
        child.set('sentinel', 'owned-data')
        self.ctx.hset(DBINDEX_NAME, 1, owner_token)

        def release():
            main = MainDB(self.redis_db(0))
            database = KbDB(1, self.redis_db(1), owner_token=owner_token)
            try:
                main.release_database(database)
                return 'released'
            except OspdOpenvasError:
                return 'rejected'

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = sorted(executor.map(lambda _: release(), range(2)))

        self.assertEqual(outcomes, ['rejected', 'released'])
        self.assertEqual(child.dbsize(), 0)
        self.assertIsNone(self.ctx.hget(DBINDEX_NAME, 1))

    def test_legacy_owner_marker_is_released_atomically(self):
        child = self.redis_db(1)
        child.set('sentinel', 'legacy-owner-data')
        self.ctx.hset(DBINDEX_NAME, 1, '1')

        MainDB(self.ctx).release_database(KbDB(1, child, owner_token='1'))

        self.assertEqual(child.dbsize(), 0)
        self.assertIsNone(self.ctx.hget(DBINDEX_NAME, 1))

    def test_exact_row_and_total_payload_boundaries(self):
        row = 'x' * (4 * 1024 * 1024)
        for _ in range(16):
            self.assertEqual(self.admit(row), 1)

        self.assertEqual(
            int(self.ctx.get(self.PENDING_BYTES)), 64 * 1024 * 1024
        )
        self.assertEqual(self.admit('x'), -2)
        self.assertEqual(self.ctx.llen(self.SOURCE), 16)
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'pending-capacity')

        self.ctx.flushdb()
        self.assertEqual(self.admit(row), 1)
        self.assertEqual(self.admit(row + 'x'), -1)
        self.assertEqual(self.ctx.llen(self.SOURCE), 1)
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'row-too-large')

    def test_capacity_rejection_still_allows_accepted_rows_to_drain(self):
        self.assertEqual(self.admit('oldest', max_items=2), 1)
        self.assertEqual(self.admit('newest', max_items=2), 1)
        self.assertEqual(self.admit('rejected', max_items=2), -2)

        claimed = self.ctx.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            *self.queue_keys(),
            1000,
            16 * 1024 * 1024,
            4 * 1024 * 1024,
            'claim-after-capacity',
        )
        self.assertEqual(claimed, ['claim-after-capacity', 'oldest', 'newest'])

    def test_type_valid_oversized_claim_is_rejected_before_full_read(self):
        oversized = 'x' * (40 * 1024 * 1024)
        self.ctx.rpush(self.CLAIM, oversized)
        self.ctx.rpush(self.CLAIM_ADMISSION_IDS, 'corrupt-id')
        self.ctx.rpush(self.CLAIM_RESULT_SIZES, str(len(oversized)))
        self.ctx.set(self.CLAIM_ID, 'corrupt-claim')
        self.ctx.set(self.PENDING_COUNT, 1)
        self.ctx.set(self.PENDING_BYTES, len(oversized))

        claimed = self.ctx.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            *self.queue_keys(),
            1000,
            16 * 1024 * 1024,
            4 * 1024 * 1024,
            'replacement-claim',
        )

        self.assertEqual(claimed, [])
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'counter-state')

    def test_type_valid_claim_count_over_limit_is_rejected(self):
        pipe = self.ctx.pipeline(transaction=False)
        for index in range(1001):
            pipe.rpush(self.CLAIM, 'x')
            pipe.rpush(self.CLAIM_ADMISSION_IDS, f'id-{index}')
            pipe.rpush(self.CLAIM_RESULT_SIZES, '1')
        pipe.set(self.CLAIM_ID, 'oversized-claim')
        pipe.set(self.PENDING_COUNT, 1001)
        pipe.set(self.PENDING_BYTES, 1001)
        pipe.execute()

        claimed = self.ctx.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            *self.queue_keys(),
            1000,
            16 * 1024 * 1024,
            4 * 1024 * 1024,
            'replacement-claim',
        )

        self.assertEqual(claimed, [])
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'counter-state')

    def test_exact_pending_count_boundary(self):
        pipe = self.ctx.pipeline(transaction=False)
        for _ in range(10_000):
            pipe.eval(
                self.admission_script,
                9,
                self.SOURCE,
                self.CLAIM,
                self.FAILURE,
                self.PENDING_COUNT,
                self.PENDING_BYTES,
                self.ADMISSION_IDS,
                self.CLAIM_ADMISSION_IDS,
                self.RESULT_SIZES,
                self.CLAIM_RESULT_SIZES,
                f'admission-{_}',
                'x',
                4 * 1024 * 1024,
                10_000,
                64 * 1024 * 1024,
            )
        self.assertTrue(all(result == 1 for result in pipe.execute()))
        self.assertEqual(self.admit('x'), -2)
        self.assertEqual(self.ctx.llen(self.SOURCE), 10_000)
        self.assertEqual(int(self.ctx.get(self.PENDING_COUNT)), 10_000)

    def test_concurrent_producers_cannot_exceed_shared_budget(self):
        def produce(index: int) -> int:
            ctx = redis.Redis.from_url(self.redis_url, decode_responses=True)
            return self.admit(
                f'result-{index}',
                max_items=20,
                max_bytes=4096,
                admission_id=f'admission-{index}',
                ctx=ctx,
            )

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(produce, range(64)))

        self.assertEqual(results.count(1), 20)
        self.assertEqual(self.ctx.llen(self.SOURCE), 20)
        self.assertEqual(int(self.ctx.get(self.PENDING_COUNT)), 20)
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'pending-capacity')

    def test_claim_replay_and_exact_ack_preserve_counters(self):
        self.assertEqual(self.admit('oldest'), 1)
        self.assertEqual(self.admit('newest'), 1)
        keys = (
            self.SOURCE,
            self.CLAIM,
            self.CLAIM_ID,
            self.PENDING_COUNT,
            self.PENDING_BYTES,
            self.FAILURE,
            self.ADMISSION_IDS,
            self.CLAIM_ADMISSION_IDS,
            self.RESULT_SIZES,
            self.CLAIM_RESULT_SIZES,
        )
        claimed = self.ctx.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            *keys,
            1000,
            16 * 1024 * 1024,
            4 * 1024 * 1024,
            'claim-1',
        )
        self.assertEqual(claimed, ['claim-1', 'oldest', 'newest'])
        self.assertEqual(int(self.ctx.get(self.PENDING_COUNT)), 2)
        self.assertEqual(int(self.ctx.get(self.PENDING_BYTES)), 12)

        restarted = redis.Redis.from_url(self.redis_url, decode_responses=True)
        replayed = restarted.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            *keys,
            1000,
            16 * 1024 * 1024,
            4 * 1024 * 1024,
            'claim-2',
        )
        self.assertEqual(replayed, claimed)
        ack_keys = (
            self.CLAIM,
            self.CLAIM_ID,
            self.PENDING_COUNT,
            self.PENDING_BYTES,
            self.FAILURE,
            self.CLAIM_ADMISSION_IDS,
            self.CLAIM_RESULT_SIZES,
        )
        self.assertEqual(
            restarted.eval(
                ACK_RESULT_CLAIM_SCRIPT, 7, *ack_keys, 'wrong-claim'
            ),
            0,
        )
        self.assertEqual(
            restarted.eval(ACK_RESULT_CLAIM_SCRIPT, 7, *ack_keys, 'claim-1'),
            2,
        )
        self.assertEqual(
            restarted.eval(ACK_RESULT_CLAIM_SCRIPT, 7, *ack_keys, 'claim-1'),
            1,
        )
        self.assertFalse(restarted.exists(self.CLAIM))
        self.assertFalse(restarted.exists(self.PENDING_COUNT))
        self.assertFalse(restarted.exists(self.PENDING_BYTES))
        self.assertFalse(restarted.exists(self.CLAIM_ADMISSION_IDS))
        self.assertFalse(restarted.exists(self.CLAIM_RESULT_SIZES))

    def test_missing_claim_id_with_retained_rows_fails_closed(self):
        self.assertEqual(self.admit('retained'), 1)
        keys = (
            self.SOURCE,
            self.CLAIM,
            self.CLAIM_ID,
            self.PENDING_COUNT,
            self.PENDING_BYTES,
            self.FAILURE,
            self.ADMISSION_IDS,
            self.CLAIM_ADMISSION_IDS,
            self.RESULT_SIZES,
            self.CLAIM_RESULT_SIZES,
        )
        self.ctx.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            *keys,
            1000,
            16 * 1024 * 1024,
            4 * 1024 * 1024,
            'claim-1',
        )
        self.ctx.delete(self.CLAIM_ID)
        ack_keys = (
            self.CLAIM,
            self.CLAIM_ID,
            self.PENDING_COUNT,
            self.PENDING_BYTES,
            self.FAILURE,
            self.CLAIM_ADMISSION_IDS,
            self.CLAIM_RESULT_SIZES,
        )

        self.assertEqual(
            self.ctx.eval(ACK_RESULT_CLAIM_SCRIPT, 7, *ack_keys, 'claim-1'),
            -1,
        )
        self.assertTrue(self.ctx.exists(self.CLAIM))
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'counter-state')

    def test_missing_counters_fail_closed(self):
        self.ctx.lpush(self.SOURCE, 'legacy')
        self.assertEqual(self.admit('new'), -4)
        self.assertEqual(self.ctx.lindex(self.FAILURE, 0), 'counter-state')

    def test_lost_reply_replay_is_idempotent(self):
        self.assertEqual(self.admit('once', admission_id='stable-id'), 1)
        self.assertEqual(self.admit('once', admission_id='stable-id'), 1)
        self.assertEqual(self.ctx.lrange(self.SOURCE, 0, -1), ['once'])
        self.assertEqual(
            self.ctx.lrange(self.ADMISSION_IDS, 0, -1), ['stable-id']
        )
        self.assertEqual(self.ctx.lrange(self.RESULT_SIZES, 0, -1), ['4'])
        self.assertEqual(int(self.ctx.get(self.PENDING_COUNT)), 1)
        self.assertEqual(int(self.ctx.get(self.PENDING_BYTES)), 4)

    def test_corrupt_types_and_byte_counters_fail_closed(self):
        self.ctx.set(self.SOURCE, 'wrong-type')
        self.assertEqual(
            OpenvasDB.get_result_queue_failure(self.ctx, *self.queue_keys()),
            'counter-state',
        )

        self.ctx.flushdb()
        self.ctx.set(self.FAILURE, 'wrong-type')
        self.assertEqual(
            OpenvasDB.get_result_queue_failure(self.ctx, *self.queue_keys()),
            'queue-state-unreadable',
        )

        self.ctx.flushdb()
        self.assertEqual(self.admit('evidence'), 1)
        self.ctx.set(self.PENDING_BYTES, 0)
        self.assertEqual(
            OpenvasDB.get_result_queue_failure(self.ctx, *self.queue_keys()),
            'counter-state',
        )

        self.ctx.flushdb()
        self.assertEqual(self.admit('evidence'), 1)
        self.ctx.lset(self.SOURCE, 0, 'expanded-evidence')
        self.assertEqual(
            self.ctx.eval(
                CLAIM_RESULT_ITEMS_SCRIPT,
                10,
                *self.queue_keys(),
                1000,
                16 * 1024 * 1024,
                4 * 1024 * 1024,
                'claim-corrupt-payload',
            ),
            [],
        )
        self.assertEqual(
            OpenvasDB.get_result_queue_failure(self.ctx, *self.queue_keys()),
            'counter-state',
        )

    def test_preflight_rejects_acl_without_exact_queue_keys(self):
        self.ctx.execute_command(
            'ACL',
            'SETUSER',
            'default',
            'resetkeys',
            '~test',
            '~__turbovas_result_admission_probe__',
            '+@all',
        )
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (  # pylint: disable=protected-access
            self.redis_url
        )
        try:
            with self.assertRaises(OspdOpenvasError):
                OpenvasDB.validate_result_admission_backend()
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )
            self.ctx.execute_command(
                'ACL', 'SETUSER', 'default', 'resetkeys', '~*'
            )

    def queue_keys(self):
        return (
            self.SOURCE,
            self.CLAIM,
            self.CLAIM_ID,
            self.PENDING_COUNT,
            self.PENDING_BYTES,
            self.FAILURE,
            self.ADMISSION_IDS,
            self.CLAIM_ADMISSION_IDS,
            self.RESULT_SIZES,
            self.CLAIM_RESULT_SIZES,
        )

    def test_result_admission_backend_preflight(self):
        previous_address = (
            OpenvasDB._db_address
        )  # pylint: disable=protected-access
        OpenvasDB._db_address = (  # pylint: disable=protected-access
            self.redis_url
        )
        try:
            OpenvasDB.validate_result_admission_backend()
        finally:
            OpenvasDB._db_address = (  # pylint: disable=protected-access
                previous_address
            )
