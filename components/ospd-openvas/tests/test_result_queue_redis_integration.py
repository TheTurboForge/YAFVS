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

import redis

from ospd_openvas.db import (
    ACK_RESULT_CLAIM_SCRIPT,
    CLAIM_RESULT_ITEMS_SCRIPT,
    OpenvasDB,
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
        socket_path = Path(cls.redis_directory.name) / 'redis.sock'
        cls.redis_url = f'unix://{socket_path}'
        cls.redis_process = subprocess.Popen(
            [
                REDIS_SERVER,
                '--port',
                '0',
                '--protected-mode',
                'yes',
                '--unixsocket',
                str(socket_path),
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
        self.ctx.flushdb()

    def tearDown(self):
        self.ctx.flushdb()

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
        self.assertFalse(restarted.exists(self.CLAIM))
        self.assertFalse(restarted.exists(self.PENDING_COUNT))
        self.assertFalse(restarted.exists(self.PENDING_BYTES))
        self.assertFalse(restarted.exists(self.CLAIM_ADMISSION_IDS))
        self.assertFalse(restarted.exists(self.CLAIM_RESULT_SIZES))

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
