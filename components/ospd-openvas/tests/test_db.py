# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later


# pylint: disable=unused-argument

"""Unit Test for ospd-openvas"""

import logging

from unittest import TestCase
from unittest.mock import call, patch, MagicMock

from redis.exceptions import ConnectionError as RCE
from redis.exceptions import WatchError

from ospd.errors import RequiredArgument
from ospd_openvas.db import (
    DBINDEX_NAME,
    KbDB,
    MainDB,
    OpenvasDB,
    ResultClaimAck,
    ScanDB,
    time,
)
from ospd_openvas.errors import OspdOpenvasError

from tests.helper import assert_called

OWNER_TOKEN = '11111111-1111-4111-8111-111111111111'
OTHER_OWNER_TOKEN = '22222222-2222-4222-8222-222222222222'


@patch('ospd_openvas.db.redis.Redis')
class TestOpenvasDB(TestCase):
    @patch.object(OpenvasDB, 'create_context')
    def test_validate_result_admission_backend(
        self, mock_create_context: MagicMock, mock_redis: MagicMock
    ):
        ctx = mock_create_context.return_value
        ctx.info.return_value = {'redis_version': '7.2.4'}
        ctx.config_get.return_value = {'maxmemory': '0'}
        ctx.execute_command.side_effect = [
            'default',
            *['OK'] * len(OpenvasDB.RESULT_ADMISSION_REDIS_COMMANDS),
        ]

        OpenvasDB.validate_result_admission_backend()

        ctx.info.assert_called_once_with('server')
        ctx.config_get.assert_called_once_with('maxmemory')
        self.assertEqual(
            ctx.execute_command.call_count,
            len(OpenvasDB.RESULT_ADMISSION_REDIS_COMMANDS) + 1,
        )

    @patch.object(OpenvasDB, 'create_context')
    def test_validate_result_admission_backend_rejects_bounded_redis(
        self, mock_create_context: MagicMock, mock_redis: MagicMock
    ):
        ctx = mock_create_context.return_value
        ctx.info.return_value = {'redis_version': '7.2.4'}
        ctx.config_get.return_value = {'maxmemory': '1048576'}
        ctx.execute_command.side_effect = [
            'default',
            *['OK'] * len(OpenvasDB.RESULT_ADMISSION_REDIS_COMMANDS),
        ]

        with self.assertRaisesRegex(OspdOpenvasError, 'maxmemory=0'):
            OpenvasDB.validate_result_admission_backend()

    @patch.object(OpenvasDB, 'create_context')
    def test_validate_result_admission_backend_rejects_denied_command(
        self, mock_create_context: MagicMock, mock_redis: MagicMock
    ):
        ctx = mock_create_context.return_value
        ctx.info.return_value = {'redis_version': '7.2.4'}
        ctx.config_get.return_value = {'maxmemory': '0'}
        ctx.execute_command.side_effect = [
            'scanner',
            'OK',
            "This user has no permissions to run the 'get' command",
            *['OK'] * (len(OpenvasDB.RESULT_ADMISSION_REDIS_COMMANDS) - 2),
        ]

        with self.assertRaisesRegex(OspdOpenvasError, 'command set'):
            OpenvasDB.validate_result_admission_backend()

    @patch('ospd_openvas.db.Openvas')
    def test_get_db_connection(
        self, mock_openvas: MagicMock, mock_redis: MagicMock
    ):
        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        self.assertIsNone(OpenvasDB.get_database_address())

        # set the first time
        mock_openvas.get_settings.return_value = {'db_address': '/foo/bar'}

        self.assertEqual(OpenvasDB.get_database_address(), "unix:///foo/bar")

        self.assertEqual(mock_openvas.get_settings.call_count, 2)

        # should cache address
        self.assertEqual(OpenvasDB.get_database_address(), "unix:///foo/bar")
        self.assertEqual(mock_openvas.get_settings.call_count, 2)

    @patch('ospd_openvas.db.Openvas')
    def test_create_context_fail(self, mock_openvas: MagicMock, mock_redis):
        mock_redis.from_url.side_effect = RCE
        mock_check = mock_openvas.check.return_value
        mock_check.get.return_value = True

        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        logging.Logger.error = MagicMock()

        with patch.object(time, 'sleep', return_value=None):
            with self.assertRaises(SystemExit):
                OpenvasDB.create_context()

        logging.Logger.error.assert_called_with(  # pylint: disable=no-member
            'Redis Error: Not possible to connect to the kb.'
        )

    @patch('ospd_openvas.db.Openvas')
    def test_create_context_success(self, mock_openvas: MagicMock, mock_redis):
        ctx = mock_redis.from_url.return_value
        mock_check = mock_openvas.check.return_value
        mock_check.get.return_value = True

        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        ret = OpenvasDB.create_context()
        self.assertIs(ret, ctx)

    def test_select_database_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            OpenvasDB.select_database(None, 1)

        with self.assertRaises(RequiredArgument):
            OpenvasDB.select_database(mock_redis, None)

    def test_select_database(self, mock_redis):
        mock_redis.execute_command.return_value = mock_redis

        OpenvasDB.select_database(mock_redis, 1)

        mock_redis.execute_command.assert_called_with('SELECT 1')

    def test_get_list_item_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_list_item(None, 'foo')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_list_item(ctx, None)

    def test_get_list_item(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.lrange.return_value = ['1234']

        ret = OpenvasDB.get_list_item(ctx, 'name')

        self.assertEqual(ret, ['1234'])
        assert_called(ctx.lrange)

    def test_get_last_list_item(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.rpop.return_value = 'foo'

        ret = OpenvasDB.get_last_list_item(ctx, 'name')

        self.assertEqual(ret, 'foo')
        ctx.rpop.assert_called_with('name')

    def test_get_last_list_item_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_last_list_item(ctx, None)

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_last_list_item(None, 'name')

    def test_remove_list_item(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.lrem.return_value = 1

        OpenvasDB.remove_list_item(ctx, 'name', '1234')

        ctx.lrem.assert_called_once_with('name', count=0, value='1234')

    def test_remove_list_item_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.remove_list_item(None, '1', 'bar')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.remove_list_item(ctx, None, 'bar')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.remove_list_item(ctx, '1', None)

    def test_get_single_item_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_single_item(None, 'foo')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_single_item(ctx, None)

    def test_get_single_item(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.lindex.return_value = 'a'

        value = OpenvasDB.get_single_item(ctx, 'a')

        self.assertEqual(value, 'a')
        ctx.lindex.assert_called_once_with('a', 0)

    def test_add_single_list(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipeline = ctx.pipeline.return_value
        pipeline.delete.return_value = None
        pipeline.execute.return_value = (None, 0)

        OpenvasDB.add_single_list(ctx, 'a', ['12', '11', '12'])

        pipeline.delete.assert_called_once_with('a')
        pipeline.rpush.assert_called_once_with('a', '12', '11', '12')
        assert_called(pipeline.execute)

    def test_add_single_item(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.rpush.return_value = 1

        OpenvasDB.add_single_item(ctx, 'a', ['12', '12'])

        ctx.rpush.assert_called_once_with('a', '12')

    def test_add_single_item_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.add_single_item(None, '1', ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.add_single_item(ctx, None, ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.add_single_item(ctx, '1', None)

    def test_set_single_item_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.set_single_item(None, '1', ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.set_single_item(ctx, None, ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.set_single_item(ctx, '1', None)

    def test_pop_list_items_no_results(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipeline = ctx.pipeline.return_value
        pipeline.lrange.return_value = None
        pipeline.delete.return_value = None
        pipeline.execute.return_value = (None, 0)

        ret = OpenvasDB.pop_list_items(ctx, 'foo')

        self.assertEqual(ret, [])

        pipeline.lrange.assert_called_once_with('foo', 0, -1)
        pipeline.delete.assert_called_once_with('foo')
        assert_called(pipeline.execute)

    def test_pop_list_items_with_results(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipeline = ctx.pipeline.return_value
        pipeline.lrange.return_value = None
        pipeline.delete.return_value = None
        pipeline.execute.return_value = [['c', 'b', 'a'], 2]

        ret = OpenvasDB.pop_list_items(ctx, 'results')

        # reversed list
        self.assertEqual(ret, ['a', 'b', 'c'])

        pipeline.lrange.assert_called_once_with('results', 0, -1)
        pipeline.delete.assert_called_once_with('results')
        assert_called(pipeline.execute)

    @patch('ospd_openvas.db.uuid.uuid4', return_value='claim-1')
    def test_claim_list_items_moves_bounded_oldest_batch(
        self, _mock_uuid, mock_redis
    ):
        ctx = mock_redis.from_url.return_value
        ctx.eval.return_value = ['claim-1', 'oldest', 'newer']

        claim_id, results = OpenvasDB.claim_list_items(
            ctx,
            'results',
            'claim',
            'claim-id',
            'pending-count',
            'pending-bytes',
            'admission-failure',
            'admission-ids',
            'claim-admission-ids',
            'result-sizes',
            'claim-result-sizes',
            max_items=2,
            max_bytes=1024,
            max_item_bytes=512,
        )

        self.assertEqual(claim_id, 'claim-1')
        self.assertEqual(results, ['oldest', 'newer'])
        self.assertEqual(
            ctx.eval.call_args.args[1:],
            (
                10,
                'results',
                'claim',
                'claim-id',
                'pending-count',
                'pending-bytes',
                'admission-failure',
                'admission-ids',
                'claim-admission-ids',
                'result-sizes',
                'claim-result-sizes',
                2,
                1024,
                512,
                'claim-1',
            ),
        )

    def test_claim_list_items_replays_existing_batch(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.eval.return_value = ['claim-1', 'oldest', 'newer']

        claim_id, results = OpenvasDB.claim_list_items(
            ctx,
            'results',
            'claim',
            'claim-id',
            'pending-count',
            'pending-bytes',
            'admission-failure',
            'admission-ids',
            'claim-admission-ids',
            'result-sizes',
            'claim-result-sizes',
            max_items=2,
            max_bytes=1024,
            max_item_bytes=512,
        )

        self.assertEqual(claim_id, 'claim-1')
        self.assertEqual(results, ['oldest', 'newer'])

    @patch('ospd_openvas.db.uuid.uuid4', return_value='claim-1')
    def test_claim_list_items_returns_oversized_quarantine_marker(
        self, _mock_uuid, mock_redis
    ):
        ctx = mock_redis.from_url.return_value
        marker = '{"turbovas_internal":"oversized_result","bytes":2048}'
        ctx.eval.return_value = ['claim-1', marker]

        claim_id, results = OpenvasDB.claim_list_items(
            ctx,
            'results',
            'claim',
            'claim-id',
            'pending-count',
            'pending-bytes',
            'admission-failure',
            'admission-ids',
            'claim-admission-ids',
            'result-sizes',
            'claim-result-sizes',
            max_items=10,
            max_bytes=1024,
            max_item_bytes=512,
        )

        self.assertEqual(claim_id, 'claim-1')
        self.assertEqual(results, [marker])

    def test_ack_list_claim_requires_exact_current_id(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.eval.side_effect = [0, 1, 2, -1]

        self.assertEqual(
            OpenvasDB.ack_list_claim(
                ctx,
                'claim',
                'claim-id',
                'pending-count',
                'pending-bytes',
                'admission-failure',
                'claim-admission-ids',
                'claim-result-sizes',
                'wrong',
            ),
            ResultClaimAck.MISMATCH,
        )
        self.assertEqual(
            OpenvasDB.ack_list_claim(
                ctx,
                'claim',
                'claim-id',
                'pending-count',
                'pending-bytes',
                'admission-failure',
                'claim-admission-ids',
                'claim-result-sizes',
                'claim-1',
            ),
            ResultClaimAck.MISSING,
        )
        self.assertEqual(
            OpenvasDB.ack_list_claim(
                ctx,
                'claim',
                'claim-id',
                'pending-count',
                'pending-bytes',
                'admission-failure',
                'claim-admission-ids',
                'claim-result-sizes',
                'claim-1',
            ),
            ResultClaimAck.RELEASED,
        )
        self.assertEqual(
            OpenvasDB.ack_list_claim(
                ctx,
                'claim',
                'claim-id',
                'pending-count',
                'pending-bytes',
                'admission-failure',
                'claim-admission-ids',
                'claim-result-sizes',
                'claim-1',
            ),
            ResultClaimAck.CORRUPT,
        )
        self.assertEqual(ctx.eval.call_count, 4)

    def test_set_single_item(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipeline = ctx.pipeline.return_value
        pipeline.delete.return_value = None
        pipeline.rpush.return_value = None
        pipeline.execute.return_value = None

        OpenvasDB.set_single_item(ctx, 'foo', ['bar'])

        pipeline.delete.assert_called_once_with('foo')
        pipeline.rpush.assert_called_once_with('foo', 'bar')
        assert_called(pipeline.execute)

    def test_get_pattern(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.keys.return_value = ['a', 'b']
        ctx.lrange.return_value = [1, 2, 3]

        ret = OpenvasDB.get_pattern(ctx, 'a')

        self.assertEqual(ret, [['a', [1, 2, 3]], ['b', [1, 2, 3]]])

    def test_get_pattern_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_pattern(None, 'a')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_pattern(ctx, None)

    def test_get_filenames_and_oids_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_filenames_and_oids(None, None, None)

    def test_get_filenames_and_oids(self, mock_redis):
        def _pars(item):
            return item[4:]

        ctx = mock_redis.from_url.return_value
        ctx.keys.return_value = ['nvt:1', 'nvt:2']
        ctx.lindex.side_effect = ['aa', 'ab']

        ret = OpenvasDB.get_filenames_and_oids(ctx, "nvt:*", _pars)

        self.assertEqual(list(ret), [('aa', '1'), ('ab', '2')])

    def test_get_keys_by_pattern_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_keys_by_pattern(None, 'a')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_keys_by_pattern(ctx, None)

    def test_get_keys_by_pattern(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.keys.return_value = ['nvt:2', 'nvt:1']

        ret = OpenvasDB.get_keys_by_pattern(ctx, 'nvt:*')

        # Return sorted list
        self.assertEqual(ret, ['nvt:1', 'nvt:2'])

    def test_get_key_count(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        ctx.keys.return_value = ['aa', 'ab']

        ret = OpenvasDB.get_key_count(ctx, "foo")

        self.assertEqual(ret, 2)
        ctx.keys.assert_called_with('foo')

    def test_get_key_count_with_default_pattern(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        ctx.keys.return_value = ['aa', 'ab']

        ret = OpenvasDB.get_key_count(ctx)

        self.assertEqual(ret, 2)
        ctx.keys.assert_called_with('*')

    def test_get_key_count_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_key_count(None)

    @patch('ospd_openvas.db.Openvas')
    def test_find_database_by_pattern_none(
        self, mock_openvas: MagicMock, mock_redis
    ):
        ctx = mock_redis.from_url.return_value
        ctx.keys.return_value = None

        mock_check = mock_openvas.check.return_value
        mock_check.get.return_value = True

        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        new_ctx, index = OpenvasDB.find_database_by_pattern('foo*', 123)

        self.assertIsNone(new_ctx)
        self.assertIsNone(index)

    @patch('ospd_openvas.db.Openvas')
    def test_find_database_by_pattern(
        self, mock_openvas: MagicMock, mock_redis
    ):
        ctx = mock_redis.from_url.return_value

        mock_check = mock_openvas.check.return_value
        mock_check.get.return_value = True

        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        # keys is called twice per iteration
        ctx.keys.side_effect = [None, None, None, None, True, True]

        new_ctx, index = OpenvasDB.find_database_by_pattern('foo*', 123)

        self.assertEqual(new_ctx, ctx)
        self.assertEqual(index, 2)


@patch('ospd_openvas.db.OpenvasDB')
class ScanDBTestCase(TestCase):
    @patch('ospd_openvas.db.redis.Redis')
    def setUp(self, mock_redis):  # pylint: disable=arguments-differ
        self.ctx = mock_redis.from_url.return_value
        self.db = ScanDB(10, self.ctx)

    def test_claim_results(self, mock_openvas_db):
        mock_openvas_db.claim_list_items.return_value = (
            'claim-1',
            ['some result'],
        )

        ret = self.db.claim_results(
            max_items=10, max_bytes=1024, max_item_bytes=512
        )

        self.assertEqual(ret, ('claim-1', ['some result']))
        mock_openvas_db.claim_list_items.assert_called_with(
            self.ctx,
            'internal/results',
            'internal/results.ospd-claim',
            'internal/results.ospd-claim-id',
            'internal/results.pending-count',
            'internal/results.pending-bytes',
            'internal/results.admission-failure',
            'internal/results.admission-ids',
            'internal/results.ospd-claim-admission-ids',
            'internal/results.sizes',
            'internal/results.ospd-claim-sizes',
            max_items=10,
            max_bytes=1024,
            max_item_bytes=512,
        )

    def test_get_status(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'some status'

        ret = self.db.get_status('foo')

        self.assertEqual(ret, 'some status')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_get_result_admission_failure(self, mock_openvas_db):
        mock_openvas_db.get_result_queue_failure.return_value = (
            'pending-capacity'
        )

        ret = self.db.get_result_admission_failure()

        self.assertEqual(ret, 'pending-capacity')
        mock_openvas_db.get_result_queue_failure.assert_called_with(
            self.ctx,
            'internal/results',
            'internal/results.ospd-claim',
            'internal/results.ospd-claim-id',
            'internal/results.pending-count',
            'internal/results.pending-bytes',
            'internal/results.admission-failure',
            'internal/results.admission-ids',
            'internal/results.ospd-claim-admission-ids',
            'internal/results.sizes',
            'internal/results.ospd-claim-sizes',
        )

    def test_select(self, mock_openvas_db):
        ret = self.db.select(11, OWNER_TOKEN)

        self.assertIs(ret, self.db)
        self.assertEqual(self.db.index, 11)
        self.assertEqual(self.db.owner_token, OWNER_TOKEN)

        mock_openvas_db.select_database.assert_called_with(self.ctx, 11)

    def test_flush(self, mock_openvas_db):
        self.db.flush()

        self.ctx.flushdb.assert_called_with()


@patch('ospd_openvas.db.OpenvasDB')
class KbDBTestCase(TestCase):
    @patch('ospd_openvas.db.redis.Redis')
    def setUp(self, mock_redis):  # pylint: disable=arguments-differ
        self.ctx = mock_redis.from_url.return_value
        self.db = KbDB(10, self.ctx, owner_token=OWNER_TOKEN)

    def test_claim_results(self, mock_openvas_db):
        mock_openvas_db.claim_list_items.return_value = (
            'claim-1',
            ['some results'],
        )

        ret = self.db.claim_results(
            max_items=10, max_bytes=1024, max_item_bytes=512
        )

        self.assertEqual(ret, ('claim-1', ['some results']))
        mock_openvas_db.claim_list_items.assert_called_with(
            self.ctx,
            'internal/results',
            'internal/results.ospd-claim',
            'internal/results.ospd-claim-id',
            'internal/results.pending-count',
            'internal/results.pending-bytes',
            'internal/results.admission-failure',
            'internal/results.admission-ids',
            'internal/results.ospd-claim-admission-ids',
            'internal/results.sizes',
            'internal/results.ospd-claim-sizes',
            max_items=10,
            max_bytes=1024,
            max_item_bytes=512,
        )

    def test_get_status(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'some status'

        ret = self.db.get_status('foo')

        self.assertEqual(ret, 'some status')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_get_result_admission_failure(self, mock_openvas_db):
        mock_openvas_db.get_result_queue_failure.return_value = 'row-too-large'

        ret = self.db.get_result_admission_failure()

        self.assertEqual(ret, 'row-too-large')
        mock_openvas_db.get_result_queue_failure.assert_called_with(
            self.ctx,
            'internal/results',
            'internal/results.ospd-claim',
            'internal/results.ospd-claim-id',
            'internal/results.pending-count',
            'internal/results.pending-bytes',
            'internal/results.admission-failure',
            'internal/results.admission-ids',
            'internal/results.ospd-claim-admission-ids',
            'internal/results.sizes',
            'internal/results.ospd-claim-sizes',
        )

    def test_get_scan_status(self, mock_openvas_db):
        status = [
            '192.168.0.1/10/120',
            '192.168.0.2/35/120',
        ]

        mock_openvas_db.pop_list_items.return_value = status

        ret = self.db.get_scan_status()

        self.assertEqual(ret, status)
        mock_openvas_db.pop_list_items.assert_called_with(
            self.ctx, 'internal/status'
        )

    def test_flush(self, mock_openvas_db):
        self.db.flush()

        self.ctx.flushdb.assert_called_with()

    def test_add_scan_id(self, mock_openvas_db):
        self.db.add_scan_id('bar')

        set_calls = mock_openvas_db.set_single_item.call_args_list
        self.assertEqual(
            set_calls[0].args,
            (self.ctx, 'internal/turbovas.owner-token', [OWNER_TOKEN]),
        )
        self.assertEqual(
            set_calls[1].args,
            (self.ctx, 'internal/turbovas.db-kind', ['parent']),
        )

        calls = mock_openvas_db.add_single_item.call_args_list

        call = calls[0]
        kwargs = call[0]

        self.assertEqual(kwargs[1], 'internal/bar')
        self.assertEqual(kwargs[2], ['new'])

        call = calls[1]
        kwargs = call[0]

        self.assertEqual(kwargs[1], 'internal/scanid')
        self.assertEqual(kwargs[2], ['bar'])

    def test_add_scan_preferences(self, mock_openvas_db):
        prefs = ['foo', 'bar']

        self.db.add_scan_preferences('foo', prefs)

        mock_openvas_db.add_single_item.assert_called_with(
            self.ctx, 'internal/foo/scanprefs', prefs
        )

    @patch('ospd_openvas.db.OpenvasDB')
    def test_add_credentials_to_scan_preferences(
        self, mock_redis, mock_openvas_db
    ):
        prefs = ['foo', 'bar']

        ctx = mock_redis.from_url.return_value
        mock_openvas_db.create_context.return_value = ctx

        self.db.add_credentials_to_scan_preferences('scan_id', prefs)

        mock_openvas_db.create_context.assert_called_with(
            self.db.index, encoding='utf-8'
        )

        mock_openvas_db.add_single_item.assert_called_with(
            ctx, 'internal/scan_id/scanprefs', prefs
        )

    def test_add_scan_process_id(self, mock_openvas_db):
        self.db.add_scan_process_id(123)

        mock_openvas_db.add_single_item.assert_called_with(
            self.ctx, 'internal/ovas_pid', [123]
        )

    def test_get_scan_process_id(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = '123'

        ret = self.db.get_scan_process_id()

        self.assertEqual(ret, '123')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/ovas_pid'
        )

    def test_get_notus_manifest_validates_exact_sealed_entries(
        self, mock_openvas_db
    ):
        mock_openvas_db.get_single_item.side_effect = [None, 'mqtt']
        raw_entry = (
            '{"run_id":"11111111-1111-4111-8111-111111111111",'
            '"start_message_id":"22222222-2222-4222-8222-222222222222",'
            '"host_ip":"2001:db8::1"}'
        )
        entry = {
            'run_id': '11111111-1111-4111-8111-111111111111',
            'start_message_id': '22222222-2222-4222-8222-222222222222',
            'host_ip': '2001:db8::1',
        }
        mock_openvas_db.get_list_item.return_value = [raw_entry]

        self.assertEqual(self.db.get_notus_manifest(), ('mqtt', [entry]))

    def test_get_notus_manifest_rejects_redis_bytes_and_non_strings(
        self, mock_openvas_db
    ):
        raw_entry = (
            b'{"run_id":"11111111-1111-4111-8111-111111111111",'
            b'"start_message_id":"22222222-2222-4222-8222-222222222222",'
            b'"host_ip":"2001:db8::1"}'
        )
        for candidate in (raw_entry, b'\xff', 7):
            with self.subTest(candidate=candidate):
                mock_openvas_db.get_single_item.side_effect = [None, 'mqtt']
                mock_openvas_db.get_list_item.return_value = [candidate]

                with self.assertRaisesRegex(
                    OspdOpenvasError, 'entry is invalid'
                ):
                    self.db.get_notus_manifest()

    def test_get_notus_manifest_rejects_duplicate_c_entries(
        self, mock_openvas_db
    ):
        raw_entry = (
            '{"run_id":"11111111-1111-4111-8111-111111111111",'
            '"start_message_id":"22222222-2222-4222-8222-222222222222",'
            '"host_ip":"2001:db8::1"}'
        )
        mock_openvas_db.get_single_item.side_effect = [None, 'mqtt']
        mock_openvas_db.get_list_item.return_value = [raw_entry, raw_entry]

        with self.assertRaisesRegex(
            OspdOpenvasError, 'identities are duplicated'
        ):
            self.db.get_notus_manifest()

    def test_get_notus_manifest_rejects_missing_seal(self, mock_openvas_db):
        mock_openvas_db.get_single_item.side_effect = [None, None]

        with self.assertRaisesRegex(OspdOpenvasError, 'did not seal'):
            self.db.get_notus_manifest()

    def test_get_notus_manifest_rejects_removed_openvasd_transport(
        self, mock_openvas_db
    ):
        mock_openvas_db.get_single_item.side_effect = [None, 'openvasd']

        with self.assertRaisesRegex(OspdOpenvasError, 'did not seal'):
            self.db.get_notus_manifest()

    def test_get_notus_manifest_rejects_failure_marker(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'failed'

        with self.assertRaisesRegex(OspdOpenvasError, 'publication failure'):
            self.db.get_notus_manifest()

    def test_remove_scan_database(self, mock_openvas_db):
        scan_db = MagicMock(spec=ScanDB)
        scan_db.index = 123
        scan_db.owner_reference = f'123:{OWNER_TOKEN}'

        self.db.remove_scan_database(scan_db)

        self.assertEqual(
            mock_openvas_db.remove_list_item.call_args_list,
            [
                call(self.ctx, 'internal/dbindex', f'123:{OWNER_TOKEN}'),
                call(self.ctx, 'internal/dbindex', '123'),
            ],
        )

    def test_target_is_finished_false(self, mock_openvas_db):
        mock_openvas_db.get_single_item.side_effect = ['new']

        ret = self.db.target_is_finished('bar')

        self.assertFalse(ret)

        calls = mock_openvas_db.get_single_item.call_args_list

        call = calls[0]
        args = call[0]

        self.assertEqual(args[1], 'internal/bar')

    def test_target_is_finished_true(self, mock_openvas_db):
        mock_openvas_db.get_single_item.side_effect = ['finished']

        ret = self.db.target_is_finished('bar')

        self.assertTrue(ret)

        calls = mock_openvas_db.get_single_item.call_args_list

        call = calls[0]
        args = call[0]

        self.assertEqual(args[1], 'internal/bar')

    def test_stop_scan(self, mock_openvas_db):
        self.db.stop_scan('foo')

        mock_openvas_db.set_single_item.assert_called_with(
            self.ctx, 'internal/foo', ['stop_all']
        )

    def test_scan_is_stopped_false(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'new'

        ret = self.db.scan_is_stopped('foo')

        self.assertFalse(ret)
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_scan_is_stopped_true(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'stop_all'

        ret = self.db.scan_is_stopped('foo')

        self.assertTrue(ret)
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_get_scan_databases(self, mock_openvas_db):
        mock_openvas_db.get_list_item.return_value = [
            f'4:{OWNER_TOKEN}',
            f'{self.db.index}:{OTHER_OWNER_TOKEN}',
            f'7:{OTHER_OWNER_TOKEN}',
            f'11:{OWNER_TOKEN}',
        ]
        mock_openvas_db.create_context.return_value.hget.side_effect = [
            OWNER_TOKEN,
            OTHER_OWNER_TOKEN,
            OWNER_TOKEN,
        ]
        mock_openvas_db.get_single_item.side_effect = [
            'scan-1',
            OWNER_TOKEN,
            OTHER_OWNER_TOKEN,
            OWNER_TOKEN,
        ]

        scan_dbs = self.db.get_scan_databases()

        scan_db = next(scan_dbs)
        self.assertEqual(scan_db.index, 4)
        self.assertEqual(scan_db.owner_token, OWNER_TOKEN)

        scan_db = next(scan_dbs)
        self.assertEqual(scan_db.index, 7)
        self.assertEqual(scan_db.owner_token, OTHER_OWNER_TOKEN)

        scan_db = next(scan_dbs)
        self.assertEqual(scan_db.index, 11)
        self.assertEqual(scan_db.owner_token, OWNER_TOKEN)

        with self.assertRaises(StopIteration):
            next(scan_dbs)

    def test_get_scan_databases_rejects_stale_tokenized_reference(
        self, mock_openvas_db
    ):
        mock_openvas_db.get_list_item.return_value = [f'4:{OWNER_TOKEN}']
        mock_openvas_db.create_context.return_value.hget.return_value = (
            OTHER_OWNER_TOKEN
        )

        with self.assertRaisesRegex(OspdOpenvasError, 'no longer matches'):
            next(self.db.get_scan_databases())

    def test_get_scan_databases_rejects_child_owner_metadata_mismatch(
        self, mock_openvas_db
    ):
        mock_openvas_db.get_list_item.return_value = [f'4:{OWNER_TOKEN}']
        mock_openvas_db.create_context.return_value.hget.return_value = (
            OWNER_TOKEN
        )
        mock_openvas_db.get_single_item.side_effect = [
            'scan-1',
            OTHER_OWNER_TOKEN,
        ]

        with self.assertRaisesRegex(
            OspdOpenvasError, 'metadata does not match'
        ):
            next(self.db.get_scan_databases())

    def test_get_scan_databases_accepts_verified_legacy_reference(
        self, mock_openvas_db
    ):
        mock_openvas_db.get_list_item.return_value = ['4']
        mock_openvas_db.get_single_item.side_effect = ['scan-1', 'scan-1']
        main_ctx = mock_openvas_db.create_context.return_value
        main_ctx.hget.side_effect = ['1', '1']

        scan_db = next(self.db.get_scan_databases())

        self.assertEqual(scan_db.index, 4)
        self.assertEqual(scan_db.owner_token, '1')
        self.assertEqual(main_ctx.hget.call_count, 2)

    def test_get_scan_databases_rejects_mismatched_legacy_reference(
        self, mock_openvas_db
    ):
        mock_openvas_db.get_list_item.return_value = ['4']
        mock_openvas_db.get_single_item.side_effect = ['scan-1', 'scan-2']
        mock_openvas_db.create_context.return_value.hget.return_value = '1'

        with self.assertRaisesRegex(
            OspdOpenvasError, 'does not belong to this scan'
        ):
            next(self.db.get_scan_databases())


@patch('ospd_openvas.db.redis.Redis')
class MainDBTestCase(TestCase):
    @patch.object(MainDB, '_legacy_reservation_migration_plan')
    @patch.object(MainDB, '_reservation_snapshot')
    def test_legacy_migration_retries_watch_abort(
        self, mock_snapshot, mock_plan, mock_redis
    ):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        mock_snapshot.return_value = {3: '1'}
        mock_plan.return_value = {
            'caches': set(),
            'parents': {3: ('scan-recovery', [])},
            'children': {},
            'tokens': {3: OWNER_TOKEN},
        }
        pipe.hlen.return_value = 1
        pipe.hget.return_value = '1'
        pipe.execute.side_effect = [WatchError(), ['OK']]

        migrated = MainDB(ctx).migrate_verified_legacy_reservations()

        self.assertEqual(migrated, 1)
        self.assertEqual(pipe.execute.call_count, 2)
        self.assertEqual(pipe.watch.call_count, 4)
        pipe.hset.assert_called_with(DBINDEX_NAME, mapping={3: OWNER_TOKEN})

    def test_max_database_index_fail(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.config_get.return_value = {}

        maindb = MainDB(ctx)

        with self.assertRaises(OspdOpenvasError):
            max_db = (  # pylint: disable=unused-variable
                maindb.max_database_index
            )

        ctx.config_get.assert_called_with('databases')

    def test_max_database_index(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.config_get.return_value = {'databases': '123'}

        maindb = MainDB(ctx)

        max_db = maindb.max_database_index

        self.assertEqual(max_db, 123)
        ctx.config_get.assert_called_with('databases')

    def test_try_database_success(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.hsetnx.return_value = 1

        maindb = MainDB(ctx)

        ret = maindb.try_database(1, OWNER_TOKEN)

        self.assertEqual(ret, True)
        ctx.hsetnx.assert_called_with(DBINDEX_NAME, 1, OWNER_TOKEN)

    def test_try_database_false(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.hsetnx.return_value = 0

        maindb = MainDB(ctx)

        ret = maindb.try_database(1, OWNER_TOKEN)

        self.assertEqual(ret, False)
        ctx.hsetnx.assert_called_with(DBINDEX_NAME, 1, OWNER_TOKEN)

    def test_try_db_index_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.hsetnx.side_effect = RCE

        maindb = MainDB(ctx)

        with self.assertRaises(OspdOpenvasError):
            maindb.try_database(1, OWNER_TOKEN)

    def test_release_database_by_index(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        pipe.hget.return_value = OWNER_TOKEN
        pipe.execute.return_value = ['OK', True, 'OK', 1]

        maindb = MainDB(ctx)

        released = maindb.release_database_by_index(3, OWNER_TOKEN)

        self.assertTrue(released)
        pipe.watch.assert_called_once_with(DBINDEX_NAME)
        pipe.execute_command.assert_has_calls(
            [call('SELECT', 3), call('SELECT', 0)]
        )
        pipe.flushdb.assert_called_once_with()
        pipe.hdel.assert_called_once_with(DBINDEX_NAME, 3)

    def test_release_database_by_index_rejects_stale_owner(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        pipe.hget.return_value = OTHER_OWNER_TOKEN

        maindb = MainDB(ctx)

        self.assertFalse(maindb.release_database_by_index(3, OWNER_TOKEN))
        pipe.unwatch.assert_called_once_with()
        pipe.flushdb.assert_not_called()
        pipe.execute.assert_not_called()

    def test_release_database_by_index_retries_watch_abort(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        pipe.hget.return_value = OWNER_TOKEN
        pipe.execute.side_effect = [
            WatchError(),
            ['OK', True, 'OK', 1],
        ]

        maindb = MainDB(ctx)

        self.assertTrue(maindb.release_database_by_index(3, OWNER_TOKEN))
        self.assertEqual(ctx.pipeline.call_count, 2)
        self.assertEqual(pipe.watch.call_count, 2)

    def test_release_database_by_index_preserves_redis_error(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        pipe.hget.return_value = OWNER_TOKEN
        pipe.execute.side_effect = RCE('release failed')

        with self.assertRaises(RCE):
            MainDB(ctx).release_database_by_index(3, OWNER_TOKEN)

    def test_release_database(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        pipe.hget.return_value = OWNER_TOKEN
        pipe.execute.return_value = ['OK', True, 'OK', 1]

        db = MagicMock()
        db.index = 3
        db.owner_token = OWNER_TOKEN
        maindb = MainDB(ctx)
        maindb.release_database(db)

        db.flush.assert_not_called()
        pipe.execute.assert_called_once_with()

    def test_release_database_refuses_stale_owner_before_flush(
        self, mock_redis
    ):
        ctx = mock_redis.from_url.return_value
        pipe = ctx.pipeline.return_value.__enter__.return_value
        pipe.hget.return_value = OTHER_OWNER_TOKEN
        db = MagicMock()
        db.index = 3
        db.owner_token = OWNER_TOKEN
        maindb = MainDB(ctx)

        with self.assertRaises(OspdOpenvasError):
            maindb.release_database(db)

        db.flush.assert_not_called()
        pipe.flushdb.assert_not_called()
        pipe.execute.assert_not_called()

    def test_reservation_token_accepts_legacy_owner_marker(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.hget.return_value = '1'

        self.assertEqual(MainDB(ctx).reservation_token(3), '1')

    def test_reservation_token_rejects_reference_delimiter(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        ctx.hget.return_value = 'owner:other'

        with self.assertRaises(OspdOpenvasError):
            MainDB(ctx).reservation_token(3)

    def test_release(self, mock_redis):
        ctx = mock_redis.from_url.return_value
        maindb = MainDB(ctx)

        with self.assertRaises(OspdOpenvasError):
            maindb.release()

        ctx.flushdb.assert_not_called()

    @patch('ospd_openvas.db.Openvas')
    def test_get_new_kb_database(self, mock_openvas: MagicMock, mock_redis):
        ctx = mock_redis.from_url.return_value

        mock_check = mock_openvas.check.return_value
        mock_check.get.return_value = True

        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        maindb = MainDB(ctx)
        maindb._max_dbindex = 123  # pylint: disable=protected-access

        ctx.hsetnx.side_effect = [0, 0, 1]

        kbdb = maindb.get_new_kb_database()

        self.assertEqual(kbdb.index, 3)
        self.assertEqual(kbdb.owner_token, ctx.hsetnx.call_args_list[2].args[2])
        ctx.flushdb.assert_called_once_with()

    def test_get_new_kb_database_none(self, mock_redis):
        ctx = mock_redis.from_url.return_value

        maindb = MainDB(ctx)
        maindb._max_dbindex = 3  # pylint: disable=protected-access

        ctx.hsetnx.side_effect = [0, 0, 0]

        kbdb = maindb.get_new_kb_database()

        self.assertIsNone(kbdb)
        ctx.flushdb.assert_not_called()

    @patch('ospd_openvas.db.OpenvasDB')
    def test_find_kb_database_by_scan_id_none(
        self, mock_openvas_db, mock_redis
    ):
        ctx = mock_redis.from_url.return_value

        new_ctx = 'bar'  # just some object to compare
        mock_openvas_db.create_context.return_value = new_ctx
        mock_openvas_db.get_key_count.return_value = None

        maindb = MainDB(ctx)
        maindb._max_dbindex = 2  # pylint: disable=protected-access

        kbdb = maindb.find_kb_database_by_scan_id('foo')

        mock_openvas_db.get_key_count.assert_called_once_with(
            new_ctx, 'internal/foo'
        )

        self.assertIsNone(kbdb)

    @patch('ospd_openvas.db.OpenvasDB')
    def test_find_kb_database_by_scan_id(self, mock_openvas_db, mock_redis):
        ctx = mock_redis.from_url.return_value

        new_ctx = 'foo'  # just some object to compare
        mock_openvas_db.create_context.return_value = new_ctx
        mock_openvas_db.get_key_count.side_effect = [0, 1]
        ctx.hget.return_value = OWNER_TOKEN

        maindb = MainDB(ctx)
        maindb._max_dbindex = 3  # pylint: disable=protected-access

        kbdb = maindb.find_kb_database_by_scan_id('foo')

        mock_openvas_db.get_key_count.assert_called_with(
            new_ctx, 'internal/foo'
        )
        self.assertEqual(kbdb.index, 2)
        self.assertIs(kbdb.ctx, new_ctx)
        self.assertEqual(kbdb.owner_token, OWNER_TOKEN)
