# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later


"""Access management for redis-based OpenVAS Scanner Database."""

import logging
import sys
import time
import uuid

from enum import IntEnum
from typing import List, NewType, Optional, Iterable, Iterator, Tuple, Callable
from urllib import parse

import redis

from ospd.errors import RequiredArgument
from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.openvas import Openvas

SOCKET_TIMEOUT = 60  # in seconds
LIST_FIRST_POS = 0
LIST_LAST_POS = -1
LIST_ALL = 0


class ResultClaimAck(IntEnum):
    """Exact outcomes from releasing one replayable Redis result claim."""

    CORRUPT = -1
    MISMATCH = 0
    MISSING = 1
    RELEASED = 2


CLAIM_RESULT_ITEMS_SCRIPT = """
local function key_type(index)
  return redis.call('TYPE', KEYS[index]).ok
end

local function memory_within(index, limit)
  local usage = redis.call('MEMORY', 'USAGE', KEYS[index])
  return not usage or usage <= limit
end

local max_items = tonumber(ARGV[1])
local max_bytes = tonumber(ARGV[2])
local max_item_bytes = tonumber(ARGV[3])
local max_pending_items = 10000
local max_pending_bytes = 67108864
local source_memory_limit = max_pending_bytes * 2 + max_pending_items * 256
local claim_memory_limit = max_bytes * 2 + max_items * 256
local source_sidecar_memory_limit = max_pending_items * 256
local claim_sidecar_memory_limit = max_items * 256

local function list_or_none(index)
  local kind = key_type(index)
  return kind == 'none' or kind == 'list'
end

local function string_or_none(index)
  local kind = key_type(index)
  return kind == 'none' or kind == 'string'
end

local function mark_failure(code)
  if key_type(6) == 'none' then
    redis.call('RPUSH', KEYS[6], code)
  elseif key_type(6) == 'list' and redis.call('LLEN', KEYS[6]) == 0 then
    redis.call('RPUSH', KEYS[6], code)
  end
end

if not list_or_none(1) or not list_or_none(2)
  or not string_or_none(3) or not string_or_none(4)
  or not string_or_none(5) or not list_or_none(6)
  or not list_or_none(7) or not list_or_none(8)
  or not list_or_none(9) or not list_or_none(10) then
  mark_failure('counter-state')
  return {}
end
local source_count = redis.call('LLEN', KEYS[1])
local claim_count = redis.call('LLEN', KEYS[2])
if source_count ~= redis.call('LLEN', KEYS[7])
  or source_count ~= redis.call('LLEN', KEYS[9])
  or claim_count ~= redis.call('LLEN', KEYS[8])
  or claim_count ~= redis.call('LLEN', KEYS[10])
  or source_count > max_pending_items or claim_count > max_items
  or not memory_within(1, source_memory_limit)
  or not memory_within(2, claim_memory_limit)
  or not memory_within(7, source_sidecar_memory_limit)
  or not memory_within(8, claim_sidecar_memory_limit)
  or not memory_within(9, source_sidecar_memory_limit)
  or not memory_within(10, claim_sidecar_memory_limit) then
  mark_failure('counter-state')
  return {}
end
local claimed = redis.call('LRANGE', KEYS[2], 0, claim_count - 1)
local claimed_ids = redis.call('LRANGE', KEYS[8], 0, claim_count - 1)
local claimed_sizes = redis.call('LRANGE', KEYS[10], 0, claim_count - 1)
local claim_id = redis.call('GET', KEYS[3])

local pending_count = tonumber(redis.call('GET', KEYS[4]))
local pending_bytes = tonumber(redis.call('GET', KEYS[5]))
if not pending_count or not pending_bytes then
  if source_count + claim_count ~= 0 then
    mark_failure('counter-state')
    return {}
  end
  pending_count = 0
  pending_bytes = 0
end
if pending_count ~= source_count + claim_count
  or pending_count < 0 or pending_bytes < 0
  or pending_count > max_pending_items
  or pending_bytes > max_pending_bytes then
  mark_failure('counter-state')
  return {}
end

local measured_bytes = 0
local source_sizes = redis.call('LRANGE', KEYS[9], 0, -1)
for _, value in ipairs(source_sizes) do
  local size = tonumber(value)
  if not size or size < 0 then
    mark_failure('counter-state')
    return {}
  end
  measured_bytes = measured_bytes + size
end
for index, value in ipairs(claimed_sizes) do
  local size = tonumber(value)
  if not size or size < 0 or size > max_item_bytes
    or string.len(claimed[index]) ~= size then
    mark_failure('counter-state')
    return {}
  end
  measured_bytes = measured_bytes + size
end
if measured_bytes ~= pending_bytes then
  mark_failure('counter-state')
  return {}
end

if #claimed > 0 then
  if not claim_id then
    claim_id = ARGV[4]
    redis.call('SET', KEYS[3], claim_id)
  end
  local response = {claim_id}
  for _, value in ipairs(claimed) do
    table.insert(response, value)
  end
  return response
end

if claim_id then
  redis.call('DEL', KEYS[3])
end
claim_id = ARGV[4]
redis.call('SET', KEYS[3], claim_id)

local claimed_bytes = 0
claimed = {}
for _ = 1, max_items do
  local candidate = redis.call('LINDEX', KEYS[1], -1)
  local candidate_id = redis.call('LINDEX', KEYS[7], -1)
  local candidate_size = tonumber(redis.call('LINDEX', KEYS[9], -1))
  if not candidate then
    break
  end
  if not candidate_id or not candidate_size
    or candidate_size < 0 or string.len(candidate) ~= candidate_size then
    mark_failure('counter-state')
    return {}
  end
  local candidate_bytes = candidate_size
  if candidate_bytes > max_item_bytes then
    redis.call('RPOP', KEYS[1])
    redis.call('RPOP', KEYS[7])
    redis.call('RPOP', KEYS[9])
    local marker = '{"turbovas_internal":"oversized_result","bytes":'
      .. tostring(candidate_bytes) .. '}'
    redis.call('RPUSH', KEYS[2], marker)
    redis.call('RPUSH', KEYS[8], candidate_id)
    redis.call('RPUSH', KEYS[10], string.len(marker))
    pending_bytes = pending_bytes - candidate_bytes + string.len(marker)
    if pending_bytes < 0 then
      mark_failure('counter-state')
      return {}
    end
    redis.call('SET', KEYS[5], pending_bytes)
    table.insert(claimed, marker)
    break
  end
  if claimed_bytes + candidate_bytes > max_bytes then
    break
  end
  candidate = redis.call('RPOP', KEYS[1])
  candidate_id = redis.call('RPOP', KEYS[7])
  candidate_size = redis.call('RPOP', KEYS[9])
  redis.call('RPUSH', KEYS[2], candidate)
  redis.call('RPUSH', KEYS[8], candidate_id)
  redis.call('RPUSH', KEYS[10], candidate_size)
  table.insert(claimed, candidate)
  claimed_bytes = claimed_bytes + candidate_bytes
end

if #claimed == 0 then
  redis.call('DEL', KEYS[3])
  return {}
end
local response = {claim_id}
for _, value in ipairs(claimed) do
  table.insert(response, value)
end
return response
"""

ACK_RESULT_CLAIM_SCRIPT = """
local function key_type(index)
  return redis.call('TYPE', KEYS[index]).ok
end

local function list_or_none(index)
  local kind = key_type(index)
  return kind == 'none' or kind == 'list'
end

local function string_or_none(index)
  local kind = key_type(index)
  return kind == 'none' or kind == 'string'
end

local function memory_within(index, limit)
  local usage = redis.call('MEMORY', 'USAGE', KEYS[index])
  return not usage or usage <= limit
end

local function mark_failure(code)
  if key_type(5) == 'none' then
    redis.call('RPUSH', KEYS[5], code)
  elseif key_type(5) == 'list' and redis.call('LLEN', KEYS[5]) == 0 then
    redis.call('RPUSH', KEYS[5], code)
  end
end

if not list_or_none(1) or not string_or_none(2)
  or not string_or_none(3) or not string_or_none(4)
  or not list_or_none(5) or not list_or_none(6)
  or not list_or_none(7) then
  mark_failure('counter-state')
  return -1
end

local current_claim = redis.call('GET', KEYS[2])
if not current_claim then
  if redis.call('LLEN', KEYS[1]) == 0
    and redis.call('LLEN', KEYS[6]) == 0
    and redis.call('LLEN', KEYS[7]) == 0 then
    return 1
  end
  mark_failure('counter-state')
  return -1
end

if current_claim == ARGV[1] then
  local max_items = 1000
  local max_bytes = 16777216
  local max_item_bytes = 4194304
  local released_count = redis.call('LLEN', KEYS[1])
  if released_count > max_items
    or released_count ~= redis.call('LLEN', KEYS[6])
    or released_count ~= redis.call('LLEN', KEYS[7])
    or not memory_within(1, max_bytes * 2 + max_items * 256)
    or not memory_within(6, max_items * 256)
    or not memory_within(7, max_items * 256) then
    mark_failure('counter-state')
    return -1
  end
  local rows = redis.call('LRANGE', KEYS[1], 0, released_count - 1)
  local row_ids = redis.call('LRANGE', KEYS[6], 0, released_count - 1)
  local row_sizes = redis.call('LRANGE', KEYS[7], 0, released_count - 1)
  local released_bytes = 0
  for index, value in ipairs(row_sizes) do
    local size = tonumber(value)
    if not size or size < 0 or size > max_item_bytes
      or string.len(rows[index]) ~= size then
      mark_failure('counter-state')
      return -1
    end
    released_bytes = released_bytes + size
  end
  if released_bytes > max_bytes then
    mark_failure('counter-state')
    return -1
  end
  local pending_count = tonumber(redis.call('GET', KEYS[3]))
  local pending_bytes = tonumber(redis.call('GET', KEYS[4]))
  if not pending_count or not pending_bytes
    or pending_count < released_count
    or pending_bytes < released_bytes then
    mark_failure('counter-state')
    return -1
  end
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[6], KEYS[7])
  pending_count = pending_count - released_count
  pending_bytes = pending_bytes - released_bytes
  if pending_count == 0 then
    redis.call('DEL', KEYS[3], KEYS[4])
  else
    redis.call('SET', KEYS[3], pending_count)
    redis.call('SET', KEYS[4], pending_bytes)
  end
  return 2
end
return 0
"""

RESULT_QUEUE_FAILURE_SCRIPT = """
local function key_type(index)
  return redis.call('TYPE', KEYS[index]).ok
end

local function list_or_none(index)
  local kind = key_type(index)
  return kind == 'none' or kind == 'list'
end

local function string_or_none(index)
  local kind = key_type(index)
  return kind == 'none' or kind == 'string'
end

local function memory_within(index, limit)
  local usage = redis.call('MEMORY', 'USAGE', KEYS[index])
  return not usage or usage <= limit
end

if key_type(6) ~= 'none' and key_type(6) ~= 'list' then
  return 'queue-state-unreadable'
end
if key_type(6) == 'list' and redis.call('LLEN', KEYS[6]) > 0 then
  return redis.call('LINDEX', KEYS[6], 0)
end
if not list_or_none(1) or not list_or_none(2)
  or not string_or_none(3) or not string_or_none(4)
  or not string_or_none(5) or not list_or_none(7)
  or not list_or_none(8) or not list_or_none(9)
  or not list_or_none(10) then
  return 'counter-state'
end

local source_count = redis.call('LLEN', KEYS[1])
local claim_count = redis.call('LLEN', KEYS[2])
if source_count ~= redis.call('LLEN', KEYS[7])
  or source_count ~= redis.call('LLEN', KEYS[9])
  or claim_count ~= redis.call('LLEN', KEYS[8])
  or claim_count ~= redis.call('LLEN', KEYS[10])
  or source_count > 10000 or claim_count > 1000
  or not memory_within(9, 2560000)
  or not memory_within(10, 256000) then
  return 'counter-state'
end

local pending_count = tonumber(redis.call('GET', KEYS[4]))
local pending_bytes = tonumber(redis.call('GET', KEYS[5]))
if not pending_count or not pending_bytes then
  if source_count + claim_count == 0 then
    return ''
  end
  return 'counter-state'
end
if pending_count ~= source_count + claim_count
  or pending_count < 0 or pending_bytes < 0
  or pending_count > 10000 or pending_bytes > 67108864 then
  return 'counter-state'
end

local measured_bytes = 0
for _, value in ipairs(redis.call('LRANGE', KEYS[9], 0, -1)) do
  local size = tonumber(value)
  if not size or size < 0 then return 'counter-state' end
  measured_bytes = measured_bytes + size
end
for _, value in ipairs(redis.call('LRANGE', KEYS[10], 0, -1)) do
  local size = tonumber(value)
  if not size or size < 0 then return 'counter-state' end
  measured_bytes = measured_bytes + size
end
if measured_bytes ~= pending_bytes then return 'counter-state' end
return ''
"""

# Possible positions of nvt values in cache list.
NVT_META_FIELDS = [
    "NVT_FILENAME_POS",
    "NVT_REQUIRED_KEYS_POS",
    "NVT_MANDATORY_KEYS_POS",
    "NVT_EXCLUDED_KEYS_POS",
    "NVT_REQUIRED_UDP_PORTS_POS",
    "NVT_REQUIRED_PORTS_POS",
    "NVT_DEPENDENCIES_POS",
    "NVT_TAGS_POS",
    "NVT_CVES_POS",
    "NVT_BIDS_POS",
    "NVT_XREFS_POS",
    "NVT_CATEGORY_POS",
    "NVT_FAMILY_POS",
    "NVT_NAME_POS",
]

# Name of the namespace usage bitmap in redis.
DBINDEX_NAME = "GVM.__GlobalDBIndex"

logger = logging.getLogger(__name__)

# Types
RedisCtx = NewType('RedisCtx', redis.Redis)


class OpenvasDB:
    """Class to connect to redis, to perform queries, and to move
    from a KB to another."""

    _db_address = None

    RESULT_ADMISSION_REDIS_KEYS = (
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
    RESULT_ADMISSION_REDIS_COMMANDS = (
        ('EVAL', 'return 1', '10', *RESULT_ADMISSION_REDIS_KEYS),
        ('GET', 'internal/results.pending-count'),
        ('SET', 'internal/results.pending-count', '1'),
        ('EXISTS', 'internal/results.admission-failure'),
        ('TYPE', 'internal/results'),
        ('LLEN', 'internal/results'),
        ('LPUSH', 'internal/results', '1'),
        ('RPUSH', 'internal/results.ospd-claim', '1'),
        ('LRANGE', 'internal/results.sizes', '0', '-1'),
        ('LINDEX', 'internal/results', '0'),
        ('RPOP', 'internal/results'),
        ('LPOS', 'internal/results.admission-ids', 'admission-id'),
        ('MEMORY', 'USAGE', 'internal/results'),
        ('DEL', 'internal/results.ospd-claim'),
    )

    @classmethod
    def get_database_address(cls) -> Optional[str]:
        if not cls._db_address:
            if not Openvas.check():
                logger.error(
                    'openvas executable not available. Please install openvas'
                    ' into your PATH.'
                )
                sys.exit(1)

            settings = Openvas.get_settings()

            cls._db_address = settings.get('db_address')
            if cls._db_address:
                # translate openvas tcp:// configuration to redis://
                cls._db_address = cls._db_address.replace("tcp://", "redis://")
                # translate non scheme to unix://
                if not parse.urlparse(cls._db_address).scheme:
                    cls._db_address = "unix://" + cls._db_address
                if cls._db_address.startswith("redis://"):
                    logger.warning(
                        "A Redis TCP connection is being used. "
                        "This feature is experimental and insecure. "
                        "It is not recommended in production environments."
                    )

        return cls._db_address

    @classmethod
    def create_context(
        cls, dbnum: int = 0, encoding: str = 'latin-1'
    ) -> RedisCtx:
        """Connect to redis to the given database or to the default db 0 .

        Arguments:
            dbnum: The db number to connect to.
            encoding: The encoding to be used to read and write.

        Return a new redis context on success.
        """
        tries = 5
        while tries:
            try:
                ctx = redis.Redis.from_url(
                    url=cls.get_database_address(),
                    db=dbnum,
                    socket_timeout=SOCKET_TIMEOUT,
                    encoding=encoding,
                    decode_responses=True,
                )

                ctx.keys("test")
            except (redis.exceptions.ConnectionError, FileNotFoundError) as err:
                logger.debug(
                    'Redis connection lost: %s. Trying again in 5 seconds.', err
                )
                tries = tries - 1
                time.sleep(5)
                continue
            break

        if not tries:
            logger.error('Redis Error: Not possible to connect to the kb.')
            sys.exit(1)

        return ctx

    @classmethod
    def validate_result_admission_backend(cls) -> None:
        """Fail before scans if Redis cannot uphold the result-queue contract."""
        ctx = cls.create_context()
        try:
            version = str(ctx.info('server').get('redis_version', ''))
            major_version = int(version.split('.', maxsplit=1)[0])
            maxmemory = int(ctx.config_get('maxmemory').get('maxmemory', -1))
            username = str(ctx.execute_command('ACL', 'WHOAMI'))
            dry_runs = [
                ctx.execute_command('ACL', 'DRYRUN', username, *command)
                for command in cls.RESULT_ADMISSION_REDIS_COMMANDS
            ]
        except (
            AttributeError,
            TypeError,
            ValueError,
            redis.RedisError,
        ) as error:
            raise OspdOpenvasError(
                'Scanner Redis cannot prove the result admission contract.'
            ) from error

        if (
            username != 'default'
            or major_version < 7
            or maxmemory != 0
            or any(str(result).upper() != 'OK' for result in dry_runs)
        ):
            raise OspdOpenvasError(
                'Scanner Redis must use the default scanner identity, be '
                'version 7 or newer, use maxmemory=0, and permit the exact '
                'bounded result-delivery keys and command set.'
            )

    @classmethod
    def find_database_by_pattern(
        cls, pattern: str, max_database_index: int
    ) -> Tuple[Optional[RedisCtx], Optional[int]]:
        """Search a pattern inside all kbs up to max_database_index.

        Returns the redis context for the db and its index as a tuple or
        None, None if the db with the pattern couldn't be found.
        """
        for i in range(0, max_database_index):
            ctx = cls.create_context(i)
            if ctx.keys(pattern):
                return (ctx, i)

        return (None, None)

    @staticmethod
    def select_database(ctx: RedisCtx, kbindex: str):
        """Use an existent redis connection and select a redis kb.

        Arguments:
            ctx: Redis context to use.
            kbindex: The new kb to select
        """
        if not ctx:
            raise RequiredArgument('select_database', 'ctx')
        if not kbindex:
            raise RequiredArgument('select_database', 'kbindex')

        ctx.execute_command('SELECT ' + str(kbindex))

    @staticmethod
    def get_list_item(
        ctx: RedisCtx,
        name: str,
        start: Optional[int] = LIST_FIRST_POS,
        end: Optional[int] = LIST_LAST_POS,
    ) -> Optional[list]:
        """Returns the specified elements from `start` to `end` of the
        list stored as `name`.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            start: first range element to get.
            end: last range element to get.

        Return List specified elements in the key.
        """
        if not ctx:
            raise RequiredArgument('get_list_item', 'ctx')
        if not name:
            raise RequiredArgument('get_list_item', 'name')

        return ctx.lrange(name, start, end)

    @staticmethod
    def get_last_list_item(ctx: RedisCtx, name: str) -> str:
        if not ctx:
            raise RequiredArgument('get_last_list_item', 'ctx')
        if not name:
            raise RequiredArgument('get_last_list_item', 'name')

        return ctx.rpop(name)

    @staticmethod
    def pop_list_items(ctx: RedisCtx, name: str) -> List[str]:
        if not ctx:
            raise RequiredArgument('pop_list_items', 'ctx')
        if not name:
            raise RequiredArgument('pop_list_items', 'name')

        pipe = ctx.pipeline()
        pipe.lrange(name, LIST_FIRST_POS, LIST_LAST_POS)
        pipe.delete(name)
        results, redis_return_code = pipe.execute()

        # The results are left-pushed. To preserver the order
        # the result list must be reversed.
        if redis_return_code:
            results.reverse()
        else:
            results = []

        return results

    @staticmethod
    def claim_list_items(
        ctx: RedisCtx,
        name: str,
        claim_name: str,
        claim_id_name: str,
        pending_count_name: str,
        pending_bytes_name: str,
        admission_failure_name: str,
        admission_ids_name: str,
        claim_admission_ids_name: str,
        result_sizes_name: str,
        claim_result_sizes_name: str,
        *,
        max_items: int,
        max_bytes: int,
        max_item_bytes: int,
    ) -> Tuple[Optional[str], List[str]]:
        """Atomically claim one bounded oldest-first replayable batch."""
        if not ctx:
            raise RequiredArgument('claim_list_items', 'ctx')
        if not name:
            raise RequiredArgument('claim_list_items', 'name')
        if not claim_name:
            raise RequiredArgument('claim_list_items', 'claim_name')
        if not claim_id_name:
            raise RequiredArgument('claim_list_items', 'claim_id_name')
        if not pending_count_name:
            raise RequiredArgument('claim_list_items', 'pending_count_name')
        if not pending_bytes_name:
            raise RequiredArgument('claim_list_items', 'pending_bytes_name')
        if not admission_failure_name:
            raise RequiredArgument('claim_list_items', 'admission_failure_name')
        if not admission_ids_name:
            raise RequiredArgument('claim_list_items', 'admission_ids_name')
        if not claim_admission_ids_name:
            raise RequiredArgument(
                'claim_list_items', 'claim_admission_ids_name'
            )
        if not result_sizes_name:
            raise RequiredArgument('claim_list_items', 'result_sizes_name')
        if not claim_result_sizes_name:
            raise RequiredArgument(
                'claim_list_items', 'claim_result_sizes_name'
            )
        if max_items <= 0:
            raise RequiredArgument('claim_list_items', 'max_items')
        if max_bytes <= 0:
            raise RequiredArgument('claim_list_items', 'max_bytes')
        if max_item_bytes <= 0 or max_item_bytes > max_bytes:
            raise RequiredArgument('claim_list_items', 'max_item_bytes')

        response = ctx.eval(
            CLAIM_RESULT_ITEMS_SCRIPT,
            10,
            name,
            claim_name,
            claim_id_name,
            pending_count_name,
            pending_bytes_name,
            admission_failure_name,
            admission_ids_name,
            claim_admission_ids_name,
            result_sizes_name,
            claim_result_sizes_name,
            max_items,
            max_bytes,
            max_item_bytes,
            str(uuid.uuid4()),
        )
        if not response:
            return None, []
        return str(response[0]), list(response[1:])

    @staticmethod
    def ack_list_claim(
        ctx: RedisCtx,
        claim_name: str,
        claim_id_name: str,
        pending_count_name: str,
        pending_bytes_name: str,
        admission_failure_name: str,
        claim_admission_ids_name: str,
        claim_result_sizes_name: str,
        claim_id: str,
    ) -> ResultClaimAck:
        """Return the exact outcome of releasing a replayable claim."""
        if not ctx:
            raise RequiredArgument('ack_list_claim', 'ctx')
        if not claim_name:
            raise RequiredArgument('ack_list_claim', 'claim_name')
        if not claim_id_name:
            raise RequiredArgument('ack_list_claim', 'claim_id_name')
        if not pending_count_name:
            raise RequiredArgument('ack_list_claim', 'pending_count_name')
        if not pending_bytes_name:
            raise RequiredArgument('ack_list_claim', 'pending_bytes_name')
        if not admission_failure_name:
            raise RequiredArgument('ack_list_claim', 'admission_failure_name')
        if not claim_admission_ids_name:
            raise RequiredArgument('ack_list_claim', 'claim_admission_ids_name')
        if not claim_result_sizes_name:
            raise RequiredArgument('ack_list_claim', 'claim_result_sizes_name')
        if not claim_id:
            raise RequiredArgument('ack_list_claim', 'claim_id')
        outcome = ctx.eval(
            ACK_RESULT_CLAIM_SCRIPT,
            7,
            claim_name,
            claim_id_name,
            pending_count_name,
            pending_bytes_name,
            admission_failure_name,
            claim_admission_ids_name,
            claim_result_sizes_name,
            claim_id,
        )
        try:
            return ResultClaimAck(int(outcome))
        except (TypeError, ValueError) as error:
            raise OspdOpenvasError(
                'Scanner Redis returned an invalid result-claim outcome.'
            ) from error

    @staticmethod
    def get_result_queue_failure(
        ctx: RedisCtx,
        name: str,
        claim_name: str,
        claim_id_name: str,
        pending_count_name: str,
        pending_bytes_name: str,
        admission_failure_name: str,
        admission_ids_name: str,
        claim_admission_ids_name: str,
        result_sizes_name: str,
        claim_result_sizes_name: str,
    ) -> Optional[str]:
        """Return a fixed fail-closed result queue health code."""
        try:
            failure = ctx.eval(
                RESULT_QUEUE_FAILURE_SCRIPT,
                10,
                name,
                claim_name,
                claim_id_name,
                pending_count_name,
                pending_bytes_name,
                admission_failure_name,
                admission_ids_name,
                claim_admission_ids_name,
                result_sizes_name,
                claim_result_sizes_name,
            )
        except redis.RedisError:
            return 'queue-state-unreadable'
        return str(failure) if failure else None

    @staticmethod
    def get_key_count(ctx: RedisCtx, pattern: Optional[str] = None) -> int:
        """Get the number of keys matching with the pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: pattern used as filter.
        """
        if not pattern:
            pattern = "*"

        if not ctx:
            raise RequiredArgument('get_key_count', 'ctx')

        return len(ctx.keys(pattern))

    @staticmethod
    def remove_list_item(ctx: RedisCtx, key: str, value: str):
        """Remove item from the key list.

        Arguments:
            ctx: Redis context to use.
            key: key name of a list.
            value: Value to be removed from the key.
        """
        if not ctx:
            raise RequiredArgument('remove_list_item ', 'ctx')
        if not key:
            raise RequiredArgument('remove_list_item', 'key')
        if not value:
            raise RequiredArgument('remove_list_item ', 'value')

        ctx.lrem(key, count=LIST_ALL, value=value)

    @staticmethod
    def get_single_item(
        ctx: RedisCtx,
        name: str,
        index: Optional[int] = LIST_FIRST_POS,
    ) -> Optional[str]:
        """Get a single KB element.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            index: index of the element to be return.
                   Defaults to the first element in the list.

        Return the first element of the list or None if the name couldn't be
        found.
        """
        if not ctx:
            raise RequiredArgument('get_single_item', 'ctx')
        if not name:
            raise RequiredArgument('get_single_item', 'name')

        return ctx.lindex(name, index)

    @staticmethod
    def add_single_list(ctx: RedisCtx, name: str, values: Iterable):
        """Add a single KB element with one or more values.
        The values can be repeated. If the key already exists will
        be removed an completely replaced.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            value: Elements to add to the key.
        """
        if not ctx:
            raise RequiredArgument('add_single_list', 'ctx')
        if not name:
            raise RequiredArgument('add_single_list', 'name')
        if not values:
            raise RequiredArgument('add_single_list', 'value')

        pipe = ctx.pipeline()
        pipe.delete(name)
        pipe.rpush(name, *values)
        pipe.execute()

    @staticmethod
    def add_single_item(
        ctx: RedisCtx, name: str, values: Iterable, lpush: bool = False
    ):
        """Add a single KB element with one or more values. Don't add
        duplicated values during this operation, but if the the same
        values already exists under the key, this will not be overwritten.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            value: Elements to add to the key.
        """
        if not ctx:
            raise RequiredArgument('add_single_item', 'ctx')
        if not name:
            raise RequiredArgument('add_single_item', 'name')
        if not values:
            raise RequiredArgument('add_single_item', 'value')

        if lpush:
            ctx.lpush(name, *set(values))
            return

        ctx.rpush(name, *set(values))

    @staticmethod
    def set_single_item(ctx: RedisCtx, name: str, value: Iterable):
        """Set (replace) a single KB element. If the same key exists
        in the kb, it is completed removed. Values added are unique.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            value: New elements to add to the key.
        """
        if not ctx:
            raise RequiredArgument('set_single_item', 'ctx')
        if not name:
            raise RequiredArgument('set_single_item', 'name')
        if not value:
            raise RequiredArgument('set_single_item', 'value')

        pipe = ctx.pipeline()
        pipe.delete(name)
        pipe.rpush(name, *set(value))
        pipe.execute()

    @staticmethod
    def get_pattern(ctx: RedisCtx, pattern: str) -> List:
        """Get all items stored under a given pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: key pattern to match.

        Return a list with the elements under the matched key.
        """
        if not ctx:
            raise RequiredArgument('get_pattern', 'ctx')
        if not pattern:
            raise RequiredArgument('get_pattern', 'pattern')

        items = ctx.keys(pattern)

        elem_list = []
        for item in items:
            elem_list.append(
                [
                    item,
                    ctx.lrange(item, start=LIST_FIRST_POS, end=LIST_LAST_POS),
                ]
            )
        return elem_list

    @classmethod
    def get_keys_by_pattern(cls, ctx: RedisCtx, pattern: str) -> List[str]:
        """Get all items with index 'index', stored under
        a given pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: key pattern to match.

        Return a sorted list with the elements under the matched key
        """
        if not ctx:
            raise RequiredArgument('get_elem_pattern_by_index', 'ctx')
        if not pattern:
            raise RequiredArgument('get_elem_pattern_by_index', 'pattern')

        return sorted(ctx.keys(pattern))

    @classmethod
    def get_filenames_and_oids(
        cls, ctx: RedisCtx, pattern: str, parser: Callable[[str], str]
    ) -> Iterable[Tuple[str, str]]:
        """Get all items with index 'index', stored under
        a given pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: Pattern used for searching the keys
            parser: Callable method to remove the pattern from the keys.

        Return an iterable where each single tuple contains the filename
            as first element and the oid as the second one.
        """
        if not ctx:
            raise RequiredArgument('get_filenames_and_oids', 'ctx')
        if not pattern:
            raise RequiredArgument('get_filenames_and_oids', 'pattern')
        if not parser:
            raise RequiredArgument('get_filenames_and_oids', 'parser')

        items = cls.get_keys_by_pattern(ctx, pattern)

        return ((ctx.lindex(item, 0), parser(item)) for item in items)

    @staticmethod
    def exists(ctx: RedisCtx, key: str) -> bool:
        """Check that the given key exists in the given context.

        Arguments:
            ctx: Redis context to use.
            patternkey: key to check.

        Return a True if exists, False otherwise.
        """
        if not ctx:
            raise RequiredArgument('exists', 'ctx')

        return ctx.exists(key) == 1


class BaseDB:
    def __init__(self, kbindex: int, ctx: Optional[RedisCtx] = None):
        if ctx is None:
            self.ctx = OpenvasDB.create_context(kbindex)
        else:
            self.ctx = ctx

        self.index = kbindex

    def flush(self):
        """Flush the database"""
        self.ctx.flushdb()


class BaseKbDB(BaseDB):
    RESULT_KEY = 'internal/results'
    RESULT_CLAIM_KEY = 'internal/results.ospd-claim'
    RESULT_CLAIM_ID_KEY = 'internal/results.ospd-claim-id'
    RESULT_ADMISSION_FAILURE_KEY = 'internal/results.admission-failure'
    RESULT_PENDING_COUNT_KEY = 'internal/results.pending-count'
    RESULT_PENDING_BYTES_KEY = 'internal/results.pending-bytes'
    RESULT_ADMISSION_IDS_KEY = 'internal/results.admission-ids'
    RESULT_CLAIM_ADMISSION_IDS_KEY = 'internal/results.ospd-claim-admission-ids'
    RESULT_SIZES_KEY = 'internal/results.sizes'
    RESULT_CLAIM_SIZES_KEY = 'internal/results.ospd-claim-sizes'

    def _add_single_item(
        self, name: str, values: Iterable, utf8_enc: Optional[bool] = False
    ):
        """Changing the encoding format of an existing redis context
        is not possible. Therefore a new temporary redis context is
        created to store key-values encoded with utf-8."""
        if utf8_enc:
            ctx = OpenvasDB.create_context(self.index, encoding='utf-8')
            OpenvasDB.add_single_item(ctx, name, values)
        else:
            OpenvasDB.add_single_item(self.ctx, name, values)

    def _set_single_item(self, name: str, value: Iterable):
        """Set (replace) a single KB element.

        Arguments:
            name: key name of a list.
            value: New elements to add to the key.
        """
        OpenvasDB.set_single_item(self.ctx, name, value)

    def _get_single_item(self, name: str) -> Optional[str]:
        """Get a single KB element.

        Arguments:
            name: key name of a list.
        """
        return OpenvasDB.get_single_item(self.ctx, name)

    def _get_list_item(
        self,
        name: str,
    ) -> Optional[List]:
        """Returns the specified elements from `start` to `end` of the
        list stored as `name`.

        Arguments:
            name: key name of a list.

        Return List specified elements in the key.
        """
        return OpenvasDB.get_list_item(self.ctx, name)

    def _pop_list_items(self, name: str) -> List:
        return OpenvasDB.pop_list_items(self.ctx, name)

    def _remove_list_item(self, key: str, value: str):
        """Remove item from the key list.

        Arguments:
            key: key name of a list.
            value: Value to be removed from the key.
        """
        OpenvasDB.remove_list_item(self.ctx, key, value)

    def claim_results(
        self, *, max_items: int, max_bytes: int, max_item_bytes: int
    ) -> Tuple[Optional[str], List[str]]:
        """Claim a bounded replayable batch of oldest scanner results."""
        return OpenvasDB.claim_list_items(
            self.ctx,
            self.RESULT_KEY,
            self.RESULT_CLAIM_KEY,
            self.RESULT_CLAIM_ID_KEY,
            self.RESULT_PENDING_COUNT_KEY,
            self.RESULT_PENDING_BYTES_KEY,
            self.RESULT_ADMISSION_FAILURE_KEY,
            self.RESULT_ADMISSION_IDS_KEY,
            self.RESULT_CLAIM_ADMISSION_IDS_KEY,
            self.RESULT_SIZES_KEY,
            self.RESULT_CLAIM_SIZES_KEY,
            max_items=max_items,
            max_bytes=max_bytes,
            max_item_bytes=max_item_bytes,
        )

    def ack_result_claim(self, claim_id: str) -> bool:
        return self.ack_result_claim_state(claim_id) == ResultClaimAck.RELEASED

    def ack_result_claim_state(self, claim_id: str) -> ResultClaimAck:
        """Return the exact release outcome for one result claim."""
        return OpenvasDB.ack_list_claim(
            self.ctx,
            self.RESULT_CLAIM_KEY,
            self.RESULT_CLAIM_ID_KEY,
            self.RESULT_PENDING_COUNT_KEY,
            self.RESULT_PENDING_BYTES_KEY,
            self.RESULT_ADMISSION_FAILURE_KEY,
            self.RESULT_CLAIM_ADMISSION_IDS_KEY,
            self.RESULT_CLAIM_SIZES_KEY,
            claim_id,
        )

    def has_pending_results(self) -> bool:
        return bool(
            self.ctx.llen(self.RESULT_KEY)
            or self.ctx.llen(self.RESULT_CLAIM_KEY)
        )

    def get_result_admission_failure(self) -> Optional[str]:
        """Return a fixed fail-closed result delivery failure code."""
        return OpenvasDB.get_result_queue_failure(
            self.ctx,
            self.RESULT_KEY,
            self.RESULT_CLAIM_KEY,
            self.RESULT_CLAIM_ID_KEY,
            self.RESULT_PENDING_COUNT_KEY,
            self.RESULT_PENDING_BYTES_KEY,
            self.RESULT_ADMISSION_FAILURE_KEY,
            self.RESULT_ADMISSION_IDS_KEY,
            self.RESULT_CLAIM_ADMISSION_IDS_KEY,
            self.RESULT_SIZES_KEY,
            self.RESULT_CLAIM_SIZES_KEY,
        )

    def get_status(self, openvas_scan_id: str) -> Optional[str]:
        """Return the status of the host scan"""
        return self._get_single_item(f'internal/{openvas_scan_id}')

    def __repr__(self):
        return f'<{self.__class__.__name__} index={self.index}>'


class ScanDB(BaseKbDB):
    """Database for a scanning a single host"""

    def select(self, kbindex: int) -> "ScanDB":
        """Select a redis kb.

        Arguments:
            kbindex: The new kb to select
        """
        OpenvasDB.select_database(self.ctx, kbindex)
        self.index = kbindex
        return self


class KbDB(BaseKbDB):
    def get_scan_databases(self) -> Iterator[ScanDB]:
        """Returns an iterator yielding corresponding ScanDBs

        The returned Iterator can't be converted to an Iterable like a List.
        Each yielded ScanDB must be used independently in a for loop. If the
        Iterator gets converted into an Iterable all returned ScanDBs will use
        the same redis context pointing to the same redis database.
        """
        dbs = self._get_list_item('internal/dbindex')
        scan_db = ScanDB(self.index)
        for kbindex in dbs:
            if kbindex == self.index:
                continue

            yield scan_db.select(kbindex)

    def add_scan_id(self, scan_id: str):
        self._add_single_item(f'internal/{scan_id}', ['new'])
        self._add_single_item('internal/scanid', [scan_id])

    def add_scan_preferences(self, openvas_scan_id: str, preferences: Iterable):
        self._add_single_item(
            f'internal/{openvas_scan_id}/scanprefs', preferences
        )

    def add_credentials_to_scan_preferences(
        self, openvas_scan_id: str, preferences: Iterable
    ):
        """Force the usage of the utf-8 encoding, since some credentials
        contain special chars not supported by latin-1 encoding."""
        self._add_single_item(
            f'internal/{openvas_scan_id}/scanprefs',
            preferences,
            utf8_enc=True,
        )

    def add_scan_process_id(self, pid: int):
        self._add_single_item('internal/ovas_pid', [pid])

    def get_scan_process_id(self) -> Optional[str]:
        return self._get_single_item('internal/ovas_pid')

    def remove_scan_database(self, scan_db: ScanDB):
        self._remove_list_item('internal/dbindex', scan_db.index)

    def target_is_finished(self, scan_id: str) -> bool:
        """Check if a target has finished."""

        status = self._get_single_item(f'internal/{scan_id}')

        if status is None:
            logger.error(
                "%s: Target set as finished because redis returned None as "
                "scanner status.",
                scan_id,
            )

        return status == 'finished' or status is None

    def stop_scan(self, openvas_scan_id: str):
        self._set_single_item(f'internal/{openvas_scan_id}', ['stop_all'])

    def scan_is_stopped(self, scan_id: str) -> bool:
        """Check if the scan should be stopped"""
        status = self._get_single_item(f'internal/{scan_id}')
        return status == 'stop_all'

    def get_scan_status(self) -> List:
        """Get and remove the oldest host scan status from the list.

        Return a string which represents the host scan status.
        """
        return self._pop_list_items("internal/status")


class MainDB(BaseDB):
    """Main Database"""

    DEFAULT_INDEX = 0

    def __init__(self, ctx=None):
        super().__init__(self.DEFAULT_INDEX, ctx)

        self._max_dbindex = None

    @property
    def max_database_index(self):
        """Set the number of databases have been configured into kbr struct."""
        if self._max_dbindex is None:
            resp = self.ctx.config_get('databases')

            if len(resp) == 1:
                self._max_dbindex = int(resp.get('databases'))
            else:
                raise OspdOpenvasError(
                    'Redis Error: Not possible to get max_dbindex.'
                ) from None

        return self._max_dbindex

    def try_database(self, index: int) -> bool:
        """Check if a redis db is already in use. If not, set it
        as in use and return.

        Arguments:
            ctx: Redis object connected to the kb with the
                DBINDEX_NAME key.
            index: Number intended to be used.

        Return True if it is possible to use the db. False if the given db
            number is already in use.
        """
        _in_use = 1
        try:
            resp = self.ctx.hsetnx(DBINDEX_NAME, index, _in_use)
        except:
            raise OspdOpenvasError(
                f'Redis Error: Not possible to set {DBINDEX_NAME}.'
            ) from None

        return resp == 1

    def get_new_kb_database(self) -> Optional[KbDB]:
        """Return a new kb db to an empty kb."""
        for index in range(1, self.max_database_index):
            if self.try_database(index):
                kbdb = KbDB(index)
                kbdb.flush()
                return kbdb

        return None

    def find_kb_database_by_scan_id(
        self, scan_id: str
    ) -> Tuple[Optional[str], Optional["KbDB"]]:
        """Find a kb db by via a scan id"""
        for index in range(1, self.max_database_index):
            ctx = OpenvasDB.create_context(index)
            if OpenvasDB.get_key_count(ctx, f'internal/{scan_id}'):
                return KbDB(index, ctx)

        return None

    def check_consistency(self, scan_id) -> Tuple[Optional[KbDB], int]:
        """Check if the current scan id already exists in a kb.

        Return a tuple with the kb or none, and an error code, being 0 if
        the db is clean, -1 on old finished scan, -2 on still running scan.
        """
        err = 0

        kb = self.find_kb_database_by_scan_id(scan_id)
        current_status = None
        if kb:
            current_status = kb.get_status(scan_id)
        if current_status == "finished":
            err = -1
        elif current_status == "stop_all" or current_status == "ready":
            err = -2

        return (kb, err)

    def release_database(self, database: BaseDB):
        # Keep the index reserved until its old contents are gone.  Returning
        # it first allows another scan to reuse it before flush completes.
        database.flush()
        self.release_database_by_index(database.index)

    def release_database_by_index(self, index: int):
        self.ctx.hdel(DBINDEX_NAME, index)

    def release(self):
        self.release_database(self)
