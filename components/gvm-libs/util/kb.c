/* SPDX-FileCopyrightText: 2014-2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Knowledge base management API - Redis backend.
 */

#define _GNU_SOURCE

#include "kb.h"
#include "uuidutils.h"

#include <errno.h> /* for ENOMEM, EINVAL, EPROTO, EALREADY, ECONN... */
#include <glib.h>  /* for g_log, g_free */
#include <hiredis/hiredis.h> /* for redisReply, freeReplyObject, redisCommand */
#include <stdbool.h>         /* for bool, true, false */
#include <stdio.h>
#include <stdlib.h> /* for atoi */
#include <string.h> /* for strlen, strerror, strncpy, memset */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

#if GLIB_CHECK_VERSION(2, 67, 3)
#define memdup g_memdup2
#else
#define memdup g_memdup
#endif

/**
 * @file kb.c
 *
 * @brief Contains specialized structures and functions to use redis as a KB
 *        server.
 */

/**
 * @brief Name of the namespace usage bitmap in redis.
 */
#define GLOBAL_DBINDEX_NAME "GVM.__GlobalDBIndex"
#define DATABASE_RELEASE_MAX_ATTEMPTS 3

#define SCANNER_RESULT_KEY "internal/results"
#define SCANNER_RESULT_CLAIM_KEY "internal/results.ospd-claim"
#define SCANNER_RESULT_ADMISSION_FAILURE_KEY \
  "internal/results.admission-failure"
#define SCANNER_RESULT_PENDING_COUNT_KEY "internal/results.pending-count"
#define SCANNER_RESULT_PENDING_BYTES_KEY "internal/results.pending-bytes"
#define SCANNER_RESULT_ADMISSION_IDS_KEY "internal/results.admission-ids"
#define SCANNER_RESULT_CLAIM_ADMISSION_IDS_KEY "internal/results.ospd-claim-admission-ids"
#define SCANNER_RESULT_SIZES_KEY "internal/results.sizes"
#define SCANNER_RESULT_CLAIM_SIZES_KEY "internal/results.ospd-claim-sizes"
#define SCANNER_RESULT_MAX_ITEM_BYTES (4ULL * 1024ULL * 1024ULL)
#define SCANNER_RESULT_MAX_PENDING_ITEMS 10000ULL
#define SCANNER_RESULT_MAX_PENDING_BYTES (64ULL * 1024ULL * 1024ULL)

static const char *SCANNER_RESULT_ADMISSION_SCRIPT =
  "local function key_type(index) "
  "return redis.call('TYPE', KEYS[index]).ok end "
  "local function list_or_none(index) "
  "local kind = key_type(index); "
  "return kind == 'none' or kind == 'list' end "
  "local function string_or_none(index) "
  "local kind = key_type(index); "
  "return kind == 'none' or kind == 'string' end "
  "local function memory_within(index, limit) "
  "local usage = redis.call('MEMORY', 'USAGE', KEYS[index]); "
  "return not usage or usage <= limit end "
  "local function mark_failure(code) "
  "if key_type(3) == 'none' then "
  "redis.call('RPUSH', KEYS[3], code) "
  "elseif key_type(3) == 'list' and redis.call('LLEN', KEYS[3]) == 0 then "
  "redis.call('RPUSH', KEYS[3], code) end end "
  "if redis.call('EXISTS', KEYS[3]) == 1 then return -3 end "
  "if not list_or_none(1) or not list_or_none(2) "
  "or not list_or_none(3) or not string_or_none(4) "
  "or not string_or_none(5) or not list_or_none(6) "
  "or not list_or_none(7) or not list_or_none(8) "
  "or not list_or_none(9) then "
  "mark_failure('counter-state'); return -4 end "
  "local max_items = tonumber(ARGV[4]); "
  "local max_bytes = tonumber(ARGV[5]); "
  "local payload_memory_limit = max_bytes * 2 + max_items * 256; "
  "local sidecar_memory_limit = max_items * 256; "
  "if not memory_within(1, payload_memory_limit) "
  "or not memory_within(2, payload_memory_limit) "
  "or not memory_within(6, sidecar_memory_limit) "
  "or not memory_within(7, sidecar_memory_limit) "
  "or not memory_within(8, sidecar_memory_limit) "
  "or not memory_within(9, sidecar_memory_limit) then "
  "mark_failure('counter-state'); return -4 end "
  "local source_count = redis.call('LLEN', KEYS[1]); "
  "local claim_count = redis.call('LLEN', KEYS[2]); "
  "if source_count ~= redis.call('LLEN', KEYS[6]) "
  "or source_count ~= redis.call('LLEN', KEYS[8]) "
  "or claim_count ~= redis.call('LLEN', KEYS[7]) "
  "or claim_count ~= redis.call('LLEN', KEYS[9]) then "
  "mark_failure('counter-state'); return -4 end "
  "local row_bytes = string.len(ARGV[2]); "
  "if row_bytes > tonumber(ARGV[3]) then "
  "redis.call('RPUSH', KEYS[3], 'row-too-large'); return -1 end "
  "local count = tonumber(redis.call('GET', KEYS[4])); "
  "local bytes = tonumber(redis.call('GET', KEYS[5])); "
  "local queued = source_count + claim_count; "
  "if not count or not bytes then "
  "if queued ~= 0 then "
  "mark_failure('counter-state'); return -4 end "
  "count = 0; bytes = 0 end "
  "if count ~= queued or count < 0 or bytes < 0 "
  "or count > max_items or bytes > max_bytes then "
  "mark_failure('counter-state'); return -4 end "
  "if redis.call('LPOS', KEYS[6], ARGV[1]) "
  "or redis.call('LPOS', KEYS[7], ARGV[1]) then return 1 end "
  "if count + 1 > max_items or bytes + row_bytes > max_bytes then "
  "redis.call('RPUSH', KEYS[3], 'pending-capacity'); return -2 end "
  "redis.call('LPUSH', KEYS[1], ARGV[2]); "
  "redis.call('LPUSH', KEYS[6], ARGV[1]); "
  "redis.call('LPUSH', KEYS[8], tostring(row_bytes)); "
  "redis.call('SET', KEYS[4], count + 1); "
  "redis.call('SET', KEYS[5], bytes + row_bytes); "
  "return 1";

static const struct kb_operations KBRedisOperations;

/**
 * @brief Subclass of struct kb, it contains the redis-specific fields, such as
 *        the redis context, current DB (namespace) id and the server socket
 *        path.
 */
struct kb_redis
{
  struct kb kb;        /**< Parent KB handle. */
  unsigned int max_db; /**< Max # of databases. */
  unsigned int db;     /**< Namespace ID number, 0 if uninitialized. */
  redisContext *rctx;  /**< Redis client context. */
  char *path;          /**< Path to the server socket. */
  char *owner_token;   /**< Unique namespace owner/fencing token. */
};
#define redis_kb(__kb) ((struct kb_redis *) (__kb))

static int
redis_delete_all (struct kb_redis *);
static int redis_lnk_reset (kb_t);
static int
redis_flush_all (kb_t, const char *);
static redisReply *
redis_cmd (struct kb_redis *kbr, const char *fmt, ...);

/**
 * @brief Attempt to atomically acquire ownership of a database.
 *
 * @return 0 on success, negative integer otherwise.
 */
static int
try_database_index (struct kb_redis *kbr, int index)
{
  redisContext *ctx = kbr->rctx;
  redisReply *rep;
  int rc = 0;

  if (kbr->owner_token == NULL)
    kbr->owner_token = gvm_uuid_make ();
  if (kbr->owner_token == NULL)
    return -ENOMEM;

  rep = redisCommand (ctx, "HSETNX %s %d %s", GLOBAL_DBINDEX_NAME, index,
                      kbr->owner_token);
  if (rep == NULL)
    return -ENOMEM;

  if (rep->type != REDIS_REPLY_INTEGER)
    rc = -EPROTO;
  else if (rep->integer == 0)
    rc = -EALREADY;
  else
    kbr->db = index;

  freeReplyObject (rep);

  return rc;
}

/**
 * @brief Flush and release a DB only while its exact owner token remains set.
 *
 * The watched index is always in DB 0.  The flush and index deletion are
 * executed by one Redis transaction so a replaced owner cannot be flushed.
 *
 * @return 0 on success, negative integer otherwise.
 */
static int
redis_flush_and_release_db (struct kb_redis *kbr)
{
  redisReply *rep = NULL;
  redisContext *ctx;
  size_t owner_token_len;
  unsigned int attempt;
  int rc = -EIO;

  if (kbr == NULL || kbr->rctx == NULL || kbr->db == 0
      || kbr->owner_token == NULL)
    return -EINVAL;

  ctx = kbr->rctx;
  owner_token_len = strlen (kbr->owner_token);
  for (attempt = 0; attempt < DATABASE_RELEASE_MAX_ATTEMPTS; attempt++)
    {
      rep = redisCommand (ctx, "SELECT 0");
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        goto cleanup;
      freeReplyObject (rep);
      rep = NULL;

      rep = redisCommand (ctx, "WATCH %s", GLOBAL_DBINDEX_NAME);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        goto cleanup;
      freeReplyObject (rep);
      rep = NULL;

      rep = redisCommand (ctx, "HGET %s %u", GLOBAL_DBINDEX_NAME, kbr->db);
      if (rep == NULL)
        goto unwatch;
      if (rep->type != REDIS_REPLY_STRING || rep->len != owner_token_len
          || memcmp (rep->str, kbr->owner_token, owner_token_len) != 0)
        {
          rc = -EPERM;
          goto unwatch;
        }
      freeReplyObject (rep);
      rep = NULL;

      rep = redisCommand (ctx, "MULTI");
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        goto unwatch;
      freeReplyObject (rep);
      rep = NULL;

      rep = redisCommand (ctx, "SELECT %u", kbr->db);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS
          || strcmp (rep->str, "QUEUED") != 0)
        goto discard;
      freeReplyObject (rep);
      rep = redisCommand (ctx, "FLUSHDB");
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS
          || strcmp (rep->str, "QUEUED") != 0)
        goto discard;
      freeReplyObject (rep);
      rep = redisCommand (ctx, "SELECT 0");
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS
          || strcmp (rep->str, "QUEUED") != 0)
        goto discard;
      freeReplyObject (rep);
      rep = redisCommand (ctx, "HDEL %s %u", GLOBAL_DBINDEX_NAME, kbr->db);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS
          || strcmp (rep->str, "QUEUED") != 0)
        goto discard;
      freeReplyObject (rep);
      rep = redisCommand (ctx, "EXEC");
      if (rep == NULL)
        goto cleanup;
      if (rep->type == REDIS_REPLY_NIL)
        {
          freeReplyObject (rep);
          rep = NULL;
          continue;
        }
      if (rep->type != REDIS_REPLY_ARRAY || rep->elements != 4
          || rep->element[0]->type != REDIS_REPLY_STATUS
          || rep->element[1]->type != REDIS_REPLY_STATUS
          || rep->element[2]->type != REDIS_REPLY_STATUS
          || rep->element[3]->type != REDIS_REPLY_INTEGER
          || rep->element[3]->integer != 1)
        goto cleanup;

      rc = 0;
      goto cleanup;

    discard:
      if (rep != NULL)
        {
          freeReplyObject (rep);
          rep = NULL;
        }
      rep = redisCommand (ctx, "DISCARD");
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        goto cleanup;
      freeReplyObject (rep);
      rep = NULL;
      return -EIO;

    unwatch:
      if (rep != NULL)
        {
          freeReplyObject (rep);
          rep = NULL;
        }
      rep = redisCommand (ctx, "UNWATCH");
      if (rep != NULL)
        freeReplyObject (rep);
      return rc;
    }

  rc = -EAGAIN;

cleanup:
  if (rep != NULL)
    freeReplyObject (rep);
  return rc;
}

/**
 * @brief Set the number of databases have been configured
 *        into kbr struct.
 *
 * @param[in] kbr Subclass of struct kb where to save the max db index founded.
 *
 * @return 0 on success, -1 on error.
 */
static int
fetch_max_db_index (struct kb_redis *kbr)
{
  int rc = 0;
  redisContext *ctx = kbr->rctx;
  redisReply *rep = NULL;

  rep = redisCommand (ctx, "CONFIG GET databases");
  if (rep == NULL)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: redis command failed with '%s'", __func__, ctx->errstr);
      rc = -1;
      goto err_cleanup;
    }

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: cannot retrieve max DB number: %s", __func__, rep->str);
      rc = -1;
      goto err_cleanup;
    }

  if (rep->elements == 2)
    {
      kbr->max_db = (unsigned) atoi (rep->element[1]->str);
    }
  else
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: unexpected reply length (%zd)", __func__, rep->elements);
      rc = -1;
      goto err_cleanup;
    }

  g_debug ("%s: maximum DB number: %u", __func__, kbr->max_db);

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Select DB.
 *
 * WARNING: do not call redis_cmd in here, since our context is not fully
 * acquired yet!
 *
 * @param[in] kbr Subclass of struct kb where to save the db index.
 *
 * @return 0 on success, -1 on error.
 */
static int
select_database (struct kb_redis *kbr)
{
  int rc;
  bool reconnecting;
  redisContext *ctx = kbr->rctx;
  redisReply *rep = NULL;

  reconnecting = kbr->db > 0;
  if (kbr->db == 0)
    {
      unsigned i;

      if (kbr->max_db == 0)
        fetch_max_db_index (kbr);

      for (i = 1; i < kbr->max_db; i++)
        {
          rc = try_database_index (kbr, i);
          if (rc == 0)
            break;
        }
    }

  /* No DB available, give up. */
  if (kbr->db == 0)
    {
      rc = -1;
      goto err_cleanup;
    }

  if (reconnecting)
    {
      size_t owner_token_len;

      if (kbr->owner_token == NULL)
        {
          rc = -EPERM;
          goto err_cleanup;
        }

      owner_token_len = strlen (kbr->owner_token);
      rep = redisCommand (ctx, "HGET %s %u", GLOBAL_DBINDEX_NAME, kbr->db);
      if (rep == NULL || rep->type != REDIS_REPLY_STRING
          || rep->len != owner_token_len
          || memcmp (rep->str, kbr->owner_token, owner_token_len) != 0)
        {
          g_warning ("%s: refusing to reconnect to Redis DB %u without its "
                     "exact owner token",
                     __func__, kbr->db);
          rc = -EPERM;
          goto err_cleanup;
        }
      freeReplyObject (rep);
      rep = NULL;
    }

  rep = redisCommand (ctx, "SELECT %u", kbr->db);
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

static inline const char *
parse_port_of_addr (const char *addr, int tcp_indicator_len)
{
  const char *tmp;
  int is_ip_v6;
  tmp = strrchr (addr + tcp_indicator_len, ':');
  if (tmp == NULL)
    return NULL;
  is_ip_v6 = addr[tcp_indicator_len] == '[';
  if (is_ip_v6 && (tmp - 1)[0] != ']')
    return NULL;
  return tmp + 1;
}

static redisContext *
connect_redis (const char *addr, int len)
{
  const char *tcp_indicator = "tcp://";
  const int tcp_indicator_len = strlen (tcp_indicator);
  const int redis_default_port = 6379;

  int port, host_len;
  const char *tmp;
  char *host;
  redisContext *result;
  static int warn_flag = 0;

  if (len < tcp_indicator_len + 1)
    goto unix_connect;
  if (memcmp (addr, tcp_indicator, tcp_indicator_len) != 0)
    goto unix_connect;
  host_len = len - tcp_indicator_len;
  tmp = parse_port_of_addr (addr, tcp_indicator_len);
  if (tmp == NULL)
    port = redis_default_port;
  else
    {
      port = atoi (tmp);
      host_len -= strlen (tmp) + 1;
    }
  host = calloc (1, host_len);
  memmove (host, addr + tcp_indicator_len, host_len);
  result = redisConnect (host, port);
  if (warn_flag == 0)
    {
      g_warning ("A Redis TCP connection is being used. This feature is "
                 "experimental and insecure, since it is not an encrypted "
                 "channel. We discourage its usage in production environments");
      warn_flag = 1;
    }
  free (host);
  return result;
unix_connect:
  return redisConnectUnix (addr);
}

/**
 * @brief Get redis context if it is already connected or do a
 *        a connection.
 *
 * @param[in] kbr Subclass of struct kb where to fetch the context.
 *                or where it is saved in case of a new connection.
 *
 * @return 0 on success, -1 on connection error, -2 on unavailable DB slot.
 */
static int
get_redis_ctx (struct kb_redis *kbr)
{
  int rc;

  if (kbr->rctx != NULL)
    return 0;

  kbr->rctx = connect_redis (kbr->path, strlen (kbr->path));
  if (kbr->rctx == NULL || kbr->rctx->err)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: redis connection error to %s: %s", __func__, kbr->path,
             kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
      return -1;
    }

  rc = select_database (kbr);
  if (rc)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "No redis DB available");
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
      return -2;
    }

  g_debug ("%s: connected to redis://%s/%d", __func__, kbr->path, kbr->db);
  return 0;
}

/**
 * @brief Test redis connection.
 *
 * @param[in] kbr Subclass of struct kb to test.
 *
 * @return 0 on success, negative integer on error.
 */
static int
redis_test_connection (struct kb_redis *kbr)
{
  int rc = 0;
  redisReply *rep;

  rep = redis_cmd (kbr, "PING");
  if (rep == NULL)
    {
      /* not 100% relevant but hiredis doesn't provide us with proper error
       * codes. */
      rc = -ECONNREFUSED;
      goto out;
    }

  if (rep->type != REDIS_REPLY_STATUS)
    {
      rc = -EINVAL;
      goto out;
    }

  if (g_ascii_strcasecmp (rep->str, "PONG"))
    {
      rc = -EPROTO;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Delete all entries and release ownership on the namespace.
 *
 * @param[in] kb KB handle to release.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_delete (kb_t kb)
{
  struct kb_redis *kbr;
  int rc = 0;

  kbr = redis_kb (kb);

  if (kbr->db > 0 && kbr->owner_token != NULL)
    {
      rc = redis_flush_and_release_db (kbr);
      if (rc != 0)
        g_warning (
          "%s: refusing to delete Redis DB %u without its exact owner token",
          __func__, kbr->db);
    }
  else if (kbr->db > 0)
    {
      rc = -EPERM;
      g_warning ("%s: refusing to delete unowned Redis DB %u", __func__,
                 kbr->db);
    }

  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  g_free (kbr->path);
  g_free (kbr->owner_token);
  g_free (kb);
  return rc;
}

/**
 * @brief Return the kb index
 *
 * @param[in] kb KB handle.
 *
 * @return kb_index on success, null on error.
 */
static int
redis_get_kb_index (kb_t kb)
{
  int i;
  i = ((struct kb_redis *) kb)->db;
  if (i > 0)
    return i;
  return -1;
}

/**
 * @brief Return the immutable owner token for an allocated KB.
 */
static const char *
redis_get_owner_token (kb_t kb)
{
  return redis_kb (kb)->owner_token;
}

/**
 * @brief Attempt to purge dirty pages.
 *
 * Attempt to purge dirty pages so these can be reclaimed by the allocator.
 * This command only works when using jemalloc as an allocator, and evaluates
 * to a benign NOOP for all others. Command is applied to complete redis
 * instance and not only single db.
 *
 * @param[in] kb KB handle where to run the command.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_memory_purge (kb_t kb)
{
  redisReply *rep;
  int rc = 0;

  rep = redis_cmd (redis_kb (kb), "MEMORY PURGE");
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Initialize a new Knowledge Base object.
 *
 * @param[in] kb  Reference to a kb_t to initialize.
 * @param[in] kb_path   Path to KB.
 *
 * @return 0 on success, -1 on connection error, -2 when no DB is available, -3
 * when given kb_path was NULL.
 */
static int
redis_new (kb_t *kb, const char *kb_path)
{
  struct kb_redis *kbr;
  int rc = 0;

  if (kb_path == NULL)
    return -3;

  kbr = g_malloc0 (sizeof (struct kb_redis));
  kbr->kb.kb_ops = &KBRedisOperations;
  kbr->path = g_strdup (kb_path);

  rc = get_redis_ctx (kbr);
  if (rc < 0)
    {
      redis_delete ((kb_t) kbr);
      return rc;
    }
  if (redis_test_connection (kbr))
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: cannot access redis at '%s'", __func__, kb_path);
      redis_delete ((kb_t) kbr);
      return -1;
    }

  /* Ensure that the new kb is clean before exposing it to callers. */
  if (redis_delete_all (kbr))
    {
      g_warning ("%s: refusing to use Redis DB %u after cleanup failed",
                 __func__, kbr->db);
      redis_delete ((kb_t) kbr);
      return -1;
    }

  *kb = (kb_t) kbr;

  /* Try to make unused memory available for the OS again. */
  if (redis_memory_purge (*kb))
    g_warning ("%s: Memory purge was not successful", __func__);

  return rc;
}

/**
 * @brief Connect to a Knowledge Base object with the given kb_index.
 *
 * @param[in] kb_path   Path to KB.
 * @param[in] kb_index       DB index
 *
 * @return Knowledge Base object, NULL otherwise.
 */
static kb_t
redis_direct_conn (const char *kb_path, const int kb_index,
                   const char *owner_token)
{
  struct kb_redis *kbr;
  redisReply *rep;
  size_t owner_token_len;

  if (kb_path == NULL || kb_index <= 0 || owner_token == NULL
      || owner_token[0] == '\0')
    return NULL;
  owner_token_len = strlen (owner_token);
  if (owner_token_len > 128)
    return NULL;

  kbr = g_malloc0 (sizeof (struct kb_redis));
  kbr->kb.kb_ops = &KBRedisOperations;
  kbr->path = g_strdup (kb_path);

  kbr->rctx = connect_redis (kbr->path, strlen (kbr->path));
  if (kbr->rctx == NULL || kbr->rctx->err)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: redis connection error to %s: %s", __func__, kbr->path,
             kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
      redisFree (kbr->rctx);
      g_free (kbr->path);
      g_free (kbr);
      return NULL;
    }
  kbr->db = kb_index;
  rep =
    redisCommand (kbr->rctx, "HGET %s %d", GLOBAL_DBINDEX_NAME, kb_index);
  if (rep == NULL || rep->type != REDIS_REPLY_STRING
      || rep->len != owner_token_len
      || memcmp (rep->str, owner_token, owner_token_len) != 0)
    {
      if (rep != NULL)
        freeReplyObject (rep);
      redisFree (kbr->rctx);
      g_free (kbr->path);
      g_free (kbr);
      return NULL;
    }
  kbr->owner_token = g_strdup (owner_token);
  freeReplyObject (rep);
  rep = redisCommand (kbr->rctx, "SELECT %d", kb_index);
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      if (rep != NULL)
        freeReplyObject (rep);
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
      g_free (kbr->path);
      g_free (kbr->owner_token);
      g_free (kbr);
      return NULL;
    }
  freeReplyObject (rep);
  return (kb_t) kbr;
}

/**
 * @brief Find an existing Knowledge Base object with key.
 *
 * @param[in] kb_path   Path to KB.
 * @param[in] key       Marker key to search for in KB objects.
 *
 * @return Knowledge Base object, NULL otherwise.
 */
static kb_t
redis_find (const char *kb_path, const char *key)
{
  struct kb_redis *kbr;
  unsigned int i = 1;

  if (kb_path == NULL)
    return NULL;

  kbr = g_malloc0 (sizeof (struct kb_redis));
  kbr->kb.kb_ops = &KBRedisOperations;
  kbr->path = g_strdup (kb_path);

  do
    {
      redisReply *rep;

      kbr->rctx = connect_redis (kbr->path, strlen (kbr->path));
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error to %s: %s", __func__, kbr->path,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          g_free (kbr->path);
          g_free (kbr->owner_token);
          g_free (kbr);
          return NULL;
        }

      if (kbr->max_db == 0)
        fetch_max_db_index (kbr);

      kbr->db = i;
      rep = redisCommand (kbr->rctx, "HGET %s %d", GLOBAL_DBINDEX_NAME, i);
      if (rep == NULL || rep->type != REDIS_REPLY_STRING)
        {
          if (rep != NULL)
            freeReplyObject (rep);
          i++;
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          continue;
        }
      g_free (kbr->owner_token);
      kbr->owner_token = g_strdup (rep->str);
      freeReplyObject (rep);
      rep = redisCommand (kbr->rctx, "SELECT %u", i);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        {
          if (rep != NULL)
            freeReplyObject (rep);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
        }
      else
        {
          freeReplyObject (rep);
          if (key)
            {
              char *tmp = kb_item_get_str (&kbr->kb, key);
              if (tmp)
                {
                  g_free (tmp);
                  return (kb_t) kbr;
                }
            }
          redisFree (kbr->rctx);
        }
      i++;
    }
  while (i < kbr->max_db);

  g_free (kbr->path);
  g_free (kbr->owner_token);
  g_free (kbr);
  return NULL;
}

/**
 * @brief Release a KB item (or a list).
 *
 * @param[in] item Item or list to be release
 */
void
kb_item_free (struct kb_item *item)
{
  while (item != NULL)
    {
      struct kb_item *next;

      next = item->next;
      if (item->type == KB_TYPE_STR && item->v_str != NULL)
        g_free (item->v_str);
      g_free (item);
      item = next;
    }
}

/**
 * @brief Give a single KB item.
 *
 * @param[in] name Name of the item.
 * @param[in] elt A redisReply element where to fetch the item.
 * @param[in] force_int To force string to integer conversion.
 *
 * @return Single retrieve kb_item on success, NULL otherwise.
 */
static struct kb_item *
redis2kbitem_single (const char *name, const redisReply *elt, int force_int)
{
  struct kb_item *item;
  size_t namelen;

  if (elt->type != REDIS_REPLY_STRING && elt->type != REDIS_REPLY_INTEGER)
    return NULL;

  namelen = strlen (name) + 1;

  item = g_malloc0 (sizeof (struct kb_item) + namelen);
  if (elt->type == REDIS_REPLY_INTEGER)
    {
      item->type = KB_TYPE_INT;
      item->v_int = elt->integer;
    }
  else if (force_int)
    {
      item->type = KB_TYPE_INT;
      item->v_int = atoi (elt->str);
    }
  else
    {
      item->type = KB_TYPE_STR;
      item->v_str = memdup (elt->str, elt->len + 1);
      item->len = elt->len;
    }

  item->next = NULL;
  item->namelen = namelen;
  memset (item->name, 0, namelen);
  memcpy (item->name, name, namelen);

  return item;
}

/**
 * @brief Fetch a KB item or list from a redis Reply.
 *
 * @param[in] name Name of the item.
 * @param[in] rep A redisReply element where to fetch the item.
 *
 * @return kb_item or list on success, NULL otherwise.
 */
static struct kb_item *
redis2kbitem (const char *name, const redisReply *rep)
{
  struct kb_item *kbi;

  kbi = NULL;

  switch (rep->type)
    {
      unsigned int i;

    case REDIS_REPLY_STRING:
    case REDIS_REPLY_INTEGER:
      kbi = redis2kbitem_single (name, rep, 0);
      break;

    case REDIS_REPLY_ARRAY:
      for (i = 0; i < rep->elements; i++)
        {
          struct kb_item *tmpitem;

          tmpitem = redis2kbitem_single (name, rep->element[i], 0);
          if (tmpitem == NULL)
            break;

          if (kbi != NULL)
            {
              tmpitem->next = kbi;
              kbi = tmpitem;
            }
          else
            kbi = tmpitem;
        }
      break;

    case REDIS_REPLY_NIL:
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_ERROR:
    default:
      break;
    }

  return kbi;
}

/**
 * @brief Execute a redis command and get a redis reply.
 *
 * @param[in] kbr Subclass of struct kb to connect to.
 * @param[in] fmt Formatted variable argument list with the cmd to be executed.
 *
 * @return Redis reply on success, NULL otherwise.
 */
static redisReply *
redis_cmd (struct kb_redis *kbr, const char *fmt, ...)
{
  redisReply *rep;
  va_list ap, aq;
  int retry = 0;

  va_start (ap, fmt);
  do
    {
      if (get_redis_ctx (kbr) < 0)
        {
          va_end (ap);
          return NULL;
        }

      va_copy (aq, ap);
      rep = redisvCommand (kbr->rctx, fmt, aq);
      va_end (aq);

      if (kbr->rctx->err)
        {
          if (rep != NULL)
            freeReplyObject (rep);

          redis_lnk_reset ((kb_t) kbr);
          retry = !retry;
        }
      else
        retry = 0;
    }
  while (retry);

  va_end (ap);

  return rep;
}

/**
 * @brief Get a single KB element.
 *
 * @param[in] kb KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @param[in] type Desired element type.
 *
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static struct kb_item *
redis_get_single (kb_t kb, const char *name, enum kb_item_type type)
{
  struct kb_item *kbi;
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = redis_kb (kb);
  kbi = NULL;

  rep = redis_cmd (kbr, "LINDEX %s -1", name);
  if (rep == NULL || rep->type != REDIS_REPLY_STRING)
    {
      kbi = NULL;
      goto out;
    }

  kbi = redis2kbitem_single (name, rep, type == KB_TYPE_INT);

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return kbi;
}

/**
 * @brief Get a single KB string item.
 *
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 *
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static char *
redis_get_str (kb_t kb, const char *name)
{
  struct kb_item *kbi;

  kbi = redis_get_single (kb, name, KB_TYPE_STR);
  if (kbi != NULL)
    {
      char *res;

      res = kbi->v_str;
      kbi->v_str = NULL;
      kb_item_free (kbi);
      return res;
    }
  return NULL;
}

/**
 * @brief Atomically admit one bounded scanner result into Redis.
 *
 * The pending budget covers both the producer list and OSPD's replayable
 * claim. A rejected write leaves only a bounded fixed failure marker for OSPD
 * to turn into an interrupted, incomplete scan.
 *
 * @return 0 on success, non-zero when the result was rejected or Redis failed.
 */
static int
redis_push_scanner_result (kb_t kb, const char *value)
{
  struct kb_redis *kbr;
  char *admission_id;
  gboolean retry_warning_logged = FALSE;
  redisReply *rep = NULL;
  int rc = -1;

  if (!value)
    return -1;

  admission_id = gvm_uuid_make ();
  if (!admission_id)
    return -1;

  kbr = redis_kb (kb);
  while (1)
    {
      rep = redis_cmd (
        kbr,
        "EVAL %s 9 %s %s %s %s %s %s %s %s %s %s %b %llu %llu %llu",
        SCANNER_RESULT_ADMISSION_SCRIPT, SCANNER_RESULT_KEY,
        SCANNER_RESULT_CLAIM_KEY, SCANNER_RESULT_ADMISSION_FAILURE_KEY,
        SCANNER_RESULT_PENDING_COUNT_KEY, SCANNER_RESULT_PENDING_BYTES_KEY,
        SCANNER_RESULT_ADMISSION_IDS_KEY,
        SCANNER_RESULT_CLAIM_ADMISSION_IDS_KEY, SCANNER_RESULT_SIZES_KEY,
        SCANNER_RESULT_CLAIM_SIZES_KEY, admission_id, value, strlen (value),
        SCANNER_RESULT_MAX_ITEM_BYTES, SCANNER_RESULT_MAX_PENDING_ITEMS,
        SCANNER_RESULT_MAX_PENDING_BYTES);
      if (rep && rep->type == REDIS_REPLY_INTEGER)
        {
          if (rep->integer == 1)
            rc = 0;
          break;
        }

      if (rep)
        freeReplyObject (rep);
      rep = NULL;
      if (!retry_warning_logged)
        {
          g_warning ("Scanner result delivery lost its Redis connection; "
                     "retrying until Redis recovers or the scanner is "
                     "stopped.");
          retry_warning_logged = TRUE;
        }

      /* Result callers historically ignore this return value. Returning on a
       * transport failure could therefore let a scan complete without the
       * missing evidence. The idempotent admission ID makes retries safe. */
      g_usleep (G_USEC_PER_SEC);
    }

  if (rep)
    freeReplyObject (rep);
  g_free (admission_id);

  return rc;
}

/**
 * @brief Push a new entry under a given key.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Key to push to.
 * @param[in] value Value to push.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_push_str (kb_t kb, const char *name, const char *value)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;

  if (!value)
    return -1;

  if (strcmp (name, SCANNER_RESULT_KEY) == 0)
    return redis_push_scanner_result (kb, value);

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "LPUSH %s %s", name, value);
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Pops a single KB string item.
 *
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the key from where to retrieve.
 *
 * @return A string to be freed or NULL if list is empty or on error.
 */
static char *
redis_pop_str (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  redisReply *rep;
  char *value = NULL;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "RPOP %s", name);
  if (!rep)
    return NULL;

  if (rep->type == REDIS_REPLY_STRING)
    value = g_strdup (rep->str);
  freeReplyObject (rep);

  return value;
}

/**
 * @brief Get a single KB integer item.
 *
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 *
 * @return An integer.
 */
static int
redis_get_int (kb_t kb, const char *name)
{
  struct kb_item *kbi;

  kbi = redis_get_single (kb, name, KB_TYPE_INT);
  if (kbi != NULL)
    {
      int res;

      res = kbi->v_int;
      kb_item_free (kbi);
      return res;
    }
  return -1;
}

/**
 * @brief Get field of a NVT.
 *
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] oid       OID of NVT to get from.
 * @param[in] position  Position of field to get.
 *
 * @return Value of field, NULL otherwise.
 */
static char *
redis_get_nvt (kb_t kb, const char *oid, enum kb_nvt_pos position)
{
  struct kb_redis *kbr;
  redisReply *rep;
  char *res = NULL;

  kbr = redis_kb (kb);
  if (position >= NVT_TIMESTAMP_POS)
    rep = redis_cmd (kbr, "LINDEX filename:%s %d", oid,
                     position - NVT_TIMESTAMP_POS);
  else
    rep = redis_cmd (kbr, "LINDEX nvt:%s %d", oid, position);
  if (!rep)
    return NULL;
  if (rep->type == REDIS_REPLY_INTEGER)
    res = g_strdup_printf ("%lld", rep->integer);
  else if (rep->type == REDIS_REPLY_STRING)
    res = g_strdup (rep->str);
  freeReplyObject (rep);

  return res;
}

/**
 * @brief Get a full NVT.
 *
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] oid       OID of NVT to get.
 *
 * @return nvti_t of NVT, NULL otherwise.
 */
static nvti_t *
redis_get_nvt_all (kb_t kb, const char *oid)
{
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = redis_kb (kb);
  rep =
    redis_cmd (kbr, "LRANGE nvt:%s %d %d", oid, NVT_FILENAME_POS, NVT_NAME_POS);
  if (!rep)
    return NULL;
  if (rep->type != REDIS_REPLY_ARRAY || rep->elements != NVT_NAME_POS + 1)
    {
      freeReplyObject (rep);
      return NULL;
    }
  else
    {
      nvti_t *nvti = nvti_new ();

      nvti_set_oid (nvti, oid);
      nvti_set_required_keys (nvti, rep->element[NVT_REQUIRED_KEYS_POS]->str);
      nvti_set_mandatory_keys (nvti, rep->element[NVT_MANDATORY_KEYS_POS]->str);
      nvti_set_excluded_keys (nvti, rep->element[NVT_EXCLUDED_KEYS_POS]->str);
      nvti_set_required_udp_ports (
        nvti, rep->element[NVT_REQUIRED_UDP_PORTS_POS]->str);
      nvti_set_required_ports (nvti, rep->element[NVT_REQUIRED_PORTS_POS]->str);
      nvti_set_dependencies (nvti, rep->element[NVT_DEPENDENCIES_POS]->str);
      nvti_set_tag (nvti, rep->element[NVT_TAGS_POS]->str);
      nvti_add_refs (nvti, "cve", rep->element[NVT_CVES_POS]->str, "");
      nvti_add_refs (nvti, "bid", rep->element[NVT_BIDS_POS]->str, "");
      nvti_add_refs (nvti, NULL, rep->element[NVT_XREFS_POS]->str, "");
      nvti_set_category (nvti, atoi (rep->element[NVT_CATEGORY_POS]->str));
      nvti_set_family (nvti, rep->element[NVT_FAMILY_POS]->str);
      nvti_set_name (nvti, rep->element[NVT_NAME_POS]->str);

      freeReplyObject (rep);
      return nvti;
    }
}

/**
 * @brief Get all items stored under a given name.
 *
 * @param[in] kb  KB handle where to fetch the items.
 * @param[in] name  Name of the elements to retrieve.
 *
 * @return Linked struct kb_item instances to be freed with kb_item_free() or
 *         NULL if no element was found or on error.
 */
static struct kb_item *
redis_get_all (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  struct kb_item *kbi;
  redisReply *rep;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "LRANGE %s 0 -1", name);
  if (rep == NULL)
    return NULL;

  kbi = redis2kbitem (name, rep);

  freeReplyObject (rep);

  return kbi;
}

/**
 * @brief Get all items stored under a given pattern.
 *
 * @param[in] kb  KB handle where to fetch the items.
 * @param[in] pattern  '*' pattern of the elements to retrieve.
 *
 * @return Linked struct kb_item instances to be freed with kb_item_free() or
 *         NULL if no element was found or on error.
 */
static struct kb_item *
redis_get_pattern (kb_t kb, const char *pattern)
{
  struct kb_redis *kbr;
  struct kb_item *kbi = NULL;
  redisReply *rep;
  unsigned int i;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "KEYS %s", pattern);
  if (!rep)
    return NULL;
  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return NULL;
    }

  if (get_redis_ctx (kbr) < 0)
    return NULL;
  for (i = 0; i < rep->elements; i++)
    redisAppendCommand (kbr->rctx, "LRANGE %s 0 -1", rep->element[i]->str);

  for (i = 0; i < rep->elements; i++)
    {
      struct kb_item *tmp;
      redisReply *rep_range;

      redisGetReply (kbr->rctx, (void **) &rep_range);
      if (!rep)
        continue;
      tmp = redis2kbitem (rep->element[i]->str, rep_range);
      if (!tmp)
        {
          freeReplyObject (rep_range);
          continue;
        }

      if (kbi)
        {
          struct kb_item *tmp2;

          tmp2 = tmp;
          while (tmp->next)
            tmp = tmp->next;
          tmp->next = kbi;
          kbi = tmp2;
        }
      else
        kbi = tmp;
      freeReplyObject (rep_range);
    }

  freeReplyObject (rep);
  return kbi;
}

/**
 * @brief Get all NVT OIDs.
 *
 * @param[in] kb  KB handle where to fetch the items.
 *
 * @return Linked list of all OIDs or NULL.
 */
static GSList *
redis_get_oids (kb_t kb)
{
  struct kb_redis *kbr;
  redisReply *rep;
  GSList *list = NULL;
  size_t i;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "KEYS nvt:*");
  if (!rep)
    return NULL;

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return NULL;
    }

  /* Fetch OID values from key names nvt:OID. */
  for (i = 0; i < rep->elements; i++)
    list = g_slist_prepend (list, g_strdup (rep->element[i]->str + 4));
  freeReplyObject (rep);

  return list;
}

/**
 * @brief Count all items stored under a given pattern.
 *
 * @param[in] kb  KB handle where to count the items.
 * @param[in] pattern  '*' pattern of the elements to count.
 *
 * @return Count of items.
 */
static size_t
redis_count (kb_t kb, const char *pattern)
{
  struct kb_redis *kbr;
  redisReply *rep;
  size_t count;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "KEYS %s", pattern);
  if (rep == NULL)
    return 0;

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return 0;
    }

  count = rep->elements;
  freeReplyObject (rep);
  return count;
}

/**
 * @brief Delete all entries under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_del_items (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "DEL %s", name);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new unique and volatile entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] expire Item expire.
 * @param[in] len  Value length. Used for blobs.
 * @param[in] pos  Which position the value is appended to. 0 for right,
 *                 1 for left position in the list.
 *
 * @return 0 on success, -1 on error.
 */
static int
redis_add_str_unique_volatile (kb_t kb, const char *name, const char *str,
                               int expire, size_t len, int pos)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;
  redisContext *ctx;

  kbr = redis_kb (kb);
  if (get_redis_ctx (kbr) < 0)
    return -1;
  ctx = kbr->rctx;

  /* Some VTs still rely on values being unique (ie. a value inserted multiple
   * times, will only be present once.)
   * Once these are fixed, the LREM becomes redundant and should be removed.
   */
  if (len == 0)
    {
      redisAppendCommand (ctx, "LREM %s 1 %s", name, str);
      redisAppendCommand (ctx, "%s %s %s", pos ? "LPUSH" : "RPUSH", name, str);
      redisAppendCommand (ctx, "EXPIRE %s %d", name, expire);
      /* Check LREM reply. */
      redisGetReply (ctx, (void **) &rep);
      if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
        g_debug ("Key '%s' already contained value '%s'", name, str);
      freeReplyObject (rep);
      /* Check PUSH reply. */
      redisGetReply (ctx, (void **) &rep);
      if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
        {
          rc = -1;
          goto out;
        }
      /* Check EXPIRE reply. */
      redisGetReply (ctx, (void **) &rep);
      if (rep == NULL || rep->type == REDIS_REPLY_ERROR
          || (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer != 1))
        {
          g_warning ("%s: Not able to set expire", __func__);
          rc = -1;
          goto out;
        }
    }
  else
    {
      redisAppendCommand (ctx, "LREM %s 1 %b", name, str, len);
      redisAppendCommand (ctx, "%s %s %b", pos ? "LPUSH" : "RPUSH", name, str,
                          len);
      redisAppendCommand (ctx, "EXPIRE %s %d", name, expire);
      /* Check LREM reply. */
      redisGetReply (ctx, (void **) &rep);
      if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
        g_debug ("Key '%s' already contained string '%s'", name, str);
      freeReplyObject (rep);
      /* Check PUSH reply. */
      redisGetReply (ctx, (void **) &rep);
      if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
        {
          rc = -1;
          goto out;
        }
      /* Check EXPIRE reply. */
      redisGetReply (ctx, (void **) &rep);
      if (rep == NULL || rep->type == REDIS_REPLY_ERROR
          || (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer != 1))
        {
          g_warning ("%s: Not able to set expire", __func__);
          rc = -1;
          goto out;
        }
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @param[in] pos  Which position the value is appended to. 0 for right,
 *                 1 for left position in the list.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_add_str_unique (kb_t kb, const char *name, const char *str, size_t len,
                      int pos)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;
  redisContext *ctx;

  kbr = redis_kb (kb);
  if (get_redis_ctx (kbr) < 0)
    return -1;
  ctx = kbr->rctx;

  /* Some VTs still rely on values being unique (ie. a value inserted multiple
   * times, will only be present once.)
   * Once these are fixed, the LREM becomes redundant and should be removed.
   */
  if (len == 0)
    {
      redisAppendCommand (ctx, "LREM %s 1 %s", name, str);
      redisAppendCommand (ctx, "%s %s %s", pos ? "LPUSH" : "RPUSH", name, str);
      redisGetReply (ctx, (void **) &rep);
      if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
        g_debug ("Key '%s' already contained value '%s'", name, str);
      freeReplyObject (rep);
      redisGetReply (ctx, (void **) &rep);
    }
  else
    {
      redisAppendCommand (ctx, "LREM %s 1 %b", name, str, len);
      redisAppendCommand (ctx, "%s %s %b", pos ? "LPUSH" : "RPUSH", name, str,
                          len);
      redisGetReply (ctx, (void **) &rep);
      if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
        g_debug ("Key '%s' already contained string '%s'", name, str);
      freeReplyObject (rep);
      redisGetReply (ctx, (void **) &rep);
    }
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_add_str (kb_t kb, const char *name, const char *str, size_t len)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);
  if (len == 0)
    rep = redis_cmd (kbr, "RPUSH %s %s", name, str);
  else
    rep = redis_cmd (kbr, "RPUSH %s %b", name, str, len);
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep)
    freeReplyObject (rep);
  return rc;
}

/**
 * @brief Set (replace) a new entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @param[in] len  Value length. Used for blobs.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_set_str (kb_t kb, const char *name, const char *val, size_t len)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  redisContext *ctx;
  int rc = 0, i = 4;

  kbr = redis_kb (kb);
  if (get_redis_ctx (kbr) < 0)
    return -1;
  ctx = kbr->rctx;
  redisAppendCommand (ctx, "MULTI");
  redisAppendCommand (ctx, "DEL %s", name);
  if (len == 0)
    redisAppendCommand (ctx, "RPUSH %s %s", name, val);
  else
    redisAppendCommand (ctx, "RPUSH %s %b", name, val, len);
  redisAppendCommand (ctx, "EXEC");
  while (i--)
    {
      redisGetReply (ctx, (void **) &rep);
      if (!rep || rep->type == REDIS_REPLY_ERROR)
        rc = -1;
      if (rep)
        freeReplyObject (rep);
    }

  return rc;
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @param[in] expire Item expire.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_add_int_unique_volatile (kb_t kb, const char *name, int val, int expire)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;
  redisContext *ctx;

  kbr = redis_kb (kb);
  if (get_redis_ctx (kbr) < 0)
    return -1;
  ctx = kbr->rctx;
  redisAppendCommand (ctx, "LREM %s 1 %d", name, val);
  redisAppendCommand (ctx, "RPUSH %s %d", name, val);
  redisAppendCommand (ctx, "EXPIRE %s %d", name, expire);
  /* Check LREM reply. */
  redisGetReply (ctx, (void **) &rep);
  if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
    g_debug ("Key '%s' already contained integer '%d'", name, val);
  freeReplyObject (rep);
  /* Check PUSH reply. */
  redisGetReply (ctx, (void **) &rep);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto out;
    }
  /* Check EXPIRE reply. */
  redisGetReply (ctx, (void **) &rep);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR
      || (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer != 1))
    {
      g_warning ("%s: Not able to set expire", __func__);
      rc = -1;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_add_int_unique (kb_t kb, const char *name, int val)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;
  redisContext *ctx;

  kbr = redis_kb (kb);
  if (get_redis_ctx (kbr) < 0)
    return -1;
  ctx = kbr->rctx;
  redisAppendCommand (ctx, "LREM %s 1 %d", name, val);
  redisAppendCommand (ctx, "RPUSH %s %d", name, val);
  redisGetReply (ctx, (void **) &rep);
  if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
    g_debug ("Key '%s' already contained integer '%d'", name, val);
  freeReplyObject (rep);
  redisGetReply (ctx, (void **) &rep);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_add_int (kb_t kb, const char *name, int val)
{
  redisReply *rep;
  int rc = 0;

  rep = redis_cmd (redis_kb (kb), "RPUSH %s %d", name, val);
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Set (replace) a new entry under a given name.
 *
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_set_int (kb_t kb, const char *name, int val)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  redisContext *ctx;
  int rc = 0, i = 4;

  kbr = redis_kb (kb);
  if (get_redis_ctx (redis_kb (kb)) < 0)
    return -1;
  ctx = kbr->rctx;
  redisAppendCommand (ctx, "MULTI");
  redisAppendCommand (ctx, "DEL %s", name);
  redisAppendCommand (ctx, "RPUSH %s %d", name, val);
  redisAppendCommand (ctx, "EXEC");
  while (i--)
    {
      redisGetReply (ctx, (void **) &rep);
      if (!rep || rep->type == REDIS_REPLY_ERROR)
        rc = -1;
      if (rep)
        freeReplyObject (rep);
    }

  return rc;
}

/**
 * @brief Insert a new nvt.
 *
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] nvt       nvt to store.
 * @param[in] filename  Path to nvt to store.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_add_nvt (kb_t kb, const nvti_t *nvt, const char *filename)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;
  unsigned int i;
  gchar *cves, *bids, *xrefs;

  if (!nvt || !filename)
    return -1;

  cves = nvti_refs (nvt, "cve", "", 0);
  bids = nvti_refs (nvt, "bid", "", 0);
  xrefs = nvti_refs (nvt, NULL, "cve,bid", 1);

  kbr = redis_kb (kb);
  rep = redis_cmd (
    kbr, "RPUSH nvt:%s %s %s %s %s %s %s %s %s %s %s %s %d %s %s",
    nvti_oid (nvt), filename,
    nvti_required_keys (nvt) ? nvti_required_keys (nvt) : "",
    nvti_mandatory_keys (nvt) ? nvti_mandatory_keys (nvt) : "",
    nvti_excluded_keys (nvt) ? nvti_excluded_keys (nvt) : "",
    nvti_required_udp_ports (nvt) ? nvti_required_udp_ports (nvt) : "",
    nvti_required_ports (nvt) ? nvti_required_ports (nvt) : "",
    nvti_dependencies (nvt) ? nvti_dependencies (nvt) : "",
    nvti_tag (nvt) ? nvti_tag (nvt) : "", cves ? cves : "", bids ? bids : "",
    xrefs ? xrefs : "", nvti_category (nvt), nvti_family (nvt),
    nvti_name (nvt));
  g_free (cves);
  g_free (bids);
  g_free (xrefs);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep != NULL)
    freeReplyObject (rep);

  if (nvti_pref_len (nvt))
    redis_cmd (kbr, "DEL oid:%s:prefs", nvti_oid (nvt));
  for (i = 0; i < nvti_pref_len (nvt); i++)
    {
      const nvtpref_t *pref = nvti_pref (nvt, i);

      rep = redis_cmd (kbr, "RPUSH oid:%s:prefs %d|||%s|||%s|||%s",
                       nvti_oid (nvt), nvtpref_id (pref), nvtpref_name (pref),
                       nvtpref_type (pref), nvtpref_default (pref));
      if (!rep || rep->type == REDIS_REPLY_ERROR)
        rc = -1;
      if (rep)
        freeReplyObject (rep);
    }
  rep = redis_cmd (kbr, "RPUSH filename:%s %lu %s", filename, time (NULL),
                   nvti_oid (nvt));
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep)
    freeReplyObject (rep);
  return rc;
}

/**
 * @brief Reset connection to the KB. This is called after each fork() to make
 *        sure connections aren't shared between concurrent processes.
 *
 * @param[in] kb KB handle.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_lnk_reset (kb_t kb)
{
  struct kb_redis *kbr;

  kbr = redis_kb (kb);

  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  return 0;
}

/**
 * @brief Flush all the KB's content. Delete all namespaces.
 *
 * @param[in] kb        KB handle.
 * @param[in] except    Don't flush DB with except key.
 *
 * @return 0 on success, non-null on error.
 */
static int
redis_flush_all (kb_t kb, const char *except)
{
  unsigned int i = 1;
  int rc = 0;
  struct kb_redis *kbr;

  kbr = redis_kb (kb);
  if (kbr->rctx)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  g_debug ("%s: deleting all DBs at %s except %s", __func__, kbr->path, except);
  do
    {
      redisReply *rep;

      kbr->rctx = connect_redis (kbr->path, strlen (kbr->path));
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error to %s: %s", __func__, kbr->path,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          rc = -1;
          goto cleanup;
        }

      kbr->db = i;
      rep = redisCommand (kbr->rctx, "HGET %s %d", GLOBAL_DBINDEX_NAME, i);
      if (rep == NULL || rep->type != REDIS_REPLY_STRING)
        {
          freeReplyObject (rep);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          i++;
          continue;
        }
      g_free (kbr->owner_token);
      kbr->owner_token = g_strdup (rep->str);
      freeReplyObject (rep);
      rep = redisCommand (kbr->rctx, "SELECT %u", i);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        {
          freeReplyObject (rep);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          rc = -1;
          goto cleanup;
        }
      else
        {
          freeReplyObject (rep);
          /* Don't remove DB if it has "except" key. */
          if (except)
            {
              char *tmp = kb_item_get_str (kb, except);
              if (tmp)
                {
                  g_free (tmp);
                  i++;
                  redisFree (kbr->rctx);
                  kbr->rctx = NULL;
                  continue;
                }
            }
          rc = redis_flush_and_release_db (kbr);
          if (rc != 0)
            {
              g_warning (
                "%s: refusing to delete Redis DB %u without its exact owner "
                "token",
                __func__, kbr->db);
              goto cleanup;
            }
          g_clear_pointer (&kbr->owner_token, g_free);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
        }
      i++;
    }
  while (i < kbr->max_db);

cleanup:
  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }
  g_free (kbr->path);
  g_free (kbr->owner_token);
  g_free (kb);
  return rc;
}

/**
 * @brief Save all the elements from the KB.
 *
 * @param[in] kb        KB handle.
 *
 * @return 0 on success, -1 on error.
 */
static int
redis_save (kb_t kb)
{
  int rc;
  redisReply *rep;
  struct kb_redis *kbr;

  kbr = redis_kb (kb);
  g_debug ("%s: saving all elements from KB #%u", __func__, kbr->db);
  rep = redis_cmd (kbr, "SAVE");
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Delete all the KB's content.
 *
 * @param[in] kbr Subclass of struct kb.
 *
 * @return 0 on success, non-null on error.
 */
int
redis_delete_all (struct kb_redis *kbr)
{
  int rc;
  redisReply *rep;
  struct sigaction new_action, original_action;

  /* Ignore SIGPIPE, in case of a lost connection. */
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

  if (kbr)
    g_debug ("%s: deleting all elements from KB #%u", __func__, kbr->db);
  rep = redis_cmd (kbr, "FLUSHDB");
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (sigaction (SIGPIPE, &original_action, NULL))
    return -1;
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Default KB operations.
 *
 * No selection mechanism is provided yet since there's only one
 * implementation (redis-based).
 */
static const struct kb_operations KBRedisOperations = {
  .kb_new = redis_new,
  .kb_find = redis_find,
  .kb_delete = redis_delete,
  .kb_get_single = redis_get_single,
  .kb_get_str = redis_get_str,
  .kb_get_int = redis_get_int,
  .kb_get_nvt = redis_get_nvt,
  .kb_get_nvt_all = redis_get_nvt_all,
  .kb_get_nvt_oids = redis_get_oids,
  .kb_push_str = redis_push_str,
  .kb_pop_str = redis_pop_str,
  .kb_get_all = redis_get_all,
  .kb_get_pattern = redis_get_pattern,
  .kb_count = redis_count,
  .kb_add_str = redis_add_str,
  .kb_add_str_unique = redis_add_str_unique,
  .kb_add_str_unique_volatile = redis_add_str_unique_volatile,
  .kb_set_str = redis_set_str,
  .kb_add_int = redis_add_int,
  .kb_add_int_unique = redis_add_int_unique,
  .kb_add_int_unique_volatile = redis_add_int_unique_volatile,
  .kb_set_int = redis_set_int,
  .kb_add_nvt = redis_add_nvt,
  .kb_del_items = redis_del_items,
  .kb_lnk_reset = redis_lnk_reset,
  .kb_save = redis_save,
  .kb_flush = redis_flush_all,
  .kb_direct_conn = redis_direct_conn,
  .kb_get_kb_index = redis_get_kb_index,
  .kb_get_owner_token = redis_get_owner_token};

const struct kb_operations *KBDefaultOperations = &KBRedisOperations;
