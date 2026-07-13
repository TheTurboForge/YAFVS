/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_socket_resources.h"

#include <string.h>
#include <sys/select.h>
#include <unistd.h>

struct nasl_udp_socket_record
{
  int socket_fd;
  int length;
  char *data;
};

static void
nasl_udp_socket_record_free (gpointer value)
{
  struct nasl_udp_socket_record *record = value;

  if (record == NULL)
    return;
  if (record->socket_fd >= 0)
    close (record->socket_fd);
  g_free (record->data);
  g_free (record);
}

static GHashTable *
nasl_udp_socket_cache_new (void)
{
  return g_hash_table_new_full (g_int_hash, g_int_equal, g_free,
                                nasl_udp_socket_record_free);
}

gboolean
nasl_receive_length_is_valid (long int length)
{
  return length > 0 && length <= NASL_MAX_RECEIVE_SIZE;
}

gboolean
nasl_receive_line_length_is_valid (long int length)
{
  return length > 0 && length < NASL_MAX_RECEIVE_SIZE;
}

gboolean
nasl_socket_fd_is_selectable (int socket_fd)
{
  return socket_fd >= 0 && socket_fd < FD_SETSIZE;
}

gboolean
nasl_udp_socket_register (GHashTable **cache, int socket_fd)
{
  struct nasl_udp_socket_record *record;
  int *key;

  if (cache == NULL || !nasl_socket_fd_is_selectable (socket_fd))
    return FALSE;
  if (*cache == NULL)
    *cache = nasl_udp_socket_cache_new ();
  if (g_hash_table_contains (*cache, &socket_fd))
    return TRUE;
  if (g_hash_table_size (*cache) >= NASL_MAX_UDP_SOCKETS)
    return FALSE;

  key = g_new (int, 1);
  *key = socket_fd;
  record = g_new0 (struct nasl_udp_socket_record, 1);
  record->socket_fd = socket_fd;
  g_hash_table_insert (*cache, key, record);
  return TRUE;
}

gboolean
nasl_udp_socket_is_owned (GHashTable *cache, int socket_fd)
{
  return cache != NULL && g_hash_table_contains (cache, &socket_fd);
}

gboolean
nasl_udp_socket_store (GHashTable *cache, int socket_fd, const char *data,
                       int length)
{
  struct nasl_udp_socket_record *record;

  if (cache == NULL || length < 0 || (length > 0 && data == NULL))
    return FALSE;

  if (!nasl_udp_socket_is_owned (cache, socket_fd))
    return FALSE;
  record = g_hash_table_lookup (cache, &socket_fd);
  g_free (record->data);
  record->data = length > 0 ? g_malloc ((gsize) length) : NULL;
  if (length > 0)
    memcpy (record->data, data, (gsize) length);
  record->length = length;
  return TRUE;
}

const char *
nasl_udp_socket_data (GHashTable *cache, int socket_fd, int *length)
{
  struct nasl_udp_socket_record *record;

  if (cache == NULL)
    return NULL;
  record = g_hash_table_lookup (cache, &socket_fd);
  if (record == NULL || record->data == NULL)
    return NULL;
  if (length)
    *length = record->length;
  return record->data;
}

gboolean
nasl_udp_socket_close (GHashTable *cache, int socket_fd)
{
  return cache != NULL && g_hash_table_remove (cache, &socket_fd);
}

guint
nasl_udp_socket_count (GHashTable *cache)
{
  return cache == NULL ? 0 : g_hash_table_size (cache);
}

void
nasl_udp_socket_cache_destroy (GHashTable **cache)
{
  if (cache == NULL || *cache == NULL)
    return;
  g_hash_table_destroy (*cache);
  *cache = NULL;
}
