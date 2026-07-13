/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef NASL_SOCKET_RESOURCES_H
#define NASL_SOCKET_RESOURCES_H

#include <glib.h>

/* Match the scanner's safe TCP concurrency ceiling for per-plugin UDP
 * ownership. The retained feed's largest literal receive is 64 KiB; 16 MiB
 * leaves ample protocol headroom without permitting script-selected unbounded
 * allocation. */
#define NASL_MAX_UDP_SOCKETS 128U
#define NASL_MAX_RECEIVE_SIZE (16L * 1024L * 1024L)

gboolean
nasl_receive_length_is_valid (long int length);

gboolean
nasl_receive_line_length_is_valid (long int length);

gboolean
nasl_socket_fd_is_selectable (int socket_fd);

/* Successful registration transfers descriptor-close ownership to the cache.
 * A rejected descriptor remains owned by the caller. */
gboolean
nasl_udp_socket_register (GHashTable **cache, int socket_fd);

gboolean
nasl_udp_socket_is_owned (GHashTable *cache, int socket_fd);

gboolean
nasl_udp_socket_store (GHashTable *cache, int socket_fd, const char *data,
                       int length);

const char *
nasl_udp_socket_data (GHashTable *cache, int socket_fd, int *length);

gboolean
nasl_udp_socket_close (GHashTable *cache, int socket_fd);

guint
nasl_udp_socket_count (GHashTable *cache);

void
nasl_udp_socket_cache_destroy (GHashTable **cache);

#endif
