/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_socket_resources.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static int
test_fd (void)
{
  int fd = socket (AF_INET, SOCK_DGRAM, 0);

  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (fcntl (fd, F_SETFD, FD_CLOEXEC), ==, 0);
  return fd;
}

static void
test_select_descriptor_budget (void)
{
  g_assert_false (nasl_socket_fd_is_selectable (-1));
  g_assert_true (nasl_socket_fd_is_selectable (0));
  g_assert_true (nasl_socket_fd_is_selectable (FD_SETSIZE - 1));
  g_assert_false (nasl_socket_fd_is_selectable (FD_SETSIZE));
}

static void
assert_closed (int fd)
{
  errno = 0;
  g_assert_cmpint (fcntl (fd, F_GETFD), ==, -1);
  g_assert_cmpint (errno, ==, EBADF);
}

static void
test_receive_length_budget (void)
{
  g_assert_false (nasl_receive_length_is_valid (-1));
  g_assert_false (nasl_receive_length_is_valid (0));
  g_assert_true (nasl_receive_length_is_valid (65536));
  g_assert_true (nasl_receive_length_is_valid (NASL_MAX_RECEIVE_SIZE));
  g_assert_false (nasl_receive_length_is_valid (NASL_MAX_RECEIVE_SIZE + 1));
  g_assert_true (nasl_receive_line_length_is_valid (NASL_MAX_RECEIVE_SIZE - 1));
  g_assert_false (nasl_receive_line_length_is_valid (NASL_MAX_RECEIVE_SIZE));
}

static void
test_store_replaces_and_destroy_closes (void)
{
  const char first[] = {'a', '\0', 'b'};
  const char second[] = {'x', 'y'};
  GHashTable *cache = NULL;
  const char *stored;
  int length = -1;
  int fd = test_fd ();

  g_assert_true (nasl_udp_socket_register (&cache, fd));
  g_assert_true (nasl_udp_socket_is_owned (cache, fd));
  g_assert_true (nasl_udp_socket_store (cache, fd, first, sizeof (first)));
  stored = nasl_udp_socket_data (cache, fd, &length);
  g_assert_cmpint (length, ==, sizeof (first));
  g_assert_cmpmem (stored, length, first, sizeof (first));

  g_assert_true (nasl_udp_socket_store (cache, fd, second, sizeof (second)));
  stored = nasl_udp_socket_data (cache, fd, &length);
  g_assert_cmpint (length, ==, sizeof (second));
  g_assert_cmpmem (stored, length, second, sizeof (second));

  nasl_udp_socket_cache_destroy (&cache);
  g_assert_null (cache);
  assert_closed (fd);
}

static void
test_store_does_not_adopt_reused_descriptor (void)
{
  const char payload[] = "data";
  GHashTable *cache = NULL;
  int owned_fd = test_fd ();
  int replacement_fd;

  g_assert_true (nasl_udp_socket_register (&cache, owned_fd));
  g_assert_true (nasl_udp_socket_close (cache, owned_fd));
  g_assert_false (nasl_udp_socket_is_owned (cache, owned_fd));
  assert_closed (owned_fd);

  replacement_fd = test_fd ();
  if (replacement_fd != owned_fd)
    {
      g_assert_cmpint (dup2 (replacement_fd, owned_fd), ==, owned_fd);
      close (replacement_fd);
      replacement_fd = owned_fd;
    }

  g_assert_false (
    nasl_udp_socket_store (cache, replacement_fd, payload, sizeof (payload)));
  g_assert_false (nasl_udp_socket_is_owned (cache, replacement_fd));
  nasl_udp_socket_cache_destroy (&cache);
  g_assert_cmpint (fcntl (replacement_fd, F_GETFD), !=, -1);
  close (replacement_fd);
}

static void
test_remove_closes_descriptor (void)
{
  GHashTable *cache = NULL;
  int fd = test_fd ();

  g_assert_true (nasl_udp_socket_register (&cache, fd));
  g_assert_true (nasl_udp_socket_close (cache, fd));
  g_assert_cmpuint (nasl_udp_socket_count (cache), ==, 0);
  assert_closed (fd);
  nasl_udp_socket_cache_destroy (&cache);
}

static void
test_socket_limit_preserves_rejected_descriptor (void)
{
  GHashTable *cache = NULL;
  int first_fd = -1;
  int rejected_fd;
  guint index;

  for (index = 0; index < NASL_MAX_UDP_SOCKETS; index++)
    {
      int fd = test_fd ();
      if (first_fd < 0)
        first_fd = fd;
      g_assert_true (nasl_udp_socket_register (&cache, fd));
    }
  g_assert_cmpuint (nasl_udp_socket_count (cache), ==, NASL_MAX_UDP_SOCKETS);

  rejected_fd = test_fd ();
  g_assert_false (nasl_udp_socket_register (&cache, rejected_fd));
  g_assert_cmpint (fcntl (rejected_fd, F_GETFD), !=, -1);

  nasl_udp_socket_cache_destroy (&cache);
  assert_closed (first_fd);
  g_assert_cmpint (fcntl (rejected_fd, F_GETFD), !=, -1);
  close (rejected_fd);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/socket/receive-length", test_receive_length_budget);
  g_test_add_func ("/nasl/socket/select-descriptor",
                   test_select_descriptor_budget);
  g_test_add_func ("/nasl/socket/store-destroy",
                   test_store_replaces_and_destroy_closes);
  g_test_add_func ("/nasl/socket/no-adopt-reused-fd",
                   test_store_does_not_adopt_reused_descriptor);
  g_test_add_func ("/nasl/socket/remove-close", test_remove_closes_descriptor);
  g_test_add_func ("/nasl/socket/descriptor-limit",
                   test_socket_limit_preserves_rejected_descriptor);
  return g_test_run ();
}
