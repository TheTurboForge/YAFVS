/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_telnet_copy.h"

#include <glib.h>
#include <string.h>

static void
assert_copy (size_t length)
{
  unsigned char *source = g_malloc (length == 0 ? 1 : length);
  unsigned char *destination = g_malloc (length + 1);
  size_t offset;

  for (offset = 0; offset < length; offset++)
    source[offset] = (unsigned char) ((offset % 251) + 1);
  if (length > 2)
    source[length / 2] = '\0';

  memset (destination, 0xa5, length + 1);
  nasl_telnet_copy_response (destination, source, length);

  g_assert_cmpmem (destination, length, source, length);
  g_assert_cmpuint (destination[length], ==, '\0');

  g_free (destination);
  g_free (source);
}

static void
test_empty_response (void)
{
  assert_copy (0);
}

static void
test_one_byte_response (void)
{
  assert_copy (1);
}

static void
test_partial_response (void)
{
  assert_copy (1023);
}

static void
test_full_response (void)
{
  assert_copy (1024);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/telnet/empty", test_empty_response);
  g_test_add_func ("/nasl/telnet/one-byte", test_one_byte_response);
  g_test_add_func ("/nasl/telnet/partial", test_partial_response);
  g_test_add_func ("/nasl/telnet/full", test_full_response);

  return g_test_run ();
}
