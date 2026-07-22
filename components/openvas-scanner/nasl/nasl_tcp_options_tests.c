/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_tcp_options.h"

#include <glib.h>
#include <netinet/tcp.h>
#include <string.h>

static void
test_parses_valid_options (void)
{
  const uint8_t options[] = {
    TCPOPT_NOP,
    TCPOPT_MAXSEG,
    4,
    0x05,
    0xb4,
    TCPOPT_WINDOW,
    3,
    7,
    TCPOPT_SACK_PERMITTED,
    2,
    TCPOPT_TIMESTAMP,
    10,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    2,
    TCPOPT_EOL,
  };
  struct tcp_options parsed = {0};

  g_assert_true (nasl_parse_tcp_options (options, sizeof (options), &parsed));
  g_assert_cmpuint (parsed.mss.kind, ==, TCPOPT_MAXSEG);
  g_assert_cmpuint (parsed.wscale.wscale, ==, 7);
  g_assert_cmpuint (parsed.sack_perm.kind, ==, TCPOPT_SACK_PERMITTED);
  g_assert_cmpuint (parsed.tstamp.kind, ==, TCPOPT_TIMESTAMP);
}

static void
test_rejects_zero_length_sack (void)
{
  const uint8_t options[] = {TCPOPT_SACK, 0};
  struct tcp_options parsed = {0};

  g_assert_false (nasl_parse_tcp_options (options, sizeof (options), &parsed));
}

static void
test_rejects_truncated_timestamp (void)
{
  const uint8_t options[] = {TCPOPT_TIMESTAMP, 10, 0, 0};
  struct tcp_options parsed = {0};

  g_assert_false (nasl_parse_tcp_options (options, sizeof (options), &parsed));
}

static void
test_rejects_missing_length (void)
{
  const uint8_t options[] = {TCPOPT_MAXSEG};
  struct tcp_options parsed = {0};

  g_assert_false (nasl_parse_tcp_options (options, sizeof (options), &parsed));
}

static void
test_stops_safely_at_unknown_option (void)
{
  const uint8_t options[] = {TCPOPT_WINDOW, 3, 7, 0xfe, 2};
  struct tcp_options parsed = {0};

  g_assert_true (nasl_parse_tcp_options (options, sizeof (options), &parsed));
  g_assert_cmpuint (parsed.wscale.wscale, ==, 7);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/tcp-options/valid", test_parses_valid_options);
  g_test_add_func ("/nasl/tcp-options/zero-length-sack",
                   test_rejects_zero_length_sack);
  g_test_add_func ("/nasl/tcp-options/truncated-timestamp",
                   test_rejects_truncated_timestamp);
  g_test_add_func ("/nasl/tcp-options/missing-length",
                   test_rejects_missing_length);
  g_test_add_func ("/nasl/tcp-options/unknown",
                   test_stops_safely_at_unknown_option);
  return g_test_run ();
}
