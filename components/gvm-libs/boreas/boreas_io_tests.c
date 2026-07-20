/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "boreas_io.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (boreas_io);
BeforeEach (boreas_io)
{
}
AfterEach (boreas_io)
{
}

Ensure (boreas_io, scanner_result_messages_use_versioned_json)
{
  gchar *limit = host_limit_result_message (7);
  gchar *dead = dead_host_result_message (3);

  assert_that (
    limit,
    is_equal_to_string (
      "{\"version\":1,\"result_type\":\"ERRMSG\",\"host_ip\":\"\","
      "\"host_name\":\" \",\"port\":\" \",\"oid\":\" \","
      "\"value\":\"Maximum number of allowed scans reached. There may still "
      "be alive hosts available which are not scanned. Number of alive hosts "
      "not scanned: [7]\",\"uri\":\"\"}"));
  assert_that (dead,
               is_equal_to_string (
                 "{\"version\":1,\"result_type\":\"DEADHOST\",\"host_ip\":\"\","
                 "\"host_name\":\" \",\"port\":\" \",\"oid\":\" \","
                 "\"value\":\"3\",\"uri\":\"\"}"));

  g_free (limit);
  g_free (dead);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, boreas_io,
                         scanner_result_messages_use_versioned_json);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
